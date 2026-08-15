import { randomUUID } from "node:crypto";

import {
  SSEClientTransport,
  SseError,
} from "@modelcontextprotocol/sdk/client/sse.js";
import { getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  DatabaseMcpServer,
  McpServerErrorStatusEnum,
  McpServerTypeEnum,
} from "@repo/zod-types";
import express from "express";
import { findActualExecutable } from "spawn-rx";
import { z } from "zod";

import logger from "@/utils/logger";

import { mcpServersRepository } from "../../db/repositories";
import mcpProxy from "../../lib/mcp-proxy";
import { transformDockerUrl } from "../../lib/metamcp/client";
import { mcpServerPool } from "../../lib/metamcp/mcp-server-pool";
import { resolveEnvVariables } from "../../lib/metamcp/utils";
import { ProcessManagedStdioTransport } from "../../lib/stdio-transport/process-managed-transport";
import { assertPublicMcpUrl, createGuardedFetch } from "./url-guard";

const SSE_HEADERS_PASSTHROUGH = ["authorization"];
const STREAMABLE_HTTP_HEADERS_PASSTHROUGH = [
  "authorization",
  "mcp-session-id",
  "last-event-id",
];

const defaultEnvironment = {
  ...getDefaultEnvironment(),
};

// Cooldown mechanism for failed STDIO commands
const STDIO_COOLDOWN_DURATION = 10000; // 10 seconds
const stdioCommandCooldowns = new Map<string, number>();

// Function to create a key for STDIO commands
const createStdioKey = (
  command: string,
  args: string[],
  env: Record<string, string>,
) => {
  return `${command}:${args.join(",")}:${JSON.stringify(env)}`;
};

// Function to check if a STDIO command is in cooldown
const isStdioInCooldown = (
  command: string,
  args: string[],
  env: Record<string, string>,
): boolean => {
  const key = createStdioKey(command, args, env);
  const cooldownEnd = stdioCommandCooldowns.get(key);
  if (cooldownEnd && Date.now() < cooldownEnd) {
    return true;
  }
  if (cooldownEnd && Date.now() >= cooldownEnd) {
    stdioCommandCooldowns.delete(key);
  }
  return false;
};

// Function to set a STDIO command in cooldown
const setStdioCooldown = (
  command: string,
  args: string[],
  env: Record<string, string>,
) => {
  const key = createStdioKey(command, args, env);
  stdioCommandCooldowns.set(key, Date.now() + STDIO_COOLDOWN_DURATION);
};

/** What a STDIO proxy session was actually started with. */
export interface StdioSpawnParams {
  serverUuid: string;
  serverName: string;
  errorStatus: string | null;
  cmd: string;
  args: string[];
  env: Record<string, string>;
}

/** Single string form of a command line, used only to IDENTIFY a row. */
const commandLine = (command: string, args: string): string =>
  `${command} ${args}`.trim();

/**
 * One refusal string for every way a request can fail to name a server the
 * caller may start. Unknown uuid, malformed uuid, wrong transport type, a
 * command line nobody registered, and somebody else's private server all
 * answer identically — the alternative tells a caller which of those it hit,
 * which is a server-enumeration oracle on a route that starts processes.
 */
const NO_SUCH_SERVER =
  "No registered STDIO MCP server matches this request. Connect to a server that exists in the server list.";

/**
 * Guard rail, deliberately kept even though nothing today can trip it.
 *
 * `mcp_servers.uuid` is a Postgres `uuid` column, so a value that is not one
 * makes the driver raise 22P02 instead of matching no row — and the value here
 * is caller-supplied, including the literal string "undefined" that a stale
 * bundle sends. Uncaught on this path, that surfaces as a 500 serialising a
 * driver error object.
 *
 * It cannot happen as the code stands, because the ownership scope below
 * resolves by filtering an already-fetched set IN MEMORY and no caller-supplied
 * uuid reaches the database at all. This check exists so that the day someone
 * reintroduces a by-uuid lookup for efficiency — the obvious optimisation —
 * they inherit the validation rather than the driver error. Being unreachable
 * is the reason it is cheap, not a reason to drop it.
 */
const uuidSchema = z.string().uuid();

/**
 * The session user, as `betterAuthMcpMiddleware` leaves it on the request.
 * Mirrors the shape `requireAdminMcpMiddleware` reads.
 */
type SessionUser = { id?: string; role?: string };

/**
 * Find the registered `mcp_servers` row a STDIO proxy request is asking to
 * start, or throw.
 *
 * The request IDENTIFIES a server; it does not describe one. That distinction
 * is the whole point of this function: the spawn parameters used to be read
 * straight off the query string, so whatever `command` a caller sent is what
 * the backend executed with its own environment. Sourcing them from the row
 * instead means an unregistered command has nowhere to come from.
 *
 * Two ways to identify, in order:
 *  - `mcpServerUuid`, which is what the UI sends and is unambiguous.
 *  - the FULL command line, matched exactly against a registered STDIO row.
 *    This exists so a browser still holding an older bundle keeps working; it
 *    is not a second source of truth, because the matched row's stored values
 *    are what gets spawned either way. Matching is deliberately on the whole
 *    line and never on the executable alone — a `command`-only match would
 *    accept `npx <anything>` the moment one registered server used `npx`.
 *
 * SCOPED TO WHAT THE CALLER MAY SEE, by the same predicate the server list
 * itself uses (`findAllAccessibleToUser`: public rows plus the caller's own).
 * The admin gate on this router answers "may this person use the proxy at
 * all", not "whose servers may they start" — without this scope an admin could
 * name another user's PRIVATE server, one that never appears in their own UI,
 * and drive its tools with that user's stored `env` secrets. Being able to
 * reach a route is not the same as being entitled to every row behind it.
 */
const findRegisteredStdioServer = async (
  req: express.Request,
): Promise<DatabaseMcpServer> => {
  const user = (req as express.Request & { user?: SessionUser }).user;
  const userId = user?.id;

  if (!userId) {
    // Fail closed. The gates ahead of this router already refuse a session
    // without a user id, so reaching here means the chain changed.
    logger.warn("STDIO proxy request refused: no session user on the request");
    throw new Error(NO_SUCH_SERVER);
  }

  const accessible = await mcpServersRepository.findAllAccessibleToUser(userId);

  const requestedUuid =
    typeof req.query.mcpServerUuid === "string"
      ? req.query.mcpServerUuid
      : undefined;

  if (requestedUuid) {
    if (!uuidSchema.safeParse(requestedUuid).success) {
      logger.warn("STDIO proxy request refused: malformed server identifier");
      throw new Error(NO_SUCH_SERVER);
    }

    const server = accessible.find(
      (candidate) =>
        candidate.uuid === requestedUuid &&
        candidate.type === McpServerTypeEnum.enum.STDIO &&
        candidate.command,
    );
    if (!server) {
      logger.warn(
        "STDIO proxy request refused: no accessible server matches the requested identifier",
      );
      throw new Error(NO_SUCH_SERVER);
    }
    return server;
  }

  const requested = commandLine(
    typeof req.query.command === "string" ? req.query.command : "",
    typeof req.query.args === "string" ? req.query.args : "",
  );
  const server = accessible.find(
    (candidate) =>
      candidate.type === McpServerTypeEnum.enum.STDIO &&
      candidate.command &&
      commandLine(candidate.command, (candidate.args || []).join(" ")) ===
        requested,
  );

  if (!server) {
    // The refused command is NOT echoed: it is caller-controlled text, and the
    // reason a request lands here at all is usually that someone sent one.
    logger.warn(
      "STDIO proxy request refused: no registered server matches the requested command",
    );
    throw new Error(NO_SUCH_SERVER);
  }

  return server;
};

/**
 * Build the spawn parameters for a resolved server row.
 *
 * `args` comes from the stored array rather than from a shell-parse of the
 * request's flattened string, so an argument that legitimately contains a
 * space survives instead of being split into two.
 */
const buildStdioSpawnParams = (server: DatabaseMcpServer): StdioSpawnParams => {
  const env = {
    ...process.env,
    ...defaultEnvironment,
    ...resolveEnvVariables(server.env || {}),
  } as Record<string, string>;

  const { cmd, args } = findActualExecutable(
    server.command || "",
    server.args || [],
  );

  return {
    serverUuid: server.uuid,
    serverName: server.name,
    errorStatus: server.error_status ?? null,
    cmd,
    args,
    env,
  };
};

/**
 * Resolve what a STDIO proxy request may spawn, from the server record only.
 *
 * Exported for unit tests (server.spawn-source.test.ts); the production caller
 * is `createTransport` below.
 */
export const resolveStdioSpawnParams = async (
  req: express.Request,
): Promise<StdioSpawnParams> =>
  buildStdioSpawnParams(await findRegisteredStdioServer(req));

/**
 * Spawn parameters resolved for THIS request.
 *
 * The crash and cooldown handlers on the routes below need the same values the
 * process was actually started with. They used to re-derive them from the query
 * string, which no longer decides anything — re-deriving would key the cooldown
 * on one command line while the process ran another.
 */
const resolvedStdioParams = new WeakMap<express.Request, StdioSpawnParams>();

/**
 * Refusal for a remote-transport request whose caller cannot be identified.
 * Same wording discipline as NO_SUCH_SERVER above: it describes nothing about
 * the estate.
 */
const NO_REMOTE_SERVER_CONTEXT =
  "Unable to establish who is making this request. Sign in again and retry.";

/**
 * Find the registered `mcp_servers` row that describes a REMOTE (SSE or
 * STREAMABLE_HTTP) destination, SCOPED TO WHAT THE CALLER MAY SEE, or
 * undefined when nothing they can see matches.
 *
 * The row does NOT authorise the connection — `assertPublicMcpUrl` decides
 * whether a destination may be reached at all, and an unregistered public URL
 * is meant to connect. What the row supplies is STORED CREDENTIALS: its
 * `headers` jsonb is merged into every outbound request, and that jsonb is
 * where a server's vendor API keys live.
 *
 * So the lookup used to be `findAll()` — every row in the installation — and
 * matched on the URL the CALLER sent. Naming another user's PRIVATE server's
 * URL therefore merged THAT user's stored API keys into a request whose
 * destination the caller chose. The admin gate on this router answers "may
 * this person use the proxy at all", not "whose stored credentials may they
 * spend". Same predicate as the server list itself (`findAllAccessibleToUser`:
 * public rows plus the caller's own), and the same reasoning as the STDIO
 * resolver above.
 *
 * Returns undefined rather than throwing when nothing matches, deliberately.
 * A URL with no row is the "point the Inspector at a server that is not saved
 * yet" flow and must still connect — just with no stored headers attached. It
 * also means an inaccessible row and a nonexistent row produce IDENTICAL
 * behaviour, so this cannot be used to test whether a given URL is registered
 * to somebody else.
 */
const findAccessibleRemoteServer = async (
  req: express.Request,
  transportType: string,
  url: string,
): Promise<DatabaseMcpServer | undefined> => {
  const user = (req as express.Request & { user?: SessionUser }).user;
  const userId = user?.id;

  if (!userId) {
    // Fail closed. The gates ahead of this router already refuse a session
    // without a user id, so reaching here means the chain changed — and the
    // fallback that "helpfully" widens to every row is the bug being fixed.
    logger.warn(
      "Remote MCP proxy request refused: no session user on the request",
    );
    throw new Error(NO_REMOTE_SERVER_CONTEXT);
  }

  const accessible = await mcpServersRepository.findAllAccessibleToUser(userId);

  return accessible.find(
    (candidate) => candidate.type === transportType && candidate.url === url,
  );
};

// Function to get HTTP headers.
// Supports only "SSE" and "STREAMABLE_HTTP" transport types.
const getHttpHeaders = (
  req: express.Request,
  transportType: string,
): Record<string, string> => {
  const headers: Record<string, string> = {
    Accept:
      transportType === McpServerTypeEnum.enum.SSE
        ? "text/event-stream"
        : "text/event-stream, application/json",
  };
  const defaultHeaders =
    transportType === McpServerTypeEnum.enum.SSE
      ? SSE_HEADERS_PASSTHROUGH
      : STREAMABLE_HTTP_HEADERS_PASSTHROUGH;

  for (const key of defaultHeaders) {
    if (req.headers[key] === undefined) {
      continue;
    }

    const value = req.headers[key];
    headers[key] = Array.isArray(value) ? value[value.length - 1] : value;
  }

  // If the header "x-custom-auth-header" is present, use its value as the custom header name.
  if (req.headers["x-custom-auth-header"] !== undefined) {
    const customHeaderName = req.headers["x-custom-auth-header"] as string;
    const lowerCaseHeaderName = customHeaderName.toLowerCase();
    if (req.headers[lowerCaseHeaderName] !== undefined) {
      const value = req.headers[lowerCaseHeaderName];
      headers[customHeaderName] = value as string;
    }
  }
  return headers;
};

const serverRouter = express.Router();

// Auth (session) and authorization (admin-only) are applied once by the
// parent router in `routers/mcp-proxy.ts`, so every route below is already
// admin-gated by the time it runs. Do NOT mount this router anywhere else:
// /stdio, /sse and POST /mcp all reach `createTransport`, which starts a
// registered MCP server with the backend's environment.

const webAppTransports: Map<string, Transport> = new Map<string, Transport>(); // Web app transports by web app sessionId
const serverTransports: Map<string, Transport> = new Map<string, Transport>(); // Server Transports by web app sessionId

// Session cleanup function
const cleanupSession = async (sessionId: string) => {
  logger.info(`Cleaning up proxy session ${sessionId}`);

  // Clean up web app transport
  const webAppTransport = webAppTransports.get(sessionId);
  if (webAppTransport) {
    try {
      await webAppTransport.close();
    } catch (error) {
      logger.error(
        `Error closing web app transport for session ${sessionId}:`,
        error,
      );
    }
    webAppTransports.delete(sessionId);
  }

  // Clean up server transport
  const serverTransport = serverTransports.get(sessionId);
  if (serverTransport) {
    try {
      await serverTransport.close();
    } catch (error) {
      logger.error(
        `Error closing server transport for session ${sessionId}:`,
        error,
      );
    }
    serverTransports.delete(sessionId);
  }

  logger.info(`Session ${sessionId} cleanup completed`);
};

const createTransport = async (req: express.Request): Promise<Transport> => {
  const query = req.query;
  // Only the transport type is logged. The whole query used to be dumped here,
  // and an older client still sends its server's `env` in it — i.e. that line
  // wrote vendor API keys into the application log. Nothing on this path reads
  // the query for spawn input any more, so there is nothing left worth logging.
  //
  // JSON.stringify, not bare interpolation: the value is caller-supplied, so an
  // embedded newline would forge whole log lines. The dump this replaced
  // escaped CRLF for free by virtue of being stringified; interpolating one
  // field out of it would quietly give that back.
  logger.info(
    `MCP proxy connection request: transportType=${JSON.stringify(query.transportType)}`,
  );

  const transportType = query.transportType as string;

  if (transportType === McpServerTypeEnum.enum.STDIO) {
    // Command, args and env come from the `mcp_servers` row and nowhere else.
    // `query.command` / `query.args` / `query.env` are no longer read as spawn
    // input at all — see findRegisteredStdioServer.
    const spawnParams = await resolveStdioSpawnParams(req);
    const { cmd, args, env } = spawnParams;
    resolvedStdioParams.set(req, spawnParams);

    // Check if this command is in cooldown
    if (isStdioInCooldown(cmd, args, env)) {
      logger.info(`STDIO command in cooldown: ${cmd} ${args.join(" ")}`);
      const cooldownEnd = stdioCommandCooldowns.get(
        createStdioKey(cmd, args, env),
      );
      if (cooldownEnd) {
        throw new Error(
          `Command "${cmd} ${args.join(" ")}" is in cooldown. Please wait ${Math.ceil((cooldownEnd - Date.now()) / 1000)} seconds before retrying.`,
        );
      }
    }

    // Check if the server is in error state. Read off the row already loaded
    // above rather than re-fetching it by uuid.
    if (spawnParams.errorStatus === McpServerErrorStatusEnum.enum.ERROR) {
      logger.info(
        `Server ${spawnParams.serverName} (${spawnParams.serverUuid}) is in ERROR state`,
      );
      throw new Error(
        `Server is in error state and cannot be connected to. Please check the server configuration and try again later.`,
      );
    }

    logger.info(
      `STDIO transport: server=${spawnParams.serverName} (${spawnParams.serverUuid})`,
    );

    const transport = new ProcessManagedStdioTransport({
      command: cmd,
      args,
      env,
      stderr: "pipe",
    });

    try {
      await transport.start();
      return transport;
    } catch (error) {
      // If the transport fails to start, put it in cooldown
      setStdioCooldown(cmd, args, env);
      logger.info(
        `STDIO command failed, setting cooldown: ${cmd} ${args.join(" ")}`,
      );
      throw error;
    }
  } else if (transportType === McpServerTypeEnum.enum.SSE) {
    const url = transformDockerUrl(query.url as string);

    // The destination is caller-supplied, so it is checked BEFORE anything is
    // opened and before the database is asked about it — see ./url-guard. The
    // check is by address range rather than by "is this row registered",
    // because pointing the Inspector at a not-yet-saved public server is a
    // flow that has to keep working.
    const target = await assertPublicMcpUrl(url);

    // Find the row this URL belongs to, among the rows the caller may see.
    // Its stored `headers` are merged below, so an unscoped lookup here hands
    // out another user's vendor API keys — see findAccessibleRemoteServer.
    const matchingServer = await findAccessibleRemoteServer(
      req,
      transportType,
      url,
    );

    // Error state is read off the row already loaded rather than re-fetched by
    // uuid: the re-fetch was a second, UNSCOPED lookup of a row we are already
    // holding, which is the exact call this fix exists to remove from the path.
    if (matchingServer?.error_status === McpServerErrorStatusEnum.enum.ERROR) {
      logger.info(
        `Server ${matchingServer.name} (${matchingServer.uuid}) is in ERROR state`,
      );
      throw new Error(
        `Server is in error state and cannot be connected to. Please check the server configuration and try again later.`,
      );
    }

    // Merge custom headers from database with passthrough headers from request
    const headers = {
      ...(matchingServer?.headers || {}),
      ...getHttpHeaders(req, transportType),
    };

    // Header NAMES only. `headers` is the row's stored `headers` jsonb merged
    // with the request's passthrough `authorization`, so stringifying the whole
    // object wrote both the caller's bearer token and the server's vendor API
    // keys into app.log on every SSE connect. The names are what a connectivity
    // problem is actually diagnosed from; the values never were.
    //
    // The url is JSON.stringify'd for the same reason the transportType above
    // is: it is caller-supplied, so interpolating it raw lets an embedded
    // newline forge whole log lines.
    logger.info(
      `SSE transport: url=${JSON.stringify(url)}, headers=[${Object.keys(headers).join(", ")}]`,
    );

    // Every request this transport makes goes through the guard, not just the
    // one validated above. The SSE back-channel POSTs to whatever endpoint the
    // REMOTE server advertises in its `endpoint` event — remote-controlled
    // input that never passes through this handler — and `eventSourceInit.fetch`
    // takes precedence over the `fetch` option inside the SDK, so both have to
    // be set for the stream and the POSTs to be covered.
    const guardedFetch = createGuardedFetch();

    const transport = new SSEClientTransport(target, {
      eventSourceInit: {
        fetch: (url, init) => guardedFetch(url, { ...init, headers }),
      },
      requestInit: {
        headers,
      },
      fetch: guardedFetch,
    });
    await transport.start();
    return transport;
  } else if (transportType === McpServerTypeEnum.enum.STREAMABLE_HTTP) {
    const url = transformDockerUrl(query.url as string);

    // Same destination check as the SSE branch above — see ./url-guard.
    const target = await assertPublicMcpUrl(url);

    // Same caller-scoped row lookup and same in-memory error-state read as the
    // SSE branch above — see findAccessibleRemoteServer.
    const matchingServer = await findAccessibleRemoteServer(
      req,
      transportType,
      url,
    );

    if (matchingServer?.error_status === McpServerErrorStatusEnum.enum.ERROR) {
      logger.info(
        `Server ${matchingServer.name} (${matchingServer.uuid}) is in ERROR state`,
      );
      throw new Error(
        `Server is in error state and cannot be connected to. Please check the server configuration and try again later.`,
      );
    }

    // Merge custom headers from database with passthrough headers from request
    const headers = {
      ...(matchingServer?.headers || {}),
      ...getHttpHeaders(req, transportType),
    };

    // Covers the transport's own reconnects and every redirect hop, which the
    // one-shot check above cannot reach.
    const transport = new StreamableHTTPClientTransport(target, {
      requestInit: {
        headers,
      },
      fetch: createGuardedFetch(),
    });
    await transport.start();
    return transport;
  } else {
    logger.error(`Invalid transport type: ${transportType}`);
    throw new Error("Invalid transport type specified");
  }
};

serverRouter.get("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string;
  // logger.info(`Received GET message for sessionId ${sessionId}`);
  try {
    const transport = webAppTransports.get(
      sessionId,
    ) as StreamableHTTPServerTransport;
    if (!transport) {
      res.status(404).end("Session not found");
      return;
    } else {
      await transport.handleRequest(req, res);
    }
  } catch (error) {
    logger.error("Error in /mcp route:", error);
    res.status(500).json(error);
  }
});

serverRouter.post("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  let serverTransport: Transport | undefined;
  if (!sessionId) {
    try {
      logger.info("New StreamableHttp connection request");
      try {
        serverTransport = await createTransport(req);
      } catch (error) {
        if (error instanceof SseError && error.code === 401) {
          logger.error(
            "Received 401 Unauthorized from MCP server:",
            error.message,
          );
          res.status(401).json(error);
          return;
        }

        throw error;
      }

      logger.info("Created StreamableHttp server transport");

      // Set up crash detection for STDIO transports in StreamableHttp route
      if (serverTransport instanceof ProcessManagedStdioTransport) {
        serverTransport.onprocesscrash = async (exitCode, signal) => {
          logger.warn(
            `StreamableHttp STDIO process crashed with code: ${exitCode}, signal: ${signal}`,
          );

          const spawnParams = resolvedStdioParams.get(req);

          if (spawnParams) {
            // Report crash to server pool
            const { serverUuid } = spawnParams;
            mcpServerPool
              .handleServerCrashWithoutNamespace(serverUuid, exitCode, signal)
              .catch((error) => {
                logger.error(
                  `Error reporting StreamableHttp STDIO crash to server pool for ${serverUuid}:`,
                  error,
                );
              });
          } else {
            logger.warn(
              "Could not determine server UUID for crashed StreamableHttp STDIO process",
            );
          }
        };
      }

      // Generate session ID upfront for better tracking
      const newSessionId = randomUUID();

      const webAppTransport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => newSessionId,
        onsessioninitialized: (sessionId) => {
          webAppTransports.set(sessionId, webAppTransport);
          if (serverTransport) {
            serverTransports.set(sessionId, serverTransport);
          }
          logger.info("Client <-> Proxy  sessionId: " + sessionId);
        },
      });
      logger.info("Created StreamableHttp client transport");

      await webAppTransport.start();

      // Set up proxy connection with error handling
      try {
        mcpProxy({
          transportToClient: webAppTransport,
          transportToServer: serverTransport,
          onCleanup: async () => {
            await cleanupSession(newSessionId);
          },
        });
      } catch (error) {
        logger.error(
          `Error setting up proxy for session ${newSessionId}:`,
          error,
        );
        await cleanupSession(newSessionId);
        throw error;
      }

      // Handle the actual request - don't pass req.body since it wasn't parsed
      await (webAppTransport as StreamableHTTPServerTransport).handleRequest(
        req,
        res,
      );
    } catch (error) {
      logger.error("Error in /mcp POST route:", error);
      res.status(500).json(error);
    }
  } else {
    // logger.info(`Received POST message for sessionId ${sessionId}`);
    try {
      const transport = webAppTransports.get(
        sessionId,
      ) as StreamableHTTPServerTransport;
      if (!transport) {
        res.status(404).end("Transport not found for sessionId " + sessionId);
      } else {
        await (transport as StreamableHTTPServerTransport).handleRequest(
          req,
          res,
        );
      }
    } catch (error) {
      logger.error("Error in /mcp route:", error);
      res.status(500).json(error);
    }
  }
});

serverRouter.delete("/mcp", async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  const mcpServerName = (req.query.mcpServerName as string) || "Unknown Server";
  logger.info(
    `Received DELETE message for sessionId ${sessionId}, MCP server: ${mcpServerName}`,
  );

  if (sessionId) {
    try {
      const serverTransport = serverTransports.get(
        sessionId,
      ) as StreamableHTTPClientTransport;
      if (!serverTransport) {
        res.status(404).end("Transport not found for sessionId " + sessionId);
        return;
      }

      // Terminate the session and clean up
      try {
        await serverTransport.terminateSession();
      } catch (error) {
        logger.warn(`Warning: Error terminating session ${sessionId}:`, error);
        // Continue with cleanup even if termination fails
      }

      await cleanupSession(sessionId);
      logger.info(
        `Session ${sessionId} terminated and cleaned up successfully`,
      );
      res.status(200).end();
    } catch (error) {
      logger.error("Error in /mcp DELETE route:", error);
      res.status(500).json(error);
    }
  } else {
    res.status(400).end("Missing sessionId");
  }
});

serverRouter.get("/stdio", async (req, res) => {
  try {
    logger.info("New STDIO connection request");
    let serverTransport: Transport | undefined;
    try {
      serverTransport = await createTransport(req);
      logger.info("Created server transport");
    } catch (error) {
      if (error instanceof SseError && error.code === 401) {
        logger.error(
          "Received 401 Unauthorized from MCP server. Authentication failure.",
        );
        res.status(401).json(error);
        return;
      }

      throw error;
    }

    const webAppTransport = new SSEServerTransport(
      "/mcp-proxy/server/message",
      res,
    );
    logger.info("Created client transport");

    webAppTransports.set(webAppTransport.sessionId, webAppTransport);
    serverTransports.set(webAppTransport.sessionId, serverTransport);

    // Handle cleanup when connection closes
    const handleConnectionClose = () => {
      logger.info(`Connection closed for session ${webAppTransport.sessionId}`);
      cleanupSession(webAppTransport.sessionId);
    };

    // Handle various connection termination scenarios
    res.on("close", handleConnectionClose);
    res.on("finish", handleConnectionClose);
    res.on("error", (error) => {
      logger.error(
        `Response error for SSE session ${webAppTransport.sessionId}:`,
        error,
      );
      handleConnectionClose();
    });

    await webAppTransport.start();

    const stdinTransport = serverTransport as ProcessManagedStdioTransport;

    // Set up crash detection for the server pool
    stdinTransport.onprocesscrash = async (exitCode, signal) => {
      logger.warn(
        `STDIO process crashed with code: ${exitCode}, signal: ${signal}`,
      );

      const spawnParams = resolvedStdioParams.get(req);

      if (spawnParams) {
        const { serverUuid } = spawnParams;
        logger.info(
          `Reporting crash to server pool for server UUID: ${serverUuid}`,
        );
        // Report crash to server pool
        mcpServerPool
          .handleServerCrashWithoutNamespace(serverUuid, exitCode, signal)
          .catch((error) => {
            logger.error(
              `Error reporting STDIO crash to server pool for ${serverUuid}:`,
              error,
            );
          });
      } else {
        logger.warn(
          "Could not determine server UUID for crashed STDIO process",
        );
      }
    };

    // Monitor for quick failures and set cooldown
    const commandStartTime = Date.now();
    const QUICK_FAILURE_THRESHOLD = 5000; // 5 seconds

    // Handle transport close events
    stdinTransport.onclose = () => {
      const runTime = Date.now() - commandStartTime;
      const spawnParams = resolvedStdioParams.get(req);
      if (runTime < QUICK_FAILURE_THRESHOLD && spawnParams) {
        // Process failed quickly, likely a startup error
        const { cmd, args, env } = spawnParams;

        setStdioCooldown(cmd, args, env);
        logger.info(
          `STDIO process terminated quickly (${runTime}ms), setting cooldown: ${cmd} ${args.join(" ")}`,
        );
      }
    };

    if (stdinTransport.stderr) {
      stdinTransport.stderr.on("data", (chunk: Buffer) => {
        const errorContent = chunk.toString();
        if (errorContent.includes("MODULE_NOT_FOUND")) {
          webAppTransport
            .send({
              jsonrpc: "2.0",
              method: "notifications/stderr",
              params: {
                content: "Command not found, transports removed",
              },
            })
            .catch((error) => {
              // Ignore "Not connected" errors during cleanup
              if (error?.message && !error.message.includes("Not connected")) {
                logger.error("Error sending stderr notification:", error);
              }
            });
          webAppTransport.close();
          cleanupSession(webAppTransport.sessionId);
          logger.error("Command not found, transports removed");
        } else {
          // Check for common startup errors that should trigger cooldown
          const spawnParams = resolvedStdioParams.get(req);
          if (
            spawnParams &&
            (errorContent.includes("ENOENT") ||
              errorContent.includes("no such file or directory"))
          ) {
            const { cmd, args, env } = spawnParams;

            setStdioCooldown(cmd, args, env);
            logger.info(
              `STDIO process reported startup error, setting cooldown: ${cmd} ${args.join(" ")}`,
            );
          }

          webAppTransport
            .send({
              jsonrpc: "2.0",
              method: "notifications/stderr",
              params: {
                content: errorContent,
              },
            })
            .catch((error) => {
              // Ignore "Not connected" errors as they're expected when connections close
              if (error?.message && !error.message.includes("Not connected")) {
                logger.error("Error sending stderr notification:", error);
              }
            });
        }
      });
    }

    mcpProxy({
      transportToClient: webAppTransport,
      transportToServer: serverTransport,
      onCleanup: async () => {
        await cleanupSession(webAppTransport.sessionId);
      },
    });
  } catch (error) {
    logger.error("Error in /stdio route:", error);
    res.status(500).json(error);
  }
});

serverRouter.get("/sse", async (req, res) => {
  try {
    logger.info(
      "New SSE connection request. NOTE: The sse transport is deprecated and has been replaced by StreamableHttp",
    );
    let serverTransport: Transport | undefined;
    try {
      serverTransport = await createTransport(req);
    } catch (error) {
      if (error instanceof SseError && error.code === 401) {
        logger.error(
          "Received 401 Unauthorized from MCP server. Authentication failure.",
        );
        res.status(401).json(error);
        return;
      } else if (error instanceof SseError && error.code === 404) {
        logger.error(
          "Received 404 not found from MCP server. Does the MCP server support SSE?",
        );
        res.status(404).json(error);
        return;
      } else if (JSON.stringify(error).includes("ECONNREFUSED")) {
        logger.error("Connection refused. Is the MCP server running?");
        res.status(500).json(error);
      } else {
        throw error;
      }
    }

    if (serverTransport) {
      const webAppTransport = new SSEServerTransport(
        "/mcp-proxy/server/message",
        res,
      );
      webAppTransports.set(webAppTransport.sessionId, webAppTransport);
      logger.info("Created client transport");
      if (serverTransport) {
        serverTransports.set(webAppTransport.sessionId, serverTransport);
      }
      logger.info("Created server transport");

      // Handle cleanup when connection closes
      const handleConnectionClose = () => {
        logger.info(
          `Connection closed for session ${webAppTransport.sessionId}`,
        );
        cleanupSession(webAppTransport.sessionId);
      };

      // Handle various connection termination scenarios
      res.on("close", handleConnectionClose);
      res.on("finish", handleConnectionClose);
      res.on("error", (error) => {
        logger.error(
          `Response error for STDIO session ${webAppTransport.sessionId}:`,
          error,
        );
        handleConnectionClose();
      });

      await webAppTransport.start();

      mcpProxy({
        transportToClient: webAppTransport,
        transportToServer: serverTransport,
        onCleanup: async () => {
          await cleanupSession(webAppTransport.sessionId);
        },
      });
    }
  } catch (error) {
    logger.error("Error in /sse route:", error);
    res.status(500).json(error);
  }
});

serverRouter.post("/message", async (req, res) => {
  try {
    const sessionId = req.query.sessionId;
    // logger.info(`Received POST message for sessionId ${sessionId}`);

    const transport = webAppTransports.get(
      sessionId as string,
    ) as SSEServerTransport;
    if (!transport) {
      res.status(404).end("Session not found");
      return;
    }
    await transport.handlePostMessage(req, res);
  } catch (error) {
    logger.error("Error in /message route:", error);
    res.status(500).json(error);
  }
});

serverRouter.get("/health", (req, res) => {
  res.json({
    status: "ok",
  });
});

export default serverRouter;
