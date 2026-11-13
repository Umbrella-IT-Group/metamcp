import { randomUUID } from "node:crypto";

import {
  SSEClientTransport,
  SseError,
} from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  FetchLike,
  Transport,
} from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  DatabaseMcpServer,
  McpServerErrorStatusEnum,
  McpServerTypeEnum,
} from "@repo/zod-types";
import express from "express";
import { findActualExecutable } from "spawn-rx";
import { z } from "zod";

import { describeDbError } from "@/lib/db-error-summary";
import {
  assertPublicMcpUrl,
  createGuardedFetch,
  type InternalOnlyCredentials,
  isInternalTarget,
  type McpUrlGuardOptions,
  NOT_A_PERMITTED_TARGET,
  type ValidatedMcpTarget,
} from "@/lib/metamcp/url-guard";
import logger from "@/utils/logger";

import {
  mcpServersRepository,
  oauthSessionsRepository,
} from "../../db/repositories";
import { getInjectedServerNames } from "../../lib/m365/config";
import mcpProxy from "../../lib/mcp-proxy";
import {
  ASSERTED_ACTOR_HEADER,
  normalizeAssertedActor,
} from "../../lib/metamcp/asserted-actor";
import {
  POOL_GUARD_OPTIONS,
  transformDockerUrl,
} from "../../lib/metamcp/client";
import {
  MCP_REQUEST_BODY_LIMIT_BYTES,
  refuseDeclaredOversize,
} from "../../lib/metamcp/mcp-request-body-limit";
import { mcpServerPool } from "../../lib/metamcp/mcp-server-pool";
import { resolveServerBearerToken } from "../../lib/metamcp/server-bearer-crypto";
import {
  assertStdioServersAllowed,
  STDIO_SERVERS_DISABLED_MESSAGE,
  StdioServersDisabledError,
} from "../../lib/metamcp/stdio-policy";
import {
  getDefaultEnvironment,
  resolveEnvVariables,
} from "../../lib/metamcp/utils";
import {
  isVerifiedCallerHeaderName,
  VERIFIED_CALLER_HEADER,
  VERIFIED_CALLER_IDENTITY_HEADER,
  withoutVerifiedCallerHeader,
} from "../../lib/metamcp/verified-caller";
import { ProcessManagedStdioTransport } from "../../lib/stdio-transport/process-managed-transport";

// `x-mcp-actor` is best-effort, client-asserted attribution: it names who an
// action is on behalf of so backend MCPs (shell-broker, ninja, inventory) can
// stamp the operator on their audit rows and the shell-broker approval page
// instead of a generic default. It is NOT an authentication control — the
// security identity stays the endpoint API-key auth, and for shell-broker the
// CF-Access-verified approver — so forwarding a caller-set value is safe.
// Lowercase because Node lowercases incoming header names.
const SSE_HEADERS_PASSTHROUGH = ["authorization", "x-mcp-actor"];
const STREAMABLE_HTTP_HEADERS_PASSTHROUGH = [
  "authorization",
  "mcp-session-id",
  "last-event-id",
  "x-mcp-actor",
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
 * Mirrors the shape `requireAdminMcpMiddleware` reads, plus the account email
 * `inspectorCaller` (metamcp.ts) reads.
 */
type SessionUser = { id?: string; role?: string; email?: unknown };

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
 *
 * The child env is the SAME curated allowlist the pool path uses
 * (`lib/metamcp/utils` getDefaultEnvironment, applied to the server env in
 * `convertDbServerToParams` and spawned via `lib/metamcp/client.ts`) plus this
 * server's own resolved env, and NOT a spread of the whole gateway
 * `process.env`. Matching that curated function rather than the SDK's shorter
 * default keeps an Inspector-spawned server's inherited env (PATH, proxy and
 * CA-cert variables) identical to a pool-spawned one, and stops an npx MCP an
 * admin registers from inheriting DATABASE_URL, BETTER_AUTH_SECRET and every
 * vendor secret. A server that genuinely needs a gateway variable still names
 * it explicitly with a `${VAR}` placeholder, which `resolveEnvVariables` fills.
 */
const buildStdioSpawnParams = (server: DatabaseMcpServer): StdioSpawnParams => {
  const env = {
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
 * Refusal for an `x-custom-auth-header` that names either gateway-set
 * identity header. See getHttpHeaders.
 */
const INSPECTOR_RESERVED_HEADER =
  "X-Umbrella-User-Id and X-Umbrella-Caller are set by the gateway from the signed-in caller and cannot be supplied as a custom header.";

/**
 * A matched row's stored headers, for merging into an Inspector connection:
 * all of them except X-Umbrella-User-Id and X-Umbrella-Caller (any casing,
 * surrounding whitespace ignored), whatever the row's name.
 *
 * Identity headers are gateway-set only (`lib/metamcp/verified-caller.ts`).
 * These direct transports go through the guarded fetch, which adds the
 * gateway trust header on every internal hop (an MCP_PROXY_URL_ALLOWED_HOSTS
 * entry included), so a backend that trusts the identity headers beside it
 * must never see a value someone typed into a server row, whichever row the
 * connection matched. The pool drops the same names from every row
 * (`storedHeadersForPool` in `lib/metamcp/client.ts`), and server create,
 * update and bulk import refuse them, so only rows saved before that refusal
 * can still hold one.
 */
const storedHeadersFor = (
  server: DatabaseMcpServer | undefined,
): Record<string, string> => withoutVerifiedCallerHeader(server?.headers || {});

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
    // X-Umbrella-User-Id and X-Umbrella-Caller are set by the gateway from
    // the verified caller for the backends that act on them
    // (VERIFIED_CALLER_SERVER_NAMES, and the m365 injection for the user id).
    // Copying a caller-chosen value onto either would hand such a backend
    // someone else's identity, so the Inspector refuses both names outright,
    // for every destination, rather than drop them silently.
    if (isVerifiedCallerHeaderName(customHeaderName)) {
      throw new Error(INSPECTOR_RESERVED_HEADER);
    }
    const lowerCaseHeaderName = customHeaderName.toLowerCase();
    if (req.headers[lowerCaseHeaderName] !== undefined) {
      const value = req.headers[lowerCaseHeaderName];
      headers[customHeaderName] = value as string;
    }
  }
  return headers;
};

/**
 * The one answer for every way a request that names a remote server by
 * `mcpServerUuid` fails to open it: no session user, a malformed uuid, a uuid
 * the caller cannot see (another user's private server included), a row of
 * another transport type or with no url, a row marked ERROR, and a row whose
 * address the destination guard refuses. Constant for the reason
 * NO_SUCH_SERVER is: an answer that differs by cause tells a caller which rows
 * exist. The specific reason goes to the log, naming the row by name and uuid
 * when there is one, never by its url.
 */
const REGISTERED_SERVER_REFUSED =
  "This MCP server cannot be opened here: it is not a server you can see, it is in an error state, or its address is not one this gateway connects to. The gateway log records the specific reason.";

/**
 * Thrown by the by-uuid path of `openRemoteServer` before anything is opened.
 * Each route answers it with REGISTERED_SERVER_REFUSED_BODY and HTTP 400.
 */
class RegisteredServerRefusedError extends Error {
  constructor() {
    super(REGISTERED_SERVER_REFUSED);
    this.name = "RegisteredServerRefusedError";
  }
}

/** A remote transport's destination, fetch and headers, ready to construct. */
interface RemoteConnection {
  url: URL;
  /** Every request the transport makes goes through this. */
  fetch: FetchLike;
  headers: Record<string, string>;
  /** How the connect log names the destination. Never carries a query string. */
  logTarget: string;
}

/**
 * Find the registered remote row a request names by `mcpServerUuid`, or throw
 * RegisteredServerRefusedError.
 *
 * The STDIO resolver's rules (findRegisteredStdioServer): the identifier must
 * be a uuid, the row must be one the caller may see (`findAllAccessibleToUser`:
 * public rows plus their own), its type must be the requested transport, and
 * it must have a url. Its error state is read off this same row.
 */
const findRegisteredRemoteServer = async (
  req: express.Request,
  transportType: string,
): Promise<{ server: DatabaseMcpServer; url: string }> => {
  const userId = (req as express.Request & { user?: SessionUser }).user?.id;
  if (!userId) {
    // Fail closed. The gates ahead of this router already refuse a session
    // without a user id, so reaching here means the chain changed.
    logger.warn(
      "Registered server request refused: no session user on the request",
    );
    throw new RegisteredServerRefusedError();
  }

  const requestedUuid = req.query.mcpServerUuid;
  if (
    typeof requestedUuid !== "string" ||
    !uuidSchema.safeParse(requestedUuid).success
  ) {
    logger.warn(
      "Registered server request refused: malformed server identifier",
    );
    throw new RegisteredServerRefusedError();
  }

  const accessible = await mcpServersRepository.findAllAccessibleToUser(userId);
  const server = accessible.find(
    (candidate) =>
      candidate.uuid === requestedUuid && candidate.type === transportType,
  );
  if (!server || !server.url) {
    logger.warn(
      "Registered server request refused: no accessible server of this transport type matches the requested identifier",
    );
    throw new RegisteredServerRefusedError();
  }

  if (server.error_status === McpServerErrorStatusEnum.enum.ERROR) {
    logger.info(`Server ${server.name} (${server.uuid}) is in ERROR state`);
    throw new RegisteredServerRefusedError();
  }

  return { server, url: server.url };
};

/**
 * The verified caller headers (`verified-caller.ts`) on the by-uuid path. The
 * guard deletes both on every hop and sets neither (`InternalOnlyCredentials`
 * in url-guard.ts), whatever put them on the request: a row's stored headers
 * included, whether or not the row is named in VERIFIED_CALLER_SERVER_NAMES.
 * Stripped by destination rather than by row name, so an identity stored on
 * a row never stands in for the signed-in caller. A backend that requires
 * them lists its tools here and refuses to execute one, which fails closed.
 */
const NO_VERIFIED_CALLER: InternalOnlyCredentials = Object.freeze({
  headerNames: [VERIFIED_CALLER_HEADER, VERIFIED_CALLER_IDENTITY_HEADER],
  forInternalHop: async () => undefined,
});

/**
 * NO_VERIFIED_CALLER plus `Authorization`, for a row named in
 * M365_INJECTED_SERVER_NAMES (`getInjectedServerNames`). A backend named there
 * takes Authorization on a gateway-trusted request as the per-user Graph token
 * the gateway mints inside the guard for the request's user, and nothing else
 * (`createM365Credentials`, lib/m365/injected-fetch.ts, invariants 1, 2 and
 * 7). This path mints no such token, so it sends no Authorization at all: not
 * the browser's, not the row's OAuth token or stored bearer, not one in the
 * row's stored headers. The guard deletes it on every hop. Such a backend
 * lists its tools without one and refuses to execute a tool, which fails
 * closed.
 */
const NO_CALLER_CREDENTIALS: InternalOnlyCredentials = Object.freeze({
  headerNames: [
    "authorization",
    VERIFIED_CALLER_HEADER,
    VERIFIED_CALLER_IDENTITY_HEADER,
  ],
  forInternalHop: async () => undefined,
});

/**
 * The guard posture for a registered row opened by uuid: the pooled data
 * plane's own (POOL_GUARD_OPTIONS in client.ts). It permits the private ranges
 * the gateway's backends live on, pins every socket to the addresses it
 * validated, refuses the never-a-backend ranges (metadata, CGNAT, multicast,
 * reserved) and every cross-origin redirect, and sends X-Gateway-Auth and
 * X-MCP-Actor only to an internal destination, so a third-party server
 * someone registered gets neither.
 *
 * On top of it, the caller headers the guard deletes on every hop and never
 * sets (NO_VERIFIED_CALLER, or NO_CALLER_CREDENTIALS for an m365-injected row).
 */
const registeredServerGuardOptions = (
  server: DatabaseMcpServer,
): McpUrlGuardOptions => ({
  ...POOL_GUARD_OPTIONS,
  internalOnlyCredentials: getInjectedServerNames().has(server.name)
    ? NO_CALLER_CREDENTIALS
    : NO_VERIFIED_CALLER,
});

/**
 * Whether a target's resolved addresses mix internal-service ranges with
 * public ones. The pool's posture accepts such an answer and treats it as
 * external; here it is refused, because which of the two the connection lands
 * on is then up to the resolver's ordering.
 */
const resolvesBothWays = (target: ValidatedMcpTarget): boolean => {
  const internal = target.addresses.filter((address) =>
    isInternalTarget({ url: target.url, addresses: [address] }),
  ).length;
  return internal > 0 && internal < target.addresses.length;
};

/**
 * A fetch that refuses every request whose origin is not `origin` and hands
 * the rest to `fetch`. The guarded fetch already refuses a cross-origin
 * redirect under this posture; this covers the first hop of each request,
 * which on SSE is the back-channel endpoint the remote server advertises.
 * The row authorised one origin, not every address in the same private range,
 * and the pin keeps that true whatever a future SDK does with its URLs.
 */
const pinnedToOrigin =
  (origin: string, fetch: FetchLike): FetchLike =>
  async (input, init) => {
    let requested: string | undefined;
    try {
      requested = (input instanceof URL ? input : new URL(input)).origin;
    } catch {
      requested = undefined;
    }
    if (requested !== origin) {
      logger.warn(
        "MCP proxy remote URL refused: a request off the registered server's origin",
      );
      throw new Error(NOT_A_PERMITTED_TARGET);
    }
    return fetch(input, init);
  };

/** A copy of `headers` without `name` (lowercase) in any casing. */
const withoutHeader = (
  headers: Record<string, string>,
  name: string,
): Record<string, string> =>
  Object.fromEntries(
    Object.entries(headers).filter(([key]) => key.toLowerCase() !== name),
  );

/**
 * The credential the pool presents to this row (client.ts
 * createMetaMcpClient): its OAuth access token, else its stored bearer,
 * decrypted at the point of use. Null when the row yields neither.
 *
 * The browser cannot supply the stored bearer (the server serializer never
 * sends it), so without this a bearer-protected row could not be opened from
 * the admin UI at all.
 */
const registeredServerToken = async (
  server: DatabaseMcpServer,
): Promise<string | null> => {
  const oauthSession = await oauthSessionsRepository.findByMcpServerUuid(
    server.uuid,
  );
  return (
    oauthSession?.tokens?.access_token ||
    resolveServerBearerToken(server.bearerToken)
  );
};

/**
 * Headers for a registered row opened by uuid: its stored headers, then the
 * request's passthrough (getHttpHeaders), with two replacements.
 *  - X-MCP-Actor is the signed-in admin's account email, read as
 *    `inspectorCaller` (metamcp.ts) reads it (only beside a non-empty user id),
 *    never the browser's value or a stored one. None is sent without one. The
 *    guard drops it on any hop that is not internal.
 *  - Authorization is the row's own credential (registeredServerToken); the
 *    browser's passthrough is used only when the row yields none.
 */
const registeredServerHeaders = async (
  req: express.Request,
  transportType: string,
  server: DatabaseMcpServer,
): Promise<Record<string, string>> => {
  let headers = withoutHeader(
    { ...(server.headers || {}), ...getHttpHeaders(req, transportType) },
    ASSERTED_ACTOR_HEADER,
  );

  const user = (req as express.Request & { user?: SessionUser }).user;
  const actor =
    typeof user?.id === "string" && user.id !== ""
      ? normalizeAssertedActor(user.email)
      : undefined;
  if (actor) headers[ASSERTED_ACTOR_HEADER] = actor;

  const token = await registeredServerToken(server);
  if (token) {
    headers = withoutHeader(headers, "authorization");
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
};

/**
 * Open a registered remote row by uuid (the server page and the Inspector's
 * server targets send one). `query.url` is not read on this path: the row
 * decides where the connection goes, so two rows sharing a url cannot be
 * confused, and a destination is reached only by naming a row the caller may
 * see. It connects to `transformDockerUrl(row.url)` under the pool's posture,
 * public row or private, pinned to the row's origin.
 */
const openRegisteredServer = async (
  req: express.Request,
  transportType: string,
): Promise<RemoteConnection> => {
  const { server, url } = await findRegisteredRemoteServer(req, transportType);
  const label = `server=${server.name} (${server.uuid})`;
  const options = registeredServerGuardOptions(server);

  let target: ValidatedMcpTarget;
  try {
    target = await assertPublicMcpUrl(transformDockerUrl(url), options);
  } catch (error) {
    // The guard has logged its specific reason; its messages carry no url.
    logger.warn(
      `Registered server refused: ${label}: ${error instanceof Error ? error.message : "destination check failed"}`,
    );
    throw new RegisteredServerRefusedError();
  }
  if (resolvesBothWays(target)) {
    logger.warn(
      `Registered server refused: ${label}: its host resolves to internal and public addresses at once`,
    );
    throw new RegisteredServerRefusedError();
  }

  return {
    url: target.url,
    fetch: pinnedToOrigin(target.url.origin, createGuardedFetch(options)),
    headers: await registeredServerHeaders(req, transportType, server),
    logTarget: label,
  };
};

/**
 * Open a remote destination named by `query.url` (no `mcpServerUuid`): a tab
 * holding an older bundle, or a URL that is not saved. The strict posture:
 * public destinations only, so this path never reaches the private network.
 */
const openByUrl = async (
  req: express.Request,
  transportType: string,
): Promise<RemoteConnection> => {
  const url = transformDockerUrl(req.query.url as string);

  // The destination is caller-supplied, so it is checked BEFORE anything is
  // opened and before the database is asked about it (see the url-guard module). The
  // check is by address range rather than by "is this row registered",
  // because pointing the Inspector at a not-yet-saved public server is a
  // flow that has to keep working.
  const target = await assertPublicMcpUrl(url);

  // Find the row this URL belongs to, among the rows the caller may see.
  // Its stored `headers` are merged below, so an unscoped lookup here hands
  // out another user's vendor API keys: see findAccessibleRemoteServer.
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

  return {
    url: target.url,
    // `allowlistOrigin` is what keeps an MCP_PROXY_URL_ALLOWED_HOSTS entry from
    // becoming a hole: the exemption applies to the origin the operator typed
    // and to nothing else this transport is later told to fetch.
    fetch: createGuardedFetch({ allowlistOrigin: target.url.origin }),
    // Merge custom headers from database with passthrough headers from request
    headers: {
      ...storedHeadersFor(matchingServer),
      ...getHttpHeaders(req, transportType),
    },
    // ORIGIN AND PATH ONLY, never the query string. Hosted MCP servers
    // routinely carry their credential in it (`?api_key=`, `?token=`). It is
    // JSON.stringify'd because the value is caller-supplied, and an embedded
    // newline forges log lines.
    logTarget: `url=${JSON.stringify(target.url.origin + target.url.pathname)}`,
  };
};

/**
 * Where a remote (SSE or STREAMABLE_HTTP) Inspector connection goes, and with
 * what. A request that carries `mcpServerUuid` at all is resolved by uuid and
 * nothing else (openRegisteredServer); a request without one keeps the strict
 * by-url path (openByUrl), unchanged.
 *
 * Before 2026-11-13 only the by-url path existed, and every backend the
 * gateway serves is on the private container network, so the admin UI's
 * server page refused every registered server.
 */
const openRemoteServer = (
  req: express.Request,
  transportType: string,
): Promise<RemoteConnection> =>
  req.query.mcpServerUuid !== undefined
    ? openRegisteredServer(req, transportType)
    : openByUrl(req, transportType);

const serverRouter = express.Router();

// The Inspector's SDK includes response text in its error message. A fixed
// message stays useful without serializing a query, its params or its cause.
const PROXY_ERROR_BODY = {
  error: "internal_server_error",
  message: "MCP proxy request failed. Check the gateway logs for details.",
} as const;

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

/**
 * Tear down a POST /mcp session whose first request the transport answered
 * without initializing it: a body over the limit found while reading it (a
 * declared oversize never gets this far, see refuseDeclaredOversize),
 * invalid JSON, or a first request that is not an `initialize`. The client got
 * no session id, so nothing could ever reach this session again, and without
 * this its upstream transport (a STDIO child, an SSE stream) stayed open.
 * `cleanupSession` cannot do it: its maps are filled by `onsessioninitialized`,
 * which never ran.
 *
 * The server transport goes first. Its close reaches the proxy wiring
 * (lib/mcp-proxy), which marks the server side closed and closes the client
 * transport itself, so the client transport's close below is normally a no-op
 * (the SDK transport ignores a second close) rather than the wiring's cue to
 * close the upstream a second time. It is there for when the wiring did not
 * run.
 */
const closeUninitializedSession = async (
  sessionId: string,
  webAppTransport: Transport | undefined,
  serverTransport: Transport,
) => {
  logger.info(
    `Proxy session ${sessionId} was not initialized; closing its transports`,
  );
  try {
    await serverTransport.close();
  } catch (error) {
    logger.error(
      `Error closing server transport for uninitialized session ${sessionId}:`,
      error,
    );
  }
  try {
    await webAppTransport?.close();
  } catch (error) {
    logger.error(
      `Error closing web app transport for uninitialized session ${sessionId}:`,
      error,
    );
  }
};

/**
 * The answer to a request for a stdio server while stdio servers are disabled
 * (see lib/metamcp/stdio-policy). A constant: it never echoes the request, and
 * it is the same on POST /mcp, GET /stdio and GET /sse. JSON-RPC shaped, like
 * the body-limit refusal, so an MCP client shows the message.
 */
const STDIO_DISABLED_BODY = Object.freeze({
  jsonrpc: "2.0",
  error: { code: -32000, message: STDIO_SERVERS_DISABLED_MESSAGE },
  id: null,
});

/**
 * Answer a stdio policy refusal from `createTransport` with HTTP 400 and
 * return true; return false for any other error. Each route calls it first in
 * the catch around `createTransport`, whose fall-through answers an ordinary
 * throw with HTTP 500. Nothing has been started when this error is thrown, so
 * there is nothing to close.
 */
const answerStdioPolicyRefusal = (
  error: unknown,
  res: express.Response,
): boolean => {
  if (!(error instanceof StdioServersDisabledError)) return false;
  logger.warn(
    "MCP proxy request refused: stdio servers are disabled on this gateway",
  );
  res.status(400).json(STDIO_DISABLED_BODY);
  return true;
};

/**
 * The answer to a remote server request by uuid that cannot be opened (see
 * REGISTERED_SERVER_REFUSED). A constant, JSON-RPC shaped, and the same on
 * every route, like STDIO_DISABLED_BODY.
 */
const REGISTERED_SERVER_REFUSED_BODY = Object.freeze({
  jsonrpc: "2.0",
  error: { code: -32000, message: REGISTERED_SERVER_REFUSED },
  id: null,
});

/**
 * Answer a RegisteredServerRefusedError from `createTransport` with HTTP 400
 * and return true; return false for any other error. Called beside
 * answerStdioPolicyRefusal. The reason was logged where it was thrown, and
 * nothing has been opened yet, so there is nothing to close.
 */
const answerRegisteredServerRefusal = (
  error: unknown,
  res: express.Response,
): boolean => {
  if (!(error instanceof RegisteredServerRefusedError)) return false;
  res.status(400).json(REGISTERED_SERVER_REFUSED_BODY);
  return true;
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
    // The stdio policy gate (see lib/metamcp/stdio-policy), before the row is
    // resolved, the cooldown is consulted or a transport exists. Each route
    // below answers this typed error with STDIO_DISABLED_BODY and HTTP 400.
    assertStdioServersAllowed();

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
    // Destination, fetch and headers: by uuid for a registered row, else the
    // strict by-url path (see openRemoteServer).
    const {
      url,
      fetch: guardedFetch,
      headers,
      logTarget,
    } = await openRemoteServer(req, transportType);

    // Header NAMES only. `headers` is the row's stored `headers` jsonb merged
    // with the request's passthrough `authorization`, so stringifying the whole
    // object wrote both the caller's bearer token and the server's vendor API
    // keys into app.log on every SSE connect. The names are what a connectivity
    // problem is actually diagnosed from; the values never were. The
    // destination is named by row (`server=<name> (<uuid>)`) or by origin and
    // path, never with its query string (see RemoteConnection.logTarget).
    logger.info(
      `SSE transport: ${logTarget}, headers=[${Object.keys(headers).join(", ")}]`,
    );

    // Every request this transport makes goes through the guard, not just the
    // one validated above. The SSE back-channel POSTs to whatever endpoint the
    // REMOTE server advertises in its `endpoint` event — remote-controlled
    // input that never passes through this handler — and `eventSourceInit.fetch`
    // takes precedence over the `fetch` option inside the SDK, so both have to
    // be set for the stream and the POSTs to be covered.
    //
    // Back-channel coverage rests on the PINNED SDK (1.30.0) honouring
    // `opts.fetch` for the POST to the server-advertised endpoint. If that pin
    // moves, re-check `client/sse.js` still routes that POST through it.
    const transport = new SSEClientTransport(url, {
      eventSourceInit: {
        fetch: (input, init) => guardedFetch(input, { ...init, headers }),
      },
      requestInit: {
        headers,
      },
      fetch: guardedFetch,
    });
    await transport.start();
    return transport;
  } else if (transportType === McpServerTypeEnum.enum.STREAMABLE_HTTP) {
    // Same resolution as the SSE branch above (see openRemoteServer).
    const {
      url,
      fetch: guardedFetch,
      headers,
    } = await openRemoteServer(req, transportType);

    // Covers the transport's own reconnects and every redirect hop, which the
    // one-shot check cannot reach.
    const transport = new StreamableHTTPClientTransport(url, {
      requestInit: {
        headers,
      },
      fetch: guardedFetch,
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
    logger.error("Error in /mcp route:", describeDbError(error));
    res.status(500).json(PROXY_ERROR_BODY);
  }
});

// A declared oversize is refused before `createTransport` starts anything.
serverRouter.post("/mcp", refuseDeclaredOversize, async (req, res) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  let serverTransport: Transport | undefined;
  // Hoisted so the error path below can tell what this request started.
  let newSessionId: string | undefined;
  let webAppTransport: StreamableHTTPServerTransport | undefined;
  if (!sessionId) {
    try {
      logger.info("New StreamableHttp connection request");
      try {
        serverTransport = await createTransport(req);
      } catch (error) {
        if (answerStdioPolicyRefusal(error, res)) {
          return;
        }
        if (answerRegisteredServerRefusal(error, res)) {
          return;
        }
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
                  describeDbError(error),
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
      const sessionIdForRequest = randomUUID();
      newSessionId = sessionIdForRequest;

      const transportToClient = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => sessionIdForRequest,
        // See lib/metamcp/mcp-request-body-limit for the value and why.
        maxRequestBodySize: MCP_REQUEST_BODY_LIMIT_BYTES,
        onsessioninitialized: (sessionId) => {
          webAppTransports.set(sessionId, transportToClient);
          if (serverTransport) {
            serverTransports.set(sessionId, serverTransport);
          }
          logger.info("Client <-> Proxy  sessionId: " + sessionId);
        },
      });
      webAppTransport = transportToClient;
      logger.info("Created StreamableHttp client transport");

      await transportToClient.start();

      // Set up proxy connection. A throw here reaches the catch below, which
      // closes both transports (the session is not initialized yet).
      mcpProxy({
        transportToClient,
        transportToServer: serverTransport,
        onCleanup: async () => {
          await cleanupSession(sessionIdForRequest);
        },
      });

      // Handle the actual request - don't pass req.body since it wasn't parsed
      await transportToClient.handleRequest(req, res);

      // Answered without initializing: no session id went out, so close what
      // this request started. An initialized session is left as it is.
      if (transportToClient.sessionId === undefined) {
        await closeUninitializedSession(
          sessionIdForRequest,
          transportToClient,
          serverTransport,
        );
      }
    } catch (error) {
      logger.error("Error in /mcp POST route:", describeDbError(error));
      // Close what this request started unless it became a live session. The
      // proxy wiring or the first request can throw before
      // `onsessioninitialized` fills the session maps, and `cleanupSession`
      // finds nothing in empty maps, so the upstream transport (a STDIO child,
      // an SSE stream) used to stay open with no session id that could ever
      // reach it. A session that did initialize is left as the success path
      // leaves it: its id went to the client, which can use it or DELETE it.
      if (
        serverTransport &&
        newSessionId &&
        webAppTransports.get(newSessionId) !== webAppTransport
      ) {
        await closeUninitializedSession(
          newSessionId,
          webAppTransport,
          serverTransport,
        );
      }
      // A throw after the response started cannot be answered with a status.
      if (!res.headersSent) {
        res.status(500).json(PROXY_ERROR_BODY);
      }
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
      logger.error("Error in /mcp route:", describeDbError(error));
      res.status(500).json(PROXY_ERROR_BODY);
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
      logger.error("Error in /mcp DELETE route:", describeDbError(error));
      res.status(500).json(PROXY_ERROR_BODY);
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
      if (answerStdioPolicyRefusal(error, res)) {
        return;
      }
      if (answerRegisteredServerRefusal(error, res)) {
        return;
      }
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
              describeDbError(error),
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
    logger.error("Error in /stdio route:", describeDbError(error));
    res.status(500).json(PROXY_ERROR_BODY);
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
      if (answerStdioPolicyRefusal(error, res)) {
        return;
      }
      if (answerRegisteredServerRefusal(error, res)) {
        return;
      }
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
        logger.error(
          "Connection refused. Is the MCP server running?",
          describeDbError(error),
        );
        res.status(500).json(PROXY_ERROR_BODY);
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
    logger.error("Error in /sse route:", describeDbError(error));
    res.status(500).json(PROXY_ERROR_BODY);
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
    logger.error("Error in /message route:", describeDbError(error));
    res.status(500).json(PROXY_ERROR_BODY);
  }
});

serverRouter.get("/health", (req, res) => {
  res.json({
    status: "ok",
  });
});

export default serverRouter;
