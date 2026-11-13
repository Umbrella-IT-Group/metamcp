/**
 * The backend MCP server the gateway fronts during a conformance run: a plain
 * Streamable HTTP server on loopback, speaking the real SDK so the wire format
 * is the one the gateway's own backend client expects. It uses the low-level
 * `Server` class on purpose: the high-level `McpServer` rewrites input schemas
 * through zod, which would strip the raw JSON Schema 2020-12 keywords the
 * `json-schema-2020-12` scenario looks for.
 *
 * Sessions are stateful (one `Server` plus transport per initialize), because
 * the gateway's pool holds a few long-lived connections to each backend and
 * reuses them across its own sessions. Handlers keep no state of their own, so
 * sharing a connection between gateway sessions is safe.
 */
import { randomUUID } from "node:crypto";
import http from "node:http";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  isInitializeRequest,
  ListToolsRequestSchema,
  SetLevelRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { createFixtureHandlers, FIXTURE_TOOLS } from "./fixture-tools";

const MAX_BODY_BYTES = 1024 * 1024;

export interface FixtureServerOptions {
  /** Injected so tests never wait on a real timer. Defaults to `setTimeout`. */
  sleep?: (ms: number) => Promise<void>;
}

export interface FixtureServer {
  /** Resolves with the bound port (useful when `port` is 0). */
  listen(port: number, host?: string): Promise<number>;
  close(): Promise<void>;
}

interface Session {
  server: Server;
  transport: StreamableHTTPServerTransport;
}

function jsonRpcError(
  res: http.ServerResponse,
  status: number,
  code: number,
  message: string,
): void {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(
    JSON.stringify({ jsonrpc: "2.0", error: { code, message }, id: null }),
  );
}

async function readJsonBody(req: http.IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > MAX_BODY_BYTES) throw new Error("request body too large");
    chunks.push(buf);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

export function createFixtureServer(
  opts: FixtureServerOptions = {},
): FixtureServer {
  const handlers = createFixtureHandlers({ sleep: opts.sleep });
  const sessions = new Map<string, Session>();

  function newSession(): Session {
    const server = new Server(
      { name: "conformance-fixture", version: "1.0.0" },
      { capabilities: { tools: {}, logging: {} } },
    );
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: FIXTURE_TOOLS.map((t) => ({ ...t })),
    }));
    server.setRequestHandler(CallToolRequestSchema, async (request, extra) =>
      handlers.callTool(request.params.name, request.params.arguments, extra),
    );
    server.setRequestHandler(SetLevelRequestSchema, async () => ({}));

    const session: Session = {
      server,
      transport: new StreamableHTTPServerTransport({
        sessionIdGenerator: randomUUID,
        onsessioninitialized: (id) => {
          sessions.set(id, session);
        },
      }),
    };
    session.transport.onclose = () => {
      const id = session.transport.sessionId;
      if (id) sessions.delete(id);
    };
    return session;
  }

  async function handleMcp(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    const sessionId = req.headers["mcp-session-id"];
    const existing =
      typeof sessionId === "string" ? sessions.get(sessionId) : undefined;

    if (req.method === "POST") {
      let body: unknown;
      try {
        body = await readJsonBody(req);
      } catch {
        jsonRpcError(res, 400, -32700, "Parse error");
        return;
      }
      if (existing) {
        await existing.transport.handleRequest(req, res, body);
        return;
      }
      if (typeof sessionId === "string") {
        jsonRpcError(res, 404, -32001, "Session not found");
        return;
      }
      if (!isInitializeRequest(body)) {
        jsonRpcError(
          res,
          400,
          -32000,
          "Bad Request: no session and not an initialize request",
        );
        return;
      }
      const session = newSession();
      await session.server.connect(session.transport);
      await session.transport.handleRequest(req, res, body);
      return;
    }

    if (req.method === "GET" || req.method === "DELETE") {
      if (!existing) {
        jsonRpcError(
          res,
          typeof sessionId === "string" ? 404 : 400,
          -32000,
          "Invalid or missing session",
        );
        return;
      }
      await existing.transport.handleRequest(req, res);
      return;
    }

    res.writeHead(405, { allow: "GET, POST, DELETE" });
    res.end();
  }

  const httpServer = http.createServer((req, res) => {
    const pathname = (req.url ?? "").split("?")[0];
    if (req.method === "GET" && pathname === "/health") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"status":"ok"}');
      return;
    }
    if (pathname === "/mcp") {
      handleMcp(req, res).catch(() => {
        if (!res.headersSent) jsonRpcError(res, 500, -32603, "Internal error");
        else res.end();
      });
      return;
    }
    res.writeHead(404);
    res.end();
  });

  return {
    listen: (port, host = "127.0.0.1") =>
      new Promise((resolve, reject) => {
        httpServer.once("error", reject);
        httpServer.listen(port, host, () => {
          const address = httpServer.address();
          resolve(typeof address === "object" && address ? address.port : port);
        });
      }),
    close: async () => {
      await Promise.allSettled(
        [...sessions.values()].map((s) => s.transport.close()),
      );
      sessions.clear();
      await new Promise<void>((resolve) => {
        httpServer.close(() => resolve());
        httpServer.closeAllConnections();
      });
    },
  };
}
