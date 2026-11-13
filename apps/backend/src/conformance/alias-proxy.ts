/**
 * A loopback proxy between the conformance runner and the gateway. The runner
 * cannot send headers and knows nothing of the gateway's `Server__tool` naming,
 * so this adds exactly two things: the API key on every request, and the tool
 * prefix on `tools/call` names (stripped again from `tools/list` results).
 *
 * Everything else must pass through as the runner sent it. In particular Host
 * and Origin reach the gateway verbatim, because the DNS-rebinding scenario
 * sends a hostile Host and expects the gateway to refuse it; a proxy that
 * normalised them would turn a real gateway defect into a pass.
 *
 * It is built on `node:http` rather than `fetch` for the same reason (fetch
 * rewrites Host), and the upstream hop uses a non-keep-alive agent so a pooled
 * socket the gateway has already closed (its default 5 s idle timeout) cannot
 * surface as a false 502.
 *
 * The key lives only in memory here and is never logged: `log` receives fixed
 * wording, methods, statuses and error codes, never a header, a body, a tool
 * name or the key.
 */
import http from "node:http";

import {
  addPrefixToToolCalls,
  SseEventRewriter,
  stripPrefixFromToolList,
} from "./alias-rewrite";

const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;

/** RFC 9110 section 7.6.1 hop-by-hop fields, plus the de-facto `proxy-connection`. */
const HOP_BY_HOP = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
];

export interface AliasProxyOptions {
  /** Full URL of the gateway's MCP endpoint, e.g. http://127.0.0.1:12009/metamcp/ns/mcp */
  upstream: string;
  apiKey: string;
  prefix: string;
  log: (message: string) => void;
  maxBodyBytes?: number;
}

export interface AliasProxy {
  /** Resolves with the bound port (useful when `port` is 0). */
  listen(port: number, host?: string): Promise<number>;
  close(): Promise<void>;
}

/** The fields a message must not forward: hop-by-hop plus any `Connection` names. */
function hopByHopFields(headers: http.IncomingHttpHeaders): Set<string> {
  const names = new Set(HOP_BY_HOP);
  const connection = headers.connection;
  const listed = Array.isArray(connection) ? connection.join(",") : connection;
  for (const token of (listed ?? "").split(",")) {
    const name = token.trim().toLowerCase();
    if (name) names.add(name);
  }
  return names;
}

function sendJson(
  res: http.ServerResponse,
  status: number,
  body: unknown,
): void {
  const payload = Buffer.from(JSON.stringify(body));
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": String(payload.length),
  });
  res.end(payload);
}

export function createAliasProxy(opts: AliasProxyOptions): AliasProxy {
  const upstream = new URL(opts.upstream);
  const maxBody = opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  const agent = new http.Agent({ keepAlive: false });
  const log = opts.log;

  /** Forward one request; `body` is undefined for GET and DELETE. */
  function forward(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    search: string,
    body: Buffer | undefined,
  ): void {
    const drop = hopByHopFields(req.headers);
    // Replaced or recomputed, never forwarded: the client's own credentials,
    // a length that no longer matches a rewritten body, and an encoding the
    // rewriter could not read.
    for (const name of [
      "content-length",
      "accept-encoding",
      "authorization",
      "x-api-key",
    ]) {
      drop.add(name);
    }
    const headers: http.OutgoingHttpHeaders = {};
    for (const [name, value] of Object.entries(req.headers)) {
      if (value !== undefined && !drop.has(name)) headers[name] = value;
    }
    headers.authorization = `Bearer ${opts.apiKey}`;
    if (body !== undefined) headers["content-length"] = String(body.length);

    const outbound = http.request(
      {
        // URL.hostname includes IPv6 brackets; node:http expects the bare
        // address here or it tries to resolve "[::1]" as a DNS name.
        hostname: upstream.hostname.replace(/^\[|\]$/g, ""),
        port: upstream.port || 80,
        path: `${upstream.pathname}${search}`,
        method: req.method,
        headers,
        agent,
      },
      (up) => {
        log(`${req.method} /mcp -> ${up.statusCode}`);
        relay(up, res);
      },
    );

    outbound.on("error", (error: NodeJS.ErrnoException) => {
      log(`upstream request failed: ${error.code ?? "error"}`);
      if (!res.headersSent) sendJson(res, 502, { error: "bad_gateway" });
      else res.destroy();
    });
    // A client that goes away must not leave the upstream stream running.
    res.on("close", () => {
      if (!res.writableFinished) outbound.destroy();
    });

    if (body !== undefined) outbound.end(body);
    else outbound.end();
  }

  function relay(up: http.IncomingMessage, res: http.ServerResponse): void {
    const status = up.statusCode ?? 502;
    const drop = hopByHopFields(up.headers);
    const headers: http.OutgoingHttpHeaders = {};
    for (const [name, value] of Object.entries(up.headers)) {
      if (value !== undefined && !drop.has(name)) headers[name] = value;
    }
    const contentType = String(up.headers["content-type"] ?? "").toLowerCase();

    if (contentType.startsWith("text/event-stream")) {
      // Streamed, not buffered: progress and log events must arrive live.
      delete headers["content-length"];
      res.writeHead(status, headers);
      const rewriter = new SseEventRewriter(opts.prefix);
      up.on("data", (chunk: Buffer) => {
        const out = rewriter.push(chunk);
        if (out) res.write(out);
      });
      up.on("end", () => {
        const tail = rewriter.end();
        if (tail) res.write(tail);
        res.end();
      });
      up.on("error", () => res.destroy());
      return;
    }

    if (contentType.startsWith("application/json")) {
      const chunks: Buffer[] = [];
      up.on("data", (chunk: Buffer) => chunks.push(chunk));
      up.on("error", () => res.destroy());
      up.on("end", () => {
        let payload = Buffer.concat(chunks);
        try {
          const parsed: unknown = JSON.parse(payload.toString("utf8"));
          const stripped = stripPrefixFromToolList(parsed, opts.prefix);
          if (stripped !== parsed)
            payload = Buffer.from(JSON.stringify(stripped));
        } catch {
          // Not JSON after all: pass the bytes through untouched.
        }
        headers["content-length"] = String(payload.length);
        res.writeHead(status, headers);
        res.end(payload);
      });
      return;
    }

    res.writeHead(status, headers);
    up.on("error", () => res.destroy());
    up.pipe(res);
  }

  const server = http.createServer((req, res) => {
    const url = req.url ?? "";
    const queryStart = url.indexOf("?");
    const pathname = queryStart < 0 ? url : url.slice(0, queryStart);
    const search = queryStart < 0 ? "" : url.slice(queryStart);

    if (req.method === "GET" && pathname === "/__health") {
      sendJson(res, 200, { status: "ok" });
      return;
    }
    // Exactly /mcp and nothing broader: no accidental open relay to the rest
    // of the gateway.
    if (pathname !== "/mcp") {
      sendJson(res, 404, { error: "not_found" });
      return;
    }
    if (req.method !== "POST") {
      forward(req, res, search, undefined);
      return;
    }

    const chunks: Buffer[] = [];
    let size = 0;
    let tooLarge = false;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      // Keep reading (and discard) after the cap so the client can finish
      // sending and read the 413, instead of seeing a reset connection.
      if (size > maxBody) tooLarge = true;
      else chunks.push(chunk);
    });
    req.on("error", () => res.destroy());
    req.on("end", () => {
      if (tooLarge) {
        log("request body over the limit");
        sendJson(res, 413, { error: "payload_too_large" });
        return;
      }
      const original = Buffer.concat(chunks);
      let outgoing = original;
      try {
        const parsed: unknown = JSON.parse(original.toString("utf8"));
        const rewritten = addPrefixToToolCalls(parsed, opts.prefix);
        if (rewritten !== parsed)
          outgoing = Buffer.from(JSON.stringify(rewritten));
      } catch {
        // Malformed JSON goes upstream byte for byte, so the gateway's own
        // error handling is what answers it.
      }
      forward(req, res, search, outgoing);
    });
  });

  return {
    listen: (port, host = "127.0.0.1") =>
      new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, host, () => {
          const address = server.address();
          resolve(typeof address === "object" && address ? address.port : port);
        });
      }),
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
        agent.destroy();
      }),
  };
}
