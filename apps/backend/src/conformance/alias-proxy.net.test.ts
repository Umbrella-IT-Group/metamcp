/**
 * The alias proxy carries only two things for the conformance runner, which
 * cannot send headers and does not know the gateway's `Server__tool` naming:
 * the API key, and the tool-name prefix. Every other byte must pass through as
 * the runner sent it, because the DNS-rebinding scenario depends on Host and
 * Origin arriving unchanged and any extra rewriting would hide a gateway defect.
 *
 * A real loopback upstream records exactly what it receives; nothing above the
 * socket is faked. Streaming cases gate on promises, never timers.
 *
 * Oracles: RFC 9110 section 7.6.1 (hop-by-hop fields, including those named by
 * `Connection`, are not forwarded), RFC 9112 section 6.2 (Content-Length must
 * equal the body actually sent), and Node's documented `http` behaviour that
 * destroying a client request closes the upstream socket.
 */
import http from "node:http";
import type { AddressInfo } from "node:net";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { createAliasProxy } from "./alias-proxy";

const KEY = `sk_mt_${"ab12cd34".repeat(8)}`;
const PREFIX = "Fixture";

interface Seen {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
}

type Responder = (
  req: http.IncomingMessage,
  res: http.ServerResponse,
  seen: Seen,
) => void;

let upstream: http.Server;
let upstreamPort: number;
let seen: Seen[];
let respond: Responder;
let proxy: ReturnType<typeof createAliasProxy>;
let proxyPort: number;
let logged: string[];
let closed: Array<() => Promise<void>>;

async function listen(server: http.Server): Promise<number> {
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return (server.address() as AddressInfo).port;
}

async function startProxy(
  over: Partial<Parameters<typeof createAliasProxy>[0]> = {},
  port = upstreamPort,
) {
  proxy = createAliasProxy({
    upstream: `http://127.0.0.1:${port}/metamcp/ns/mcp`,
    apiKey: KEY,
    prefix: PREFIX,
    log: (m) => logged.push(m),
    ...over,
  });
  proxyPort = await proxy.listen(0, "127.0.0.1");
  closed.push(() => proxy.close());
}

beforeEach(async () => {
  seen = [];
  logged = [];
  closed = [];
  respond = (_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end("{}");
  };
  upstream = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const rec = {
        method: req.method ?? "",
        url: req.url ?? "",
        headers: req.headers,
        body: Buffer.concat(chunks),
      };
      seen.push(rec);
      respond(req, res, rec);
    });
  });
  upstreamPort = await listen(upstream);
  closed.push(
    () =>
      new Promise<void>((r) => {
        upstream.close(() => r());
        upstream.closeAllConnections();
      }),
  );
  await startProxy();
});

afterEach(async () => {
  for (const c of closed.reverse()) await c();
});

interface Reply {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
}

function send(opts: {
  method?: string;
  path?: string;
  headers?: Record<string, string>;
  body?: Buffer | string;
}): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port: proxyPort,
        method: opts.method ?? "POST",
        path: opts.path ?? "/mcp",
        headers: opts.headers,
        agent: false,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks),
          }),
        );
      },
    );
    req.on("error", reject);
    if (opts.body !== undefined) req.write(opts.body);
    req.end();
  });
}

const json = { "content-type": "application/json" };
const rpc = (m: unknown) => JSON.stringify(m);
const callMsg = (name: string) => ({
  jsonrpc: "2.0",
  id: 1,
  method: "tools/call",
  params: { name, arguments: {} },
});
const listMsg = (names: string[]) => ({
  jsonrpc: "2.0",
  id: 1,
  result: {
    tools: names.map((name) => ({
      name,
      description: "d",
      inputSchema: { type: "object" },
    })),
  },
});

describe("request side", () => {
  it("connects to an IPv6 loopback upstream accepted by the config parser", async () => {
    const v6 = http.createServer((_req, res) => {
      res.writeHead(200, json);
      res.end('{"source":"ipv6"}');
    });
    const port = await new Promise<number>((resolve, reject) => {
      v6.once("error", reject);
      v6.listen(0, "::1", () => resolve((v6.address() as AddressInfo).port));
    });
    closed.push(
      () =>
        new Promise<void>((resolve) => {
          v6.close(() => resolve());
          v6.closeAllConnections();
        }),
    );
    await proxy.close();
    await startProxy({ upstream: `http://[::1]:${port}/metamcp/ns/mcp` });
    const reply = await send({ headers: json, body: rpc(callMsg("a")) });
    expect(reply.status).toBe(200);
    expect(JSON.parse(reply.body.toString("utf8"))).toEqual({ source: "ipv6" });
  });

  it("injects the key and replaces anything the client sent for authentication", async () => {
    await send({
      headers: {
        ...json,
        authorization: "Bearer client-supplied",
        "x-api-key": "client-key",
      },
      body: rpc(callMsg("a")),
    });
    expect(seen).toHaveLength(1);
    expect(seen[0].headers.authorization).toBe(`Bearer ${KEY}`);
    expect(seen[0].headers["x-api-key"]).toBeUndefined();
  });

  it("prefixes the tool name and recomputes content-length for the longer body", async () => {
    const original = rpc(callMsg("test_simple_text"));
    await send({ headers: json, body: original });
    const body = seen[0].body.toString("utf8");
    expect(JSON.parse(body).params.name).toBe("Fixture__test_simple_text");
    expect(body.length).toBeGreaterThan(original.length);
    expect(Number(seen[0].headers["content-length"])).toBe(seen[0].body.length);
  });

  it("passes Host and Origin through verbatim and drops accept-encoding", async () => {
    await send({
      headers: {
        ...json,
        host: "evil.example.com",
        origin: "http://evil.example.com",
        "accept-encoding": "gzip",
      },
      body: rpc(callMsg("a")),
    });
    expect(seen[0].headers.host).toBe("evil.example.com");
    expect(seen[0].headers.origin).toBe("http://evil.example.com");
    expect(seen[0].headers["accept-encoding"]).toBeUndefined();
  });

  it("does not forward hop-by-hop fields, including those the Connection header names", async () => {
    await send({
      headers: {
        ...json,
        connection: "keep-alive, x-custom-hop",
        "x-custom-hop": "1",
        "keep-alive": "timeout=5",
        te: "trailers",
        "proxy-authorization": "Basic Zm9vOmJhcg==",
        "mcp-session-id": "sess-1",
      },
      body: rpc(callMsg("a")),
    });
    const h = seen[0].headers;
    expect(h["x-custom-hop"]).toBeUndefined();
    expect(h["keep-alive"]).toBeUndefined();
    expect(h.te).toBeUndefined();
    expect(h["proxy-authorization"]).toBeUndefined();
    // End-to-end fields the protocol needs are kept.
    expect(h["mcp-session-id"]).toBe("sess-1");
    expect(h["content-type"]).toBe("application/json");
  });

  it("forwards a malformed JSON body byte for byte", async () => {
    const bad = Buffer.from('{"jsonrpc": "2.0", "method": tools/call', "utf8");
    await send({ headers: json, body: bad });
    expect(seen[0].body.equals(bad)).toBe(true);
  });

  it("rewrites every tools/call in a batch and leaves other members alone", async () => {
    await send({
      headers: json,
      body: rpc([callMsg("a"), { jsonrpc: "2.0", id: 2, method: "ping" }]),
    });
    const sent = JSON.parse(seen[0].body.toString("utf8"));
    expect(sent[0].params.name).toBe("Fixture__a");
    expect(sent[1]).toEqual({ jsonrpc: "2.0", id: 2, method: "ping" });
  });

  it("proxies GET and DELETE with the session header and no body handling", async () => {
    for (const method of ["GET", "DELETE"]) {
      await send({
        method,
        headers: { "mcp-session-id": "sess-9", accept: "text/event-stream" },
      });
    }
    expect(seen.map((s) => s.method)).toEqual(["GET", "DELETE"]);
    for (const s of seen) {
      expect(s.headers["mcp-session-id"]).toBe("sess-9");
      expect(s.headers.authorization).toBe(`Bearer ${KEY}`);
      expect(s.body.length).toBe(0);
    }
  });

  it("maps /mcp onto the upstream path and keeps the query string", async () => {
    await send({
      path: "/mcp?x=1&y=two",
      headers: json,
      body: rpc(callMsg("a")),
    });
    expect(seen[0].url).toBe("/metamcp/ns/mcp?x=1&y=two");
  });

  it("answers 404 for anything but exactly /mcp, and /__health locally", async () => {
    for (const p of ["/mcp/x", "/other", "/", "/mcpx"]) {
      expect((await send({ method: "GET", path: p })).status, p).toBe(404);
    }
    const health = await send({ method: "GET", path: "/__health" });
    expect(health.status).toBe(200);
    expect(seen).toHaveLength(0);
  });

  it("accepts a body of exactly 1 MiB and refuses one byte more with 413 and no upstream request", async () => {
    const pad = (n: number) => {
      const head = '{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"';
      const tail = '"}}';
      return Buffer.from(
        head + "x".repeat(n - head.length - tail.length) + tail,
      );
    };
    const exact = pad(1024 * 1024);
    expect((await send({ headers: json, body: exact })).status).toBe(200);
    expect(seen).toHaveLength(1);

    const over = pad(1024 * 1024 + 1);
    expect((await send({ headers: json, body: over })).status).toBe(413);
    expect(seen).toHaveLength(1);
  });

  it("honours a smaller configured cap", async () => {
    await proxy.close();
    await startProxy({ maxBodyBytes: 64 });
    expect((await send({ headers: json, body: "x".repeat(65) })).status).toBe(
      413,
    );
    expect(seen).toHaveLength(0);
  });
});

describe("response side", () => {
  it("strips the prefix from a JSON tools/list result and sends a matching content-length", async () => {
    respond = (_req, res) => {
      const body = Buffer.from(rpc(listMsg(["Fixture__a", "Fixture__b"])));
      res.writeHead(200, {
        ...json,
        "content-length": String(body.length),
        "mcp-session-id": "s1",
      });
      res.end(body);
    };
    const r = await send({
      headers: json,
      body: rpc({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    const names = JSON.parse(r.body.toString("utf8")).result.tools.map(
      (t: { name: string }) => t.name,
    );
    expect(names).toEqual(["a", "b"]);
    expect(Number(r.headers["content-length"])).toBe(r.body.length);
    expect(r.headers["mcp-session-id"]).toBe("s1");
    expect(r.headers["content-type"]).toContain("application/json");
  });

  it("passes the upstream status through", async () => {
    respond = (_req, res) => {
      res.writeHead(401, json);
      res.end(rpc({ error: "invalid_api_key" }));
    };
    const r = await send({ headers: json, body: rpc(callMsg("a")) });
    expect(r.status).toBe(401);
    expect(JSON.parse(r.body.toString("utf8"))).toEqual({
      error: "invalid_api_key",
    });
  });

  it("passes a non-JSON body and an unparseable JSON body through untouched", async () => {
    respond = (_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("Fixture__a plain text");
    };
    expect(
      (await send({ headers: json, body: rpc(callMsg("a")) })).body.toString(),
    ).toBe("Fixture__a plain text");

    respond = (_req, res) => {
      res.writeHead(200, json);
      res.end("{ Fixture__a not json");
    };
    expect(
      (await send({ headers: json, body: rpc(callMsg("a")) })).body.toString(),
    ).toBe("{ Fixture__a not json");
  });

  it("passes a bodiless 202 through", async () => {
    respond = (_req, res) => {
      res.writeHead(202);
      res.end();
    };
    const r = await send({
      headers: json,
      body: rpc({ jsonrpc: "2.0", method: "notifications/initialized" }),
    });
    expect(r.status).toBe(202);
    expect(r.body.length).toBe(0);
  });

  it("strips an SSE tools/list split across chunks and delivers the first event before the upstream finishes", async () => {
    let releaseUpstream!: () => void;
    const gate = new Promise<void>((r) => (releaseUpstream = r));
    const ev = (names: string[]) => `data: ${rpc(listMsg(names))}\n\n`;
    const first = ev(["Fixture__a"]);
    respond = (_req, res) => {
      res.writeHead(200, {
        "content-type": "text/event-stream",
        "mcp-session-id": "s2",
      });
      res.write(first.slice(0, 25));
      res.write(first.slice(25));
      void gate.then(() => {
        res.write(ev(["Fixture__b"]));
        res.end();
      });
    };

    const result = await new Promise<{
      session?: string | string[];
      firstEvent: string;
      full: string;
    }>((resolve, reject) => {
      const req = http.request(
        {
          host: "127.0.0.1",
          port: proxyPort,
          method: "POST",
          path: "/mcp",
          headers: json,
          agent: false,
        },
        (res) => {
          let text = "";
          let firstEvent: string | undefined;
          res.setEncoding("utf8");
          res.on("data", (c: string) => {
            text += c;
            if (firstEvent === undefined && text.includes("\n\n")) {
              // Snapshot while the upstream is still open: the gate below is
              // only released after this point, so this event cannot have
              // been held back until the stream ended.
              firstEvent = text;
              releaseUpstream();
            }
          });
          res.on("end", () =>
            resolve({
              session: res.headers["mcp-session-id"],
              firstEvent: firstEvent ?? "",
              full: text,
            }),
          );
        },
      );
      req.on("error", reject);
      req.end(rpc({ jsonrpc: "2.0", id: 1, method: "tools/list" }));
    });
    expect(result.session).toBe("s2");
    expect(result.firstEvent).toBe(ev(["a"]));
    expect(result.full).toBe(ev(["a"]) + ev(["b"]));
  });

  it("destroys the upstream request when the client goes away", async () => {
    let upstreamClosed!: () => void;
    const closedSignal = new Promise<void>((r) => (upstreamClosed = r));
    respond = (req, res) => {
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.write(": open\n\n");
      res.on("close", upstreamClosed);
    };
    await new Promise<void>((resolve, reject) => {
      const req = http.request(
        {
          host: "127.0.0.1",
          port: proxyPort,
          method: "GET",
          path: "/mcp",
          agent: false,
        },
        (res) => {
          res.once("data", () => {
            req.destroy();
            resolve();
          });
        },
      );
      req.on("error", () => undefined);
      req.on("timeout", reject);
      req.end();
    });
    await closedSignal;
  });

  it("answers 502 when the upstream is down", async () => {
    await proxy.close();
    const dead = http.createServer();
    const deadPort = await listen(dead);
    await new Promise<void>((r) => dead.close(() => r()));
    await startProxy({}, deadPort);
    const r = await send({ headers: json, body: rpc(callMsg("a")) });
    expect(r.status).toBe(502);
    expect(r.headers["content-type"]).toContain("application/json");
  });
});

describe("logging", () => {
  it("never receives the key, a header value or a body", async () => {
    await send({
      headers: {
        ...json,
        authorization: "Bearer client-supplied-token",
        "x-api-key": "client-key-value",
        origin: "http://o.example",
      },
      body: rpc({
        ...callMsg("secret_tool_name"),
        params: {
          name: "secret_tool_name",
          arguments: { password: "hunter2" },
        },
      }),
    });
    respond = (_req, res) => {
      res.writeHead(500, json);
      res.end("boom");
    };
    await send({ headers: json, body: rpc(callMsg("a")) });
    await proxy.close();
    const dead = http.createServer();
    const deadPort = await listen(dead);
    await new Promise<void>((r) => dead.close(() => r()));
    await startProxy({}, deadPort);
    await send({ headers: json, body: rpc(callMsg("a")) });

    const all = logged.join("\n");
    for (const forbidden of [
      KEY,
      "client-supplied-token",
      "client-key-value",
      "hunter2",
      "secret_tool_name",
      "Bearer",
    ]) {
      expect(all, forbidden).not.toContain(forbidden);
    }
  });
});
