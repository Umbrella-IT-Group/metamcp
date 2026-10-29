/**
 * RFC 9728 OAuth challenges on the public MCP data plane.
 *
 * Authentication-required responses for known and unknown names must remain
 * indistinguishable: the pointer is built from the request path, not DB state.
 *
 * The pointer is also the one place request text reaches a response header.
 * `resource_metadata` sits inside a quoted `WWW-Authenticate` parameter, and
 * Node's HTTP parser passes a raw `"` or `\` in the request target through to
 * Express (pinned below over a real socket), so the path is scoped only when
 * it is exactly `/metamcp/<name>/(mcp|sse|api)` in a closed alphabet, and
 * every other path gets the unscoped URL every challenge carried before.
 */
import http from "node:http";
import net from "node:net";

import type { DatabaseEndpoint } from "@repo/zod-types";
import express from "express";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import {
  sendApiKeyRequiredResponse,
  sendAuthenticationRequiredChallenge,
  sendOAuthChallengeResponse,
} from "./auth-challenge";

const originalAppUrl = process.env.APP_URL;
afterEach(() => {
  if (originalAppUrl === undefined) delete process.env.APP_URL;
  else process.env.APP_URL = originalAppUrl;
});

const UNSCOPED =
  "https://mcp.example.test/.well-known/oauth-protected-resource";

/**
 * The exact shape of a well-formed challenge: three parameters, each a quoted
 * string with no quote, backslash or control character inside. A request path
 * that could end a quoted string early would fail this.
 */
const WELL_FORMED_CHALLENGE =
  /^Bearer realm="MetaMCP", scope="mcp", resource_metadata="([^"\\\p{Cc}]*)"$/u;

interface FakeResponse {
  statusCode: number;
  body: Record<string, unknown> | undefined;
  headers: Record<string, string>;
  status(code: number): FakeResponse;
  set(name: string, value: string): FakeResponse;
  json(body: Record<string, unknown>): FakeResponse;
}

function makeResponse(): FakeResponse {
  const response: FakeResponse = {
    statusCode: 200,
    body: undefined,
    headers: {},
    status(code) {
      response.statusCode = code;
      return response;
    },
    set(name, value) {
      response.headers[name] = value;
      return response;
    },
    json(body) {
      response.body = body;
      return response;
    },
  };
  return response;
}

function makeRequest(
  resourcePath: string,
  baseUrl = "/metamcp",
): express.Request {
  return {
    baseUrl,
    path: resourcePath,
    originalUrl: `${baseUrl}${resourcePath}?session=private`,
    headers: {},
    protocol: "https",
    get: () => "mcp.example.test",
  } as unknown as express.Request;
}

function run(
  request: express.Request,
  handler: (req: express.Request, res: express.Response) => unknown,
): FakeResponse {
  const response = makeResponse();
  handler(request, response as unknown as express.Response);
  return response;
}

function comparable(response: FakeResponse) {
  const { timestamp: _timestamp, ...body } = response.body ?? {};
  return { status: response.statusCode, headers: response.headers, body };
}

describe("MCP OAuth WWW-Authenticate resource metadata", () => {
  it.each(["mcp", "sse", "api"])(
    "points to the exact scoped discovery document for %s",
    (transport) => {
      process.env.APP_URL = "https://mcp.example.test/";
      const request = makeRequest(`/gpt-personal/${transport}`);
      const known = run(request, (req, res) =>
        sendOAuthChallengeResponse(req, res, {} as DatabaseEndpoint),
      );
      const unknown = run(request, sendAuthenticationRequiredChallenge);
      const expected =
        `https://mcp.example.test/.well-known/oauth-protected-resource` +
        `/metamcp/gpt-personal/${transport}`;

      expect(known.statusCode).toBe(401);
      expect(known.headers["WWW-Authenticate"]).toContain(
        `resource_metadata="${expected}"`,
      );
      expect(known.headers["WWW-Authenticate"]).toContain('scope="mcp"');
      expect(known.headers["WWW-Authenticate"]).toMatch(WELL_FORMED_CHALLENGE);
      expect(known.body?.resource_metadata).toBe(expected);
      expect(JSON.stringify(known)).not.toContain("session=private");
      expect(comparable(unknown)).toEqual(comparable(known));
    },
  );

  it("preserves encoded endpoint paths without copying the query string", () => {
    process.env.APP_URL = "https://mcp.example.test///";
    const response = run(
      makeRequest("/my%20endpoint/mcp"),
      sendAuthenticationRequiredChallenge,
    );

    expect(response.body?.resource_metadata).toBe(
      "https://mcp.example.test/.well-known/oauth-protected-resource" +
        "/metamcp/my%20endpoint/mcp",
    );
    expect(response.headers["WWW-Authenticate"]).not.toContain("///");
  });

  it("keeps a generic challenge for requests outside the public MCP mount", () => {
    process.env.APP_URL = "https://mcp.example.test";
    const response = run(
      makeRequest("/elsewhere", "/other"),
      sendAuthenticationRequiredChallenge,
    );
    expect(response.body?.resource_metadata).toBe(UNSCOPED);
  });

  it("does not start OAuth for an API-key-only endpoint, and its body matches the OAuth one", () => {
    // No WWW-Authenticate (that is what stops an OAuth-capable client from
    // abandoning its configured key), but the SAME body an OAuth endpoint
    // gives at this URL: a different `resource_metadata` here would let an
    // anonymous caller read the endpoint's auth mode off the body.
    process.env.APP_URL = "https://mcp.example.test/";
    const request = makeRequest("/gpt-personal/mcp");
    const apiKeyOnly = run(request, sendApiKeyRequiredResponse);
    const oauth = run(request, sendAuthenticationRequiredChallenge);

    expect(apiKeyOnly.statusCode).toBe(401);
    expect(apiKeyOnly.headers["WWW-Authenticate"]).toBeUndefined();
    expect(apiKeyOnly.body?.resource_metadata).toBe(
      `${UNSCOPED}/metamcp/gpt-personal/mcp`,
    );
    expect(comparable(apiKeyOnly).body).toEqual(comparable(oauth).body);
  });
});

describe("a request path is scoped only when it is exactly a public MCP resource", () => {
  it.each([
    ["a suffix after the transport", "/gpt-personal/mcp/extra"],
    ["a trailing slash", "/gpt-personal/mcp/"],
    ["the SSE message leg", "/gpt-personal/message"],
    ["an OpenAPI tool call", "/gpt-personal/api/some_tool"],
    ["an empty name", "//mcp"],
    ["a raw double quote", '/gpt"personal/mcp'],
    [
      "a header-parameter breakout",
      '/x",resource_metadata="https:\\\\evil.example\\prm/mcp',
    ],
    ["a backslash", "/gpt\\personal/mcp"],
    ["a comma", "/gpt,personal/mcp"],
    ["a control character", "/gpt\u0001personal/mcp"],
    ["non-ASCII", "/café/mcp"],
    ["a dot segment", "/../mcp"],
    ["an encoded dot segment", "/%2e%2e/mcp"],
  ])("falls back to the unscoped URL for %s", (_label, path) => {
    process.env.APP_URL = "https://mcp.example.test";
    const challenge = run(
      makeRequest(path),
      sendAuthenticationRequiredChallenge,
    );
    const apiKey = run(makeRequest(path), sendApiKeyRequiredResponse);

    expect(challenge.statusCode).toBe(401);
    expect(challenge.headers["WWW-Authenticate"]).toMatch(
      WELL_FORMED_CHALLENGE,
    );
    expect(challenge.headers["WWW-Authenticate"]).toContain(
      `resource_metadata="${UNSCOPED}"`,
    );
    expect(challenge.body?.resource_metadata).toBe(UNSCOPED);
    expect(apiKey.body?.resource_metadata).toBe(UNSCOPED);
  });

  it("keeps an encoded quote encoded, so the header stays well formed", () => {
    process.env.APP_URL = "https://mcp.example.test";
    const challenge = run(
      makeRequest("/a%22b/mcp"),
      sendAuthenticationRequiredChallenge,
    );
    const header = challenge.headers["WWW-Authenticate"];

    expect(header).toMatch(WELL_FORMED_CHALLENGE);
    expect(header?.match(WELL_FORMED_CHALLENGE)?.[1]).toBe(
      `${UNSCOPED}/metamcp/a%22b/mcp`,
    );
  });
});

describe("over a real socket: what Node and Express hand the challenge", () => {
  // Raw writes because `fetch` and `http.request` either refuse or re-encode
  // a quote in the request target before a byte is sent, and the point is to
  // see the bytes a hostile client can actually put on the wire.
  let server: http.Server;
  let port: number;

  beforeAll(async () => {
    const router = express.Router();
    router.post("/:endpoint_name/mcp", (req, res) => {
      sendAuthenticationRequiredChallenge(req, res);
    });
    router.post("/:endpoint_name/*rest", (req, res) => {
      sendAuthenticationRequiredChallenge(req, res);
    });
    const app = express();
    app.use("/metamcp", router);
    server = http.createServer(app);
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    port = (server.address() as net.AddressInfo).port;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  function rawPost(target: string): Promise<{
    statusLine: string;
    wwwAuthenticate: string | undefined;
  }> {
    return new Promise((resolve, reject) => {
      const socket = net.connect(port, "127.0.0.1", () => {
        socket.write(
          `POST ${target} HTTP/1.1\r\nHost: mcp.example.test\r\n` +
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
          "latin1",
        );
      });
      let raw = "";
      socket.setEncoding("latin1");
      socket.on("data", (chunk) => {
        raw += chunk;
      });
      socket.on("error", reject);
      socket.on("close", () => {
        const [head = ""] = raw.split("\r\n\r\n");
        const [statusLine = "", ...headerLines] = head.split("\r\n");
        const header = headerLines.find((line) =>
          line.toLowerCase().startsWith("www-authenticate:"),
        );
        resolve({
          statusLine,
          wwwAuthenticate: header?.slice("www-authenticate:".length).trim(),
        });
      });
    });
  }

  it("scopes the canonical path", async () => {
    process.env.APP_URL = "https://mcp.example.test";
    const { statusLine, wwwAuthenticate } = await rawPost(
      "/metamcp/gpt-personal/mcp?session=private",
    );

    expect(statusLine).toBe("HTTP/1.1 401 Unauthorized");
    expect(wwwAuthenticate).toMatch(WELL_FORMED_CHALLENGE);
    expect(wwwAuthenticate?.match(WELL_FORMED_CHALLENGE)?.[1]).toBe(
      `${UNSCOPED}/metamcp/gpt-personal/mcp`,
    );
  });

  it.each([
    ["a raw double quote", '/metamcp/x",error="injected/mcp'],
    ["a backslash", "/metamcp/x\\y/mcp"],
    ["a suffix after the transport", "/metamcp/gpt-personal/mcp/extra"],
  ])(
    "reaches the challenge with %s and answers with the unscoped URL",
    async (_label, target) => {
      // The 401 proves the parser passed the bytes through and Express routed
      // them to the challenge: if a future Node refused them with a 400
      // instead, this fails loudly rather than guarding nothing.
      process.env.APP_URL = "https://mcp.example.test";
      const { statusLine, wwwAuthenticate } = await rawPost(target);

      expect(statusLine).toBe("HTTP/1.1 401 Unauthorized");
      expect(wwwAuthenticate).toMatch(WELL_FORMED_CHALLENGE);
      expect(wwwAuthenticate?.match(WELL_FORMED_CHALLENGE)?.[1]).toBe(UNSCOPED);
      expect(wwwAuthenticate).not.toContain("injected");
    },
  );
});
