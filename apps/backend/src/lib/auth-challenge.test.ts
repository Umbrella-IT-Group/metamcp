/**
 * RFC 9728 OAuth challenges on the public MCP data plane.
 *
 * Authentication-required responses for known and unknown names must remain
 * indistinguishable: the pointer is built from the request path, not DB state.
 */
import type { DatabaseEndpoint } from "@repo/zod-types";
import express from "express";
import { afterEach, describe, expect, it } from "vitest";

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
    expect(response.body?.resource_metadata).toBe(
      "https://mcp.example.test/.well-known/oauth-protected-resource",
    );
  });

  it("does not start OAuth for an API-key-only endpoint", () => {
    process.env.APP_URL = "https://mcp.example.test/";
    const response = run(
      makeRequest("/gpt-personal/mcp"),
      sendApiKeyRequiredResponse,
    );
    expect(response.statusCode).toBe(401);
    expect(response.headers["WWW-Authenticate"]).toBeUndefined();
    expect(response.body?.resource_metadata).toBe(
      "https://mcp.example.test/.well-known/oauth-protected-resource",
    );
  });
});
