/**
 * Every OAuth route answers on its exact lowercase path only.
 *
 * Express matches routes case-insensitively by default, so before this change
 * `/OAuth/Authorize` reached the same handler as `/oauth/authorize`. A gate in
 * front of the gateway that matches paths exactly (an edge access policy on
 * `/oauth/authorize`, say) would not treat the other spelling as the same
 * endpoint. Each OAuth router is now created with `caseSensitive: true`
 * (oauthRouterOptions in ./utils), so only the paths the discovery metadata
 * advertises route, and any other spelling falls through to the app's 404.
 *
 * Run over a real socket against the real mounted router (./index), the way
 * ./body-limit.test.ts does, so the router options are what is under test and
 * not a copy of them. A catch-all after the OAuth router marks a request that
 * no OAuth route claimed, which is how "routed" is told apart from a handler's
 * own 4xx.
 */

import type { Server } from "node:http";

import express from "express";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// ./index.ts starts a cleanup interval against this barrel at import time;
// the requests below stop at validation and never reach most of these.
vi.mock("../../db/repositories", () => ({
  oauthRepository: {
    cleanupExpired: vi.fn().mockResolvedValue(undefined),
    pruneUnapprovedDcrClients: vi.fn().mockResolvedValue(0),
    upsertClient: vi.fn().mockResolvedValue(undefined),
    getClient: vi.fn().mockResolvedValue(null),
    getAccessToken: vi.fn().mockResolvedValue(null),
    getByRefreshToken: vi.fn().mockResolvedValue(null),
    getRotatedRefreshToken: vi.fn().mockResolvedValue(null),
  },
  toolCallAuditRepository: { pruneOlderThan: vi.fn().mockResolvedValue(0) },
  endpointsRepository: {
    hasOAuthEnabledEndpoint: vi.fn().mockResolvedValue(true),
    findByName: vi.fn().mockResolvedValue({ enable_oauth: true }),
  },
  usersRepository: { isDisabled: vi.fn().mockResolvedValue(false) },
  apiKeysRepository: { validateApiKey: vi.fn().mockResolvedValue(null) },
}));

// ../../auth builds the drizzle adapter at import time and throws without a
// database; the authorization sub-router pulls it in.
vi.mock("../../auth", () => ({
  auth: {
    api: { getSession: vi.fn() },
    handler: vi.fn(async () => new Response("null", { status: 200 })),
  },
}));

process.env.APP_URL = "https://gateway.example.test";
process.env.BETTER_AUTH_SECRET = "test-secret-for-case-sensitive-routes";

const { default: oauthRouter } = await import("./index");
const { oauthRouterOptions } = await import("./utils");

const UNROUTED = "no-oauth-route-claimed-this";

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  const app = express();
  app.use(oauthRouter);
  app.use((_req, res) => {
    res.status(404).json({ marker: UNROUTED });
  });
  server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
});

let ipCounter = 0;

async function send(method: "GET" | "POST", path: string) {
  ipCounter += 1;
  const res = await fetch(`${baseUrl}${path}`, {
    method,
    redirect: "manual",
    headers: {
      "content-type": "application/json",
      // Distinct callers, so no per-IP limiter interferes between cases.
      "cf-connecting-ip": `198.51.100.${(ipCounter % 250) + 1}`,
    },
    body: method === "POST" ? "{}" : undefined,
  });
  const text = await res.text();
  return { status: res.status, unrouted: text.includes(UNROUTED) };
}

/** Every path the metadata advertises or the consent flow uses, and its method. */
const ADVERTISED: Array<["GET" | "POST", string]> = [
  ["GET", "/oauth/authorize"],
  ["POST", "/oauth/authorize/decision"],
  ["GET", "/oauth/consent/info"],
  ["GET", "/oauth/callback"],
  ["POST", "/oauth/token"],
  ["POST", "/oauth/register"],
  ["GET", "/oauth/register"],
  ["POST", "/oauth/revoke"],
  ["POST", "/oauth/introspect"],
  ["GET", "/oauth/userinfo"],
  ["GET", "/.well-known/oauth-authorization-server"],
  ["GET", "/.well-known/oauth-authorization-server/metamcp/example/mcp"],
  ["GET", "/.well-known/oauth-protected-resource"],
  ["GET", "/.well-known/oauth-protected-resource/metamcp/example/mcp"],
];

const MIXED_CASE: Array<["GET" | "POST", string]> = [
  ["GET", "/oauth/Authorize"],
  ["GET", "/OAUTH/authorize"],
  ["GET", "/OAuth/authorize"],
  ["GET", "/oauth/AUTHORIZE"],
  ["POST", "/oauth/authorize/Decision"],
  ["POST", "/oauth/Authorize/decision"],
  ["POST", "/OAUTH/AUTHORIZE/DECISION"],
  ["GET", "/oauth/Consent/info"],
  ["GET", "/oauth/Callback"],
  ["POST", "/oauth/Token"],
  ["POST", "/Oauth/token"],
  ["POST", "/oauth/Register"],
  ["GET", "/OAUTH/register"],
  ["POST", "/oauth/Revoke"],
  ["POST", "/oauth/Introspect"],
  ["GET", "/oauth/UserInfo"],
  ["GET", "/oauth/USERINFO"],
];

describe("OAuth routers are case-sensitive", () => {
  it("creates every OAuth router with caseSensitive", () => {
    expect(oauthRouterOptions).toEqual({ caseSensitive: true });
  });

  it.each(ADVERTISED)("routes %s %s", async (method, path) => {
    const res = await send(method, path);
    expect(res.unrouted).toBe(false);
  });

  it.each(MIXED_CASE)("answers 404 for %s %s", async (method, path) => {
    const res = await send(method, path);
    expect(res.status).toBe(404);
    expect(res.unrouted).toBe(true);
  });

  it("serves the discovery documents on their exact paths", async () => {
    for (const path of [
      "/.well-known/oauth-authorization-server",
      "/.well-known/oauth-protected-resource",
    ]) {
      const res = await send("GET", path);
      expect(res.status).toBe(200);
    }
  });
});
