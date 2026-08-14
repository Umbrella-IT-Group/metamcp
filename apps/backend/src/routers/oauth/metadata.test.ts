/**
 * Tests for the `/.well-known/oauth-*` discovery gate — upstream issue #277.
 *
 * The failure being prevented is a client break, not a leak. Claude Code
 * v2.1.85 probes these paths before connecting to any HTTP MCP server; if it
 * finds authorization server metadata it starts an OAuth flow and drops the
 * bearer token the user configured. Serving the documents unconditionally
 * therefore makes every API-key-only endpoint re-prompt for auth every
 * session.
 *
 * So the assertions come in pairs: an OAuth-enabled endpoint must still be
 * discoverable (breaking that would take the live Claude.ai connectors down),
 * and an API-key-only or unknown one must answer 404 — with the SAME body
 * either way, so discovery cannot be used to enumerate endpoint names.
 *
 * The router is driven directly as express middleware against fake req/res
 * objects, the same shape `authorization.test.ts` uses: no supertest, and
 * `../../db/repositories` mocked so `db/index.ts` (which throws without its
 * environment) stays out of the import graph.
 */

import express from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";

const loggerMock = {
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
};

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

const endpointsRepositoryMock = {
  findByName: vi.fn(),
  hasOAuthEnabledEndpoint: vi.fn(),
};

vi.mock("../../db/repositories", () => ({
  endpointsRepository: endpointsRepositoryMock,
}));

// getBaseUrl prefers APP_URL; set before the router is imported so the
// advertised endpoints are the public ones rather than the container-internal
// listener.
process.env.APP_URL = "https://mcp.example.test";

const { default: metadataRouter } = await import("./metadata");

const PROTECTED_RESOURCE = "/.well-known/oauth-protected-resource";
const AUTHORIZATION_SERVER = "/.well-known/oauth-authorization-server";
const BOTH_DOCUMENTS = [PROTECTED_RESOURCE, AUTHORIZATION_SERVER] as const;

const OAUTH_ENDPOINT = "claude-connector";
const API_KEY_ONLY_ENDPOINT = "ninja-alerts";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

interface FakeRes {
  statusCode: number;
  body: Record<string, unknown> | undefined;
  headers: Record<string, string>;
  settled: Promise<void>;
  status(code: number): FakeRes;
  json(payload: Record<string, unknown>): FakeRes;
  set(fields: Record<string, string>): FakeRes;
}

function makeRes(): FakeRes {
  let settle: () => void;
  const settled = new Promise<void>((resolve) => {
    settle = resolve;
  });

  const res: FakeRes = {
    statusCode: 200,
    body: undefined,
    headers: {},
    settled,
    status(code) {
      res.statusCode = code;
      return res;
    },
    json(payload) {
      res.body = payload;
      settle();
      return res;
    },
    set(fields) {
      Object.assign(res.headers, fields);
      return res;
    },
  };

  return res;
}

async function dispatch(path: string): Promise<FakeRes> {
  const req = {
    method: "GET",
    url: path,
    originalUrl: path,
    baseUrl: "",
    path,
    query: {},
    headers: {},
  } as unknown as express.Request;
  const res = makeRes();

  await new Promise<void>((resolve, reject) => {
    (metadataRouter as unknown as express.RequestHandler)(
      req,
      res as unknown as express.Response,
      (err?: unknown) => (err ? reject(err) : resolve()),
    );
    res.settled.then(resolve);
  });

  return res;
}

beforeEach(() => {
  vi.clearAllMocks();
  // Default fixture: a deployment that DOES run OAuth, with one endpoint of
  // each kind. Left explicit rather than defaulted inside the mock, because a
  // `vi.fn()` that lost its setup resolves undefined — which reads as "no
  // OAuth" and would make a broken gate look like a passing negative.
  endpointsRepositoryMock.hasOAuthEnabledEndpoint.mockResolvedValue(true);
  endpointsRepositoryMock.findByName.mockImplementation(
    async (name: string) => {
      if (name === OAUTH_ENDPOINT) {
        return { uuid: "ep-oauth", name, enable_oauth: true };
      }
      if (name === API_KEY_ONLY_ENDPOINT) {
        return { uuid: "ep-apikey", name, enable_oauth: false };
      }
      return undefined;
    },
  );
});

// ---------------------------------------------------------------------------
// Served
// ---------------------------------------------------------------------------

describe("discovery IS served where OAuth is in use", () => {
  it.each(BOTH_DOCUMENTS)(
    "serves %s for an endpoint with enable_oauth",
    async (document) => {
      const res = await dispatch(`${document}/metamcp/${OAUTH_ENDPOINT}/mcp`);

      expect(res.statusCode).toBe(200);
      expect(res.body).toBeDefined();
      expect(endpointsRepositoryMock.findByName).toHaveBeenCalledWith(
        OAUTH_ENDPOINT,
      );
    },
  );

  it.each(BOTH_DOCUMENTS)(
    "serves the unscoped %s while any endpoint has OAuth enabled",
    async (document) => {
      // The live Claude.ai connectors reach discovery this way: the 401
      // challenge advertises the BARE resource_metadata URL, so a 404 here
      // would break them.
      const res = await dispatch(document);

      expect(res.statusCode).toBe(200);
      expect(res.body).toBeDefined();
      expect(
        endpointsRepositoryMock.hasOAuthEnabledEndpoint,
      ).toHaveBeenCalledTimes(1);
    },
  );

  it("still advertises the public base URL, not the internal listener", async () => {
    const resource = await dispatch(PROTECTED_RESOURCE);
    expect(resource.body).toMatchObject({
      resource: "https://mcp.example.test/",
      authorization_servers: ["https://mcp.example.test"],
    });

    const server = await dispatch(AUTHORIZATION_SERVER);
    expect(server.body).toMatchObject({
      issuer: "https://mcp.example.test/",
      authorization_endpoint: "https://mcp.example.test/oauth/authorize",
      registration_endpoint: "https://mcp.example.test/oauth/register",
    });
  });

  it("decodes a percent-encoded endpoint name before looking it up", async () => {
    // `req.path` is not decoded, but `lookupEndpoint` matches the DECODED
    // param — so an endpoint whose name needs escaping must resolve to the
    // same row on both surfaces.
    endpointsRepositoryMock.findByName.mockResolvedValue({
      uuid: "ep-spaced",
      name: "my endpoint",
      enable_oauth: true,
    });

    const res = await dispatch(
      `${PROTECTED_RESOURCE}/metamcp/my%20endpoint/mcp`,
    );

    expect(res.statusCode).toBe(200);
    expect(endpointsRepositoryMock.findByName).toHaveBeenCalledWith(
      "my endpoint",
    );
  });
});

// ---------------------------------------------------------------------------
// Refused
// ---------------------------------------------------------------------------

describe("discovery is NOT served where OAuth is off", () => {
  it.each(BOTH_DOCUMENTS)(
    "404s %s for an API-key-only endpoint",
    async (document) => {
      // Issue #277 exactly: this is the endpoint whose configured bearer
      // token Claude Code would otherwise abandon.
      const res = await dispatch(
        `${document}/metamcp/${API_KEY_ONLY_ENDPOINT}/mcp`,
      );

      expect(res.statusCode).toBe(404);
      expect(res.body).toMatchObject({ error: "not_found" });
    },
  );

  it.each(BOTH_DOCUMENTS)(
    "404s the unscoped %s when NO endpoint has OAuth enabled",
    async (document) => {
      // An API-key-only deployment must not advertise an authorization server
      // at all — the fallback path is the one clients land on after the
      // endpoint-scoped probe 404s.
      endpointsRepositoryMock.hasOAuthEnabledEndpoint.mockResolvedValue(false);

      const res = await dispatch(document);

      expect(res.statusCode).toBe(404);
      expect(res.body).toMatchObject({ error: "not_found" });
    },
  );

  it.each(BOTH_DOCUMENTS)(
    "404s %s for an unknown endpoint",
    async (document) => {
      const res = await dispatch(`${document}/metamcp/no-such-endpoint/mcp`);

      expect(res.statusCode).toBe(404);
      expect(res.body).toMatchObject({ error: "not_found" });
    },
  );

  it("answers an unknown endpoint and an OAuth-disabled one identically", async () => {
    // Otherwise discovery becomes an endpoint-name oracle for an
    // unauthenticated caller.
    const disabled = await dispatch(
      `${PROTECTED_RESOURCE}/metamcp/${API_KEY_ONLY_ENDPOINT}/mcp`,
    );
    const missing = await dispatch(
      `${PROTECTED_RESOURCE}/metamcp/no-such-endpoint/mcp`,
    );

    expect(disabled.statusCode).toBe(missing.statusCode);
    expect(disabled.body).toEqual(missing.body);
  });

  it("fails closed on a path that names no MCP resource", async () => {
    // Asserted against the DEFAULT fixture, where the deployment does have an
    // OAuth endpoint — so a 404 here can only come from failing closed. If an
    // unrecognised suffix instead fell back to the unscoped document, this
    // would be a way to read the metadata out of any deployment that runs
    // OAuth on even one endpoint, whatever path was asked for.
    expect(await endpointsRepositoryMock.hasOAuthEnabledEndpoint()).toBe(true);

    for (const path of [
      `${PROTECTED_RESOURCE}/garbage`,
      `${PROTECTED_RESOURCE}/metamcp`,
      `${AUTHORIZATION_SERVER}/garbage/deeper/still`,
      `${AUTHORIZATION_SERVER}/../oauth-protected-resource`,
    ]) {
      const res = await dispatch(path);
      expect(res.statusCode, `${path} must fail closed`).toBe(404);
    }
  });

  it("only answers for the public MCP mount, not any path shaped like one", async () => {
    // `/mcp-proxy/<name>` and `/metamcp/<name>` differ by one segment, and
    // only the second is a protected resource this server publishes. Reading
    // segment[1] without checking segment[0] would answer for a resource
    // that does not exist at that URL.
    const res = await dispatch(
      `${PROTECTED_RESOURCE}/mcp-proxy/${OAUTH_ENDPOINT}/mcp`,
    );

    expect(res.statusCode).toBe(404);
    expect(endpointsRepositoryMock.findByName).not.toHaveBeenCalled();
    expect(
      endpointsRepositoryMock.hasOAuthEnabledEndpoint,
    ).not.toHaveBeenCalled();
  });

  it("never lets a refusal be cached", async () => {
    // `enable_oauth` is a runtime toggle; a shared cache holding this 404 for
    // the hour the success path asks for would keep a just-enabled endpoint
    // undiscoverable.
    const res = await dispatch(
      `${PROTECTED_RESOURCE}/metamcp/${API_KEY_ONLY_ENDPOINT}/mcp`,
    );

    expect(res.statusCode).toBe(404);
    expect(res.headers["Cache-Control"]).toBe("no-store");
  });

  it("does not touch the endpoint table more than once per request", async () => {
    // The gate runs on an unauthenticated public route.
    await dispatch(`${PROTECTED_RESOURCE}/metamcp/${OAUTH_ENDPOINT}/mcp`);

    expect(endpointsRepositoryMock.findByName).toHaveBeenCalledTimes(1);
    expect(
      endpointsRepositoryMock.hasOAuthEnabledEndpoint,
    ).not.toHaveBeenCalled();
  });
});
