/**
 * The body-size ceiling on `/oauth/*`.
 *
 * WHAT WAS WRONG. `apps/backend/src/index.ts` registers a global
 * `express.json({ limit: "50mb" })` BEFORE `app.use(oauthRouter)`. body-parser
 * marks a request as read and every later parser no-ops against it, so
 * whichever runs first sets the ceiling — which meant the 10mb the OAuth
 * router asked for never bound anything, and the largest body an anonymous
 * caller could push into `POST /oauth/register` was 50mb.
 *
 * The fix is an ordering one (the global parser now skips OAuth-served paths
 * so the router's own parser binds), and ordering is exactly the kind of thing
 * that looks right in a diff and is wrong on the wire. So these run over a
 * REAL socket against the REAL router, and the mount order below is copied
 * from ../../index — it is a model of that file, not that file, because
 * index.ts calls `app.listen` at module scope and cannot be imported.
 *
 * `rejects an oversized body even when the app-level parser is 50mb` is the
 * assertion that bites: without the skip in ../../index the request is parsed
 * by the big parser and reaches the handler, and every other test here still
 * passes.
 */

import type { Server } from "node:http";

import express from "express";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// The OAuth sub-routers share this barrel, and ./index.ts starts a cleanup
// interval against it at import time. Only the members these requests reach
// need to answer.
vi.mock("../../db/repositories", () => ({
  oauthRepository: {
    cleanupExpired: vi.fn().mockResolvedValue(undefined),
    pruneUnusedClients: vi.fn().mockResolvedValue(0),
    upsertClient: vi.fn().mockResolvedValue(undefined),
  },
  toolCallAuditRepository: { pruneOlderThan: vi.fn().mockResolvedValue(0) },
  endpointsRepository: {
    hasOAuthEnabledEndpoint: vi.fn().mockResolvedValue(true),
    findAllWithNamespaces: vi.fn().mockResolvedValue([]),
  },
  usersRepository: { isDisabled: vi.fn().mockResolvedValue(false) },
}));

// ../../auth builds the drizzle adapter at import time and throws without a
// database; the authorization sub-router pulls it in.
vi.mock("../../auth", () => ({
  auth: { api: { getSession: vi.fn() }, handler: vi.fn() },
}));

process.env.APP_URL = "https://gateway.example.test";
process.env.BETTER_AUTH_SECRET = "test-secret-for-body-limit-suite";

const { default: oauthRouter } = await import("./index");
const { isOAuthServedPath, OAUTH_BODY_LIMIT } = await import("./utils");
const { errorHandler } = await import(
  "../../middleware/error-handler.middleware"
);

/** Comfortably over 256kb, comfortably under anything a socket struggles with. */
const OVERSIZED_BYTES = 300 * 1024;

/** The registration a real connector sends, so the cap can be shown harmless. */
const CLAUDE_REGISTRATION = {
  client_name: "Claude",
  redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
  grant_types: ["authorization_code"],
  response_types: ["code"],
  token_endpoint_auth_method: "none",
};

/**
 * Build an app whose OAuth mount matches ../../index.
 *
 * `skipOAuthInGlobalParser` exists so the broken wiring can be stood up
 * alongside the fixed one: with it false, the app-level 50mb parser consumes
 * `/oauth/*` first and the router's own limit is dead code.
 */
async function startApp(skipOAuthInGlobalParser: boolean): Promise<{
  server: Server;
  baseUrl: string;
}> {
  const app = express();

  app.use((req, res, next) => {
    if (
      req.path.startsWith("/mcp-proxy/") ||
      req.path.startsWith("/metamcp/")
    ) {
      next();
    } else if (skipOAuthInGlobalParser && isOAuthServedPath(req.path)) {
      next();
    } else {
      express.json({ limit: "50mb" })(req, res, next);
    }
  });

  app.use(oauthRouter);

  // Stands in for every non-OAuth route: it must keep the generous app-level
  // limit, so the scoping is shown to be scoping rather than a global squeeze.
  app.post("/trpc/anything", (req, res) => {
    res.status(200).json({ received: typeof req.body === "object" });
  });

  app.use(errorHandler);

  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;

  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

let fixed: { server: Server; baseUrl: string };
let unfixed: { server: Server; baseUrl: string };

beforeAll(async () => {
  fixed = await startApp(true);
  unfixed = await startApp(false);
});

afterAll(async () => {
  await new Promise((resolve) => fixed.server.close(resolve));
  await new Promise((resolve) => unfixed.server.close(resolve));
});

function postJson(baseUrl: string, path: string, body: unknown) {
  return fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

/** A body whose serialised size is just over the cap. */
function oversizedRegistration() {
  return {
    ...CLAUDE_REGISTRATION,
    client_name: "x".repeat(OVERSIZED_BYTES),
  };
}

describe("/oauth/* body limit", () => {
  it("pins the limit at 256kb", () => {
    // The constant itself. Every assertion below would still pass if it were
    // raised back to 50mb by way of a much larger fixture.
    expect(OAUTH_BODY_LIMIT).toBe("256kb");
  });

  it("rejects an oversized DCR body with 413", async () => {
    const response = await postJson(
      fixed.baseUrl,
      "/oauth/register",
      oversizedRegistration(),
    );

    expect(response.status).toBe(413);
  });

  it("rejects an oversized body even when the app-level parser is 50mb", async () => {
    // The regression guard for the ordering. Remove the OAuth skip from the
    // global parser in ../../index and this is the only test that notices:
    // the big parser consumes the stream first, the router's parser no-ops,
    // and 300kb of anonymous input reaches the handler.
    const withSkip = await postJson(
      fixed.baseUrl,
      "/oauth/register",
      oversizedRegistration(),
    );
    const withoutSkip = await postJson(
      unfixed.baseUrl,
      "/oauth/register",
      oversizedRegistration(),
    );

    expect(withSkip.status).toBe(413);
    expect(withoutSkip.status).not.toBe(413);
  });

  it("still accepts a real Claude connector registration", async () => {
    // The half that matters more than the refusal: 256kb must be invisible to
    // the flow this endpoint exists for.
    const response = await postJson(
      fixed.baseUrl,
      "/oauth/register",
      CLAUDE_REGISTRATION,
    );

    expect(response.status).toBe(201);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body.client_id).toMatch(/^mcp_client_/);
    expect(body.redirect_uris).toEqual(CLAUDE_REGISTRATION.redirect_uris);
  });

  it("leaves non-OAuth routes on the generous app-level limit", async () => {
    const response = await postJson(fixed.baseUrl, "/trpc/anything", {
      blob: "x".repeat(OVERSIZED_BYTES),
    });

    expect(response.status).toBe(200);
  });
});

describe("isOAuthServedPath", () => {
  // Whole-segment matching, not `startsWith("/oauth")`. A loose test would
  // steer paths this router does not serve away from the app-level parser and
  // leave them with NO body parser at all, since the router's own parser only
  // fires on `/oauth/`.
  it("matches the paths the OAuth router serves", () => {
    for (const path of [
      "/oauth",
      "/oauth/register",
      "/oauth/token",
      "/.well-known",
      "/.well-known/oauth-authorization-server",
    ]) {
      expect(isOAuthServedPath(path)).toBe(true);
    }
  });

  it("does not match a path that merely starts with the same letters", () => {
    for (const path of [
      "/oauthsomething",
      "/oauth-not-ours",
      "/oauth-clients",
      "/api/auth/session",
      "/trpc/anything",
    ]) {
      expect(isOAuthServedPath(path)).toBe(false);
    }
  });
});
