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
 * REAL socket against the REAL router.
 *
 * THE GLOBAL PARSER IS ALSO THE REAL ONE NOW. The first cut of this file
 * hand-copied the branches out of ../../index into the model app below, on the
 * grounds that index.ts calls `app.listen` at module scope and cannot be
 * imported. That made the suite worthless as a regression guard for the very
 * fix it was written for: deleting the OAuth skip from index.ts left every
 * test here green, because the copy in the test still had it. The branches now
 * live in ../../lib/global-body-parser, which index.ts mounts and this file
 * imports, so the thing under test is the thing that runs.
 *
 * `rejects an oversized body even when the app-level parser is 50mb` is the
 * assertion that bites: remove the OAuth skip from ../../lib/global-body-parser
 * and the request is parsed by the big parser and reaches the handler. The
 * `unfixed` app is that broken wiring, stood up deliberately, so the
 * before/after can be asserted in one test rather than described in a comment.
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
const { globalBodyParser, GLOBAL_JSON_BODY_LIMIT, RAW_STREAM_PREFIXES } =
  await import("../../lib/global-body-parser");
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
 * `skipOAuthInGlobalParser` selects WHICH global parser is mounted, and the
 * asymmetry is the point:
 *
 *  - true  -> the REAL `globalBodyParser` that ../../index mounts. Nothing
 *             about its branching is restated here, so deleting the OAuth skip
 *             from that module breaks this app.
 *  - false -> a deliberate reconstruction of the PRE-FIX wiring, kept only as
 *             the control the fixed app is compared against. It is allowed to
 *             be a copy because it is modelling code that no longer exists.
 */
async function startApp(skipOAuthInGlobalParser: boolean): Promise<{
  server: Server;
  baseUrl: string;
}> {
  const app = express();

  if (skipOAuthInGlobalParser) {
    app.use(globalBodyParser);
  } else {
    app.use((req, res, next) => {
      if (
        req.path.startsWith("/mcp-proxy/") ||
        req.path.startsWith("/metamcp/")
      ) {
        next();
      } else {
        express.json({ limit: GLOBAL_JSON_BODY_LIMIT })(req, res, next);
      }
    });
  }

  app.use(oauthRouter);

  // Stands in for every non-OAuth route: it must keep the generous app-level
  // limit, so the scoping is shown to be scoping rather than a global squeeze.
  app.post("/trpc/anything", (req, res) => {
    res.status(200).json({ received: typeof req.body === "object" });
  });

  // Stands in for the MCP data plane. These paths hand the socket to a
  // transport that reads it itself, so the assertion is not about a SIZE at
  // all: `req.body` must still be undefined here, because any parser running
  // would have consumed the stream out from under that transport.
  app.post("/metamcp/raw", (req, res) => {
    res.status(200).json({ parsed: req.body !== undefined });
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

/**
 * The lanes of ../../lib/global-body-parser, driven through the exported
 * middleware itself.
 *
 * These overlap the suite above on purpose. That one asks "is the OAuth
 * surface capped", which is the security question; this one asks "does the
 * module index.ts mounts route each lane to the parser it claims to", which is
 * the question that catches someone deleting a branch. Before the extraction
 * there was no way to ask the second one at all.
 */
describe("globalBodyParser lanes", () => {
  it("pins the global limit at 50mb", () => {
    expect(GLOBAL_JSON_BODY_LIMIT).toBe("50mb");
  });

  it("binds the 256kb OAuth limit on an OAuth-served path", async () => {
    // 300kb is under the 50mb global and over the 256kb OAuth limit, so a 413
    // can only mean the OAuth parser is the one that bound. Drop the
    // isOAuthServedPath branch from globalBodyParser and this returns 201.
    const response = await postJson(
      fixed.baseUrl,
      "/oauth/register",
      oversizedRegistration(),
    );

    expect(response.status).toBe(413);
    expect(OAUTH_BODY_LIMIT).toBe("256kb");
  });

  it("binds the 50mb global limit on a non-OAuth path", async () => {
    // The same 300kb body, one path over. If the OAuth limit had been applied
    // globally rather than scoped, this would 413 too — which is the failure
    // this half exists to rule out.
    const response = await postJson(fixed.baseUrl, "/trpc/anything", {
      blob: "x".repeat(OVERSIZED_BYTES),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ received: true });
  });

  it("leaves raw-stream paths with no parser at all", async () => {
    const response = await postJson(fixed.baseUrl, "/metamcp/raw", {
      anything: true,
    });

    expect(response.status).toBe(200);
    // `parsed: true` would mean the JSON parser consumed the MCP data plane's
    // stream — a different and worse bug than an oversized body.
    expect(await response.json()).toEqual({ parsed: false });
  });

  it("declares the raw-stream prefixes as whole mount points", () => {
    // Trailing slashes matter: without them `/metamcp-something` would also
    // skip the parser and reach its handler with no body.
    expect(RAW_STREAM_PREFIXES).toEqual(["/mcp-proxy/", "/metamcp/"]);
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
