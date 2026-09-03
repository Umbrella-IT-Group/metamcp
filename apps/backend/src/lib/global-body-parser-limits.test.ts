/**
 * The per-surface body ceilings `globalBodyParser` picks for `/api/auth` and
 * `/trpc`.
 *
 * WHAT WAS WRONG. `apps/backend/src/index.ts` mounts `globalBodyParser` first,
 * and before this change it parsed `/api/auth` and `/trpc` at the 50mb global
 * limit. body-parser marks a request read and every later parser no-ops, so
 * that 50mb was the ceiling that bound: an Access-authenticated caller could
 * force a 50mb JSON parse per request on the sign-in relay and on tRPC, up to
 * the sign-in limiter's budget.
 *
 * The fix is a routing-order one (the module now routes those two prefixes to
 * their own smaller parsers), and routing-order looks right in a diff and is
 * wrong on the wire, so these run over a REAL socket against the REAL module
 * `index.ts` mounts. The `unfixed` app reconstructs the pre-fix wiring (one
 * 50mb parser for everything non-raw, non-OAuth) as the control the fixed app
 * is compared against.
 */

import type { Server } from "node:http";

import express from "express";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

process.env.APP_URL = "https://gateway.example.test";
process.env.BETTER_AUTH_SECRET = "test-secret-for-body-limit-lanes";

const {
  globalBodyParser,
  AUTH_RELAY_BODY_LIMIT,
  TRPC_BODY_LIMIT,
  GLOBAL_JSON_BODY_LIMIT,
} = await import("./global-body-parser");
const { errorHandler } = await import("../middleware/error-handler.middleware");

/** Over 64kb and over 1mb respectively, both comfortably under 50mb. */
const OVER_AUTH_BYTES = 100 * 1024;
const OVER_TRPC_BYTES = 1200 * 1024;
/** Under 1mb but over 64kb: accepted on /trpc, refused on /api/auth. */
const MID_BYTES = 300 * 1024;

async function startApp(fixed: boolean): Promise<{
  server: Server;
  baseUrl: string;
}> {
  const app = express();

  if (fixed) {
    app.use(globalBodyParser);
  } else {
    // The pre-fix wiring: one generous parser for everything that is not a raw
    // stream, kept only as the control. Allowed to be a copy because it is
    // modelling code that no longer exists.
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

  const echo = (req: express.Request, res: express.Response) => {
    res.status(200).json({ received: typeof req.body === "object" });
  };
  app.post("/api/auth/sign-up/email", echo);
  app.post("/api/auth/sign-in/email", echo);
  app.post("/trpc/frontend/anything", echo);
  // Stands in for a route on the generous 50mb default lane, so the scoping is
  // shown to be scoping rather than a global squeeze.
  app.post("/other/anything", echo);

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

describe("/api/auth body limit", () => {
  it("pins the limit at 64kb", () => {
    expect(AUTH_RELAY_BODY_LIMIT).toBe("64kb");
  });

  it("refuses an oversized sign-up body with 413", async () => {
    const response = await postJson(fixed.baseUrl, "/api/auth/sign-up/email", {
      password: "x".repeat(OVER_AUTH_BYTES),
    });
    expect(response.status).toBe(413);
  });

  it("refuses an oversized sign-in body with 413", async () => {
    const response = await postJson(fixed.baseUrl, "/api/auth/sign-in/email", {
      password: "x".repeat(OVER_AUTH_BYTES),
    });
    expect(response.status).toBe(413);
  });

  it("accepts a real sign-in body", async () => {
    const response = await postJson(fixed.baseUrl, "/api/auth/sign-in/email", {
      email: "user@example.test",
      password: "correct horse battery staple",
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ received: true });
  });

  it("bound the 64kb limit, not the 50mb global one", async () => {
    // The regression guard for the routing order. Remove the /api/auth lane
    // from globalBodyParser and this body is parsed by the 50mb parser and
    // reaches the handler with a 200 instead.
    const withLane = await postJson(fixed.baseUrl, "/api/auth/sign-in/email", {
      password: "x".repeat(OVER_AUTH_BYTES),
    });
    const withoutLane = await postJson(
      unfixed.baseUrl,
      "/api/auth/sign-in/email",
      { password: "x".repeat(OVER_AUTH_BYTES) },
    );
    expect(withLane.status).toBe(413);
    expect(withoutLane.status).not.toBe(413);
  });
});

describe("/trpc body limit", () => {
  it("pins the limit at 1mb", () => {
    expect(TRPC_BODY_LIMIT).toBe("1mb");
  });

  it("refuses an oversized tRPC body with 413", async () => {
    const response = await postJson(fixed.baseUrl, "/trpc/frontend/anything", {
      blob: "x".repeat(OVER_TRPC_BYTES),
    });
    expect(response.status).toBe(413);
  });

  it("accepts a body under 1mb that /api/auth would refuse", async () => {
    // 300kb is over the 64kb auth ceiling and under the 1mb tRPC ceiling, so a
    // 200 here can only mean the tRPC lane bound its own larger limit.
    const response = await postJson(fixed.baseUrl, "/trpc/frontend/anything", {
      blob: "x".repeat(MID_BYTES),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ received: true });
  });

  it("bound the 1mb limit, not the 50mb global one", async () => {
    const withLane = await postJson(fixed.baseUrl, "/trpc/frontend/anything", {
      blob: "x".repeat(OVER_TRPC_BYTES),
    });
    const withoutLane = await postJson(
      unfixed.baseUrl,
      "/trpc/frontend/anything",
      { blob: "x".repeat(OVER_TRPC_BYTES) },
    );
    expect(withLane.status).toBe(413);
    expect(withoutLane.status).not.toBe(413);
  });
});

describe("the generous default lane is untouched", () => {
  it("still accepts a 300kb body on a non-scoped path", async () => {
    const response = await postJson(fixed.baseUrl, "/other/anything", {
      blob: "x".repeat(MID_BYTES),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ received: true });
    expect(GLOBAL_JSON_BODY_LIMIT).toBe("50mb");
  });
});
