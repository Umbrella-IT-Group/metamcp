/**
 * FIND-007: tRPC error responses disclosed internal stack traces.
 *
 * `@trpc/server` attaches `data.stack` to every error shape whenever its
 * `isDev` flag is on, and `isDev` defaults to
 * `process.env.NODE_ENV !== "production"`. Nothing in the gateway's image or
 * compose files ever sets NODE_ENV, so the deployed server ran permanently in
 * "dev" and shipped absolute `/app/...` paths plus bundled dependency names
 * and versions to any caller who could provoke a 4xx or 5xx — including an
 * unauthenticated one, since UNAUTHORIZED itself carried a stack.
 *
 * These tests drive the REAL error path (`fetchRequestHandler`, the same
 * shaping pipeline the express adapter uses) rather than a `createCaller`,
 * because `errorFormatter` runs when an error is serialised for the wire and
 * a direct caller never reaches it.
 *
 * The `control` block is load-bearing: without it, every assertion below
 * would also pass on a machine where NODE_ENV happened to be "production",
 * i.e. the suite would go green while the fix was absent. The control builds
 * an otherwise-identical tRPC instance with NO errorFormatter and asserts a
 * stack IS present, pinning the fact that this environment is one where the
 * leak would occur.
 */

import { publicProcedure, router } from "@repo/trpc";
import { initTRPC, TRPCError } from "@trpc/server";
import { fetchRequestHandler } from "@trpc/server/adapters/fetch";
import { describe, expect, it, vi } from "vitest";

// apps/backend/src/trpc.ts imports ./auth, which throws at module load
// without BETTER_AUTH_SECRET/APP_URL and pulls in a live pg Pool. The tRPC
// instance under test is independent of all of that.
vi.mock("../auth", () => ({
  auth: { handler: vi.fn() },
}));

const boom = () => {
  throw new Error("internal detail that must not reach the client");
};

/** POST/GET a procedure through the real HTTP error-shaping pipeline. */
async function callOverHttp(
  appRouter: Parameters<typeof fetchRequestHandler>[0]["router"],
  path: string,
  ctx: unknown = {},
) {
  const response = await fetchRequestHandler({
    endpoint: "/trpc",
    req: new Request(`http://test.invalid/trpc/${path}`, { method: "GET" }),
    router: appRouter,
    createContext: () => ctx as never,
    onError: () => {
      // Swallow: tRPC logs unhandled procedure errors to console by default
      // and these are deliberate throws.
    },
  });

  return {
    status: response.status,
    body: (await response.json()) as {
      error?: {
        message?: string;
        code?: number;
        data?: Record<string, unknown>;
      };
    },
  };
}

describe("control — this environment DOES leak without an errorFormatter", () => {
  it("a default initTRPC instance attaches data.stack", async () => {
    const bare = initTRPC.create();
    const bareRouter = bare.router({
      explode: bare.procedure.query(boom),
    });

    const { body } = await callOverHttp(bareRouter, "explode");

    // If this ever fails, NODE_ENV is "production" in the test environment
    // and the assertions in the blocks below have stopped proving anything.
    expect(body.error?.data?.stack).toBeTypeOf("string");
  });
});

describe("@repo/trpc instance — the one every production router is built from", () => {
  const appRouter = router({
    explode: publicProcedure.query(boom),
    unauthorized: publicProcedure.query(() => {
      throw new TRPCError({ code: "UNAUTHORIZED", message: "nope" });
    }),
  });

  it("strips data.stack from an unexpected internal error", async () => {
    const { status, body } = await callOverHttp(appRouter, "explode");

    expect(status).toBe(500);
    expect(body.error?.data).toBeDefined();
    expect(body.error?.data).not.toHaveProperty("stack");
  });

  it("strips data.stack from an unauthenticated rejection", async () => {
    // The pre-auth surface matters most: this shape was reachable by anyone.
    const { status, body } = await callOverHttp(appRouter, "unauthorized");

    expect(status).toBe(401);
    expect(body.error?.data).not.toHaveProperty("stack");
  });

  it("keeps the fields clients legitimately need", async () => {
    const { body } = await callOverHttp(appRouter, "explode");

    expect(body.error?.data?.code).toBe("INTERNAL_SERVER_ERROR");
    expect(body.error?.data?.httpStatus).toBe(500);
    expect(body.error?.data?.path).toBe("explode");
  });

  it("leaks no absolute source path anywhere in the serialised body", async () => {
    // Broader than the property check above: catches a stack re-appearing
    // under a different key, or being folded into another field.
    //
    // Scope note: this asserts on FILE PATHS, not on the error message.
    // @trpc/server passes an unexpected error's `message` straight through
    // for INTERNAL_SERVER_ERROR regardless of NODE_ENV, so the text of a
    // thrown internal error still reaches the caller. That is upstream
    // behaviour independent of FIND-007's stack leak, and redacting it would
    // also blank the TRPCError messages the frontend surfaces to users
    // ("Access denied: You can only view servers you own", etc.). Left as a
    // separate decision rather than silently changed here.
    const { body } = await callOverHttp(appRouter, "explode");

    expect(JSON.stringify(body)).not.toMatch(/\bat .*[/\\].*:\d+:\d+/);
    expect(JSON.stringify(body)).not.toContain(".ts:");
  });
});

describe("apps/backend own initTRPC instance", () => {
  it("strips data.stack too", async () => {
    // Currently only `createContext` is consumed from this module, but the
    // instance exports procedures, so the formatter is pinned here as well —
    // an errorFormatter only covers the instance it was passed to.
    const backendTrpc = await import("../trpc");

    const appRouter = backendTrpc.router({
      explode: backendTrpc.publicProcedure.query(boom),
    });

    const { status, body } = await callOverHttp(appRouter, "explode");

    expect(status).toBe(500);
    expect(body.error?.data).toBeDefined();
    expect(body.error?.data).not.toHaveProperty("stack");
  });
});
