/**
 * The `/trpc` request cap, and specifically the two ways it could be wrong.
 *
 * It could fail to limit — `/trpc` had no limiter at all, and every anonymous
 * `protectedProcedure` call writes an `authn.denied` row to an append-only
 * table, so an unbounded caller is an unbounded writer.
 *
 * Or it could limit the wrong thing, which is the worse failure and the one
 * this file exists for. Keying on `req.ip` would put every caller in ONE
 * bucket, because this fork deliberately leaves express `trust proxy` unset
 * and the backend sits behind an in-container rewrite — the first busy admin
 * would then lock out the whole organisation. The keying assertions below are
 * the regression guard for that.
 */

import express from "express";
import { describe, expect, it, vi } from "vitest";

import { AuthRateLimiter } from "@/lib/auth-rate-limiter";

import {
  createTrpcRateLimitMiddleware,
  TRPC_RATE_LIMIT_MAX,
  TRPC_RATE_LIMIT_WINDOW_MS,
} from "./trpc-rate-limit.middleware";

/** A caller as the middleware sees it: only `auditClientIp` is consulted. */
function request(fields: {
  auditClientIp?: string;
  ip?: string;
}): express.Request {
  return {
    ...fields,
    socket: { remoteAddress: "127.0.0.1" },
  } as unknown as express.Request;
}

interface Result {
  passed: boolean;
  statusCode: number | undefined;
  body: unknown;
  headers: Record<string, string>;
}

function call(
  middleware: ReturnType<typeof createTrpcRateLimitMiddleware>,
  req: express.Request,
): Result {
  const result: Result = {
    passed: false,
    statusCode: undefined,
    body: undefined,
    headers: {},
  };
  const res = {
    status(code: number) {
      result.statusCode = code;
      return res;
    },
    json(payload: unknown) {
      result.body = payload;
      return res;
    },
    set(name: string, value: string) {
      result.headers[name] = value;
      return res;
    },
  };
  middleware(req, res as unknown as express.Response, () => {
    result.passed = true;
  });
  return result;
}

describe("trpc rate limit — refusing a flood", () => {
  it("blocks an anonymous flood once the budget is spent", () => {
    // A small injected budget stands in for the real 600; driving 600 real
    // calls would test the loop, not the middleware.
    const middleware = createTrpcRateLimitMiddleware(
      new AuthRateLimiter(3, 60_000),
    );
    const flooder = () => request({ auditClientIp: "203.0.113.7" });

    expect(call(middleware, flooder()).passed).toBe(true);
    expect(call(middleware, flooder()).passed).toBe(true);
    expect(call(middleware, flooder()).passed).toBe(true);

    const refused = call(middleware, flooder());
    expect(refused.passed).toBe(false);
    expect(refused.statusCode).toBe(429);
    expect(refused.body).toMatchObject({ error: "Too many requests" });
  });

  it("tells a well-behaved client when to come back", () => {
    const middleware = createTrpcRateLimitMiddleware(
      new AuthRateLimiter(1, 60_000),
    );
    call(middleware, request({ auditClientIp: "203.0.113.7" }));

    const refused = call(middleware, request({ auditClientIp: "203.0.113.7" }));

    expect(refused.headers["Retry-After"]).toBe("60");
  });

  it("lets the caller back in once the window rolls over", () => {
    vi.useFakeTimers();
    try {
      const middleware = createTrpcRateLimitMiddleware(
        new AuthRateLimiter(1, 60_000),
      );
      const caller = () => request({ auditClientIp: "203.0.113.7" });

      expect(call(middleware, caller()).passed).toBe(true);
      expect(call(middleware, caller()).passed).toBe(false);

      vi.advanceTimersByTime(60_001);

      expect(call(middleware, caller()).passed).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("trpc rate limit — NOT throttling legitimate use", () => {
  /**
   * The failure this guards against is an outage caused by the control meant
   * to prevent one. Both existing identifiers in lib/auth-rate-limiter key on
   * `req.ip`, which behind the in-container rewrite is the same loopback
   * address for every caller — one shared organisation-wide bucket. Reusing
   * that key here would mean one busy admin refusing the whole company.
   */
  it("gives each client IP its own budget, so one caller cannot spend another's", () => {
    const middleware = createTrpcRateLimitMiddleware(
      new AuthRateLimiter(2, 60_000),
    );

    // One caller burns their whole budget.
    call(middleware, request({ auditClientIp: "203.0.113.7" }));
    call(middleware, request({ auditClientIp: "203.0.113.7" }));
    expect(
      call(middleware, request({ auditClientIp: "203.0.113.7" })).passed,
    ).toBe(false);

    // A different admin is unaffected.
    expect(
      call(middleware, request({ auditClientIp: "198.51.100.4" })).passed,
    ).toBe(true);
  });

  it("ignores req.ip entirely — that key is the shared-bucket trap", () => {
    const middleware = createTrpcRateLimitMiddleware(
      new AuthRateLimiter(1, 60_000),
    );

    // Same loopback `req.ip` for both, as production actually presents them;
    // only CF-Connecting-IP differs. If the middleware keyed on req.ip the
    // second call would be refused.
    call(
      middleware,
      request({ auditClientIp: "203.0.113.7", ip: "127.0.0.1" }),
    );

    expect(
      call(
        middleware,
        request({ auditClientIp: "198.51.100.4", ip: "127.0.0.1" }),
      ).passed,
    ).toBe(true);
  });

  it("exempts the no-CF-IP class rather than collapsing it into one bucket", () => {
    // Direct-to-origin and local development have no CF-Connecting-IP. Sharing
    // one "unknown" key would let any one of them refuse all the others —
    // exactly the outage this limiter is keyed to avoid.
    const middleware = createTrpcRateLimitMiddleware(
      new AuthRateLimiter(1, 60_000),
    );

    for (let i = 0; i < 25; i += 1) {
      expect(call(middleware, request({ ip: "127.0.0.1" })).passed).toBe(true);
    }
  });

  it("sets the shipped budget far above a real UI burst", () => {
    // The frontend uses httpBatchLink, so a dashboard's many procedure calls
    // collapse into few HTTP requests. A limiter that trips on normal admin
    // use is a limiter someone deletes.
    const middleware = createTrpcRateLimitMiddleware();
    const admin = () => request({ auditClientIp: "203.0.113.9" });

    for (let i = 0; i < 200; i += 1) {
      expect(call(middleware, admin()).passed).toBe(true);
    }
    expect(TRPC_RATE_LIMIT_MAX).toBeGreaterThanOrEqual(600);
    expect(TRPC_RATE_LIMIT_WINDOW_MS).toBe(60_000);
  });
});
