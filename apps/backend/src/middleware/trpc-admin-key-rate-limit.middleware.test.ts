/**
 * The admin-plane (control-plane) bearer failure limiter on /trpc (migration
 * 0038), and the three ways it could be wrong.
 *
 * It could fail to refuse a flood of failed admin-key verifications. It could
 * refuse the wrong caller — specifically a cookie-authenticated human carrying a
 * stale bearer, whom the foreman ruling says must NEVER draw a 429 (cookie
 * precedence). Or it could quietly COUNT valid traffic: this middleware only
 * CHECKS; the record happens in admin-plane-auth on a failed verification, so a
 * request passing through here must not move the counter. Each is pinned below.
 *
 * The limiter is INJECTED with a small budget rather than driving the real 20,
 * same pattern as trpc-rate-limit.middleware.test.ts.
 */

import express from "express";
import { beforeEach, describe, expect, it } from "vitest";

import {
  AuthRateLimiter,
  getAdminKeyRateLimitIdentifier,
} from "@/lib/auth-rate-limiter";

import { createTrpcAdminKeyRateLimitMiddleware } from "./trpc-admin-key-rate-limit.middleware";

function request(fields: {
  bearer?: boolean;
  cookie?: boolean;
  cfIp?: string;
}): express.Request {
  const headers: Record<string, string> = {};
  if (fields.bearer) headers.authorization = "Bearer sk_mt_some_key";
  if (fields.cookie) headers.cookie = "better-auth.session_token=abc";
  if (fields.cfIp) headers["cf-connecting-ip"] = fields.cfIp;
  return { headers } as unknown as express.Request;
}

interface Result {
  passed: boolean;
  statusCode: number | undefined;
  headers: Record<string, string>;
  body: unknown;
}

function call(
  middleware: ReturnType<typeof createTrpcAdminKeyRateLimitMiddleware>,
  req: express.Request,
): Result {
  const result: Result = {
    passed: false,
    statusCode: undefined,
    headers: {},
    body: undefined,
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

let limiter: AuthRateLimiter;
let middleware: ReturnType<typeof createTrpcAdminKeyRateLimitMiddleware>;

/** Spend the whole budget for the identifier a request would key on. */
function fillBudget(req: express.Request, budget: number) {
  const id = getAdminKeyRateLimitIdentifier(req);
  for (let i = 0; i < budget; i++) limiter.recordFailedAttempt(id);
}

beforeEach(() => {
  limiter = new AuthRateLimiter(3, 60_000);
  middleware = createTrpcAdminKeyRateLimitMiddleware(limiter);
});

describe("admin-key rate limit — refusing a failure flood", () => {
  it("429s a Bearer request once the per-IP failure budget is spent", () => {
    const bearer = () => request({ bearer: true, cfIp: "203.0.113.20" });
    fillBudget(bearer(), 3);

    const refused = call(middleware, bearer());
    expect(refused.passed).toBe(false);
    expect(refused.statusCode).toBe(429);
    expect(refused.headers["Retry-After"]).toBeDefined();
    expect(refused.body).toMatchObject({ error: "too_many_requests" });
  });

  it("buckets the no-header class rather than exempting it", () => {
    // A Bearer request with no CF-Connecting-IP keys on the shared
    // no-trusted-ip bucket — counting failed credentials means this class must
    // be bucketed, not waved through.
    const noHeader = () => request({ bearer: true });
    fillBudget(noHeader(), 3);

    expect(call(middleware, noHeader()).statusCode).toBe(429);
  });
});

describe("admin-key rate limit — what it must NOT refuse", () => {
  it("only checks, never records: passing requests do not move the counter", () => {
    const bearer = () => request({ bearer: true, cfIp: "203.0.113.21" });
    // Drive more requests than the budget THROUGH the middleware; each should
    // pass, because a valid request never scores and the middleware does not
    // record on its own.
    for (let i = 0; i < 10; i++) {
      expect(call(middleware, bearer()).passed).toBe(true);
    }
  });

  it("skips a request carrying a session cookie even when over budget (precedence)", () => {
    const bearerCookie = () =>
      request({ bearer: true, cookie: true, cfIp: "203.0.113.22" });
    // Fill the budget for this IP first...
    fillBudget(request({ bearer: true, cfIp: "203.0.113.22" }), 3);
    // ...a cookie-carrying request from it is still served.
    expect(call(middleware, bearerCookie()).passed).toBe(true);
  });

  it("ignores a request with no Bearer header", () => {
    fillBudget(request({ bearer: true, cfIp: "203.0.113.23" }), 3);
    // No Authorization header at all: not this limiter's concern, and not
    // refused even though the IP bucket is over budget.
    expect(call(middleware, request({ cfIp: "203.0.113.23" })).passed).toBe(
      true,
    );
  });
});
