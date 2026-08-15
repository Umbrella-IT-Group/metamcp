/**
 * `/oauth/register` gets its own rate-limit bucket, keyed on the real caller.
 *
 * WHAT WAS WRONG, and why it was a self-inflicted outage rather than a
 * control. `/oauth/register` and `/oauth/token` both carried `rateLimitToken`,
 * one limiter keyed on `req.ip` — and `trust proxy` is deliberately off (see
 * audit-context.middleware), so behind the tunnel every caller in the world
 * shares one bucket. 20 anonymous registrations in a minute therefore spent
 * the budget a paired claude.ai connector needed for its token exchange, and
 * the exchange came back 429. An endpoint anyone can reach for free must not
 * be able to close the endpoint pairing depends on.
 *
 * Two assertions carry this file. `does not spend the token endpoint's budget`
 * is the regression itself. `keys on CF-Connecting-IP, not req.ip` is the
 * other half: both requests below carry the SAME `req.ip` — the container-local
 * address that made the old bucket global — so the only thing that can
 * separate them is the Cloudflare header.
 */

import express from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const {
  rateLimitRegistration,
  rateLimitToken,
  resetRegistrationRateLimitForTests,
} = await import("./utils");

/** The registration bucket's budget. */
const REGISTRATION_BUDGET = 30;

/** The container-local address every caller shares without `trust proxy`. */
const SHARED_REQ_IP = "127.0.0.1";

interface Outcome {
  status: number;
  passed: boolean;
}

function run(
  middleware: express.RequestHandler,
  init: { clientIp?: string; reqIp?: string },
): Outcome {
  const outcome: Outcome = { status: 200, passed: false };

  const req = {
    method: "POST",
    url: "/oauth/register",
    path: "/oauth/register",
    headers: init.clientIp ? { "cf-connecting-ip": init.clientIp } : {},
    ip: init.reqIp ?? SHARED_REQ_IP,
    socket: { remoteAddress: init.reqIp ?? SHARED_REQ_IP },
  } as unknown as express.Request;

  const res = {
    status(code: number) {
      outcome.status = code;
      return res;
    },
    json() {
      return res;
    },
  } as unknown as express.Response;

  middleware(req, res, () => {
    outcome.passed = true;
  });

  return outcome;
}

const register = (clientIp: string) => run(rateLimitRegistration, { clientIp });

beforeEach(() => {
  resetRegistrationRateLimitForTests();
});

describe("rateLimitRegistration", () => {
  it("allows a full budget of registrations from one caller", () => {
    for (let i = 0; i < REGISTRATION_BUDGET; i += 1) {
      expect(register("203.0.113.10").passed).toBe(true);
    }
  });

  it("refuses the caller past its budget with a 429", () => {
    for (let i = 0; i < REGISTRATION_BUDGET; i += 1) {
      register("203.0.113.11");
    }

    const overBudget = register("203.0.113.11");
    expect(overBudget.passed).toBe(false);
    expect(overBudget.status).toBe(429);
  });

  it("keys on CF-Connecting-IP, not req.ip", () => {
    // Both callers arrive on the same `req.ip`, which is precisely the
    // condition that made the old bucket global. A second caller must still
    // have a full budget.
    for (let i = 0; i < REGISTRATION_BUDGET; i += 1) {
      register("203.0.113.12");
    }
    expect(register("203.0.113.12").passed).toBe(false);

    expect(register("203.0.113.13").passed).toBe(true);
  });

  it("falls back to req.ip when the Cloudflare header is absent", () => {
    // Direct-to-origin and local development. It degrades to the single shared
    // bucket this endpoint had before, which is the honest behaviour: without
    // the edge there is no trustworthy caller identity to key on.
    for (let i = 0; i < REGISTRATION_BUDGET; i += 1) {
      expect(run(rateLimitRegistration, { reqIp: "198.51.100.7" }).passed).toBe(
        true,
      );
    }

    expect(run(rateLimitRegistration, { reqIp: "198.51.100.7" }).passed).toBe(
      false,
    );
  });

  it("does not spend the token endpoint's budget", () => {
    // THE regression. Exhaust registration for a caller, then show that a
    // token exchange from the very same source is untouched — that is what a
    // claude.ai connector does immediately after the consent screen.
    for (let i = 0; i < REGISTRATION_BUDGET + 5; i += 1) {
      register("203.0.113.14");
    }
    expect(register("203.0.113.14").status).toBe(429);

    const tokenExchange = run(rateLimitToken, {
      clientIp: "203.0.113.14",
      reqIp: SHARED_REQ_IP,
    });
    expect(tokenExchange.passed).toBe(true);
    expect(tokenExchange.status).toBe(200);
  });
});
