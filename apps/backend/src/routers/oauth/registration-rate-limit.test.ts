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

// The registration router reaches the repository only after the body passes
// validation, and the router-level assertion below deliberately sends a body
// that never does — so nothing here should ever be called.
const upsertClientMock = vi.fn();

vi.mock("../../db/repositories", () => ({
  oauthRepository: { upsertClient: upsertClientMock },
}));

const {
  rateLimitAuth,
  rateLimitRegistration,
  rateLimitToken,
  resetRegistrationRateLimitForTests,
} = await import("./utils");
const { default: registrationRouter } = await import("./registration");

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
    // Exhaust registration for a caller, then show that a token exchange from
    // the very same source is untouched — that is what a claude.ai connector
    // does immediately after the consent screen.
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

/**
 * The authorization and token endpoints key on the caller, not the container.
 *
 * `rateLimitAuth` and `rateLimitToken` used to key on `req.ip`, which behind the
 * tunnel is one container-local address shared by every caller (`trust proxy`
 * is off), so a single source spending a bucket's worth of requests held OAuth
 * authorization and token exchange 429ed for the whole organisation. They now
 * key on CF-Connecting-IP with a `req.ip` fallback, the same shape
 * `rateLimitRegistration` uses. `/oauth/token` is the endpoint claude.ai
 * connectors call to exchange codes and refresh tokens, so this is the live
 * availability half.
 *
 * Distinct edge IPs per test because these two limiters live at module scope
 * with no reset hook — the same reason the token exchanges above pick fresh
 * addresses.
 */
const TOKEN_AUTH_BUDGET = 20;

describe.each([
  ["rateLimitToken", rateLimitToken, 10] as const,
  ["rateLimitAuth", rateLimitAuth, 20] as const,
])("%s keys per edge IP, not per container", (_label, middleware, base) => {
  it("allows a full budget from one edge IP then 429s the next request", () => {
    const ip = `192.0.2.${base}`;
    for (let i = 0; i < TOKEN_AUTH_BUDGET; i += 1) {
      expect(run(middleware, { clientIp: ip }).passed).toBe(true);
    }

    const overBudget = run(middleware, { clientIp: ip });
    expect(overBudget.passed).toBe(false);
    expect(overBudget.status).toBe(429);
  });

  it("gives a second edge IP its own budget though both share one req.ip", () => {
    const a = `192.0.2.${base + 1}`;
    const b = `192.0.2.${base + 2}`;
    for (let i = 0; i < TOKEN_AUTH_BUDGET; i += 1) {
      run(middleware, { clientIp: a });
    }
    expect(run(middleware, { clientIp: a }).passed).toBe(false);

    // b arrives on the same container-local req.ip as a — the condition that
    // made the old bucket global — and must still have a full budget.
    expect(run(middleware, { clientIp: b }).passed).toBe(true);
  });

  it("falls back to req.ip when the Cloudflare header is absent", () => {
    const reqIp = `192.0.2.${base + 3}`;
    for (let i = 0; i < TOKEN_AUTH_BUDGET; i += 1) {
      expect(run(middleware, { reqIp }).passed).toBe(true);
    }

    expect(run(middleware, { reqIp }).passed).toBe(false);
  });
});

describe("POST /oauth/register — the route is wired to its own limiter", () => {
  /**
   * THE regression, driven through the REAL route rather than the middleware.
   *
   * The tests above prove `rateLimitRegistration` behaves; only this one
   * proves `/oauth/register` USES it. Put `rateLimitToken` back on the route
   * — the exact revert this change guards against — and every assertion above
   * still passes while this one fails.
   *
   * The bodies are deliberately invalid, so `buildClientRegistration` refuses
   * them with a 400 and neither the repository nor the audit emitter is
   * reached: the limiter is route middleware and runs first, which is the only
   * thing under test.
   */
  async function registerViaRouter(clientIp: string): Promise<Outcome> {
    const outcome: Outcome = { status: 200, passed: false };
    let settle: () => void;
    const settled = new Promise<void>((resolve) => {
      settle = resolve;
    });

    const req = {
      method: "POST",
      url: "/oauth/register",
      originalUrl: "/oauth/register",
      baseUrl: "",
      path: "/oauth/register",
      body: { client_name: "no redirect uris" },
      headers: { "cf-connecting-ip": clientIp },
      ip: SHARED_REQ_IP,
      socket: { remoteAddress: SHARED_REQ_IP },
    } as unknown as express.Request;

    const res = {
      status(code: number) {
        outcome.status = code;
        return res;
      },
      json() {
        settle();
        return res;
      },
    } as unknown as express.Response;

    await new Promise<void>((resolve, reject) => {
      (registrationRouter as unknown as express.RequestHandler)(
        req,
        res,
        (err?: unknown) => (err ? reject(err) : resolve()),
      );
      settled.then(resolve);
    });

    return outcome;
  }

  it("429s past the registration budget without touching the token budget", async () => {
    const CALLER = "203.0.113.20";

    for (let i = 0; i < REGISTRATION_BUDGET; i += 1) {
      const within = await registerViaRouter(CALLER);
      // A refused-as-invalid registration, i.e. it got past the limiter.
      expect(within.status).toBe(400);
    }

    expect((await registerViaRouter(CALLER)).status).toBe(429);
    expect(upsertClientMock).not.toHaveBeenCalled();

    // The connector's token exchange, from the same source, still goes through.
    const tokenExchange = run(rateLimitToken, {
      clientIp: CALLER,
      reqIp: SHARED_REQ_IP,
    });
    expect(tokenExchange.passed).toBe(true);
  });
});
