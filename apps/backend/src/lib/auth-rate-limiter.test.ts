import { randomUUID } from "node:crypto";

import { DatabaseEndpoint } from "@repo/zod-types";
import express from "express";
import { describe, expect, it, vi } from "vitest";

import {
  AuthRateLimiter,
  authRateLimiter,
  getAuthRateLimitIdentifier,
} from "./auth-rate-limiter";

/**
 * The module-scope cleanup sweep must not own the process's lifetime.
 *
 * `auth-rate-limiter` registers a 10-minute `setInterval` at import time, and
 * this module is on the import chain of the MCP bearer middleware and of
 * `middleware/trpc-rate-limit.middleware`. A timer that is not `unref`'d keeps
 * the event loop alive for anything that merely IMPORTS the module — a test
 * run, a CLI script, a shutdown that is waiting for the loop to drain — and it
 * does so with no visible cause, because a housekeeping sweep is not what
 * anyone looks at when a process refuses to exit. The HTTP server in `index.ts`
 * is what keeps this service running; nothing here should.
 *
 * The global is stubbed rather than the timer inspected because the interval is
 * created during module evaluation and never exported, so import order is the
 * only place to observe it.
 */
describe("the cleanup sweep registered at import time", () => {
  it("is unref'd, so importing this module cannot hold the event loop open", async () => {
    const unref = vi.fn();
    // Typed with the arguments it stands in for, so the interval assertion
    // below reads a real parameter rather than an untyped tuple.
    const setIntervalSpy = vi.fn((_handler: () => void, _ms?: number) => ({
      unref,
    }));
    vi.stubGlobal("setInterval", setIntervalSpy);
    vi.resetModules();

    try {
      await import("./auth-rate-limiter");

      // The spy firing at all is what keeps this from passing vacuously if the
      // sweep is ever moved out of module scope.
      expect(setIntervalSpy).toHaveBeenCalledTimes(1);
      expect(setIntervalSpy.mock.calls[0]?.[1]).toBe(10 * 60 * 1000);
      expect(unref).toHaveBeenCalledTimes(1);
    } finally {
      vi.unstubAllGlobals();
      vi.resetModules();
    }
  });
});

const ENDPOINT_UUID = "11111111-1111-4111-8111-111111111111";

/**
 * The address every caller presents once the request has crossed the tunnel and
 * the in-container rewrite. It is a constant in production, which is the whole
 * reason these tests exist.
 */
const TUNNEL_IP = "127.0.0.1";

/**
 * Only `uuid` and `name` are read by the function under test, so the cast keeps
 * the fixture to the fields that carry meaning here rather than restating the
 * whole endpoint row for every case.
 */
const makeEndpoint = (
  uuid: string | null,
  name = "autotask",
): DatabaseEndpoint => ({ uuid, name }) as unknown as DatabaseEndpoint;

const makeReq = (options: {
  headers?: Record<string, string | string[]>;
  ip?: string;
  remoteAddress?: string;
}): express.Request =>
  ({
    headers: options.headers ?? {},
    ip: options.ip,
    socket:
      options.remoteAddress === undefined
        ? undefined
        : { remoteAddress: options.remoteAddress },
  }) as unknown as express.Request;

/**
 * WHAT THIS PINS, and why the shared-bucket case is the one that matters.
 *
 * `req.ip` is the same in-container loopback address for every caller reaching
 * this gateway through the tunnel, so keying the failed-auth limiter on it
 * produced ONE bucket per endpoint for the entire world. At 20 failures a
 * minute that is not a brute-force control, it is a denial-of-service lever:
 * whoever spends the budget first — an attacker, or a single consumer with a
 * stale credential retrying in a loop — locks every other caller of that
 * endpoint out for the rest of the window. The decisive case below is
 * therefore two DIFFERENT `cf-connecting-ip` values arriving on the SAME
 * `req.ip`, which is what the production topology actually delivers.
 */
describe("getAuthRateLimitIdentifier", () => {
  it("gives two callers sharing one tunnel address separate budgets", () => {
    const endpoint = makeEndpoint(ENDPOINT_UUID);

    const noisy = getAuthRateLimitIdentifier(
      makeReq({
        headers: { "cf-connecting-ip": "198.51.100.4" },
        ip: TUNNEL_IP,
      }),
      endpoint,
    );
    const bystander = getAuthRateLimitIdentifier(
      makeReq({
        headers: { "cf-connecting-ip": "203.0.113.7" },
        ip: TUNNEL_IP,
      }),
      endpoint,
    );

    expect(noisy).not.toBe(bystander);

    // The behavioural half. Identifiers merely differing is not the property
    // anyone cares about; what matters is that spending one caller's budget to
    // exhaustion leaves the other still served. A 2-attempt limiter stands in
    // for the 20/min production budget so the loop stays readable.
    const limiter = new AuthRateLimiter(2, 60 * 1000);
    limiter.recordFailedAttempt(noisy);
    limiter.recordFailedAttempt(noisy);

    expect(limiter.isCurrentlyLimited(noisy)).toBe(true);
    expect(limiter.isCurrentlyLimited(bystander)).toBe(false);
  });

  it("keys repeat failures from one caller into a single bucket", () => {
    const endpoint = makeEndpoint(ENDPOINT_UUID);
    const first = getAuthRateLimitIdentifier(
      makeReq({
        headers: { "cf-connecting-ip": "198.51.100.4" },
        ip: TUNNEL_IP,
      }),
      endpoint,
    );
    // Same caller, different tunnel-side address: the edge header is what
    // decides, so these must still collide. Without this the limiter would be
    // evadable by anything that changes the socket the request lands on.
    const second = getAuthRateLimitIdentifier(
      makeReq({
        headers: { "cf-connecting-ip": "198.51.100.4" },
        ip: "10.0.0.9",
      }),
      endpoint,
    );

    expect(first).toBe(second);

    const limiter = new AuthRateLimiter(2, 60 * 1000);
    limiter.recordFailedAttempt(first);
    limiter.recordFailedAttempt(second);

    expect(limiter.isCurrentlyLimited(first)).toBe(true);
  });

  it("falls back to the socket address when the edge header is absent", () => {
    const endpoint = makeEndpoint(ENDPOINT_UUID);

    // Direct-to-origin and local development have no Cloudflare header. They
    // degrade to the single shared bucket this endpoint had before rather than
    // throwing or keying everything under one literal.
    expect(
      getAuthRateLimitIdentifier(makeReq({ ip: "10.0.0.5" }), endpoint),
    ).toBe(`10.0.0.5:${ENDPOINT_UUID}`);
    expect(
      getAuthRateLimitIdentifier(
        makeReq({ remoteAddress: "192.0.2.11" }),
        endpoint,
      ),
    ).toBe(`192.0.2.11:${ENDPOINT_UUID}`);
    expect(getAuthRateLimitIdentifier(makeReq({}), endpoint)).toBe(
      `unknown:${ENDPOINT_UUID}`,
    );
  });

  it("ignores a blank or malformed edge header instead of keying on it", () => {
    const endpoint = makeEndpoint(ENDPOINT_UUID);

    expect(
      getAuthRateLimitIdentifier(
        makeReq({ headers: { "cf-connecting-ip": "   " }, ip: "10.0.0.5" }),
        endpoint,
      ),
    ).toBe(`10.0.0.5:${ENDPOINT_UUID}`);

    // Cloudflare never sends the header twice; anything that does is malformed
    // input, and picking the first value deterministically beats throwing on a
    // path whose job is to refuse bad credentials.
    expect(
      getAuthRateLimitIdentifier(
        makeReq({
          headers: { "cf-connecting-ip": ["198.51.100.4", "203.0.113.7"] },
          ip: TUNNEL_IP,
        }),
        endpoint,
      ),
    ).toBe(`198.51.100.4:${ENDPOINT_UUID}`);
  });

  it("keeps the endpoint suffix, so spam at one endpoint cannot spend another's budget", () => {
    const headers = { "cf-connecting-ip": "198.51.100.4" };
    const other = "22222222-2222-4222-8222-222222222222";

    expect(
      getAuthRateLimitIdentifier(
        makeReq({ headers, ip: TUNNEL_IP }),
        makeEndpoint(ENDPOINT_UUID),
      ),
    ).toBe(`198.51.100.4:${ENDPOINT_UUID}`);
    expect(
      getAuthRateLimitIdentifier(
        makeReq({ headers, ip: TUNNEL_IP }),
        makeEndpoint(other),
      ),
    ).toBe(`198.51.100.4:${other}`);

    // Name, then the literal, when a row carries no uuid — unchanged ordering.
    expect(
      getAuthRateLimitIdentifier(
        makeReq({ headers, ip: TUNNEL_IP }),
        makeEndpoint(null, "autotask"),
      ),
    ).toBe("198.51.100.4:autotask");
    expect(
      getAuthRateLimitIdentifier(
        makeReq({ headers, ip: TUNNEL_IP }),
        makeEndpoint(null, ""),
      ),
    ).toBe("198.51.100.4:unknown");
  });
});

/**
 * The budget itself is load-bearing and is pinned separately from the keying.
 * Re-keying the limiter per caller only helps if the per-caller allowance stays
 * where it was; quietly widening or narrowing it while the keys changed would
 * be invisible in the tests above.
 */
describe("the shared failed-auth limiter's budget", () => {
  it("refuses on the twentieth failure in a window, not sooner", () => {
    // Unique per run: the limiter is module-scoped, so a fixed key would let
    // this test spend a budget another file's traffic is counting on.
    const identifier = `budget-pin:${randomUUID()}`;

    for (let attempt = 0; attempt < 19; attempt += 1) {
      authRateLimiter.recordFailedAttempt(identifier);
    }
    expect(authRateLimiter.isCurrentlyLimited(identifier)).toBe(false);

    authRateLimiter.recordFailedAttempt(identifier);
    expect(authRateLimiter.isCurrentlyLimited(identifier)).toBe(true);
  });
});
