/**
 * The OAuth security-headers CSP pins form-action to 'self'.
 *
 * The former HTML sinks on /oauth backend routes are JSON errors now, so this
 * is defense in depth: any HTML that ever reappears on these routes must not be
 * able to POST a form to an attacker's host and around the consent screen this
 * plane depends on. `frame-ancestors 'none'` already blocks framing; this pins
 * the other direction. Driven directly as express middleware against a fake
 * req/res — no DB, no supertest.
 */

import express from "express";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const { securityHeaders } = await import("./utils");

function cspFor(path: string): string {
  const headers = new Map<string, string>();
  const req = { path } as unknown as express.Request;
  const res = {
    setHeader(name: string, value: string) {
      headers.set(name, value);
      return res;
    },
  } as unknown as express.Response;

  let nextCalled = false;
  securityHeaders(req, res, () => {
    nextCalled = true;
  });
  expect(nextCalled).toBe(true);

  return headers.get("Content-Security-Policy") ?? "";
}

describe("securityHeaders — Content-Security-Policy", () => {
  it("pins form-action to 'self'", () => {
    expect(cspFor("/oauth/authorize")).toContain("form-action 'self'");
  });

  it("keeps frame-ancestors 'none' alongside it (regression guard)", () => {
    const csp = cspFor("/oauth/authorize");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("form-action 'self'");
  });
});
