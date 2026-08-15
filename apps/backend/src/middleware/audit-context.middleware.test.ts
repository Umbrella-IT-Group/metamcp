/**
 * The per-request attribution middleware.
 *
 * Two properties matter and both are pinned here: every request gets a unique
 * id (audit rows for one request must be joinable, and rows for different
 * requests must not collide), and the client IP comes from `CF-Connecting-IP`
 * with NO fabricated fallback. A column that says `127.0.0.1` on every row —
 * which is exactly what `req.ip` yields behind the in-container Next.js
 * rewrite — is worse than one that admits it does not know, because the first
 * gets read as evidence.
 *
 * Also pinned: it always calls next(). It runs ahead of every route in the
 * gateway, so a failure here would be a total outage, not a missing log line.
 */

import express from "express";
import { describe, expect, it } from "vitest";

import type { AuditAttributedRequest } from "@/lib/audit/audit-emitter";
import { AUDIT_IP_MAX } from "@/lib/audit/audit-emitter";

import {
  auditContextMiddleware,
  CLIENT_IP_HEADER,
  resolveClientIp,
} from "./audit-context.middleware";

function run(headers: Record<string, unknown>): {
  req: AuditAttributedRequest;
  nextCalls: number;
} {
  const req = { headers } as unknown as AuditAttributedRequest;
  let nextCalls = 0;
  auditContextMiddleware(
    req as unknown as express.Request,
    {} as express.Response,
    () => {
      nextCalls += 1;
    },
  );
  return { req, nextCalls };
}

describe("auditContextMiddleware", () => {
  it("stamps a uuid request id and calls next()", () => {
    const { req, nextCalls } = run({});

    expect(req.auditRequestId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(nextCalls).toBe(1);
  });

  it("gives every request a DIFFERENT id", () => {
    expect(run({}).req.auditRequestId).not.toBe(run({}).req.auditRequestId);
  });

  it("reads the caller IP from CF-Connecting-IP", () => {
    const { req } = run({ [CLIENT_IP_HEADER]: "203.0.113.7" });

    expect(req.auditClientIp).toBe("203.0.113.7");
  });

  it("leaves the IP undefined when the header is absent", () => {
    expect(run({}).req.auditClientIp).toBeUndefined();
  });

  it("still calls next() when the headers bag is hostile", () => {
    const req = { headers: null } as unknown as express.Request;
    let nextCalls = 0;
    auditContextMiddleware(req, {} as express.Response, () => {
      nextCalls += 1;
    });

    expect(nextCalls).toBe(1);
  });
});

describe("resolveClientIp", () => {
  it("takes the first value if the header arrives duplicated", () => {
    expect(
      resolveClientIp({ [CLIENT_IP_HEADER]: ["198.51.100.4", "203.0.113.7"] }),
    ).toBe("198.51.100.4");
  });

  it("trims surrounding whitespace", () => {
    expect(resolveClientIp({ [CLIENT_IP_HEADER]: " 203.0.113.7 " })).toBe(
      "203.0.113.7",
    );
  });

  it("treats an empty header as absent rather than as an IP of ''", () => {
    expect(resolveClientIp({ [CLIENT_IP_HEADER]: "   " })).toBeUndefined();
    expect(resolveClientIp({})).toBeUndefined();
  });

  /**
   * The clamp lives here rather than at each emitter because every audit row's
   * `actor_ip` and every relay-stamped `x-audit-client-ip` is read from what
   * this function returns. `audit_log` is append-only by trigger (migration
   * 0028), so an oversized value written once is permanent.
   */
  it("clamps an absurdly long header value rather than storing it whole", () => {
    const hostile = "9".repeat(4_000);

    const resolved = resolveClientIp({ [CLIENT_IP_HEADER]: hostile });

    expect(resolved).toHaveLength(AUDIT_IP_MAX);
    expect(resolved).toBe(hostile.slice(0, AUDIT_IP_MAX));
  });

  it("leaves a full-length IPv6 address with a zone id intact", () => {
    // The longest value this column can legitimately hold: the IPv4-mapped
    // IPv6 form written out in full (45 characters) plus a zone id. If the
    // budget ever stops covering this, it is too small.
    const longest = "0000:0000:0000:0000:0000:ffff:255.255.255.255%eth0";

    expect(longest.length).toBeLessThan(AUDIT_IP_MAX);
    expect(resolveClientIp({ [CLIENT_IP_HEADER]: longest })).toBe(longest);
  });

  it("does NOT fall back to X-Forwarded-For", () => {
    // XFF is appended to, not overwritten, so a caller controls its head —
    // trusting it here would let an attacker choose what the audit archive
    // says about them. See the file-top note on `trust proxy`.
    expect(
      resolveClientIp({ "x-forwarded-for": "203.0.113.7, 10.0.0.1" }),
    ).toBeUndefined();
  });
});
