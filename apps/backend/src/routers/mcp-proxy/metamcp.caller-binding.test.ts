/**
 * Caller binding on the admin Inspector surface (migration 0030).
 *
 * Tool calls driven from the Inspector reach the same auditing middleware as
 * production traffic but carry no credential — the actor is a better-auth
 * admin session. They were therefore written as fully un-attributed rows,
 * which read exactly like rows from a path that lost its identity plumbing.
 *
 * `auth_method = 'session'` is what tells the two apart, so it is the value
 * this test pins hardest.
 */
import express from "express";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

vi.mock("@/db", () => ({ db: {}, pool: { on: vi.fn() } }));
// Reached transitively via `lib/metamcp/index` -> the repositories barrel.
vi.mock("@/db/audit-db", () => ({ auditDb: {}, auditPool: { on: vi.fn() } }));

import { inspectorCaller } from "./metamcp";

const fakeReq = (overrides: Record<string, unknown> = {}) =>
  ({ headers: {}, query: {}, ...overrides }) as unknown as express.Request;

describe("inspectorCaller", () => {
  it("attributes the call to the admin session that drove it", () => {
    expect(
      inspectorCaller(
        fakeReq({
          user: { id: "admin-user-1", role: "admin" },
          auditRequestId: "req-inspector",
          auditClientIp: "203.0.113.7",
        }),
      ),
    ).toEqual({
      apiKeyUuid: undefined,
      authMethod: "session",
      userId: "admin-user-1",
      actsAsUserId: undefined,
      callerIp: "203.0.113.7",
      requestId: "req-inspector",
    });
  });

  it("still marks the call as session-driven when the user cannot be read", () => {
    // A NULL user_id with auth_method='session' is honest: the row says the
    // call came from the admin surface even if the id was unavailable. Leaving
    // auth_method NULL instead would make it indistinguishable from a
    // consumer call whose identity plumbing broke.
    const caller = inspectorCaller(fakeReq({ auditRequestId: "req-x" }));

    expect(caller.authMethod).toBe("session");
    expect(caller.userId).toBeUndefined();
    expect(caller.requestId).toBe("req-x");
  });

  it("never fabricates a consumer label — there is no consumer on this surface", () => {
    const caller = inspectorCaller(fakeReq({ user: { id: "admin-user-1" } }));

    expect(caller.clientName).toBeUndefined();
  });
});
