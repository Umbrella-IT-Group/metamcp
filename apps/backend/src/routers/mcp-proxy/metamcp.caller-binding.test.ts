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
import { readFileSync } from "node:fs";
import { join } from "node:path";

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

/**
 * The WIRING, pinned at source level.
 *
 * `inspectorCaller` being correct is worth nothing if nothing calls it. The
 * tests above build a caller and assert its shape; every one of them stays
 * green if all three `runWithCallerContext` wraps are deleted, because the
 * function itself is untouched by that deletion. What the deletion actually
 * does is silent: the auditing middleware falls back to reading a store no
 * request entered, so Inspector tool calls resume writing the fully
 * un-attributed rows migration 0030 exists to end, and nothing fails.
 *
 * There is no express harness in this repo's test setup for these routes, so
 * the pin is a source read, the same shape
 * `routers/public-metamcp/streamable-http.test.ts` uses for the m365 identity
 * gate.
 */
describe("Inspector caller-context wiring", () => {
  const source = readFileSync(join(__dirname, "metamcp.ts"), "utf8");

  const occurrences = (pattern: RegExp) => source.match(pattern)?.length ?? 0;

  it("wraps all three tool-carrying dispatches, not merely one of them", () => {
    // A `toContain` would go green with two of the three deleted, which is
    // most of the hole. The count is the assertion.
    expect(occurrences(/runWithCallerContext\(inspectorCaller\(req\)/g)).toBe(
      3,
    );
  });

  it.each([
    [
      "POST /:uuid/mcp, new session",
      /runWithCallerContext\(inspectorCaller\(req\),\s*\(\)\s*=>\s*\(webAppTransport as StreamableHTTPServerTransport\)\.handleRequest\(/,
    ],
    [
      "POST /:uuid/mcp, existing session",
      /runWithCallerContext\(inspectorCaller\(req\),\s*\(\)\s*=>\s*\(transport as StreamableHTTPServerTransport\)\.handleRequest\(req, res\)/,
    ],
    [
      "POST /:uuid/message, SSE transport",
      /runWithCallerContext\(inspectorCaller\(req\),\s*\(\)\s*=>\s*transport\.handlePostMessage\(req, res\)/,
    ],
  ])("keeps the wrap on the %s dispatch", (_label, pattern) => {
    // Structural rather than a bare count: without these, someone could
    // satisfy the count above by wrapping something that carries no tool call
    // while a real dispatch went bare.
    expect(source).toMatch(pattern);
  });

  it("accounts for every transport dispatch in the file, wrapped or not", () => {
    // The GET `/:uuid/mcp` leg is the one deliberate exclusion: it opens the
    // server-to-client stream and carries no `tools/call`, so there is no
    // audit row for a caller context to attribute. Pinning the TOTAL is what
    // makes that exclusion explicit instead of assumed. A future route that
    // adds a fourth dispatch turns this red and has to decide, rather than
    // inheriting an un-attributed path by default.
    expect(occurrences(/\.handleRequest\(|\.handlePostMessage\(/g)).toBe(4);
  });
});
