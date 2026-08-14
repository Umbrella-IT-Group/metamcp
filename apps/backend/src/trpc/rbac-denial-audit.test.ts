/**
 * RBAC and authentication denials at the tRPC choke point.
 *
 * `requireAdmin()` and `protectedProcedure` are two functions that between
 * them gate every admin mutation and every authenticated read in the product.
 * Until now both threw and forgot: an authenticated member walking the admin
 * mutation surface, or an unauthenticated caller probing it, left no trace
 * anywhere — no row, no counter, nothing to alert on. Instrumenting these two
 * throws captures the whole surface at once, which is why they are the first
 * two emitters wired.
 *
 * Driven through the REAL production path — the real `@repo/trpc` routers,
 * the real backend sink (`trpcDenialSink`), the real emitter — with only the
 * database sink swapped for an array. Same approach as
 * member-disclosure-gates.test.ts, which drives real routers with stubbed
 * implementations.
 */

import { createLogsRouter, setTrpcAuditSink } from "@repo/trpc";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { loggerMock } = vi.hoisted(() => ({
  loggerMock: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");
const { trpcDenialSink } = await import("@/lib/audit/trpc-denial-sink");

type AuditRow = {
  action: string;
  outcome: string;
  actor_type: string;
  actor_id?: string | null;
  actor_label?: string | null;
  actor_ip?: string | null;
  actor_user_agent?: string | null;
  request_id?: string | null;
  http_status?: number | null;
  target_type?: string | null;
  target_id?: string | null;
  detail?: Record<string, unknown>;
};

const AUDIT = {
  actor_ip: "203.0.113.7",
  actor_user_agent: "Mozilla/5.0",
  request_id: "req-under-test",
};

const adminCtx = {
  user: { id: "admin-1", role: "admin", email: "admin@example.invalid" },
  session: { id: "s-admin" },
  audit: AUDIT,
};
const memberCtx = {
  user: { id: "member-1", role: "member", email: "member@example.invalid" },
  session: { id: "s-member" },
  audit: AUDIT,
};
const anonymousCtx = { audit: AUDIT };

const buildRouter = () =>
  createLogsRouter({
    getLogs: vi
      .fn()
      .mockResolvedValue({ success: true, data: [], totalCount: 0 }),
  });

let rows: AuditRow[];

/** Flush the detached promise chain `emit()` schedules. */
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

beforeEach(() => {
  vi.clearAllMocks();
  rows = [];
  setTrpcAuditSink(trpcDenialSink);
  setAuditSinkForTesting(async (event) => {
    rows.push(event as AuditRow);
  });
});

afterEach(() => {
  setTrpcAuditSink(null);
  setAuditSinkForTesting(undefined);
});

describe("rbac.denied — an authenticated non-admin is refused", () => {
  it("writes one row naming the actor AND the procedure they reached for", async () => {
    await expect(
      buildRouter().createCaller(memberCtx).get({}),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "rbac.denied",
      outcome: "denied",
      actor_type: "user",
      actor_id: "member-1",
      actor_label: "member@example.invalid",
      actor_ip: "203.0.113.7",
      actor_user_agent: "Mozilla/5.0",
      request_id: "req-under-test",
      http_status: 403,
      // Without the path, every denial in the product is the same row.
      target_type: "trpc_procedure",
      target_id: "get",
    });
    expect(rows[0].detail).toMatchObject({ trpc_type: "query" });
  });

  it("writes NOTHING when an admin is allowed through", async () => {
    await expect(
      buildRouter().createCaller(adminCtx).get({}),
    ).resolves.toMatchObject({ success: true });
    await flush();

    expect(rows).toEqual([]);
  });
});

describe("authn.denied — an unauthenticated caller is refused", () => {
  it("writes one anonymous row, still carrying IP and request id", async () => {
    await expect(
      buildRouter().createCaller(anonymousCtx).get({}),
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "authn.denied",
      outcome: "denied",
      // No session, so there is no identity to claim.
      actor_type: "anonymous",
      actor_id: null,
      actor_ip: "203.0.113.7",
      request_id: "req-under-test",
      http_status: 401,
      target_id: "get",
    });
  });

  it("does not emit rbac.denied as well — the role gate never runs", async () => {
    await expect(
      buildRouter().createCaller(anonymousCtx).get({}),
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    await flush();

    expect(rows.map((row) => row.action)).toEqual(["authn.denied"]);
  });
});

describe("degraded attribution", () => {
  it("records the denial with null IP when no request context was threaded", async () => {
    await expect(
      buildRouter()
        .createCaller({ user: { id: "member-1", role: "member" }, session: {} })
        .get({}),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    await flush();

    // A row with an unknown IP still answers "who, what, when". Dropping it
    // for want of an IP would be the worse trade.
    expect(rows[0]).toMatchObject({
      action: "rbac.denied",
      actor_id: "member-1",
      actor_ip: null,
      request_id: null,
    });
  });
});

describe("THE SAFETY PROPERTY — the gate outranks the logging", () => {
  it("a sink that THROWS still yields a clean FORBIDDEN, not a 500", async () => {
    setAuditSinkForTesting(() => {
      throw new Error("audit sink exploded");
    });

    await expect(
      buildRouter().createCaller(memberCtx).get({}),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    await flush();
  });

  it("a sink that REJECTS (database down) still yields FORBIDDEN", async () => {
    setAuditSinkForTesting(() => Promise.reject(new Error("ECONNREFUSED")));

    await expect(
      buildRouter().createCaller(memberCtx).get({}),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    await flush();
  });

  it("a sink that REJECTS still yields UNAUTHORIZED on the authn gate", async () => {
    setAuditSinkForTesting(() => Promise.reject(new Error("ECONNREFUSED")));

    await expect(
      buildRouter().createCaller(anonymousCtx).get({}),
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    await flush();
  });

  it("a registered sink that throws SYNCHRONOUSLY does not reach the caller", async () => {
    // Guards the @repo/trpc boundary itself, not the emitter behind it: a
    // future sink that is not fire-and-forget must still not be able to turn
    // a denial into a 500.
    setTrpcAuditSink(() => {
      throw new Error("registered sink exploded");
    });

    await expect(
      buildRouter().createCaller(memberCtx).get({}),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("a throwing sink does not break the SUCCESS path either", async () => {
    setTrpcAuditSink(() => {
      throw new Error("registered sink exploded");
    });

    await expect(
      buildRouter().createCaller(adminCtx).get({}),
    ).resolves.toMatchObject({ success: true });
  });
});
