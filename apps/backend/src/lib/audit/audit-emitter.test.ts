/**
 * The audit emitter's ONE contract: it must never break the request it
 * describes.
 *
 * `emit()` is called from the RBAC choke point (every admin-gated tRPC
 * mutation) and from the MCP bearer path (every proxied MCP call). Those are
 * the two hottest security paths in the gateway, so a throw escaping this
 * module would not lose a log line — it would take the product down. Every
 * failure shape a sink can produce is pinned here: a synchronous throw, a
 * rejected promise, and no sink at all.
 *
 * Also pinned: the emitter never puts a raw credential anywhere. The whole
 * point of an audit table is that it survives; a table that survives holding
 * plaintext tokens is a second breach waiting for the first.
 */

import { createHash } from "node:crypto";

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

const {
  AUDIT_USER_AGENT_MAX,
  auditRequestContext,
  credentialFingerprint,
  emit,
  resetAuditFailureReportingForTesting,
  setAuditSinkForTesting,
} = await import("./audit-emitter");

/** Flush the detached promise chain `emit()` schedules. */
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

const EVENT = {
  actor_type: "anonymous",
  action: "mcp.auth.denied",
  outcome: "denied",
} as const;

beforeEach(() => {
  vi.clearAllMocks();
  // The failure reporter throttles to one line a minute PROCESS-WIDE, so
  // without this every case after the first would observe silence for the
  // wrong reason and assert nothing.
  resetAuditFailureReportingForTesting();
});

afterEach(() => {
  setAuditSinkForTesting(undefined);
});

describe("emit — fire and forget", () => {
  it("writes the event to the registered sink", async () => {
    const rows: unknown[] = [];
    setAuditSinkForTesting(async (event) => {
      rows.push(event);
    });

    emit({ ...EVENT, action: "rbac.denied", actor_type: "user" });
    await flush();

    expect(rows).toEqual([
      { actor_type: "user", action: "rbac.denied", outcome: "denied" },
    ]);
  });

  it("returns void, so a caller cannot accidentally await the write", () => {
    setAuditSinkForTesting(async () => {});

    expect(emit(EVENT)).toBeUndefined();
  });

  it("swallows a sink that THROWS synchronously", async () => {
    setAuditSinkForTesting(() => {
      throw new Error("sink exploded");
    });

    expect(() => emit(EVENT)).not.toThrow();
    await flush();

    expect(loggerMock.warn).toHaveBeenCalled();
  });

  it("swallows a sink that REJECTS (the database-down case)", async () => {
    setAuditSinkForTesting(() => Promise.reject(new Error("ECONNREFUSED")));

    expect(() => emit(EVENT)).not.toThrow();
    await flush();

    expect(loggerMock.warn).toHaveBeenCalled();
  });

  it("is a no-op with no sink resolved (no database in this process)", async () => {
    setAuditSinkForTesting(null);

    expect(() => emit(EVENT)).not.toThrow();
    await flush();

    expect(loggerMock.warn).not.toHaveBeenCalled();
    expect(loggerMock.debug).not.toHaveBeenCalled();
  });
});

/**
 * A lost audit row must be VISIBLE, and visible without being a flood.
 *
 * These two properties pull against each other, which is why they are pinned
 * together. Production runs LOG_LEVEL=info, whose console floor in
 * utils/logger is INFO — so the old debug line reached app.log but never the
 * console a responder reads during an incident, which is the same as not
 * existing. WARN fixes that; the throttle is what keeps the fix from turning a
 * database outage on the hottest denial paths into a log flood that buries its
 * own cause.
 */
describe("failure reporting", () => {
  it("reports the first write failure at WARN, not debug", async () => {
    setAuditSinkForTesting(() => Promise.reject(new Error("boom")));

    emit(EVENT);
    await flush();

    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(loggerMock.debug).not.toHaveBeenCalled();
  });

  it("stays below ERROR — a dropped row must never page anyone", async () => {
    setAuditSinkForTesting(() => Promise.reject(new Error("boom")));

    emit(EVENT);
    await flush();

    expect(loggerMock.error).not.toHaveBeenCalled();
    expect(loggerMock.info).not.toHaveBeenCalled();
  });

  it("throttles a burst to ONE line", async () => {
    setAuditSinkForTesting(() => Promise.reject(new Error("boom")));

    for (let i = 0; i < 50; i += 1) emit(EVENT);
    await flush();

    // A database outage fails every call on the hottest paths in the gateway.
    // One line, not fifty.
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
  });

  it("carries the FULL loss forward once the window rolls over", async () => {
    // Only Date is faked; setTimeout stays real so `flush()` still resolves.
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      setAuditSinkForTesting(() => Promise.reject(new Error("boom")));

      for (let i = 0; i < 50; i += 1) emit(EVENT);
      await flush();
      expect(loggerMock.warn).toHaveBeenCalledTimes(1);
      expect(loggerMock.warn.mock.calls[0]?.[0]).toContain("1 audit row(s)");

      vi.setSystemTime(Date.now() + 61_000);
      emit(EVENT);
      await flush();

      // The window is a window, not a one-shot latch: a sink that has been
      // failing since boot has to keep saying so.
      expect(loggerMock.warn).toHaveBeenCalledTimes(2);
      // 50 + 1. This is the assertion that pins the counter as a running
      // total: a per-window delta would have stranded the 49 the first line
      // could not carry, and stranded loss is silent loss.
      expect(loggerMock.warn.mock.calls[1]?.[0]).toContain(
        "51 audit row(s) lost",
      );
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("credentialFingerprint", () => {
  const TOKEN = "sk_mt_supersecretkey1234";

  it("returns a sha256 and last-4 and NEVER the credential itself", () => {
    const fingerprint = credentialFingerprint(TOKEN);

    // Expected digest computed independently of the implementation.
    expect(fingerprint.sha256).toBe(
      createHash("sha256").update(TOKEN).digest("hex"),
    );
    expect(fingerprint.last4).toBe("1234");
    expect(JSON.stringify(fingerprint)).not.toContain(TOKEN);
    expect(JSON.stringify(fingerprint)).not.toContain("supersecret");
  });

  it("is stable, so repeated use of one stolen key correlates across rows", () => {
    expect(credentialFingerprint(TOKEN).sha256).toBe(
      credentialFingerprint(TOKEN).sha256,
    );
    expect(credentialFingerprint(TOKEN).sha256).not.toBe(
      credentialFingerprint(`${TOKEN}x`).sha256,
    );
  });

  it("returns nulls for an absent credential rather than throwing", () => {
    expect(credentialFingerprint(undefined)).toEqual({
      sha256: null,
      last4: null,
    });
    expect(credentialFingerprint("")).toEqual({ sha256: null, last4: null });
  });
});

describe("auditRequestContext", () => {
  it("reads the fields the audit-context middleware stamped", () => {
    const req = {
      headers: { "user-agent": "claude-mcp/1.0" },
      auditRequestId: "req-1",
      auditClientIp: "203.0.113.7",
    };

    expect(auditRequestContext(req as never)).toEqual({
      actor_ip: "203.0.113.7",
      actor_user_agent: "claude-mcp/1.0",
      request_id: "req-1",
    });
  });

  it("reports NULL rather than inventing an IP when the header was absent", () => {
    expect(auditRequestContext({ headers: {} } as never)).toEqual({
      actor_ip: null,
      actor_user_agent: null,
      request_id: null,
    });
  });

  it("tolerates no request at all", () => {
    expect(auditRequestContext(undefined)).toEqual({
      actor_ip: null,
      actor_user_agent: null,
      request_id: null,
    });
  });

  /**
   * `actor_user_agent` is caller-controlled text on paths that need no
   * credential, and `audit_log` has UPDATE/DELETE/TRUNCATE triggers and no
   * prune path (migration 0028) — so an oversized value is permanent. Node
   * caps a header block at 16KB, which bounds it but not usefully.
   */
  it("clamps an over-long User-Agent instead of storing it whole", () => {
    const hostile = "U".repeat(20_000);

    const { actor_user_agent } = auditRequestContext({
      headers: { "user-agent": hostile },
    } as never);

    expect(actor_user_agent).toHaveLength(AUDIT_USER_AGENT_MAX);
    expect(actor_user_agent).toBe(hostile.slice(0, AUDIT_USER_AGENT_MAX));
  });

  it("leaves a real User-Agent untouched — the clamp is a ceiling, not a policy", () => {
    const real =
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

    expect(real.length).toBeLessThan(AUDIT_USER_AGENT_MAX);
    expect(
      auditRequestContext({ headers: { "user-agent": real } } as never)
        .actor_user_agent,
    ).toBe(real);
  });
});
