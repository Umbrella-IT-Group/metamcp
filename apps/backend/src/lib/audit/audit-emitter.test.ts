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
  auditRequestContext,
  credentialFingerprint,
  emit,
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

    expect(loggerMock.debug).toHaveBeenCalled();
  });

  it("swallows a sink that REJECTS (the database-down case)", async () => {
    setAuditSinkForTesting(() => Promise.reject(new Error("ECONNREFUSED")));

    expect(() => emit(EVENT)).not.toThrow();
    await flush();

    expect(loggerMock.debug).toHaveBeenCalled();
  });

  it("is a no-op with no sink resolved (no database in this process)", async () => {
    setAuditSinkForTesting(null);

    expect(() => emit(EVENT)).not.toThrow();
    await flush();

    expect(loggerMock.debug).not.toHaveBeenCalled();
  });

  it("never logs a failure above debug — a DB blip must not flood the log", async () => {
    setAuditSinkForTesting(() => Promise.reject(new Error("boom")));

    emit(EVENT);
    await flush();

    expect(loggerMock.error).not.toHaveBeenCalled();
    expect(loggerMock.warn).not.toHaveBeenCalled();
    expect(loggerMock.info).not.toHaveBeenCalled();
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
});
