/**
 * The admin-plane (control-plane) bearer resolver (migration 0038).
 *
 * resolveAdminPlaneSession is the function createContext reaches for a /trpc
 * Authorization: Bearer once the cookie block resolved nothing. These tests pin
 * its whole contract: an admin-plane key authenticates AS its owner and carries
 * the owner's FRESH role; every failure mode returns null (fail-closed); each
 * accepted or denied request writes exactly one audit row that NEVER carries the
 * key; a failed verification records against the failure limiter and a valid one
 * does not; and the kill switch turns the whole path off before it touches the
 * database.
 *
 * The repository is mocked at the module seam (it reaches db/index). The real
 * audit emitter is used with its sink swapped, so the envelope is under test,
 * not mocked away; the real failure limiter is used with a spy on its record.
 */

import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { validateAdminPlaneApiKeyMock, loggerMock } = vi.hoisted(() => ({
  validateAdminPlaneApiKeyMock: vi.fn(),
  loggerMock: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

vi.mock("../utils/logger", () => ({ default: loggerMock }));

vi.mock("../db/repositories/api-keys.repo", () => ({
  ApiKeysRepository: class {
    validateAdminPlaneApiKey = validateAdminPlaneApiKeyMock;
  },
}));

const {
  resolveAdminPlaneSession,
  adminPlaneTokenAuthDisabled,
  warnIfAdminPlaneTokenAuthDisabled,
  __resetAdminPlaneDisabledWarningForTesting,
} = await import("./admin-plane-auth");
const { setAuditSinkForTesting } = await import("./audit/audit-emitter");
const { trpcAdminKeyRateLimiter } = await import("./auth-rate-limiter");

type AuditRow = {
  action: string;
  outcome: string;
  actor_type: string;
  actor_id?: string | null;
  target_id?: string | null;
  http_status?: number | null;
  detail?: Record<string, unknown>;
};

const ADMIN_PLANE_KEY = "sk_mt_ci_admin_plane_key_0001";
const KEY_UUID = "44444444-4444-4444-8444-444444444444";
const OWNER_ID = "ci-user-id";

const makeReq = (headers: Record<string, string> = {}): express.Request =>
  ({
    method: "POST",
    url: "/trpc/frontend/config.set",
    headers: {
      "user-agent": "metamcp-ci/1.0",
      "cf-connecting-ip": "203.0.113.9",
      ...headers,
    },
  }) as unknown as express.Request;

const activeAdminOwner = () => ({
  valid: true as const,
  key_uuid: KEY_UUID,
  disabled: false,
  user: {
    id: OWNER_ID,
    email: "ci@example.invalid",
    name: "CI Runner",
    emailVerified: true,
    image: null,
    role: "admin",
    createdAt: new Date("2026-01-01T00:00:00Z"),
    updatedAt: new Date("2026-01-01T00:00:00Z"),
  },
});

let rows: AuditRow[];
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));
let recordSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  vi.clearAllMocks();
  vi.unstubAllEnvs();
  __resetAdminPlaneDisabledWarningForTesting();
  rows = [];
  setAuditSinkForTesting(async (event) => {
    rows.push(event as AuditRow);
  });
  recordSpy = vi.spyOn(trpcAdminKeyRateLimiter, "recordFailedAttempt");
});

afterEach(() => {
  setAuditSinkForTesting(undefined);
  recordSpy.mockRestore();
  vi.unstubAllEnvs();
});

describe("resolveAdminPlaneSession — accepted", () => {
  it("authenticates a valid admin-plane key as its owner, role from the DB row", async () => {
    validateAdminPlaneApiKeyMock.mockResolvedValue(activeAdminOwner());

    const result = await resolveAdminPlaneSession(ADMIN_PLANE_KEY, makeReq());

    expect(result).not.toBeNull();
    expect(result?.user.id).toBe(OWNER_ID);
    expect(result?.user.email).toBe("ci@example.invalid");
    expect((result?.user as { role?: string }).role).toBe("admin");
    // Synthetic session is truthy (protectedProcedure only tests truthiness)
    // and marked so a heap dump names its origin.
    expect(result?.session).toBeTruthy();
    expect((result?.session as { token?: string }).token).toBe(
      "admin-plane-key",
    );
    expect(recordSpy).not.toHaveBeenCalled();
  });

  it("carries the owner's FRESH role (a demoted owner degrades to member)", async () => {
    const demoted = activeAdminOwner();
    demoted.user.role = "member";
    validateAdminPlaneApiKeyMock.mockResolvedValue(demoted);

    const result = await resolveAdminPlaneSession(ADMIN_PLANE_KEY, makeReq());
    expect((result?.user as { role?: string }).role).toBe("member");
  });

  it("writes exactly one accepted audit row that never carries the key", async () => {
    validateAdminPlaneApiKeyMock.mockResolvedValue(activeAdminOwner());

    await resolveAdminPlaneSession(ADMIN_PLANE_KEY, makeReq());
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "authn.admin_key.accepted",
      outcome: "success",
      actor_type: "api_key",
      actor_id: KEY_UUID,
      target_id: OWNER_ID,
    });
    expect(rows[0].detail).toMatchObject({ user_id: OWNER_ID });
    // The fingerprint is present; the raw key is nowhere in the row.
    expect(JSON.stringify(rows[0])).not.toContain(ADMIN_PLANE_KEY);
    const cred = (rows[0].detail as { key: { last4: string } }).key;
    expect(cred.last4).toBe(ADMIN_PLANE_KEY.slice(-4));
  });
});

describe("resolveAdminPlaneSession — rejected (fail-closed)", () => {
  it.each([["unknown_key"], ["inactive"], ["not_admin_plane"]] as const)(
    "returns null and records a failure for %s",
    async (reason) => {
      validateAdminPlaneApiKeyMock.mockResolvedValue({ valid: false, reason });

      const result = await resolveAdminPlaneSession(ADMIN_PLANE_KEY, makeReq());
      await flush();

      expect(result).toBeNull();
      expect(recordSpy).toHaveBeenCalledTimes(1);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        action: "authn.admin_key.denied",
        outcome: "denied",
        actor_type: "api_key",
        actor_id: null,
      });
      expect(rows[0].detail).toMatchObject({ reason });
      expect(JSON.stringify(rows[0])).not.toContain(ADMIN_PLANE_KEY);
    },
  );

  it("fails closed on a disabled owner and denies with owner_disabled", async () => {
    const disabled = activeAdminOwner();
    disabled.disabled = true;
    validateAdminPlaneApiKeyMock.mockResolvedValue(disabled);

    const result = await resolveAdminPlaneSession(ADMIN_PLANE_KEY, makeReq());
    await flush();

    expect(result).toBeNull();
    expect(recordSpy).toHaveBeenCalledTimes(1);
    expect(rows[0].detail).toMatchObject({ reason: "owner_disabled" });
  });
});

describe("kill switch — ADMIN_PLANE_TOKEN_AUTH_DISABLED", () => {
  it("is strict true only", () => {
    vi.stubEnv("ADMIN_PLANE_TOKEN_AUTH_DISABLED", "TRUE");
    expect(adminPlaneTokenAuthDisabled()).toBe(false);
    vi.stubEnv("ADMIN_PLANE_TOKEN_AUTH_DISABLED", "1");
    expect(adminPlaneTokenAuthDisabled()).toBe(false);
    vi.stubEnv("ADMIN_PLANE_TOKEN_AUTH_DISABLED", "true");
    expect(adminPlaneTokenAuthDisabled()).toBe(true);
  });

  it("disables the bearer path before touching the database, with no audit or count", async () => {
    vi.stubEnv("ADMIN_PLANE_TOKEN_AUTH_DISABLED", "true");
    validateAdminPlaneApiKeyMock.mockResolvedValue(activeAdminOwner());

    const result = await resolveAdminPlaneSession(ADMIN_PLANE_KEY, makeReq());
    await flush();

    expect(result).toBeNull();
    expect(validateAdminPlaneApiKeyMock).not.toHaveBeenCalled();
    expect(recordSpy).not.toHaveBeenCalled();
    expect(rows).toEqual([]);
  });

  it("logs exactly one boot warning when set, and none when unset", () => {
    vi.stubEnv("ADMIN_PLANE_TOKEN_AUTH_DISABLED", "true");
    warnIfAdminPlaneTokenAuthDisabled();
    warnIfAdminPlaneTokenAuthDisabled();
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);

    loggerMock.warn.mockClear();
    __resetAdminPlaneDisabledWarningForTesting();
    vi.stubEnv("ADMIN_PLANE_TOKEN_AUTH_DISABLED", "");
    warnIfAdminPlaneTokenAuthDisabled();
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });
});
