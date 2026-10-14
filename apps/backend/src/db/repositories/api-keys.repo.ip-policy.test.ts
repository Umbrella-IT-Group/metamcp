/**
 * The two key validators and the API-key IP policy (migration 0041).
 *
 * Pins, against the REAL validators and the REAL policy module with only the
 * database mocked:
 *  - the policy is evaluated ONLY under the explicit `ipCheck` opt-in. With no
 *    second argument (the tRPC `apiKeys.validate` oracle's call) an enforce
 *    policy is not consulted at all and the key reads valid;
 *  - an IP refusal is reported as `{ valid: false, ip_denied: true, key_uuid }`
 *    (data plane) or `reason: "ip_not_allowed"` (control plane), distinct from
 *    every other refusal so the call sites can keep it off the limiter;
 *  - ordering: an unknown or inactive key never reaches the policy; on the
 *    data plane the IP check runs BEFORE the admin-plane refusal (a wrong
 *    address learns nothing about the plane); on the control plane it runs
 *    AFTER the plane check (a data-plane key on /trpc stays a plain 401);
 *  - an accepted request stamps last_used_ip in the same throttled write as
 *    last_used_at, and only with an address that parses.
 *
 * Same chain-stub pattern as api-keys.repo.member-scope.test.ts.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const { selectChain, updateChain, getApiKeyIpPolicyMock, loggerMock } =
  vi.hoisted(() => ({
    selectChain: {
      from: vi.fn(),
      innerJoin: vi.fn(),
      where: vi.fn(),
    },
    updateChain: {
      set: vi.fn(),
      where: vi.fn(),
    },
    getApiKeyIpPolicyMock: vi.fn(),
    loggerMock: {
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
  }));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

vi.mock("../index", () => ({
  db: {
    select: vi.fn(() => selectChain),
    update: vi.fn(() => updateChain),
  },
}));

vi.mock("@/lib/config.service", () => ({
  configService: { getApiKeyIpPolicy: getApiKeyIpPolicyMock },
}));

const { ApiKeysRepository } = await import("./api-keys.repo");
const { __resetIpPolicyStateForTesting } = await import(
  "@/lib/api-key-ip-policy"
);
const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");

const KEY_UUID = "44444444-4444-4444-8444-444444444444";
const repo = new ApiKeysRepository();

const dataPlaneRow = (over: Record<string, unknown> = {}) => ({
  uuid: KEY_UUID,
  user_id: "owner-1",
  endpoint_uuid: null,
  acts_as_user_id: null,
  is_active: true,
  admin_plane: false,
  // Stale, so an accepted request stamps.
  last_used_at: null,
  allowed_cidrs: ["203.0.113.0/24"],
  ip_policy_mode: "enforce",
  ...over,
});

const adminPlaneRow = (over: Record<string, unknown> = {}) => ({
  key_uuid: KEY_UUID,
  is_active: true,
  admin_plane: true,
  last_used_at: null,
  allowed_cidrs: ["203.0.113.0/24"],
  ip_policy_mode: "enforce",
  user_id: "owner-1",
  email: "ops@example.invalid",
  name: "Ops",
  emailVerified: true,
  image: null,
  role: "admin",
  disabled: false,
  createdAt: new Date("2026-01-01T00:00:00Z"),
  updatedAt: new Date("2026-01-01T00:00:00Z"),
  ...over,
});

const ipCheck = (clientIp: string | undefined, surface = "data_plane") => ({
  clientIp,
  surface: surface as "data_plane" | "admin_plane",
  audit: {
    actor_ip: clientIp ?? null,
    actor_user_agent: null,
    request_id: null,
  },
});

beforeEach(() => {
  vi.clearAllMocks();
  __resetIpPolicyStateForTesting();
  setAuditSinkForTesting(async () => {});
  selectChain.from.mockReturnValue(selectChain);
  selectChain.innerJoin.mockReturnValue(selectChain);
  updateChain.set.mockReturnValue(updateChain);
  updateChain.where.mockResolvedValue(undefined);
  getApiKeyIpPolicyMock.mockResolvedValue({
    mode: "off",
    cidrs: [],
    problems: [],
  });
});

describe("validateApiKey: the IP policy is an explicit opt-in", () => {
  it("WITHOUT ipCheck an enforce policy is never consulted (the validate oracle's call)", async () => {
    selectChain.where.mockResolvedValue([dataPlaneRow()]);

    const result = await repo.validateApiKey("sk_mt_presented");

    expect(result.valid).toBe(true);
    expect(result).not.toHaveProperty("ip_denied");
    expect(getApiKeyIpPolicyMock).not.toHaveBeenCalled();
  });

  it("WITH ipCheck an address outside an enforce list is refused as ip_denied", async () => {
    selectChain.where.mockResolvedValue([dataPlaneRow()]);

    const result = await repo.validateApiKey(
      "sk_mt_presented",
      ipCheck("198.51.100.9"),
    );

    expect(result).toEqual({
      valid: false,
      ip_denied: true,
      key_uuid: KEY_UUID,
    });
    // A refused request is not a use: no last_used stamp.
    expect(updateChain.set).not.toHaveBeenCalled();
  });

  it("WITH ipCheck an address inside the list is served and stamps last_used_ip", async () => {
    selectChain.where.mockResolvedValue([dataPlaneRow()]);

    const result = await repo.validateApiKey(
      "sk_mt_presented",
      ipCheck("203.0.113.9"),
    );

    expect(result.valid).toBe(true);
    expect(updateChain.set).toHaveBeenCalledTimes(1);
    expect(updateChain.set.mock.calls[0][0]).toMatchObject({
      last_used_ip: "203.0.113.9",
    });
  });

  it("an unknown key never reaches the policy", async () => {
    selectChain.where.mockResolvedValue([]);
    getApiKeyIpPolicyMock.mockResolvedValue({
      mode: "enforce",
      cidrs: ["192.0.2.0/24"],
      problems: [],
    });

    const result = await repo.validateApiKey(
      "sk_mt_unknown",
      ipCheck("198.51.100.9"),
    );

    expect(result).toEqual({ valid: false });
    expect(getApiKeyIpPolicyMock).not.toHaveBeenCalled();
  });

  it("an inactive key is refused as invalid before the policy runs", async () => {
    selectChain.where.mockResolvedValue([
      dataPlaneRow({ is_active: false, allowed_cidrs: null }),
    ]);
    getApiKeyIpPolicyMock.mockResolvedValue({
      mode: "enforce",
      cidrs: ["192.0.2.0/24"],
      problems: [],
    });

    const result = await repo.validateApiKey(
      "sk_mt_revoked",
      ipCheck("198.51.100.9"),
    );

    expect(result).toEqual({ valid: false });
    expect(getApiKeyIpPolicyMock).not.toHaveBeenCalled();
  });

  it("the IP refusal comes BEFORE the admin-plane refusal on the data plane", async () => {
    selectChain.where.mockResolvedValue([dataPlaneRow({ admin_plane: true })]);

    const wrongAddress = await repo.validateApiKey(
      "sk_mt_control_plane",
      ipCheck("198.51.100.9"),
    );
    const rightAddress = await repo.validateApiKey(
      "sk_mt_control_plane",
      ipCheck("203.0.113.9"),
    );

    expect(wrongAddress).toEqual({
      valid: false,
      ip_denied: true,
      key_uuid: KEY_UUID,
    });
    expect(rightAddress).toEqual({
      valid: false,
      admin_plane: true,
      key_uuid: KEY_UUID,
    });
  });

  it("a key with no list of its own follows the global policy (one config read)", async () => {
    selectChain.where.mockResolvedValue([
      dataPlaneRow({ allowed_cidrs: null, ip_policy_mode: "off" }),
    ]);
    getApiKeyIpPolicyMock.mockResolvedValue({
      mode: "enforce",
      cidrs: ["192.0.2.0/24"],
      problems: [],
    });

    const refused = await repo.validateApiKey(
      "sk_mt_presented",
      ipCheck("198.51.100.9"),
    );
    const served = await repo.validateApiKey(
      "sk_mt_presented",
      ipCheck("192.0.2.7"),
    );

    expect(refused).toMatchObject({ valid: false, ip_denied: true });
    expect(served.valid).toBe(true);
    expect(getApiKeyIpPolicyMock).toHaveBeenCalledTimes(2);
  });

  it("does not stamp an unparsable address into last_used_ip", async () => {
    selectChain.where.mockResolvedValue([
      dataPlaneRow({ allowed_cidrs: null, ip_policy_mode: "off" }),
    ]);

    await repo.validateApiKey("sk_mt_presented", ipCheck("not-an-address"));

    expect(updateChain.set).toHaveBeenCalledTimes(1);
    expect(updateChain.set.mock.calls[0][0]).not.toHaveProperty("last_used_ip");
  });
});

describe("validateAdminPlaneApiKey: the IP policy on the control plane", () => {
  it("WITHOUT ipCheck the policy is not consulted", async () => {
    selectChain.where.mockResolvedValue([adminPlaneRow()]);

    const result = await repo.validateAdminPlaneApiKey("sk_mt_admin");

    expect(result.valid).toBe(true);
  });

  it("refuses an admin-plane key from outside its enforce list as ip_not_allowed", async () => {
    selectChain.where.mockResolvedValue([adminPlaneRow()]);

    const result = await repo.validateAdminPlaneApiKey(
      "sk_mt_admin",
      ipCheck("198.51.100.9", "admin_plane"),
    );

    expect(result).toEqual({
      valid: false,
      reason: "ip_not_allowed",
      key_uuid: KEY_UUID,
    });
    expect(updateChain.set).not.toHaveBeenCalled();
  });

  it("a data-plane key on /trpc stays not_admin_plane whatever its address", async () => {
    selectChain.where.mockResolvedValue([
      adminPlaneRow({ admin_plane: false }),
    ]);

    const result = await repo.validateAdminPlaneApiKey(
      "sk_mt_data_plane",
      ipCheck("198.51.100.9", "admin_plane"),
    );

    expect(result).toEqual({ valid: false, reason: "not_admin_plane" });
  });

  it("serves an admin-plane key from inside its list and stamps last_used_ip", async () => {
    selectChain.where.mockResolvedValue([adminPlaneRow()]);

    const result = await repo.validateAdminPlaneApiKey(
      "sk_mt_admin",
      ipCheck("203.0.113.20", "admin_plane"),
    );

    expect(result.valid).toBe(true);
    expect(updateChain.set.mock.calls[0][0]).toMatchObject({
      last_used_ip: "203.0.113.20",
    });
  });
});
