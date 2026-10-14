/**
 * Admin management of API-key IP allowlists (migration 0040), at the impl.
 *
 * Pins:
 *  - setIpPolicy validates every CIDR (reporting all bad entries), canonicalises
 *    what it stores, refuses enforce with an empty list and a per-key mode with
 *    no per-key list, answers NOT_FOUND for an unknown uuid, and writes ONE
 *    `apikey.ip_policy.set` admin row with the old and new value;
 *  - the global getter/setter round-trip through config.service, refuse the
 *    same bad inputs, and write ONE `config.api_key_ip_policy.set` row;
 *  - the tRPC `validate` oracle calls validateApiKey WITHOUT the IP-policy
 *    opt-in, so where an administrator sits never changes its answer;
 *  - the generic config.setConfig escape hatch refuses the two policy rows.
 *
 * The router gates all three procedures with adminProcedure; that gate is
 * pinned in admin-procedure tests, and the router wiring by typecheck.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const { repoMock, configServiceMock, loggerMock } = vi.hoisted(() => ({
  repoMock: {
    validateApiKey: vi.fn(),
    setIpPolicy: vi.fn(),
  },
  configServiceMock: {
    getApiKeyIpPolicy: vi.fn(),
    setApiKeyIpPolicy: vi.fn(),
    getConfig: vi.fn(),
    setConfig: vi.fn(),
  },
  loggerMock: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

vi.mock("../db/repositories", () => ({
  ApiKeysRepository: class {
    validateApiKey = repoMock.validateApiKey;
    setIpPolicy = repoMock.setIpPolicy;
  },
  endpointsRepository: { findByUuid: vi.fn() },
  usersRepository: { findById: vi.fn(), isDisabled: vi.fn() },
}));

vi.mock("../lib/config.service", () => ({ configService: configServiceMock }));

const { apiKeysImplementations } = await import("./api-keys.impl");
const { configImplementations } = await import("./config.impl");
const { setAuditSinkForTesting } = await import("../lib/audit/audit-emitter");

type AuditRow = {
  action: string;
  actor_type: string;
  actor_id?: string | null;
  target_type?: string | null;
  target_id?: string | null;
  detail?: Record<string, unknown>;
};

const KEY_UUID = "44444444-4444-4444-8444-444444444444";
const ACTOR = {
  actor_id: "admin-1",
  actor_label: "admin@example.invalid",
  actor_ip: "203.0.113.3",
  actor_user_agent: "test",
  request_id: "req-1",
};

let rows: AuditRow[];
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

beforeEach(() => {
  vi.clearAllMocks();
  rows = [];
  setAuditSinkForTesting(async (event) => {
    rows.push(event as AuditRow);
  });
  repoMock.setIpPolicy.mockImplementation(
    async (
      uuid: string,
      policy: { allowed_cidrs: string[] | null; ip_policy_mode: string },
    ) => ({
      before: { allowed_cidrs: null, ip_policy_mode: "off" },
      after: {
        uuid,
        name: "n8n-machine",
        last4: "wxyz",
        is_active: true,
        allowed_cidrs: policy.allowed_cidrs,
        ip_policy_mode: policy.ip_policy_mode,
        last_used_ip: "203.0.113.10",
      },
    }),
  );
  configServiceMock.getApiKeyIpPolicy.mockResolvedValue({
    mode: "off",
    cidrs: [],
    problems: [],
  });
});

describe("apiKeys.setIpPolicy", () => {
  it("stores the canonical list and mode, and returns the row without credential material", async () => {
    const result = await apiKeysImplementations.setIpPolicy(
      {
        uuid: KEY_UUID,
        allowed_cidrs: ["203.0.113.10", "2001:DB8::/32"],
        ip_policy_mode: "audit",
      },
      ACTOR,
    );

    expect(repoMock.setIpPolicy).toHaveBeenCalledWith(KEY_UUID, {
      allowed_cidrs: ["203.0.113.10/32", "2001:db8::/32"],
      ip_policy_mode: "audit",
    });
    expect(result).toEqual({
      uuid: KEY_UUID,
      name: "n8n-machine",
      key_prefix: "sk_mt_…wxyz",
      is_active: true,
      allowed_cidrs: ["203.0.113.10/32", "2001:db8::/32"],
      ip_policy_mode: "audit",
      last_used_ip: "203.0.113.10",
    });
  });

  it("writes one apikey.ip_policy.set row carrying old and new value", async () => {
    await apiKeysImplementations.setIpPolicy(
      {
        uuid: KEY_UUID,
        allowed_cidrs: ["203.0.113.0/24"],
        ip_policy_mode: "enforce",
      },
      ACTOR,
    );
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "apikey.ip_policy.set",
      actor_type: "user",
      actor_id: "admin-1",
      target_type: "api_key",
      target_id: KEY_UUID,
    });
    expect(rows[0].detail).toEqual({
      name: "n8n-machine",
      old_value: { allowed_cidrs: null, ip_policy_mode: "off" },
      new_value: {
        allowed_cidrs: ["203.0.113.0/24"],
        ip_policy_mode: "enforce",
      },
    });
  });

  it("accepts the any-IP exemption", async () => {
    await apiKeysImplementations.setIpPolicy(
      {
        uuid: KEY_UUID,
        allowed_cidrs: ["0.0.0.0/0", "::/0"],
        ip_policy_mode: "enforce",
      },
      ACTOR,
    );
    expect(repoMock.setIpPolicy).toHaveBeenCalledWith(KEY_UUID, {
      allowed_cidrs: ["0.0.0.0/0", "::/0"],
      ip_policy_mode: "enforce",
    });
  });

  it("returns a key to the global policy with allowed_cidrs null and mode off", async () => {
    await apiKeysImplementations.setIpPolicy(
      { uuid: KEY_UUID, allowed_cidrs: null, ip_policy_mode: "off" },
      ACTOR,
    );
    expect(repoMock.setIpPolicy).toHaveBeenCalledWith(KEY_UUID, {
      allowed_cidrs: null,
      ip_policy_mode: "off",
    });
  });

  it.each([
    [
      "a bad entry (all of them named)",
      { allowed_cidrs: ["nope", "203.0.113.5/24"], ip_policy_mode: "audit" },
      "Invalid allowlist entries",
    ],
    [
      "enforce with an empty list",
      { allowed_cidrs: [], ip_policy_mode: "enforce" },
      "empty list",
    ],
    [
      "a per-key mode with no per-key list",
      { allowed_cidrs: null, ip_policy_mode: "audit" },
      "needs a per-key list",
    ],
  ] as const)(
    "refuses %s with BAD_REQUEST and no write",
    async (_, input, msg) => {
      await expect(
        apiKeysImplementations.setIpPolicy(
          {
            uuid: KEY_UUID,
            allowed_cidrs: input.allowed_cidrs as string[] | null,
            ip_policy_mode: input.ip_policy_mode,
          },
          ACTOR,
        ),
      ).rejects.toMatchObject({
        code: "BAD_REQUEST",
        message: expect.stringContaining(msg),
      });
      expect(repoMock.setIpPolicy).not.toHaveBeenCalled();
      await flush();
      expect(rows).toHaveLength(0);
    },
  );

  it("names every bad entry, not just the first", async () => {
    await expect(
      apiKeysImplementations.setIpPolicy(
        {
          uuid: KEY_UUID,
          allowed_cidrs: ["nope", "203.0.113.5/24"],
          ip_policy_mode: "audit",
        },
        ACTOR,
      ),
    ).rejects.toMatchObject({
      message: expect.stringMatching(/"nope".*"203\.0\.113\.5\/24"/),
    });
  });

  it("answers NOT_FOUND for an unknown key and writes no audit row", async () => {
    repoMock.setIpPolicy.mockResolvedValue(null);

    await expect(
      apiKeysImplementations.setIpPolicy(
        {
          uuid: KEY_UUID,
          allowed_cidrs: ["203.0.113.0/24"],
          ip_policy_mode: "audit",
        },
        ACTOR,
      ),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
    await flush();
    expect(rows).toHaveLength(0);
  });
});

describe("apiKeys global IP policy", () => {
  it("getGlobalIpPolicy reports the stored policy, its problems and the kill switch", async () => {
    configServiceMock.getApiKeyIpPolicy.mockResolvedValue({
      mode: "audit",
      cidrs: ["203.0.113.0/24"],
      problems: ["something"],
    });
    vi.stubEnv("API_KEY_IP_POLICY_DISABLED", "true");

    const result = await apiKeysImplementations.getGlobalIpPolicy();
    vi.unstubAllEnvs();

    expect(result).toEqual({
      mode: "audit",
      allowed_cidrs: ["203.0.113.0/24"],
      problems: ["something"],
      kill_switch_active: true,
    });
  });

  it("setGlobalIpPolicy writes the canonical list, audits old and new, and reads back", async () => {
    configServiceMock.getApiKeyIpPolicy
      .mockResolvedValueOnce({ mode: "off", cidrs: [], problems: [] })
      .mockResolvedValueOnce({
        mode: "audit",
        cidrs: ["198.51.100.0/24"],
        problems: [],
      });

    const result = await apiKeysImplementations.setGlobalIpPolicy(
      { mode: "audit", allowed_cidrs: ["198.51.100.0/24"] },
      ACTOR,
    );
    await flush();

    expect(configServiceMock.setApiKeyIpPolicy).toHaveBeenCalledWith({
      mode: "audit",
      cidrs: ["198.51.100.0/24"],
    });
    expect(result).toEqual({
      mode: "audit",
      allowed_cidrs: ["198.51.100.0/24"],
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "config.api_key_ip_policy.set",
      target_type: "config_key",
      target_id: "API_KEY_IP_POLICY",
    });
    expect(rows[0].detail).toEqual({
      old_value: { mode: "off", allowed_cidrs: [] },
      new_value: { mode: "audit", allowed_cidrs: ["198.51.100.0/24"] },
    });
  });

  it("refuses enforce with an empty global list", async () => {
    await expect(
      apiKeysImplementations.setGlobalIpPolicy(
        { mode: "enforce", allowed_cidrs: [] },
        ACTOR,
      ),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(configServiceMock.setApiKeyIpPolicy).not.toHaveBeenCalled();
  });

  it("refuses a bad global entry", async () => {
    await expect(
      apiKeysImplementations.setGlobalIpPolicy(
        { mode: "audit", allowed_cidrs: ["198.51.100.1/24"] },
        ACTOR,
      ),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(configServiceMock.setApiKeyIpPolicy).not.toHaveBeenCalled();
  });
});

describe("apiKeys.validate: the admin oracle never evaluates the IP policy", () => {
  it("calls validateApiKey with the key ONLY (no IP-policy opt-in)", async () => {
    repoMock.validateApiKey.mockResolvedValue({
      valid: true,
      user_id: null,
      key_uuid: KEY_UUID,
    });

    const result = await apiKeysImplementations.validate({
      key: "sk_mt_some_key",
    });

    expect(result.valid).toBe(true);
    expect(repoMock.validateApiKey).toHaveBeenCalledTimes(1);
    // Exactly one argument: a second one is the opt-in that would make the
    // answer depend on the administrator's own address.
    expect(repoMock.validateApiKey.mock.calls[0]).toEqual(["sk_mt_some_key"]);
  });
});

describe("config.setConfig refuses the two IP-policy rows", () => {
  it.each(["API_KEY_IP_POLICY_MODE", "API_KEY_IP_ALLOWED_CIDRS"] as const)(
    "refuses %s with BAD_REQUEST before any read or write",
    async (key) => {
      await expect(
        configImplementations.setConfig({ key, value: "enforce" }, ACTOR),
      ).rejects.toMatchObject({ code: "BAD_REQUEST" });
      expect(configServiceMock.getConfig).not.toHaveBeenCalled();
      expect(configServiceMock.setConfig).not.toHaveBeenCalled();
      await flush();
      expect(rows).toHaveLength(0);
    },
  );

  it("still writes an ordinary key", async () => {
    await configImplementations.setConfig(
      { key: "MCP_TIMEOUT", value: "60000" },
      ACTOR,
    );
    expect(configServiceMock.setConfig).toHaveBeenCalledWith(
      "MCP_TIMEOUT",
      "60000",
      undefined,
    );
  });
});
