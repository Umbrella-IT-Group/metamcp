/**
 * The self-lockout rails on the IP-policy writes, and `apiKeys.deactivate`, at
 * the implementation, with the repository doubled and the transaction runner
 * real (lib/audit/admin-write.ts over a stand-in transaction).
 *
 * Rails (migration 0043 change, plan decision 2): an admin-plane key may not
 * leave itself an enforce policy its own request address is not inside, and may
 * not set a global enforce policy that excludes that address while it follows
 * the global policy. Both are judged with the request's trusted address and the
 * same matcher that evaluates a policy at request time, and refuse before the
 * write commits. A human session and a write to another key are unchanged.
 *
 * Deactivate: input is a uuid; it refuses the calling key (an upper-case
 * spelling included), writes only is_active, and records its row in the same
 * transaction whoever calls.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const { repoMock, configServiceMock, loggerMock, txAudit, txState, emitMock } =
  vi.hoisted(() => ({
    repoMock: {
      setIpPolicy: vi.fn(),
      deactivate: vi.fn(),
      lockPolicyTarget: vi.fn(),
    },
    configServiceMock: {
      getApiKeyIpPolicy: vi.fn(),
      setApiKeyIpPolicy: vi.fn(),
      getApiKeyIpPolicyInTransaction: vi.fn(),
    },
    loggerMock: {
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
    txAudit: {
      record: vi.fn(async (_tx: unknown, _event: unknown) => undefined),
    },
    // What the stand-in transaction's `select ... for share` returns: the
    // calling key's row, for the global rail.
    txState: {
      callerRow: [] as Array<{ allowed_cidrs: string[] | null }>,
      transactions: 0,
    },
    emitMock: vi.fn(),
  }));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));
vi.mock("../db/repositories", () => ({
  ApiKeysRepository: class {
    setIpPolicy = repoMock.setIpPolicy;
    deactivate = repoMock.deactivate;
    lockPolicyTarget = repoMock.lockPolicyTarget;
  },
  endpointsRepository: { findByUuid: vi.fn() },
  usersRepository: { findById: vi.fn(), isDisabled: vi.fn() },
}));
vi.mock("../lib/config.service", () => ({ configService: configServiceMock }));
vi.mock("../lib/audit/admin-event", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/audit/admin-event")>()),
  emitAdminEvent: emitMock,
}));
vi.mock("../db/index", () => ({
  db: {
    transaction: async (callback: (tx: object) => Promise<unknown>) => {
      txState.transactions += 1;
      return callback({
        select: () => ({
          from: () => ({
            where: () => ({ for: async () => txState.callerRow }),
          }),
        }),
      });
    },
  },
}));
vi.mock("../db/repositories/audit-log-tx", () => ({
  recordAuditInTransaction: txAudit.record,
}));

const { apiKeysImplementations } = await import("./api-keys.impl");
const { selfLockoutRefusal, SELF_LOCKOUT_REFUSALS } = await import(
  "../lib/api-key-self-lockout"
);
const { ADMIN_AUDIT_WRITE_FAILED_MESSAGE } = await import(
  "../lib/audit/admin-write"
);

const CALLER_UUID = "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b";
const OTHER_UUID = "22222222-2222-4222-8222-222222222222";

const actor = (over: { ip?: string | null; key?: string } = {}) => ({
  actor_id: "owner-admin-1",
  actor_label: "owner@example.test",
  actor_ip: over.ip === undefined ? "203.0.113.5" : over.ip,
  actor_user_agent: "test",
  request_id: "req-1",
  admin_plane: {
    key_uuid: over.key ?? CALLER_UUID,
    owner_user_id: "owner-admin-1",
    scope: "operator" as const,
  },
});
const humanActor = {
  actor_id: "admin-1",
  actor_label: "admin@example.test",
  actor_ip: "198.51.100.9",
  actor_user_agent: "test",
  request_id: "req-2",
};

const setPolicy = (
  uuid: string,
  cidrs: string[] | null,
  mode: "off" | "audit" | "enforce",
  who: unknown,
) =>
  apiKeysImplementations.setIpPolicy(
    { uuid, allowed_cidrs: cidrs, ip_policy_mode: mode } as never,
    who as never,
  );

beforeEach(() => {
  vi.clearAllMocks();
  txState.callerRow = [];
  txState.transactions = 0;
  txAudit.record.mockImplementation(async () => undefined);
  // The key being changed is a data-plane key unless a test says otherwise.
  repoMock.lockPolicyTarget.mockReset();
  repoMock.lockPolicyTarget.mockResolvedValue({ admin_plane: false });
  repoMock.setIpPolicy.mockImplementation(
    async (
      uuid: string,
      policy: { allowed_cidrs: string[] | null; ip_policy_mode: string },
    ) => ({
      before: { allowed_cidrs: null, ip_policy_mode: "off" },
      after: {
        uuid,
        name: "the key",
        last4: "abcd",
        is_active: true,
        allowed_cidrs: policy.allowed_cidrs,
        ip_policy_mode: policy.ip_policy_mode,
        last_used_ip: null,
      },
    }),
  );
  configServiceMock.setApiKeyIpPolicy.mockImplementation(
    async (policy: { mode: string; cidrs: string[] }) => ({
      before: { mode: "off", cidrs: [] },
      after: { mode: policy.mode, cidrs: policy.cidrs },
    }),
  );
  configServiceMock.getApiKeyIpPolicyInTransaction.mockResolvedValue({
    mode: "off",
    cidrs: [],
    problems: [],
  });
});

describe("selfLockoutRefusal: the judgement, without a database", () => {
  const enforce = (cidrs: string[]) => ({ mode: "enforce" as const, cidrs });

  it("admits an address inside an enforce list", () => {
    expect(
      selfLockoutRefusal(enforce(["203.0.113.0/24"]), "203.0.113.5", "ownList"),
    ).toBeNull();
  });

  it("refuses an address outside an enforce list, naming its source", () => {
    expect(
      selfLockoutRefusal(
        enforce(["198.51.100.0/24"]),
        "203.0.113.5",
        "ownList",
      ),
    ).toBe(SELF_LOCKOUT_REFUSALS.ownList);
    expect(
      selfLockoutRefusal(
        enforce(["198.51.100.0/24"]),
        "203.0.113.5",
        "globalList",
      ),
    ).toBe(SELF_LOCKOUT_REFUSALS.globalList);
  });

  it("matches an IPv4-mapped IPv6 address against an IPv4 list, as the gate does", () => {
    expect(
      selfLockoutRefusal(
        enforce(["203.0.113.0/24"]),
        "::ffff:203.0.113.5",
        "ownList",
      ),
    ).toBeNull();
    expect(
      selfLockoutRefusal(
        enforce(["203.0.113.0/24"]),
        "::ffff:203.0.114.5",
        "ownList",
      ),
    ).toBe(SELF_LOCKOUT_REFUSALS.ownList);
  });

  it.each([null, undefined, ""])(
    "fails closed on a request with no trusted address (%j)",
    (address) => {
      expect(
        selfLockoutRefusal(enforce(["203.0.113.0/24"]), address, "ownList"),
      ).toBe(SELF_LOCKOUT_REFUSALS.noAddress);
    },
  );

  it("fails closed on an address that does not parse", () => {
    expect(
      selfLockoutRefusal(enforce(["203.0.113.0/24"]), "not-an-ip", "ownList"),
    ).toBe(SELF_LOCKOUT_REFUSALS.ownList);
  });

  it("does not judge a policy that is not enforce", () => {
    for (const mode of ["off", "audit"] as const) {
      expect(
        selfLockoutRefusal(
          { mode, cidrs: ["198.51.100.0/24"] },
          "203.0.113.5",
          "ownList",
        ),
      ).toBeNull();
      expect(
        selfLockoutRefusal({ mode, cidrs: [] }, null, "ownList"),
      ).toBeNull();
    }
  });

  it("admits any address under the any-IP exemption", () => {
    expect(
      selfLockoutRefusal(enforce(["0.0.0.0/0", "::/0"]), null, "ownList"),
    ).toBe(SELF_LOCKOUT_REFUSALS.noAddress);
    expect(
      selfLockoutRefusal(
        enforce(["0.0.0.0/0", "::/0"]),
        "198.51.100.77",
        "ownList",
      ),
    ).toBeNull();
  });
});

describe("setIpPolicy by an admin-plane key on its OWN key", () => {
  it("refuses an enforce list that excludes the request's address, before the write", async () => {
    const failure = await setPolicy(
      CALLER_UUID,
      ["198.51.100.0/24"],
      "enforce",
      actor(),
    ).catch((e) => e);

    expect(failure).toMatchObject({
      code: "BAD_REQUEST",
      message: SELF_LOCKOUT_REFUSALS.ownList,
    });
    expect(repoMock.setIpPolicy).not.toHaveBeenCalled();
    expect(txAudit.record).not.toHaveBeenCalled();
  });

  it("accepts one that includes it, writing and recording in one transaction", async () => {
    await setPolicy(CALLER_UUID, ["203.0.113.0/24"], "enforce", actor());

    expect(txState.transactions).toBe(1);
    expect(repoMock.setIpPolicy).toHaveBeenCalledTimes(1);
    // The write received the transaction handle (a third argument).
    expect(repoMock.setIpPolicy.mock.calls[0]).toHaveLength(3);
    expect(txAudit.record).toHaveBeenCalledTimes(1);
    expect(emitMock).not.toHaveBeenCalled();
  });

  it("recognises its own key spelled in upper case", async () => {
    await expect(
      setPolicy(
        CALLER_UUID.toUpperCase(),
        ["198.51.100.0/24"],
        "enforce",
        actor(),
      ),
    ).rejects.toMatchObject({ message: SELF_LOCKOUT_REFUSALS.ownList });
  });

  it("accepts a mapped request address inside an IPv4 list", async () => {
    await setPolicy(
      CALLER_UUID,
      ["203.0.113.0/24"],
      "enforce",
      actor({ ip: "::ffff:203.0.113.5" }),
    );

    expect(repoMock.setIpPolicy).toHaveBeenCalledTimes(1);
  });

  it("fails closed when the request carries no trusted address", async () => {
    await expect(
      setPolicy(
        CALLER_UUID,
        ["203.0.113.0/24"],
        "enforce",
        actor({ ip: null }),
      ),
    ).rejects.toMatchObject({ message: SELF_LOCKOUT_REFUSALS.noAddress });
    expect(repoMock.setIpPolicy).not.toHaveBeenCalled();
  });

  it.each(["off", "audit"] as const)(
    "does not refuse a %s policy that excludes the address (it cannot lock the key out)",
    async (mode) => {
      await setPolicy(CALLER_UUID, ["198.51.100.0/24"], mode, actor());

      expect(repoMock.setIpPolicy).toHaveBeenCalledTimes(1);
    },
  );

  it("judges a key that is about to follow the global policy against the global policy, read under lock in the transaction", async () => {
    configServiceMock.getApiKeyIpPolicyInTransaction.mockResolvedValue({
      mode: "enforce",
      cidrs: ["198.51.100.0/24"],
      problems: [],
    });

    await expect(
      setPolicy(CALLER_UUID, null, "off", actor()),
    ).rejects.toMatchObject({ message: SELF_LOCKOUT_REFUSALS.globalList });
    expect(
      configServiceMock.getApiKeyIpPolicyInTransaction,
    ).toHaveBeenCalledTimes(1);
    expect(repoMock.setIpPolicy).not.toHaveBeenCalled();
  });

  it("lets a key follow a global policy that admits it, or one that is off", async () => {
    configServiceMock.getApiKeyIpPolicyInTransaction.mockResolvedValue({
      mode: "enforce",
      cidrs: ["203.0.113.0/24"],
      problems: [],
    });
    await setPolicy(CALLER_UUID, null, "off", actor());

    configServiceMock.getApiKeyIpPolicyInTransaction.mockResolvedValue({
      mode: "off",
      cidrs: [],
      problems: [],
    });
    await setPolicy(CALLER_UUID, null, "off", actor());

    expect(repoMock.setIpPolicy).toHaveBeenCalledTimes(2);
  });
});

describe("setIpPolicy outside the rail", () => {
  it("does not judge a write to another key, even one that excludes the caller", async () => {
    await setPolicy(OTHER_UUID, ["198.51.100.0/24"], "enforce", actor());

    expect(repoMock.setIpPolicy).toHaveBeenCalledTimes(1);
    expect(
      configServiceMock.getApiKeyIpPolicyInTransaction,
    ).not.toHaveBeenCalled();
  });

  it("leaves a human administrator's session unchanged: no rail, no transaction, best-effort event", async () => {
    await setPolicy(CALLER_UUID, ["198.51.100.0/24"], "enforce", humanActor);

    expect(txState.transactions).toBe(0);
    // Called with exactly the arguments it always had.
    expect(repoMock.setIpPolicy.mock.calls[0]).toHaveLength(2);
    expect(txAudit.record).not.toHaveBeenCalled();
    expect(emitMock).toHaveBeenCalledTimes(1);
  });
});

describe("setIpPolicy by an admin-plane key on a data-plane key keeps it locked and narrow", () => {
  // A key an admin-plane key creates is locked and narrow (rule 5). A second
  // call must not undo that: on a data-plane key the key may leave only an
  // enforce list of its own, 1 to 8 entries, none wider than IPv4 /24 or
  // IPv6 /48 (IPv4-mapped IPv6 counted at its IPv4 width).
  // The sentences are written out, not read from the rules module, so the
  // contract is pinned by its words and a missing rule is an assertion failure.
  const tooWide = "wider than IPv4 /24 or IPv6 /48";
  const notEnforced =
    "can set a data-plane key's IP policy only to mode enforce with 1 to 8 entries";
  const nine = Array.from({ length: 9 }, (_v, i) => `203.0.113.${i}`);

  const refused: Array<
    [string, string[] | null, "off" | "audit" | "enforce", string]
  > = [
    ["follow the global policy", null, "off", notEnforced],
    ["mode off with a list", ["203.0.113.0/24"], "off", notEnforced],
    ["mode audit with a list", ["203.0.113.0/24"], "audit", notEnforced],
    ["nine entries", nine, "enforce", notEnforced],
    ["the any-IP exemption", ["0.0.0.0/0", "::/0"], "enforce", tooWide],
    ["an IPv4 /8", ["10.0.0.0/8"], "enforce", tooWide],
    ["an IPv4 /23", ["203.0.112.0/23"], "enforce", tooWide],
    ["an IPv6 /47", ["2001:db8::/47"], "enforce", tooWide],
    ["::/48", ["::/48"], "enforce", tooWide],
    ["::ffff:0:0/96", ["::ffff:0:0/96"], "enforce", tooWide],
    ["a mapped /119", ["::ffff:203.0.112.0/119"], "enforce", tooWide],
    [
      "one wide entry among narrow ones",
      ["203.0.113.0/24", "10.0.0.0/8"],
      "enforce",
      tooWide,
    ],
  ];

  it.each(refused)(
    "refuses %s, writing nothing and leaving one denial row",
    async (_label, cidrs, mode, sentence) => {
      const failure = await setPolicy(OTHER_UUID, cidrs, mode, actor()).catch(
        (e) => e,
      );

      expect(failure).toMatchObject({
        code: "BAD_REQUEST",
        message: expect.stringContaining(sentence),
      });
      expect(repoMock.setIpPolicy).not.toHaveBeenCalled();
      expect(txAudit.record).not.toHaveBeenCalled();
      expect(emitMock).toHaveBeenCalledTimes(1);
      expect(emitMock.mock.calls[0][1]).toEqual({
        action: "apikey.ip_policy.set",
        target_type: "api_key",
        target_id: OTHER_UUID,
        outcome: "denied",
        detail: {
          rule:
            sentence === tooWide
              ? "ip_policy_change_too_wide"
              : "ip_policy_change_shape",
        },
      });
    },
  );

  it.each([
    ["an IPv4 /24", ["203.0.113.0/24"]],
    ["a single IPv4 address", ["203.0.113.7"]],
    ["a native IPv6 /48 and an IPv4 /24", ["2001:db8::/48", "198.51.100.0/24"]],
    ["a mapped /120", ["::ffff:203.0.113.0/120"]],
    ["eight entries", nine.slice(0, 8)],
  ])(
    "accepts %s, writing and recording in one transaction",
    async (_l, cidrs) => {
      await setPolicy(OTHER_UUID, cidrs, "enforce", actor());

      expect(repoMock.setIpPolicy).toHaveBeenCalledTimes(1);
      expect(txState.transactions).toBe(1);
      expect(txAudit.record).toHaveBeenCalledTimes(1);
      expect(emitMock).not.toHaveBeenCalled();
    },
  );

  it("records the denial under the key's lower-case uuid, however the request spelled it", async () => {
    // Hex letters, or upper-casing would change nothing.
    const stored = "abcdefab-2222-4222-8222-abcdefabcdef";

    await setPolicy(
      stored.toUpperCase(),
      ["10.0.0.0/8"],
      "enforce",
      actor(),
    ).catch(() => undefined);

    expect(emitMock).toHaveBeenCalledTimes(1);
    expect(emitMock.mock.calls[0][1]).toMatchObject({ target_id: stored });
  });

  it("looks the target up inside the write's transaction, by uuid", async () => {
    await setPolicy(OTHER_UUID, ["203.0.113.0/24"], "enforce", actor());

    expect(repoMock.lockPolicyTarget).toHaveBeenCalledTimes(1);
    const [handle, uuid] = repoMock.lockPolicyTarget.mock.calls[0];
    expect(handle).toBeDefined();
    expect(uuid).toBe(OTHER_UUID);
  });

  it.each([
    ["the any-IP exemption", ["0.0.0.0/0", "::/0"], "enforce"],
    ["mode off", ["203.0.113.0/24"], "off"],
    ["a wide list", ["10.0.0.0/8"], "enforce"],
  ] as const)(
    "leaves an admin-plane key's policy to the CLI's own judgement: %s is accepted",
    async (_label, cidrs, mode) => {
      // The CI key is locked to any address on purpose (its runners rotate), and
      // the operator sets that; only data-plane keys are held to the bound.
      repoMock.lockPolicyTarget.mockResolvedValue({ admin_plane: true });

      await setPolicy(OTHER_UUID, [...cidrs], mode, actor());

      expect(repoMock.setIpPolicy).toHaveBeenCalledTimes(1);
    },
  );

  it("lets a key follow the global policy when the target is an admin-plane key", async () => {
    repoMock.lockPolicyTarget.mockResolvedValue({ admin_plane: true });

    await setPolicy(OTHER_UUID, null, "off", actor());

    expect(repoMock.setIpPolicy).toHaveBeenCalledTimes(1);
  });

  it("falls through to the repository's not-found for a key that does not exist", async () => {
    repoMock.lockPolicyTarget.mockResolvedValue(null);
    repoMock.setIpPolicy.mockResolvedValue(null);

    await expect(
      setPolicy(OTHER_UUID, ["10.0.0.0/8"], "enforce", actor()),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
  });

  it("does not look up the calling key's own row, which would run ahead of the config locks", async () => {
    await setPolicy(CALLER_UUID, ["203.0.113.0/24"], "enforce", actor());

    expect(repoMock.lockPolicyTarget).not.toHaveBeenCalled();
  });

  it("leaves a human administrator's session unbounded and unqueried", async () => {
    await setPolicy(OTHER_UUID, ["0.0.0.0/0", "::/0"], "enforce", humanActor);
    await setPolicy(OTHER_UUID, null, "off", humanActor);

    expect(repoMock.setIpPolicy).toHaveBeenCalledTimes(2);
    expect(repoMock.lockPolicyTarget).not.toHaveBeenCalled();
  });
});

describe("an admin-plane key's IP-policy write fails when its audit row cannot be written", () => {
  it("rolls back and answers a fixed message", async () => {
    txAudit.record.mockRejectedValueOnce(new Error("audit_log is unavailable"));

    const failure = await setPolicy(
      OTHER_UUID,
      ["203.0.113.0/24"],
      "enforce",
      actor(),
    ).catch((e) => e);

    expect(failure.message).toBe(ADMIN_AUDIT_WRITE_FAILED_MESSAGE);
    expect(failure.message).not.toContain("unavailable");
  });
});

describe("setGlobalIpPolicy by an admin-plane key", () => {
  const setGlobal = (
    mode: "off" | "audit" | "enforce",
    cidrs: string[],
    who: unknown,
  ) =>
    apiKeysImplementations.setGlobalIpPolicy(
      { mode, allowed_cidrs: cidrs } as never,
      who as never,
    );

  it("refuses an enforce list that excludes the address while the calling key follows the global policy", async () => {
    txState.callerRow = [{ allowed_cidrs: null }];

    const failure = await setGlobal(
      "enforce",
      ["198.51.100.0/24"],
      actor(),
    ).catch((e) => e);

    expect(failure).toMatchObject({
      code: "BAD_REQUEST",
      message: SELF_LOCKOUT_REFUSALS.globalList,
    });
    // The write ran inside the transaction that the refusal rolls back, and its
    // audit row was never reached.
    expect(configServiceMock.setApiKeyIpPolicy).toHaveBeenCalledTimes(1);
    expect(txAudit.record).not.toHaveBeenCalled();
  });

  it("accepts it when the list includes the address", async () => {
    txState.callerRow = [{ allowed_cidrs: null }];

    await setGlobal("enforce", ["203.0.113.0/24"], actor());

    expect(txAudit.record).toHaveBeenCalledTimes(1);
  });

  it("does not judge a calling key that has a list of its own", async () => {
    txState.callerRow = [{ allowed_cidrs: ["203.0.113.0/24"] }];

    await setGlobal("enforce", ["198.51.100.0/24"], actor());

    expect(txAudit.record).toHaveBeenCalledTimes(1);
  });

  it("does not judge a calling key that no longer exists", async () => {
    txState.callerRow = [];

    await setGlobal("enforce", ["198.51.100.0/24"], actor());

    expect(txAudit.record).toHaveBeenCalledTimes(1);
  });

  it("fails closed with no trusted address while the calling key follows the policy", async () => {
    txState.callerRow = [{ allowed_cidrs: null }];

    await expect(
      setGlobal("enforce", ["203.0.113.0/24"], actor({ ip: null })),
    ).rejects.toMatchObject({ message: SELF_LOCKOUT_REFUSALS.noAddress });
  });

  it("leaves a human session unchanged", async () => {
    await setGlobal("enforce", ["198.51.100.0/24"], humanActor);

    expect(txState.transactions).toBe(0);
    expect(emitMock).toHaveBeenCalledTimes(1);
  });
});

describe("apiKeys.deactivate", () => {
  const deactivate = (uuid: string, who: unknown) =>
    apiKeysImplementations.deactivate({ uuid } as never, who as never);

  beforeEach(() => {
    repoMock.deactivate.mockImplementation(
      async (_tx: unknown, uuid: string) => ({
        status: "deactivated",
        key: { uuid, name: "old poller", last4: "wxyz", is_active: false },
      }),
    );
  });

  it("deactivates another key and records one apikey.revoke row in the same transaction", async () => {
    const result = await deactivate(OTHER_UUID, actor());

    expect(result).toEqual({
      uuid: OTHER_UUID,
      name: "old poller",
      key_prefix: "sk_mt_…wxyz",
      is_active: false,
      changed: true,
    });
    expect(txState.transactions).toBe(1);
    const [tx] = repoMock.deactivate.mock.calls[0];
    expect(tx).toBeDefined();
    expect(txAudit.record).toHaveBeenCalledTimes(1);
    const [, event] = txAudit.record.mock.calls[0] as [
      unknown,
      Record<string, unknown>,
    ];
    expect(event).toMatchObject({
      actor_type: "api_key",
      actor_id: CALLER_UUID,
      action: "apikey.revoke",
      target_id: OTHER_UUID,
    });
    expect(event.detail).toMatchObject({
      name: "old poller",
      is_active: false,
      via: "deactivate",
      admin_plane: { key_uuid: CALLER_UUID, scope: "operator" },
    });
  });

  it("refuses the calling key, in any spelling, before anything is written", async () => {
    for (const spelling of [CALLER_UUID, CALLER_UUID.toUpperCase()]) {
      await expect(deactivate(spelling, actor())).rejects.toMatchObject({
        code: "BAD_REQUEST",
      });
    }
    expect(txState.transactions).toBe(0);
    expect(repoMock.deactivate).not.toHaveBeenCalled();
  });

  it("returns changed: false for an already inactive key and records nothing", async () => {
    repoMock.deactivate.mockResolvedValueOnce({
      status: "unchanged",
      key: {
        uuid: OTHER_UUID,
        name: "old poller",
        last4: "wxyz",
        is_active: false,
      },
    });

    const result = await deactivate(OTHER_UUID, actor());

    expect(result.changed).toBe(false);
    expect(txAudit.record).not.toHaveBeenCalled();
  });

  it("answers NOT_FOUND for a key that does not exist and records nothing", async () => {
    repoMock.deactivate.mockResolvedValueOnce({ status: "not_found" });

    await expect(deactivate(OTHER_UUID, actor())).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    expect(txAudit.record).not.toHaveBeenCalled();
  });

  it("fails, leaving the key as it was, when the audit row cannot be written", async () => {
    txAudit.record.mockRejectedValueOnce(new Error("audit_log is unavailable"));

    const failure = await deactivate(OTHER_UUID, actor()).catch((e) => e);

    expect(failure).toMatchObject({
      code: "INTERNAL_SERVER_ERROR",
      message: ADMIN_AUDIT_WRITE_FAILED_MESSAGE,
    });
  });

  it("is transactional for a human administrator too", async () => {
    await deactivate(OTHER_UUID, humanActor);

    expect(txState.transactions).toBe(1);
    expect(txAudit.record).toHaveBeenCalledTimes(1);
    expect(emitMock).not.toHaveBeenCalled();
  });
});
