/**
 * apiKeys.create for a request that authenticated with an admin-plane key (the
 * agent mint), at the implementation, with the repository doubled and the
 * transaction runner real.
 *
 * The branch is the credential boundary of the whole feature, so what is
 * pinned here is what must hold for ANY input a caller can send:
 *  - the branch is chosen from the verified provenance in the actor bundle and
 *    the caller must be an operator-scope key with an administrator owner: a
 *    sync scope, a missing scope, an unknown scope and a demoted owner all get
 *    the standing admin-plane refusal, with nothing written;
 *  - every rule refuses BEFORE the transaction opens (no repository call, no
 *    audit row) with its one fixed sentence;
 *  - a rule the database decides (owner, endpoint, name) is refused with the
 *    same sentence the pure rules use, and rolls back with no success row;
 *  - the key and its single `apikey.create` audit row go through ONE
 *    transaction, the row is awaited, and an audit failure fails the create;
 *  - the raw value is returned once and appears in no audit row, no log line
 *    and no error, whatever the failure.
 * What the transaction does against real rows is pinned against Postgres in
 * api-key-mint.integration.test.ts.
 */

import {
  ApiKeyUpdateInputSchema,
  UpdateApiKeyRequestSchema,
} from "@repo/zod-types";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { repoMock, loggerMock, txAudit, runnerMock, emitMock } = vi.hoisted(
  () => ({
    repoMock: {
      create: vi.fn(),
      mintDataPlaneKey: vi.fn(),
      deactivate: vi.fn(),
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
    runnerMock: { transactions: 0, handles: [] as unknown[] },
    emitMock: vi.fn(),
  }),
);

vi.mock("@/utils/logger", () => ({ default: loggerMock }));
vi.mock("../db/repositories", () => ({
  ApiKeysRepository: class {
    create = repoMock.create;
    mintDataPlaneKey = repoMock.mintDataPlaneKey;
    deactivate = repoMock.deactivate;
  },
  endpointsRepository: { findByUuid: vi.fn() },
  usersRepository: {
    findById: vi.fn(),
    findRoleById: vi.fn(),
    isDisabled: vi.fn(),
  },
}));
vi.mock("../lib/config.service", () => ({
  configService: { getApiKeyIpPolicy: vi.fn(), setApiKeyIpPolicy: vi.fn() },
}));
vi.mock("../lib/audit/admin-event", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/audit/admin-event")>()),
  emitAdminEvent: emitMock,
}));
// The real runner (lib/audit/admin-write.ts), over a stand-in transaction: the
// handle is recorded so a test can see the key and the audit row shared it.
vi.mock("../db/index", () => ({
  db: {
    transaction: async (callback: (tx: object) => Promise<unknown>) => {
      runnerMock.transactions += 1;
      const tx = { id: `tx-${runnerMock.transactions}` };
      runnerMock.handles.push(tx);
      return callback(tx);
    },
  },
}));
vi.mock("../db/repositories/audit-log-tx", () => ({
  recordAuditInTransaction: txAudit.record,
}));

const { apiKeysImplementations } = await import("./api-keys.impl");
const { ApiKeyMintRefusal, MINT_REFUSALS } = await import(
  "../lib/api-key-mint-rules"
);
const { ADMIN_PLANE_FORBIDDEN_MESSAGE } = await import("@repo/trpc");
const { ADMIN_AUDIT_WRITE_FAILED_MESSAGE } = await import(
  "../lib/audit/admin-write"
);

const OPERATOR_KEY_UUID = "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b";
const NEW_KEY_UUID = "99999999-9999-4999-8999-999999999999";
const ENDPOINT_UUID = "11111111-1111-4111-8111-111111111111";
/** What a freshly generated key looks like; it must never leak anywhere. */
const RAW_KEY = `sk_mt_${"Zk9".repeat(21)}Q`;

const actorFor = (scope?: unknown) => ({
  actor_id: "owner-admin-1",
  actor_label: "owner@example.test",
  actor_ip: "203.0.113.5",
  actor_user_agent: "metamcp-admin/test",
  request_id: "req-1",
  admin_plane: {
    key_uuid: OPERATOR_KEY_UUID,
    owner_user_id: "owner-admin-1",
    ...(scope === undefined ? {} : { scope }),
  },
});
const operatorActor = actorFor("operator");

const mintInput = (over: Record<string, unknown> = {}) =>
  ({
    name: "metrics poller",
    user_id: "owner-user-1",
    endpoint_uuid: ENDPOINT_UUID,
    ip_policy: { mode: "enforce", allowed_cidrs: ["203.0.113.0/24"] },
    ...over,
  }) as never;

const call = (input: unknown, actor: unknown = operatorActor, isAdmin = true) =>
  apiKeysImplementations.create(
    input as never,
    "owner-admin-1",
    isAdmin,
    actor as never,
  );

/** Everything written anywhere, as one string, to search for the raw key. */
const everything = () =>
  JSON.stringify([
    repoMock.mintDataPlaneKey.mock.calls,
    repoMock.create.mock.calls,
    txAudit.record.mock.calls,
    emitMock.mock.calls,
    loggerMock.debug.mock.calls,
    loggerMock.info.mock.calls,
    loggerMock.warn.mock.calls,
    loggerMock.error.mock.calls,
  ]);

beforeEach(() => {
  vi.clearAllMocks();
  runnerMock.transactions = 0;
  runnerMock.handles = [];
  txAudit.record.mockImplementation(async () => undefined);
  repoMock.mintDataPlaneKey.mockImplementation(async () => ({
    uuid: NEW_KEY_UUID,
    name: "metrics poller",
    key: RAW_KEY,
    user_id: "owner-user-1",
    endpoint_uuid: ENDPOINT_UUID,
    acts_as_user_id: null,
    created_at: new Date("2026-11-12T12:00:00Z"),
  }));
});

describe("the caller must be an operator-scope key with an administrator owner", () => {
  it.each([
    ["a sync scope", actorFor("sync"), true],
    ["no scope", actorFor(undefined), true],
    ["a capitalised scope", actorFor("Operator"), true],
    ["an unknown scope", actorFor("admin"), true],
    ["a non-string scope", actorFor({ toString: () => "operator" }), true],
    ["an operator whose owner was demoted to member", operatorActor, false],
  ])(
    "refuses %s with the standing admin-plane sentence",
    async (_l, actor, admin) => {
      const failure = await call(mintInput(), actor, admin).catch((e) => e);

      expect(failure).toMatchObject({
        code: "FORBIDDEN",
        message: ADMIN_PLANE_FORBIDDEN_MESSAGE,
      });
      expect(repoMock.mintDataPlaneKey).not.toHaveBeenCalled();
      expect(runnerMock.transactions).toBe(0);
      expect(txAudit.record).not.toHaveBeenCalled();
    },
  );

  it("is chosen by the provenance, never by a field of the request", async () => {
    // Fields that look like operator claims change nothing: the sync actor is
    // refused, and an operator actor is judged only by the rules.
    const failure = await call(
      mintInput({ admin_plane_scope: "operator", scope: "operator" }),
      actorFor("sync"),
    ).catch((e) => e);
    expect(failure).toMatchObject({ message: ADMIN_PLANE_FORBIDDEN_MESSAGE });
  });

  it("does not take the human branch for an admin-plane actor, whatever the request", async () => {
    // The human branch can create any key. An admin-plane actor that asks for
    // one of those is refused by the mint rules and the human repository
    // create is never reached.
    for (const input of [
      { name: "x", admin_plane: true },
      { name: "x", admin_plane: true, admin_plane_scope: "operator" },
      {
        name: "x",
        user_id: "u",
        acts_as_user_id: "u",
        endpoint_uuid: ENDPOINT_UUID,
      },
      { name: "x", user_id: null, all_endpoints: true },
      { name: "x", all_endpoints: true },
    ]) {
      await expect(call(input)).rejects.toMatchObject({
        code: expect.stringMatching(/FORBIDDEN|BAD_REQUEST/),
      });
    }
    expect(repoMock.create).not.toHaveBeenCalled();
    expect(repoMock.mintDataPlaneKey).not.toHaveBeenCalled();
  });
});

describe("every rule refuses before anything is written", () => {
  const cases: Array<[string, keyof typeof MINT_REFUSALS, unknown]> = [
    ["admin_plane true", "admin_plane_field", mintInput({ admin_plane: true })],
    [
      "an admin-plane scope",
      "admin_plane_field",
      mintInput({ admin_plane_scope: "sync" }),
    ],
    [
      "acts-as",
      "acts_as_field",
      mintInput({ acts_as_user_id: "owner-user-1" }),
    ],
    ["acts-as null", "acts_as_field", mintInput({ acts_as_user_id: null })],
    ["a null owner", "owner_required", mintInput({ user_id: null })],
    ["an omitted owner", "owner_required", mintInput({ user_id: undefined })],
    ["an empty owner", "owner_required", mintInput({ user_id: "" })],
    ["neither scope", "scope_choice", mintInput({ endpoint_uuid: undefined })],
    ["both scopes", "scope_choice", mintInput({ all_endpoints: true })],
    ["a bad name", "name_invalid", mintInput({ name: "bad/name" })],
    ["no policy", "ip_policy_shape", mintInput({ ip_policy: undefined })],
    [
      "a non-enforce policy",
      "ip_policy_shape",
      mintInput({
        ip_policy: { mode: "audit", allowed_cidrs: ["203.0.113.0/24"] },
      }),
    ],
    [
      "nine entries",
      "ip_policy_shape",
      mintInput({
        ip_policy: {
          mode: "enforce",
          allowed_cidrs: Array.from({ length: 9 }, (_v, i) => `203.0.113.${i}`),
        },
      }),
    ],
    [
      "a wide list",
      "ip_policy_too_wide",
      mintInput({
        ip_policy: { mode: "enforce", allowed_cidrs: ["::ffff:0:0/96"] },
      }),
    ],
  ];

  it.each(cases)("%s", async (_label, rule, input) => {
    const failure = await call(input).catch((e) => e);

    expect(failure).toMatchObject({
      code: MINT_REFUSALS[rule].code,
      message: MINT_REFUSALS[rule].message,
    });
    // Nothing was written: no transaction, no key, no audit row, no emit.
    expect(runnerMock.transactions).toBe(0);
    expect(repoMock.mintDataPlaneKey).not.toHaveBeenCalled();
    expect(txAudit.record).not.toHaveBeenCalled();
    expect(emitMock).not.toHaveBeenCalled();
  });

  it("refuses while the global kill switch is on, without opening a transaction", async () => {
    process.env.API_KEY_IP_POLICY_DISABLED = "true";
    try {
      await expect(call(mintInput())).rejects.toMatchObject({
        message: MINT_REFUSALS.ip_policy_disabled.message,
      });
    } finally {
      delete process.env.API_KEY_IP_POLICY_DISABLED;
    }
    expect(runnerMock.transactions).toBe(0);
    expect(repoMock.mintDataPlaneKey).not.toHaveBeenCalled();
  });
});

describe("a valid mint", () => {
  it("passes the validated request to the repository inside one transaction and returns the key once", async () => {
    const result = await call(
      mintInput({
        ip_policy: {
          mode: "enforce",
          allowed_cidrs: ["203.0.113.7", "203.0.113.0/24"],
        },
      }),
    );

    expect(result).toEqual({
      uuid: NEW_KEY_UUID,
      name: "metrics poller",
      key: RAW_KEY,
      created_at: new Date("2026-11-12T12:00:00Z"),
    });
    expect(repoMock.mintDataPlaneKey).toHaveBeenCalledTimes(1);
    const [tx, request] = repoMock.mintDataPlaneKey.mock.calls[0];
    expect(request).toEqual({
      name: "metrics poller",
      ownerUserId: "owner-user-1",
      endpointUuid: ENDPOINT_UUID,
      allEndpoints: false,
      allowedCidrs: ["203.0.113.7/32", "203.0.113.0/24"],
    });
    // The key and its audit row share one transaction handle.
    expect(runnerMock.transactions).toBe(1);
    expect(tx).toBe(runnerMock.handles[0]);
    expect(txAudit.record).toHaveBeenCalledTimes(1);
    expect(txAudit.record.mock.calls[0][0]).toBe(runnerMock.handles[0]);
    // The human repository create and the best-effort emitter are not used.
    expect(repoMock.create).not.toHaveBeenCalled();
    expect(emitMock).not.toHaveBeenCalled();
  });

  it("mints a gateway-wide key when asked with all_endpoints: true", async () => {
    await call(mintInput({ endpoint_uuid: undefined, all_endpoints: true }));

    expect(repoMock.mintDataPlaneKey.mock.calls[0][1]).toMatchObject({
      endpointUuid: null,
      allEndpoints: true,
    });
  });

  it("records one apikey.create row naming the key, its owner, scope and policy, and the acting key", async () => {
    await call(mintInput());

    const [, event] = txAudit.record.mock.calls[0] as [
      unknown,
      Record<string, unknown>,
    ];
    expect(event).toMatchObject({
      actor_type: "api_key",
      actor_id: OPERATOR_KEY_UUID,
      actor_label: "owner@example.test",
      actor_ip: "203.0.113.5",
      request_id: "req-1",
      action: "apikey.create",
      target_type: "api_key",
      target_id: NEW_KEY_UUID,
      outcome: "success",
    });
    expect(event.detail).toEqual({
      name: "metrics poller",
      owner_user_id: "owner-user-1",
      endpoint_uuid: ENDPOINT_UUID,
      all_endpoints: false,
      acts_as_user_id: null,
      key_admin_plane: false,
      key_admin_plane_scope: "sync",
      ip_policy: { mode: "enforce", allowed_cidrs: ["203.0.113.0/24"] },
      admin_plane: {
        key_uuid: OPERATOR_KEY_UUID,
        owner_user_id: "owner-admin-1",
        scope: "operator",
      },
    });
  });

  it("puts the raw key in nothing it writes, logs or hands to the audit row", async () => {
    await call(mintInput());

    expect(everything()).not.toContain(RAW_KEY);
    expect(everything()).not.toContain(RAW_KEY.slice(6));
  });
});

describe("a refusal the database makes", () => {
  it.each([
    "owner_required",
    "endpoint_missing",
    "endpoint_not_eligible",
    "gateway_wide_blocked",
    "name_taken",
  ] as const)(
    "keeps the fixed sentence for %s and records no success row",
    async (rule) => {
      repoMock.mintDataPlaneKey.mockRejectedValueOnce(
        new ApiKeyMintRefusal(rule),
      );

      const failure = await call(mintInput()).catch((e) => e);

      expect(failure).toMatchObject({
        code: MINT_REFUSALS[rule].code,
        message: MINT_REFUSALS[rule].message,
      });
      expect(txAudit.record).not.toHaveBeenCalled();
      expect(emitMock).not.toHaveBeenCalled();
    },
  );
});

describe("when something goes wrong, nothing leaks", () => {
  it("fails the create when the audit row cannot be written, with a fixed message and no driver text", async () => {
    txAudit.record.mockRejectedValueOnce(
      new Error(`insert into audit_log ... params: ${RAW_KEY}`),
    );

    const failure = await call(mintInput()).catch((e) => e);

    expect(failure).toMatchObject({
      code: "INTERNAL_SERVER_ERROR",
      message: ADMIN_AUDIT_WRITE_FAILED_MESSAGE,
    });
    expect(JSON.stringify(failure)).not.toContain(RAW_KEY);
    expect(String((failure as Error).message)).not.toContain("audit_log");
    expect((failure as { cause?: unknown }).cause).toBeUndefined();
    expect(everything()).not.toContain(RAW_KEY);
  });

  it("answers an unexpected failure with a fixed message, never the driver's, and logs no message", async () => {
    repoMock.mintDataPlaneKey.mockRejectedValueOnce(
      new Error(`Failed query: insert into "api_keys" params: ${RAW_KEY}`),
    );

    const failure = await call(mintInput()).catch((e) => e);

    expect(failure).toMatchObject({
      code: "INTERNAL_SERVER_ERROR",
      message: "The API key could not be created.",
    });
    expect(String((failure as Error).message)).not.toContain("api_keys");
    expect((failure as { cause?: unknown }).cause).toBeUndefined();
    expect(everything()).not.toContain(RAW_KEY);
    expect(everything()).not.toContain("Failed query");
  });

  it("does not retry a failed create", async () => {
    repoMock.mintDataPlaneKey.mockRejectedValueOnce(new Error("boom"));

    await call(mintInput()).catch(() => undefined);

    expect(repoMock.mintDataPlaneKey).toHaveBeenCalledTimes(1);
  });
});

describe("the human branch", () => {
  const humanInput = (over: Record<string, unknown> = {}) =>
    ({
      name: "ops key",
      all_endpoints: true,
      ...over,
    }) as never;
  const human = (input: unknown) =>
    apiKeysImplementations.create(input as never, "admin-1", true, {
      actor_id: "admin-1",
      actor_label: "admin@example.test",
      actor_ip: null,
      actor_user_agent: null,
      request_id: null,
    });

  beforeEach(() => {
    repoMock.create.mockResolvedValue({
      uuid: NEW_KEY_UUID,
      name: "ops key",
      key: RAW_KEY,
      user_id: "admin-1",
      endpoint_uuid: null,
      acts_as_user_id: null,
      created_at: new Date("2026-11-12T12:00:00Z"),
    });
  });

  it("refuses a scope without admin_plane, for a caller that bypassed the schema", async () => {
    await expect(
      human(humanInput({ admin_plane_scope: "operator" })),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(repoMock.create).not.toHaveBeenCalled();
  });

  it("creates a data-plane key with no policy exactly as before", async () => {
    await human(humanInput());

    const written = repoMock.create.mock.calls[0][0];
    expect(written).toMatchObject({ admin_plane: false, user_id: "admin-1" });
    expect(written).not.toHaveProperty("allowed_cidrs");
    expect(written).not.toHaveProperty("ip_policy_mode");
    expect(written).not.toHaveProperty("admin_plane_scope");
    // Best-effort event, not the transaction.
    expect(emitMock).toHaveBeenCalledTimes(1);
    expect(txAudit.record).not.toHaveBeenCalled();
  });

  it.each(["sync", "operator"] as const)(
    "creates an admin-plane key of scope %s when an administrator asks for it",
    async (scope) => {
      await usersRoleAdmin();
      await human({
        name: "ci key",
        admin_plane: true,
        admin_plane_scope: scope,
      });

      expect(repoMock.create.mock.calls[0][0]).toMatchObject({
        admin_plane: true,
        admin_plane_scope: scope,
      });
      expect(emitMock.mock.calls[0][1]).toMatchObject({
        detail: expect.objectContaining({
          admin_plane: true,
          admin_plane_scope: scope,
        }),
      });
    },
  );

  it("defaults an admin-plane key to the sync scope in its audit row when none is chosen", async () => {
    await usersRoleAdmin();
    await human({ name: "ci key", admin_plane: true });

    expect(repoMock.create.mock.calls[0][0]).not.toHaveProperty(
      "admin_plane_scope",
    );
    expect(emitMock.mock.calls[0][1]).toMatchObject({
      detail: expect.objectContaining({ admin_plane_scope: "sync" }),
    });
  });

  it("accepts the optional policy, canonicalises it and persists it with the key", async () => {
    await human(
      humanInput({
        ip_policy: {
          mode: "enforce",
          allowed_cidrs: ["203.0.113.9", "10.0.0.0/8"],
        },
      }),
    );

    // The agent prefix bounds do not apply to a human administrator.
    expect(repoMock.create.mock.calls[0][0]).toMatchObject({
      allowed_cidrs: ["203.0.113.9/32", "10.0.0.0/8"],
      ip_policy_mode: "enforce",
    });
  });
});

async function usersRoleAdmin() {
  const { usersRepository } = await import("../db/repositories");
  vi.mocked(usersRepository.findRoleById).mockResolvedValue("admin");
}

describe("the scope is creation-only", () => {
  // A promotion path is exactly what a stolen key would want, so no update
  // schema carries a scope and no update parses one through.
  it("is in no update schema", () => {
    expect(Object.keys(UpdateApiKeyRequestSchema.shape)).not.toContain(
      "admin_plane_scope",
    );
    expect(Object.keys(ApiKeyUpdateInputSchema.shape)).not.toContain(
      "admin_plane_scope",
    );
  });

  it("is dropped, not forwarded, when an update request carries one", () => {
    const parsed = UpdateApiKeyRequestSchema.parse({
      uuid: "11111111-1111-4111-8111-111111111111",
      is_active: true,
      admin_plane_scope: "operator",
    });

    expect(parsed).not.toHaveProperty("admin_plane_scope");
  });
});
