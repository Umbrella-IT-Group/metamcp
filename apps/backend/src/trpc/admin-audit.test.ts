/**
 * The admin control plane's audit rows.
 *
 * Until Phase 1B every write in this group was silent. An admin session — or
 * anyone holding one — could re-open self-registration, mint a gateway-wide
 * API key, register an OAuth client or lock an account out, and the only
 * evidence afterwards was the affected row's own `updated_at`. That is the
 * 2026-08-13 incident's front door, so the config toggles are the highest
 * priority in this file.
 *
 * Driven through the REAL production path — the real `@repo/trpc` routers,
 * the real `*.impl.ts` implementations, the real emitter — with only the
 * repositories and the database sink swapped out. Same approach as
 * `rbac-denial-audit.test.ts`. Testing the impls in isolation would not catch
 * the failure that actually matters here: a router that stops forwarding the
 * actor, leaving every admin action attributed to nobody.
 *
 * Three properties are pinned throughout:
 *  1. the row names the ACTOR and the TARGET — an audit row that says
 *     "a config changed" without saying who or which is not evidence;
 *  2. the emit is on the OUTCOME path, after the write. A failed or no-op
 *     mutation must leave no row claiming it happened;
 *  3. no secret is ever persisted, and a broken sink never breaks a mutation.
 */

import {
  createApiKeysRouter,
  createConfigRouter,
  createUsersRouter,
} from "@repo/trpc";
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

// ---------------------------------------------------------------------------
// Repository / service doubles — the layer under the impls
// ---------------------------------------------------------------------------

const configServiceMock = {
  isSignupDisabled: vi.fn(),
  setSignupDisabled: vi.fn(),
  isSsoSignupDisabled: vi.fn(),
  setSsoSignupDisabled: vi.fn(),
  isBasicAuthDisabled: vi.fn(),
  setBasicAuthDisabled: vi.fn(),
  getSessionLifetime: vi.fn(),
  setSessionLifetime: vi.fn(),
  getConfig: vi.fn(),
  setConfig: vi.fn(),
  getAllConfigs: vi.fn(),
  getAuthProviders: vi.fn(),
  getMcpResetTimeoutOnProgress: vi.fn(),
  setMcpResetTimeoutOnProgress: vi.fn(),
  getMcpTimeout: vi.fn(),
  setMcpTimeout: vi.fn(),
  getMcpMaxTotalTimeout: vi.fn(),
  setMcpMaxTotalTimeout: vi.fn(),
  getMcpMaxAttempts: vi.fn(),
  setMcpMaxAttempts: vi.fn(),
};

vi.mock("../lib/config.service", () => ({
  configService: configServiceMock,
}));

const apiKeysRepositoryMock = {
  create: vi.fn(),
  update: vi.fn(),
  updateAsAdmin: vi.fn(),
  delete: vi.fn(),
  deleteAsAdmin: vi.fn(),
  findAccessibleToUser: vi.fn(),
  findAll: vi.fn(),
  validateApiKey: vi.fn(),
};

const usersRepositoryMock = {
  setDisabled: vi.fn(),
  findById: vi.fn(),
  listAll: vi.fn(),
  previewDeleteImpact: vi.fn(),
  revokeAccess: vi.fn(),
  deleteById: vi.fn(),
  isDisabled: vi.fn(),
};

const endpointsRepositoryMock = { findByUuid: vi.fn() };

const mcpServersRepositoryMock = {
  create: vi.fn(),
  update: vi.fn(),
  findByUuid: vi.fn(),
  deleteByUuid: vi.fn(),
  bulkCreate: vi.fn(),
};

const namespaceMappingsRepositoryMock = {
  findNamespacesByServerUuid: vi.fn(),
};

// `tools.impl.ts` is reached directly (no tRPC caller) by the actor-less test
// below, so its repository has to be in the same barrel mock — importing the
// real one pulls in `db/index.ts`, which throws without DATABASE_URL.
const toolsRepositoryMock = {
  syncTools: vi.fn(),
  bulkUpsert: vi.fn(),
  findByMcpServerUuid: vi.fn(),
};

vi.mock("../db/repositories", () => ({
  ApiKeysRepository: class {
    create = apiKeysRepositoryMock.create;
    update = apiKeysRepositoryMock.update;
    updateAsAdmin = apiKeysRepositoryMock.updateAsAdmin;
    delete = apiKeysRepositoryMock.delete;
    deleteAsAdmin = apiKeysRepositoryMock.deleteAsAdmin;
    findAccessibleToUser = apiKeysRepositoryMock.findAccessibleToUser;
    findAll = apiKeysRepositoryMock.findAll;
    validateApiKey = apiKeysRepositoryMock.validateApiKey;
  },
  endpointsRepository: endpointsRepositoryMock,
  mcpServersRepository: mcpServersRepositoryMock,
  namespaceMappingsRepository: namespaceMappingsRepositoryMock,
  toolsRepository: toolsRepositoryMock,
  usersRepository: usersRepositoryMock,
}));

// `mcp-servers.impl.ts` reaches the connection pools and the override cache on
// its success paths; none of that is under test here and all of it would drag
// real infrastructure into the graph.
vi.mock("../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    ensureIdleSessionForNewServer: vi.fn().mockResolvedValue(undefined),
    cleanupIdleSession: vi.fn().mockResolvedValue(undefined),
    invalidateIdleSession: vi.fn().mockResolvedValue(undefined),
  },
}));
vi.mock("../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {
    invalidateIdleServers: vi.fn().mockResolvedValue(undefined),
    invalidateOpenApiSessions: vi.fn().mockResolvedValue(undefined),
  },
}));
vi.mock("../lib/metamcp/server-error-tracker", () => ({
  serverErrorTracker: {
    clearServerErrorStatus: vi.fn().mockResolvedValue(undefined),
    isServerInErrorState: vi.fn().mockResolvedValue(false),
  },
}));
vi.mock("../lib/metamcp/metamcp-middleware/tool-overrides.functional", () => ({
  clearOverrideCache: vi.fn(),
}));
vi.mock("../lib/metamcp/utils", () => ({
  convertDbServerToParams: vi.fn().mockResolvedValue(null),
}));

const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");
const { configImplementations } = await import("./config.impl");
const { apiKeysImplementations } = await import("./api-keys.impl");
const { usersImplementations } = await import("./users.impl");
const { toolsImplementations } = await import("./tools.impl");
const { mcpServersImplementations } = await import("./mcp-servers.impl");

type AuditRow = {
  action: string;
  outcome: string;
  actor_type: string;
  actor_id?: string | null;
  actor_label?: string | null;
  actor_ip?: string | null;
  actor_user_agent?: string | null;
  request_id?: string | null;
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

/** The full secret an API key mint returns to the caller exactly once. */
const RAW_API_KEY = "sk_mt_live_do_not_ever_log_this_value";

// Real UUIDs: the api-keys zod contract validates the format, so a
// human-readable placeholder is rejected before the impl is ever reached.
const ENDPOINT_UUID = "11111111-1111-4111-8111-111111111111";
const API_KEY_UUID = "22222222-2222-4222-8222-222222222222";

let rows: AuditRow[];

/** Flush the detached promise chain `emit()` schedules. */
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

const serialized = () => JSON.stringify(rows);

const configRouter = () => createConfigRouter(configImplementations);
const apiKeysRouter = () => createApiKeysRouter(apiKeysImplementations);
const usersRouter = () => createUsersRouter(usersImplementations);

beforeEach(() => {
  vi.clearAllMocks();
  rows = [];
  setAuditSinkForTesting(async (event) => {
    rows.push(event as AuditRow);
  });
});

afterEach(() => {
  setAuditSinkForTesting(undefined);
});

// ---------------------------------------------------------------------------
// Config toggles — the incident's front door
// ---------------------------------------------------------------------------

describe("config.signup_disabled.set — the toggle that re-opens registration", () => {
  it("records the actor and BOTH the old and the new value", async () => {
    // The new value alone cannot answer "did this change anything?", which is
    // the first question asked of a toggle during an incident review.
    configServiceMock.isSignupDisabled.mockResolvedValue(true);
    configServiceMock.setSignupDisabled.mockResolvedValue(undefined);

    await expect(
      configRouter().createCaller(adminCtx).setSignupDisabled({
        disabled: false,
      }),
    ).resolves.toEqual({ success: true });
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "config.signup_disabled.set",
      outcome: "success",
      actor_type: "user",
      actor_id: "admin-1",
      actor_label: "admin@example.invalid",
      actor_ip: "203.0.113.7",
      actor_user_agent: "Mozilla/5.0",
      request_id: "req-under-test",
      target_type: "config_key",
      target_id: "DISABLE_SIGNUP",
    });
    expect(rows[0].detail).toMatchObject({
      old_value: true,
      new_value: false,
    });
  });

  it("reads the OLD value before the write, so the two are not the same read", async () => {
    const calls: string[] = [];
    configServiceMock.isSignupDisabled.mockImplementation(async () => {
      calls.push("read");
      return true;
    });
    configServiceMock.setSignupDisabled.mockImplementation(async () => {
      calls.push("write");
    });

    await configRouter().createCaller(adminCtx).setSignupDisabled({
      disabled: false,
    });

    expect(calls).toEqual(["read", "write"]);
  });

  it("emits AFTER the write — a toggle that throws leaves no row", async () => {
    configServiceMock.isSignupDisabled.mockResolvedValue(true);
    configServiceMock.setSignupDisabled.mockRejectedValue(
      new Error("config table unavailable"),
    );

    await expect(
      configRouter().createCaller(adminCtx).setSignupDisabled({
        disabled: false,
      }),
    ).rejects.toThrow();
    await flush();

    // A row claiming signup was re-opened by a call that then failed would be
    // worse than no row at all.
    expect(rows).toEqual([]);
  });

  it("still performs the toggle when the old-value read fails", async () => {
    // The toggle is the operation; the before-picture is commentary on it.
    configServiceMock.isSignupDisabled.mockRejectedValue(
      new Error("transient read failure"),
    );
    configServiceMock.setSignupDisabled.mockResolvedValue(undefined);

    await expect(
      configRouter().createCaller(adminCtx).setSignupDisabled({
        disabled: false,
      }),
    ).resolves.toEqual({ success: true });
    await flush();

    expect(configServiceMock.setSignupDisabled).toHaveBeenCalledWith(false);
    expect(rows).toHaveLength(1);
    expect(rows[0].detail).toMatchObject({
      old_value: null,
      new_value: false,
    });
  });
});

describe("the other audited config writes", () => {
  it("config.session_lifetime.set records null as a real value (unlimited)", async () => {
    configServiceMock.getSessionLifetime.mockResolvedValue(86400000);
    configServiceMock.setSessionLifetime.mockResolvedValue(undefined);

    await configRouter().createCaller(adminCtx).setSessionLifetime({
      lifetime: null,
    });
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "config.session_lifetime.set",
      target_id: "SESSION_LIFETIME",
      actor_id: "admin-1",
    });
    expect(rows[0].detail).toMatchObject({
      old_value: 86400000,
      new_value: null,
    });
  });

  it("config.set — the generic escape hatch is audited too", async () => {
    // `setConfig` accepts the full ConfigKey enum, so it can reach
    // DISABLE_SIGNUP without going through the named setter. Leaving it
    // unaudited would give the front door a second, unlogged handle.
    configServiceMock.getConfig.mockResolvedValue("true");
    configServiceMock.setConfig.mockResolvedValue(undefined);

    await configRouter().createCaller(adminCtx).setConfig({
      key: "DISABLE_SIGNUP",
      value: "false",
    });
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "config.set",
      target_type: "config_key",
      target_id: "DISABLE_SIGNUP",
      actor_id: "admin-1",
    });
    expect(rows[0].detail).toMatchObject({
      old_value: "true",
      new_value: "false",
    });
  });

  it("deliberately writes NOTHING for the MCP tuning setters", async () => {
    // Documented decision, not an oversight — see config.impl.ts. These
    // change upstream retry behaviour, not who may reach this gateway, and
    // they are the ones an operator touches routinely while debugging.
    configServiceMock.setMcpTimeout.mockResolvedValue(undefined);

    await configRouter().createCaller(adminCtx).setMcpTimeout({
      timeout: 60000,
    });
    await flush();

    expect(rows).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Admin CRUD — an admin create
// ---------------------------------------------------------------------------

describe("apikey.create — an admin mints a credential", () => {
  it("records the key's identity and scope, never the key itself", async () => {
    endpointsRepositoryMock.findByUuid.mockResolvedValue({
      uuid: ENDPOINT_UUID,
    });
    apiKeysRepositoryMock.create.mockResolvedValue({
      uuid: API_KEY_UUID,
      name: "grafana-probe",
      key: RAW_API_KEY,
      user_id: "admin-1",
      created_at: new Date("2026-08-14T00:00:00.000Z"),
    });

    const result = await apiKeysRouter().createCaller(adminCtx).create({
      name: "grafana-probe",
      endpoint_uuid: ENDPOINT_UUID,
    });
    await flush();

    // The response DOES carry the secret — exactly once, by design. The audit
    // row must not, because `audit_log` is append-only and cannot be pruned.
    expect(result.key).toBe(RAW_API_KEY);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "apikey.create",
      outcome: "success",
      actor_type: "user",
      actor_id: "admin-1",
      actor_label: "admin@example.invalid",
      target_type: "api_key",
      target_id: API_KEY_UUID,
      request_id: "req-under-test",
    });
    expect(rows[0].detail).toMatchObject({
      name: "grafana-probe",
      endpoint_uuid: ENDPOINT_UUID,
      all_endpoints: false,
    });
    expect(serialized()).not.toContain(RAW_API_KEY);
  });

  it("writes NOTHING when the mint is refused before any write", async () => {
    // A member cannot mint a scoped key (FORBIDDEN before the repository is
    // reached). The RBAC denial is Lane A's `rbac.denied` row's job; this one
    // must not also claim a key was created.
    await expect(
      apiKeysRouter()
        .createCaller({
          user: { id: "member-1", role: "member", email: "m@example.invalid" },
          session: { id: "s-member" },
          audit: AUDIT,
        })
        .create({ name: "sneaky", endpoint_uuid: ENDPOINT_UUID }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    await flush();

    expect(apiKeysRepositoryMock.create).not.toHaveBeenCalled();
    expect(rows).toEqual([]);
  });

  it("apikey.revoke is its own verb when a key is deactivated", async () => {
    apiKeysRepositoryMock.updateAsAdmin.mockResolvedValue({
      uuid: API_KEY_UUID,
      name: "grafana-probe",
      key: RAW_API_KEY,
      created_at: new Date("2026-08-14T00:00:00.000Z"),
      is_active: false,
    });

    await apiKeysRouter().createCaller(adminCtx).update({
      uuid: API_KEY_UUID,
      is_active: false,
    });
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "apikey.revoke",
      target_id: API_KEY_UUID,
      actor_id: "admin-1",
    });
    expect(serialized()).not.toContain(RAW_API_KEY);
  });
});

// ---------------------------------------------------------------------------
// users.disabled — the incident-response primitive
// ---------------------------------------------------------------------------

describe("user.disabled.set / user.enabled.set", () => {
  it("records the admin who locked the account and the account locked", async () => {
    usersRepositoryMock.setDisabled.mockResolvedValue({ disabled: true });

    await expect(
      usersRouter().createCaller(adminCtx).setDisabled({
        user_id: "attacker-1",
        disabled: true,
      }),
    ).resolves.toMatchObject({ success: true });
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "user.disabled.set",
      outcome: "success",
      actor_type: "user",
      actor_id: "admin-1",
      actor_label: "admin@example.invalid",
      target_type: "user",
      target_id: "attacker-1",
      actor_ip: "203.0.113.7",
      request_id: "req-under-test",
    });
  });

  it("uses a distinct verb for re-enabling — reversing containment is its own event", async () => {
    usersRepositoryMock.setDisabled.mockResolvedValue({ disabled: false });

    await usersRouter().createCaller(adminCtx).setDisabled({
      user_id: "attacker-1",
      disabled: false,
    });
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "user.enabled.set",
      target_id: "attacker-1",
    });
  });

  it("writes NOTHING when the target user does not exist", async () => {
    // The impl reports the miss instead of a cheerful success; the audit row
    // must not claim an account was locked when none was.
    usersRepositoryMock.setDisabled.mockResolvedValue(undefined);

    await expect(
      usersRouter().createCaller(adminCtx).setDisabled({
        user_id: "ghost",
        disabled: true,
      }),
    ).resolves.toMatchObject({ success: false, message: "User not found" });
    await flush();

    expect(rows).toEqual([]);
  });
});

describe("user.access.revoked / user.delete — the incident-response actions", () => {
  // These are the two operations an administrator performs WHILE containing an
  // incident: severing an attacker's live access, and destroying the account.
  // They tear their targets down with raw drizzle, so no better-auth hook sees
  // them — without an emitter here the table would record deleting one API key
  // but not wiping an entire identity.
  //
  // The values they touch ARE the credential set: session rows, OAuth access
  // and refresh tokens, authorization codes, API keys, M365 delegations. None
  // of it may reach `audit_log`, which is append-only with no prune path — a
  // token copied in here would outlive the revocation meant to kill it. So the
  // detail is counts plus one clamped email, and these tests assert that by
  // searching the whole serialized row for every secret the fixtures carry.
  const TARGET_ID = "44444444-4444-4444-8444-444444444444";
  const TARGET_EMAIL = "attacker@example.invalid";
  const LEAKED_SESSION_TOKEN = "session-token-must-not-be-logged";
  const LEAKED_OAUTH_TOKEN = "oauth-access-token-must-not-be-logged";
  const LEAKED_API_KEY = "sk_mt_revoked_key_must_not_be_logged";

  const REVOKED = {
    sessions_deleted: 3,
    oauth_tokens_deleted: 2,
    authorization_codes_deleted: 1,
    api_keys_deactivated: 4,
    m365_tokens_revoked: 1,
  };

  const IMPACT = {
    own_namespaces: 2,
    own_endpoints: 3,
    own_mcp_servers: 1,
    own_api_keys: 4,
    other_users_endpoints: 5,
    other_users_api_keys: 6,
    sessions: 3,
    oauth_tokens: 2,
    m365_tokens: 1,
  };

  const assertNoCredential = () => {
    for (const secret of [
      LEAKED_SESSION_TOKEN,
      LEAKED_OAUTH_TOKEN,
      LEAKED_API_KEY,
    ]) {
      expect(serialized()).not.toContain(secret);
    }
  };

  beforeEach(() => {
    usersRepositoryMock.findById.mockResolvedValue({
      id: TARGET_ID,
      email: TARGET_EMAIL,
      // Deliberately present on the row the impls read, so a future refactor
      // that spreads the whole record into `detail` fails these tests rather
      // than shipping.
      session_token: LEAKED_SESSION_TOKEN,
      oauth_token: LEAKED_OAUTH_TOKEN,
      api_key: LEAKED_API_KEY,
    });
  });

  it("revokeAccess records counts of what was cut, never the credentials", async () => {
    usersRepositoryMock.revokeAccess.mockResolvedValue(REVOKED);

    await expect(
      usersRouter().createCaller(adminCtx).revokeAccess({
        user_id: TARGET_ID,
      }),
    ).resolves.toMatchObject({ success: true });
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "user.access.revoked",
      outcome: "success",
      actor_type: "user",
      actor_id: "admin-1",
      actor_label: "admin@example.invalid",
      actor_ip: "203.0.113.7",
      request_id: "req-under-test",
      target_type: "user",
      target_id: TARGET_ID,
    });
    expect(rows[0].detail).toEqual({
      target_email: TARGET_EMAIL,
      sessions_revoked: 3,
      oauth_tokens_revoked: 2,
      auth_codes_revoked: 1,
      api_keys_revoked: 4,
      m365_tokens_revoked: 1,
    });
    assertNoCredential();
  });

  it("revokeAccess writes NOTHING when the target does not exist", async () => {
    usersRepositoryMock.findById.mockResolvedValue(undefined);

    await expect(
      usersRouter().createCaller(adminCtx).revokeAccess({ user_id: "ghost" }),
    ).resolves.toMatchObject({ success: false, message: "User not found" });
    await flush();

    expect(usersRepositoryMock.revokeAccess).not.toHaveBeenCalled();
    expect(rows).toEqual([]);
  });

  it("revokeAccess emits AFTER the teardown — a failed transaction leaves no row", async () => {
    // The repository runs its statements in ONE transaction, so a throw means
    // nothing was cut. A row claiming an attacker was severed when they were
    // not is the worst thing this table could say.
    usersRepositoryMock.revokeAccess.mockRejectedValue(
      new Error("transaction rolled back"),
    );

    await expect(
      usersRouter().createCaller(adminCtx).revokeAccess({
        user_id: TARGET_ID,
      }),
    ).rejects.toMatchObject({ code: "INTERNAL_SERVER_ERROR" });
    await flush();

    expect(rows).toEqual([]);
  });

  it("delete records the cascade counts and the only surviving email", async () => {
    usersRepositoryMock.previewDeleteImpact.mockResolvedValue(IMPACT);
    usersRepositoryMock.deleteById.mockResolvedValue(true);

    await expect(
      usersRouter().createCaller(adminCtx).delete({ user_id: TARGET_ID }),
    ).resolves.toMatchObject({ success: true });
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "user.delete",
      outcome: "success",
      actor_id: "admin-1",
      target_type: "user",
      target_id: TARGET_ID,
    });
    expect(rows[0].detail).toEqual({
      // Every FK into `users` is ON DELETE CASCADE, so this row is the only
      // place the id is still tied to a human after the statement runs.
      target_email: TARGET_EMAIL,
      own_namespaces: 2,
      own_endpoints: 3,
      own_mcp_servers: 1,
      own_api_keys: 4,
      // The cross-user reach is what an incident review asks about first.
      other_users_endpoints: 5,
      other_users_api_keys: 6,
      sessions: 3,
      oauth_tokens: 2,
      m365_tokens: 1,
    });
    assertNoCredential();
  });

  it("delete writes NOTHING when the row was already gone", async () => {
    usersRepositoryMock.previewDeleteImpact.mockResolvedValue(IMPACT);
    usersRepositoryMock.deleteById.mockResolvedValue(false);

    await expect(
      usersRouter().createCaller(adminCtx).delete({ user_id: TARGET_ID }),
    ).resolves.toMatchObject({ success: false, message: "User not found" });
    await flush();

    expect(rows).toEqual([]);
  });

  it("clamps an over-long target email on both actions", async () => {
    const monstrous = `${"a".repeat(100_000)}@example.invalid`;
    usersRepositoryMock.findById.mockResolvedValue({
      id: TARGET_ID,
      email: monstrous,
    });
    usersRepositoryMock.revokeAccess.mockResolvedValue(REVOKED);
    usersRepositoryMock.previewDeleteImpact.mockResolvedValue(IMPACT);
    usersRepositoryMock.deleteById.mockResolvedValue(true);

    await usersRouter().createCaller(adminCtx).revokeAccess({
      user_id: TARGET_ID,
    });
    await usersRouter().createCaller(adminCtx).delete({ user_id: TARGET_ID });
    await flush();

    expect(rows).toHaveLength(2);
    for (const row of rows) {
      // RFC 5321's maximum address length — the row COUNT is bounded by the
      // admin gate, the row SIZE has to be bounded here.
      expect(
        (row.detail as { target_email: string }).target_email,
      ).toHaveLength(320);
    }
  });

  it("a THROWING sink still lets a revoke and a delete succeed", async () => {
    setAuditSinkForTesting(() => {
      throw new Error("audit table is on fire");
    });
    usersRepositoryMock.revokeAccess.mockResolvedValue(REVOKED);
    usersRepositoryMock.previewDeleteImpact.mockResolvedValue(IMPACT);
    usersRepositoryMock.deleteById.mockResolvedValue(true);

    await expect(
      usersRouter().createCaller(adminCtx).revokeAccess({
        user_id: TARGET_ID,
      }),
    ).resolves.toMatchObject({ success: true });
    await expect(
      usersRouter().createCaller(adminCtx).delete({ user_id: TARGET_ID }),
    ).resolves.toMatchObject({ success: true });
    expect(usersRepositoryMock.revokeAccess).toHaveBeenCalledTimes(1);
    expect(usersRepositoryMock.deleteById).toHaveBeenCalledTimes(1);
  });

  it("a REJECTING sink still lets a delete succeed", async () => {
    // An unhandled rejection is process death under node's default
    // --unhandled-rejections=throw: the whole gateway, not one request.
    setAuditSinkForTesting(async () => {
      throw new Error("connection pool exhausted");
    });
    usersRepositoryMock.previewDeleteImpact.mockResolvedValue(IMPACT);
    usersRepositoryMock.deleteById.mockResolvedValue(true);

    await expect(
      usersRouter().createCaller(adminCtx).delete({ user_id: TARGET_ID }),
    ).resolves.toMatchObject({ success: true });
    await flush();
  });
});

// ---------------------------------------------------------------------------
// mcp-servers — the rows that sit closest to real vendor credentials
// ---------------------------------------------------------------------------

describe("mcpserver.create / .update — vendor credentials must never land", () => {
  // An MCP server row is where this gateway keeps the credentials it uses to
  // reach a third party: `bearerToken`, `env`, and `headers` (where an API key
  // lives for an HTTP backend). `audit_log` is append-only with no prune path,
  // so one of these in a `detail` blob is permanent. The claim is made in a
  // comment in the impl; this is the assertion behind it.
  const VENDOR_BEARER = "vendor-bearer-do-not-log";
  const VENDOR_ENV_SECRET = "vendor-env-api-key-do-not-log";
  const VENDOR_HEADER_SECRET = "vendor-header-secret-do-not-log";

  const serverRow = {
    uuid: "33333333-3333-4333-8333-333333333333",
    name: "vendor-backend",
    description: null,
    type: "STREAMABLE_HTTP",
    command: null,
    args: [],
    env: { VENDOR_API_KEY: VENDOR_ENV_SECRET },
    url: "https://vendor.example.invalid/mcp",
    bearerToken: VENDOR_BEARER,
    headers: { "X-Api-Key": VENDOR_HEADER_SECRET },
    error_status: null,
    created_at: new Date("2026-08-14T00:00:00.000Z"),
    user_id: "admin-1",
  };

  const assertNoVendorSecret = () => {
    for (const secret of [
      VENDOR_BEARER,
      VENDOR_ENV_SECRET,
      VENDOR_HEADER_SECRET,
    ]) {
      expect(serialized()).not.toContain(secret);
    }
  };

  it("create records identity and transport only", async () => {
    mcpServersRepositoryMock.create.mockResolvedValue(serverRow);

    await mcpServersImplementations.create(
      {
        name: serverRow.name,
        type: "STREAMABLE_HTTP",
        url: serverRow.url,
        bearerToken: VENDOR_BEARER,
        env: serverRow.env,
        headers: serverRow.headers,
      } as never,
      "admin-1",
      {
        actor_id: "admin-1",
        actor_label: "admin@example.invalid",
        ...AUDIT,
      },
    );
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "mcpserver.create",
      outcome: "success",
      actor_id: "admin-1",
      target_type: "mcp_server",
      target_id: serverRow.uuid,
    });
    expect(rows[0].detail).toMatchObject({
      name: "vendor-backend",
      type: "STREAMABLE_HTTP",
    });
    assertNoVendorSecret();
  });

  it("update — the call that ROTATES a vendor token — records neither", async () => {
    mcpServersRepositoryMock.findByUuid.mockResolvedValue(serverRow);
    mcpServersRepositoryMock.update.mockResolvedValue(serverRow);
    namespaceMappingsRepositoryMock.findNamespacesByServerUuid.mockResolvedValue(
      [],
    );

    await mcpServersImplementations.update(
      {
        uuid: serverRow.uuid,
        name: serverRow.name,
        type: "STREAMABLE_HTTP",
        url: serverRow.url,
        bearerToken: "rotated-vendor-bearer-do-not-log",
        env: serverRow.env,
        headers: serverRow.headers,
      } as never,
      "admin-1",
      {
        actor_id: "admin-1",
        actor_label: "admin@example.invalid",
        ...AUDIT,
      },
    );
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "mcpserver.update",
      target_id: serverRow.uuid,
      actor_id: "admin-1",
    });
    assertNoVendorSecret();
    expect(serialized()).not.toContain("rotated-vendor-bearer-do-not-log");
  });

  it("bulk_import writes NOTHING when every entry was rejected", async () => {
    // Guarded on the write having happened, like every other emit here: an
    // invalid server name never reaches `bulkCreate`, so a row would claim an
    // import that did not occur.
    await mcpServersImplementations.bulkImport(
      { mcpServers: { "bad name with spaces": { type: "STDIO" } } } as never,
      "admin-1",
      {
        actor_id: "admin-1",
        actor_label: "admin@example.invalid",
        ...AUDIT,
      },
    );
    await flush();

    expect(mcpServersRepositoryMock.bulkCreate).not.toHaveBeenCalled();
    expect(rows).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// The safety property, at the mutation layer
// ---------------------------------------------------------------------------

describe("a broken audit sink cannot break an admin mutation", () => {
  it("a THROWING sink still lets a config toggle succeed", async () => {
    setAuditSinkForTesting(() => {
      throw new Error("audit table is on fire");
    });
    configServiceMock.isSignupDisabled.mockResolvedValue(true);
    configServiceMock.setSignupDisabled.mockResolvedValue(undefined);

    await expect(
      configRouter().createCaller(adminCtx).setSignupDisabled({
        disabled: false,
      }),
    ).resolves.toEqual({ success: true });
    expect(configServiceMock.setSignupDisabled).toHaveBeenCalledWith(false);
  });

  it("a REJECTING sink still lets a disable succeed", async () => {
    // An unhandled rejection is process death under node's default
    // --unhandled-rejections=throw: the whole gateway, not one request.
    setAuditSinkForTesting(async () => {
      throw new Error("connection pool exhausted");
    });
    usersRepositoryMock.setDisabled.mockResolvedValue({ disabled: true });

    await expect(
      usersRouter().createCaller(adminCtx).setDisabled({
        user_id: "attacker-1",
        disabled: true,
      }),
    ).resolves.toMatchObject({ success: true });
    await flush();
  });

  it("labels an actor-less call `system`, not a phantom administrator", async () => {
    // `lib/metamcp/metamcp-proxy.ts` calls `toolsImplementations.sync`
    // directly during a proxied MCP tools/list — no session, no request, no
    // actor bundle. That row must not read as an admin action. An actor
    // bundle that EXISTS but holds nulls is a different case and stays
    // `user`: a request really was made, by someone we could not name.
    toolsRepositoryMock.syncTools.mockResolvedValue({
      upserted: [{ uuid: "t-1" }],
      deleted: [],
    });

    await toolsImplementations.sync({
      // A uuid this test file has not synced before, so the in-memory
      // tools-sync cache reports "changed" and the write branch runs.
      mcpServerUuid: "server-actorless",
      tools: [{ name: "do_thing", inputSchema: { type: "object" } }],
    } as never);
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "tools.sync",
      actor_type: "system",
      actor_id: null,
      target_id: "server-actorless",
    });
  });

  it("a hostile ctx.user does not turn a successful mutation into a 500", async () => {
    // `auditActor()` runs as an ARGUMENT to the impl call, i.e. before the
    // mutation. A throwing property read there would abort the write itself —
    // the audit path deciding whether an admin's toggle takes effect.
    const hostileCtx = {
      user: new Proxy(
        { id: "admin-1", role: "admin" },
        {
          get(target, prop) {
            if (prop === "email") throw new Error("hostile getter");
            return target[prop as keyof typeof target];
          },
        },
      ),
      session: { id: "s-admin" },
      audit: AUDIT,
    };
    configServiceMock.isSignupDisabled.mockResolvedValue(true);
    configServiceMock.setSignupDisabled.mockResolvedValue(undefined);

    await expect(
      configRouter().createCaller(hostileCtx).setSignupDisabled({
        disabled: false,
      }),
    ).resolves.toEqual({ success: true });
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "config.signup_disabled.set",
      actor_id: null,
      actor_label: null,
    });
  });
});
