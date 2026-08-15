/**
 * Module-mocked WIRING tests for the bootstrap entrypoint
 * (`initializeEnvironmentConfiguration`). The pure restore planner is
 * covered by `bootstrap.preserve.test.ts`; both PR #84 review-round
 * blockers, however, lived in the WIRING — where the preserved-key restore
 * is called from, relative to `bootstrapEndpoints` — which the planner
 * tests cannot see. These tests drive the REAL entrypoint against a
 * chain-stub `db` (same convention as `api-keys.repo.member-scope.test.ts`;
 * no live postgres in this fork's harness) and assert on the ORDER of the
 * statements it issues:
 *
 *  - the api-key restore insert is issued AFTER the endpoints insert (a
 *    restore before endpoint recreation is the FK-violation bug round 2
 *    caught), and it carries the endpoint's FRESH uuid re-resolved by name;
 *  - `ensureUser` itself issues NO api_keys insert — the deferred-restore
 *    contract means the ONLY api_keys insert in a restore run is the
 *    deferred one;
 *  - the registration controls resolve FAIL-CLOSED from an unset environment
 *    and leave an audit row when, and only when, a boot actually moves one of
 *    them. Both live in the entrypoint, so neither is reachable from a unit
 *    test of the parser;
 *  - the registration lock is written AFTER the configured users are created,
 *    which is what stops the fail-closed default from locking bootstrap out
 *    of its own onboarding path (`ensureUser` signs users up through the very
 *    route DISABLE_SIGNUP closes). Only the entrypoint's statement ORDER can
 *    show this.
 *
 * Env-driven config: each test writes the BOOTSTRAP_* vars it needs and the
 * suite restores the original environment afterwards.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// auth.ts throws without BETTER_AUTH_SECRET and connects to postgres.
//
// `authCallLog` records the length of `statementLog` at each sign-up call.
// That is the handle the create-before-lock ordering assertion needs: the
// real signup route refuses once DISABLE_SIGNUP is stored, so "which came
// first, the sign-up or the config write" is the whole safety property, and
// nothing in the statement log alone can answer it (`ensureUser` creates
// users through `auth.handler`, not through a logged insert).
const { authHandlerMock, authCallLog } = vi.hoisted(() => ({
  authHandlerMock: vi.fn(),
  authCallLog: [] as { statementsAtCall: number }[],
}));
vi.mock("../auth", () => ({ auth: { handler: authHandlerMock } }));

/**
 * Chain-stub db. Every `insert(table)` is recorded (with its values) into
 * `statementLog` in issue order — the assertion surface. Reads are routed
 * by TABLE IDENTITY (the real schema module is imported below; it is pure
 * drizzle-orm table definitions, no connection).
 */
type LoggedStatement = {
  op: "insert" | "delete";
  table: unknown;
  values?: Record<string, unknown>;
};
const { dbMock, statementLog, readFixtures } = vi.hoisted(() => {
  const statementLog: LoggedStatement[] = [];
  const readFixtures = {
    /** rows returned by select().from(apiKeysTable).leftJoin()….where() — the preserve capture */
    preservedKeyRows: [] as Record<string, unknown>[],
    /** rows returned by select().from(endpointsTable) — the restore's re-resolution load */
    endpointRows: [] as Record<string, unknown>[],
    /** rows returned by select().from(usersTable) — the restore's acts-as email → id load */
    userRows: [] as Record<string, unknown>[],
    /** FIFO responses for db.query.usersTable.findFirst */
    usersFindFirstQueue: [] as (Record<string, unknown> | undefined)[],
    /** FIFO responses for db.query.apiKeysTable.findFirst */
    apiKeysFindFirstQueue: [] as (Record<string, unknown> | undefined)[],
    /**
     * FIFO responses for db.query.configTable.findFirst — the PRE-existing
     * config rows the registration-control audit compares against. Order is
     * the entrypoint's read order: DISABLE_SIGNUP, then DISABLE_SSO_SIGNUP.
     * An exhausted queue yields `undefined` (the row does not exist), which
     * is the fresh-database case. An `Error` in the queue is a FAILED read
     * rather than a row — the only handle a test has on the catch inside
     * `readRegistrationFlag`.
     */
    configFindFirstQueue: [] as (Record<string, unknown> | Error | undefined)[],
    /** Response `auth.handler` resolves with (the Better Auth sign-up POST). */
    authHandlerResponse: {
      ok: true,
      text: async () => "",
    } as { ok: boolean; status?: number; text: () => Promise<string> },
  };

  // Import the real tables lazily inside the factory-safe closure — the
  // mock factory itself must not touch them, only the runtime calls do.
  const tableIs = (table: unknown, name: string) =>
    // drizzle stores the SQL name under a symbol; compare via the table's
    // own Symbol.for key to avoid importing drizzle internals here.
    (table as { [key: symbol]: unknown })?.[Symbol.for("drizzle:Name")] ===
    name;

  const insertChain = (table: unknown) => ({
    values: (values: Record<string, unknown>) => {
      statementLog.push({ op: "insert", table, values });
      const settled = Promise.resolve(undefined);
      return {
        then: settled.then.bind(settled),
        catch: settled.catch.bind(settled),
        onConflictDoUpdate: () => Promise.resolve(undefined),
        returning: () =>
          Promise.resolve(
            tableIs(table, "namespaces") ? [{ uuid: "ns-uuid-1" }] : [{}],
          ),
      };
    },
  });

  const dbMock = {
    insert: vi.fn(insertChain),
    update: vi.fn(() => ({
      set: () => ({ where: () => Promise.resolve(undefined) }),
    })),
    delete: vi.fn((table: unknown) => ({
      where: () => {
        statementLog.push({ op: "delete", table });
        return Promise.resolve(undefined);
      },
    })),
    select: vi.fn(() => ({
      from: (table: unknown) => {
        const bareRows = tableIs(table, "endpoints")
          ? readFixtures.endpointRows
          : tableIs(table, "users")
            ? readFixtures.userRows
            : [];
        // Self-referencing so a query may chain any number of leftJoins
        // (the preserve capture now joins endpoints AND the aliased
        // acts-as users) before its terminal where().
        const joined: {
          leftJoin: () => unknown;
          where: () => Promise<unknown[]>;
        } = {
          leftJoin: () => joined,
          where: () =>
            Promise.resolve(
              tableIs(table, "api_keys") ? readFixtures.preservedKeyRows : [],
            ),
        };
        const fromResult = Promise.resolve(bareRows) as Promise<unknown> & {
          leftJoin: () => typeof joined;
          where: () => Promise<unknown[]>;
        };
        fromResult.leftJoin = () => joined;
        fromResult.where = () => Promise.resolve(bareRows);
        return fromResult;
      },
    })),
    query: {
      usersTable: {
        findFirst: vi.fn(() =>
          Promise.resolve(readFixtures.usersFindFirstQueue.shift()),
        ),
      },
      apiKeysTable: {
        findFirst: vi.fn(() =>
          Promise.resolve(readFixtures.apiKeysFindFirstQueue.shift()),
        ),
      },
      namespacesTable: { findFirst: vi.fn(() => Promise.resolve(undefined)) },
      endpointsTable: { findFirst: vi.fn(() => Promise.resolve(undefined)) },
      configTable: {
        findFirst: vi.fn(() => {
          const next = readFixtures.configFindFirstQueue.shift();
          return next instanceof Error
            ? Promise.reject(next)
            : Promise.resolve(next);
        }),
      },
    },
  };

  return { dbMock, statementLog, readFixtures };
});
vi.mock("../db", () => ({ db: dbMock }));

/**
 * One recorded `emitAdminEvent` call. `statementsAtEmit` is the length of
 * `statementLog` at emit time — the handle the ordering assertion uses to
 * prove the row was emitted AFTER its config write, not before it.
 */
type EmittedAdminEvent = {
  actor: unknown;
  event: Record<string, unknown>;
  statementsAtEmit: number;
};
const { emitAdminEventMock, emitLog } = vi.hoisted(() => ({
  emitAdminEventMock: vi.fn(),
  emitLog: [] as EmittedAdminEvent[],
}));
vi.mock("./audit/admin-event", () => ({ emitAdminEvent: emitAdminEventMock }));

import {
  apiKeysTable,
  configTable,
  endpointsTable,
  namespacesTable,
} from "../db/schema";
import { initializeEnvironmentConfiguration } from "./bootstrap.service";

const BOOTSTRAP_ENV_KEYS = [
  "BOOTSTRAP_USER_EMAIL",
  "BOOTSTRAP_USER_PASSWORD",
  "BOOTSTRAP_USER_NAME",
  "BOOTSTRAP_USERS",
  "BOOTSTRAP_RECREATE_USER",
  "BOOTSTRAP_PRESERVE_API_KEYS",
  "BOOTSTRAP_WARN_PASSWORD_CHANGE",
  "BOOTSTRAP_ONLY_FIRST_RUN",
  "BOOTSTRAP_DELETE_OTHER_USERS",
  "BOOTSTRAP_DISABLE_REGISTRATION_UI",
  "BOOTSTRAP_DISABLE_REGISTRATION_SSO",
  "BOOTSTRAP_API_KEYS",
  "BOOTSTRAP_NAMESPACES",
  "BOOTSTRAP_ENDPOINTS",
  "BOOTSTRAP_DEBUG",
] as const;
const savedEnv: Record<string, string | undefined> = {};

beforeEach(() => {
  vi.clearAllMocks();
  statementLog.length = 0;
  emitLog.length = 0;
  authCallLog.length = 0;
  // Re-applied per test rather than baked into the hoisted `vi.fn()`: the
  // suite's `restoreAllMocks` teardown drops implementations, and the recorder
  // needs `statementLog`, which only exists once the hoisted block has run.
  emitAdminEventMock.mockImplementation(
    (actor: unknown, event: Record<string, unknown>) => {
      emitLog.push({ actor, event, statementsAtEmit: statementLog.length });
    },
  );
  // Same reason, plus one more: the response has to come from a fixture the
  // tests mutate rather than from `mockResolvedValue`, because a resolved
  // value would replace this recorder.
  authHandlerMock.mockImplementation(async () => {
    authCallLog.push({ statementsAtCall: statementLog.length });
    return readFixtures.authHandlerResponse;
  });
  readFixtures.authHandlerResponse = { ok: true, text: async () => "" };
  readFixtures.preservedKeyRows = [];
  readFixtures.endpointRows = [];
  readFixtures.userRows = [];
  readFixtures.usersFindFirstQueue = [];
  readFixtures.apiKeysFindFirstQueue = [];
  readFixtures.configFindFirstQueue = [];
  for (const key of BOOTSTRAP_ENV_KEYS) {
    savedEnv[key] = process.env[key];
    delete process.env[key];
  }
  // Bootstrap logs loudly by design — keep test output quiet and the
  // console spies available for log-content assertions.
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  for (const key of BOOTSTRAP_ENV_KEYS) {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  }
  vi.restoreAllMocks();
});

/** Standard recreate scenario: one user, one namespace, one endpoint. */
function arrangeRecreateScenario(options?: { apiKeysEnv?: string }) {
  process.env.BOOTSTRAP_USER_EMAIL = "admin@example.com";
  process.env.BOOTSTRAP_USER_PASSWORD = "hunter2hunter2";
  process.env.BOOTSTRAP_RECREATE_USER = "true";
  process.env.BOOTSTRAP_NAMESPACES = JSON.stringify([
    { name: "ns-a", is_public: true },
  ]);
  process.env.BOOTSTRAP_ENDPOINTS = JSON.stringify([
    { name: "ep-a", namespace: "ns-a", is_public: true },
  ]);
  if (options?.apiKeysEnv !== undefined) {
    process.env.BOOTSTRAP_API_KEYS = options.apiKeysEnv;
  }

  // ensureUser: existing-user check, then the post-sign-up re-read.
  readFixtures.usersFindFirstQueue = [
    { id: "old-user-id", email: "admin@example.com" },
    { id: "new-user-id", email: "admin@example.com" },
  ];
  // The preserve capture: one key OWNED by the doomed user, scoped (by
  // name) to the endpoint that the recreate cascade will destroy and
  // bootstrapEndpoints will recreate. Unbound (acts_as NULL) by default —
  // the identity-binding scenarios override this fixture.
  readFixtures.preservedKeyRows = [
    {
      name: "consumer-scoped",
      key: "sk_mt_preserved_secret",
      is_active: true,
      user_id: "old-user-id",
      endpoint_uuid: "stale-ep-uuid",
      endpoint_name: "ep-a",
      acts_as_user_id: null,
      acts_as_email: null,
    },
  ];
  // The restore pass's endpoint load — post-bootstrapEndpoints state with a
  // FRESH uuid for the recreated endpoint.
  readFixtures.endpointRows = [{ uuid: "fresh-ep-uuid", name: "ep-a" }];
  // The restore pass's users load (only issued when a preserved key carries
  // an identity binding) — post-recreate state with the FRESH user id.
  readFixtures.userRows = [{ id: "new-user-id", email: "admin@example.com" }];

  readFixtures.authHandlerResponse = { ok: true, text: async () => "" };
}

describe("bootstrap wiring — deferred api-key restore ordering (PR #84 residual)", () => {
  it("issues the api-key restore insert AFTER the endpoints insert, with the name-re-resolved fresh uuid; ensureUser issues none", async () => {
    arrangeRecreateScenario();

    await initializeEnvironmentConfiguration();

    const apiKeyInserts = statementLog.filter(
      (s) => s.op === "insert" && s.table === apiKeysTable,
    );
    const endpointInserts = statementLog.filter(
      (s) => s.op === "insert" && s.table === endpointsTable,
    );
    const namespaceInserts = statementLog.filter(
      (s) => s.op === "insert" && s.table === namespacesTable,
    );
    expect(endpointInserts).toHaveLength(1);
    expect(namespaceInserts).toHaveLength(1);

    // EXACTLY one api_keys insert in the whole run — the deferred restore.
    // BOOTSTRAP_API_KEYS is empty here, so any other insert could only have
    // come from ensureUser restoring inline again (the round-2 bug shape).
    expect(apiKeyInserts).toHaveLength(1);

    // ... and it is issued AFTER the endpoints insert (deferred until the
    // recreated endpoint exists, so the scope FK can hold).
    expect(statementLog.indexOf(apiKeyInserts[0])).toBeGreaterThan(
      statementLog.indexOf(endpointInserts[0]),
    );

    // The wiring hands the planner the POST-bootstrapEndpoints endpoint map:
    // the restored key carries the fresh uuid re-resolved by NAME — never
    // the stale preserved uuid.
    expect(apiKeyInserts[0].values).toMatchObject({
      name: "consumer-scoped",
      key: "sk_mt_preserved_secret",
      user_id: "new-user-id",
      endpoint_uuid: "fresh-ep-uuid",
    });

    // The recreate leg did run (its api_keys DELETE is in the log) — this
    // scenario genuinely exercised the destructive path, not a no-op walk.
    expect(
      statementLog.some((s) => s.op === "delete" && s.table === apiKeysTable),
    ).toBe(true);
  });
});

describe("bootstrapApiKeys log truth — pending restore for the same (user_id, name)", () => {
  it("amends the 'Created ... API key' line instead of presenting the doomed fresh value as live", async () => {
    // The config declares a key with the SAME name as the preserved key
    // ("consumer-scoped", owned by the recreated user): bootstrapApiKeys mints
    // it fresh, then the deferred restore's onConflictDoUpdate overwrites
    // it. The minted value never survives startup, so the log must not
    // present its mask as the live credential.
    arrangeRecreateScenario({
      apiKeysEnv: JSON.stringify([
        { name: "consumer-scoped", user_email: "admin@example.com" },
      ]),
    });
    // bootstrapApiKeys' existence probe: the key is gone (the recreate
    // deleted it), so the mint path runs.
    readFixtures.apiKeysFindFirstQueue = [undefined];

    await initializeEnvironmentConfiguration();

    const logCalls = (
      console.log as unknown as ReturnType<typeof vi.fn>
    ).mock.calls.map((call) => String(call[0]));
    const createdLine = logCalls.find((line) =>
      line.includes('Created private API key "consumer-scoped"'),
    );
    expect(createdLine).toBeDefined();
    // Amended: names the pending restore, and does NOT log a masked value
    // (the mask format is `sk_mt_xxxx…xxxx`) as if it were the live key.
    expect(createdLine).toContain("preserved-key restore");
    expect(createdLine).not.toMatch(/: sk_mt_/);

    // Both writes still happened: the config mint AND the restore upsert —
    // net DB state is unchanged by the log fix.
    const apiKeyInserts = statementLog.filter(
      (s) => s.op === "insert" && s.table === apiKeysTable,
    );
    expect(apiKeyInserts).toHaveLength(2);
    // Last write wins and it is the restore (the preserved value).
    expect(apiKeyInserts[apiKeyInserts.length - 1].values).toMatchObject({
      key: "sk_mt_preserved_secret",
    });
  });

  it("a non-colliding config key keeps the normal masked-value log line", async () => {
    arrangeRecreateScenario({
      apiKeysEnv: JSON.stringify([
        { name: "unrelated-key", user_email: "admin@example.com" },
      ]),
    });
    readFixtures.apiKeysFindFirstQueue = [undefined];

    await initializeEnvironmentConfiguration();

    const logCalls = (
      console.log as unknown as ReturnType<typeof vi.fn>
    ).mock.calls.map((call) => String(call[0]));
    const createdLine = logCalls.find((line) =>
      line.includes('Created private API key "unrelated-key"'),
    );
    expect(createdLine).toBeDefined();
    expect(createdLine).toMatch(/: sk_mt_/);
    expect(createdLine).not.toContain("preserved-key restore");
  });
});

describe("ensureUser early-return credential loss — preserved keys warned loudly", () => {
  function warnLines(): string[] {
    return (console.warn as unknown as ReturnType<typeof vi.fn>).mock.calls.map(
      (call) => String(call[0]),
    );
  }

  it("warns with preserved-key count + names (never values) when Better Auth sign-up fails after the keys were deleted", async () => {
    arrangeRecreateScenario();
    readFixtures.authHandlerResponse = {
      ok: false,
      status: 500,
      text: async () => "boom",
    };

    await initializeEnvironmentConfiguration();

    const lossLine = warnLines().find((line) =>
      line.includes("CANNOT be restored"),
    );
    expect(lossLine).toBeDefined();
    expect(lossLine).toContain("1 preserved API key(s)");
    expect(lossLine).toContain("admin@example.com");
    expect(lossLine).toContain("consumer-scoped"); // names…
    expect(lossLine).not.toContain("sk_mt_preserved_secret"); // …never values

    // And the restore really never ran — no api_keys insert at all.
    expect(
      statementLog.some((s) => s.op === "insert" && s.table === apiKeysTable),
    ).toBe(false);
  });

  it("warns identically when the user is missing after an ok sign-up", async () => {
    arrangeRecreateScenario();
    // Sign-up "succeeds" but the post-sign-up re-read finds nothing.
    readFixtures.usersFindFirstQueue = [
      { id: "old-user-id", email: "admin@example.com" },
      undefined,
    ];

    await initializeEnvironmentConfiguration();

    const lossLine = warnLines().find((line) =>
      line.includes("CANNOT be restored"),
    );
    expect(lossLine).toBeDefined();
    expect(lossLine).toContain("consumer-scoped");
    expect(lossLine).not.toContain("sk_mt_preserved_secret");
  });

  it("stays silent on a healthy recreate (the restore handles the keys)", async () => {
    arrangeRecreateScenario();

    await initializeEnvironmentConfiguration();

    expect(
      warnLines().find((line) => line.includes("CANNOT be restored")),
    ).toBeUndefined();
  });
});

describe("bootstrap wiring — acts-as identity binding across the recreate (PR #85 round 2)", () => {
  function warnLines(): string[] {
    return (console.warn as unknown as ReturnType<typeof vi.fn>).mock.calls.map(
      (call) => String(call[0]),
    );
  }

  it("restores an identity-bound key RE-BOUND by email to the fresh user id (never the stale id, never unbound)", async () => {
    arrangeRecreateScenario();
    // Self-bound key (owner = acted-as user, the only mintable shape after
    // the round-2 ownership invariant): both ids are the PRE-recreate ones.
    readFixtures.preservedKeyRows = [
      {
        name: "alex-m365",
        key: "sk_mt_bound_secret",
        is_active: true,
        user_id: "old-user-id",
        endpoint_uuid: "stale-ep-uuid",
        endpoint_name: "ep-a",
        acts_as_user_id: "old-user-id",
        acts_as_email: "admin@example.com",
      },
    ];

    await initializeEnvironmentConfiguration();

    const apiKeyInserts = statementLog.filter(
      (s) => s.op === "insert" && s.table === apiKeysTable,
    );
    expect(apiKeyInserts).toHaveLength(1);
    // Both stale handles were re-resolved: endpoint by NAME, identity by
    // EMAIL — each to its post-recreate value.
    expect(apiKeyInserts[0].values).toMatchObject({
      name: "alex-m365",
      key: "sk_mt_bound_secret",
      user_id: "new-user-id",
      endpoint_uuid: "fresh-ep-uuid",
      acts_as_user_id: "new-user-id",
    });
  });

  it("SKIPS loudly (no unbound restore) when the acted-as email resolves to no current user", async () => {
    arrangeRecreateScenario();
    readFixtures.preservedKeyRows = [
      {
        name: "bound-to-departed",
        key: "sk_mt_departed_secret",
        is_active: true,
        user_id: "old-user-id",
        endpoint_uuid: "stale-ep-uuid",
        endpoint_name: "ep-a",
        acts_as_user_id: "departed-user-id",
        acts_as_email: "departed@example.com",
      },
    ];
    // Post-recreate users: the acted-as account is gone.
    readFixtures.userRows = [{ id: "new-user-id", email: "admin@example.com" }];

    await initializeEnvironmentConfiguration();

    // NOT restored at all — restoring unbound would silently degrade the
    // key (it authenticates, m365 injection fail-closes, log says restored).
    expect(
      statementLog.some((s) => s.op === "insert" && s.table === apiKeysTable),
    ).toBe(false);
    const skipLine = warnLines().find((line) =>
      line.includes('"bound-to-departed"'),
    );
    expect(skipLine).toBeDefined();
    expect(skipLine).toContain("departed@example.com");
    expect(skipLine).toContain("NOT restored");
    expect(skipLine).not.toContain("sk_mt_departed_secret"); // names, never values
  });

  it("counts a foreign-owned identity-bound key in the loud warn and never restores it", async () => {
    arrangeRecreateScenario();
    // Captured only via the acts_as edge: owned by ANOTHER user but bound
    // to the recreated user's identity (a pre-invariant legacy row). The
    // user delete CASCADES it away; it must be warned about, not silently
    // destroyed — and never restored (it violates the ownership invariant).
    readFixtures.preservedKeyRows = [
      {
        name: "consumer-scoped",
        key: "sk_mt_preserved_secret",
        is_active: true,
        user_id: "old-user-id",
        endpoint_uuid: "stale-ep-uuid",
        endpoint_name: "ep-a",
        acts_as_user_id: null,
        acts_as_email: null,
      },
      {
        name: "foreign-bound-key",
        key: "sk_mt_foreign_secret",
        is_active: true,
        user_id: "some-other-user",
        endpoint_uuid: "stale-ep-uuid",
        endpoint_name: "ep-a",
        acts_as_user_id: "old-user-id",
        acts_as_email: "admin@example.com",
      },
    ];

    await initializeEnvironmentConfiguration();

    const foreignLine = warnLines().find((line) =>
      line.includes("foreign-bound-key"),
    );
    expect(foreignLine).toBeDefined();
    expect(foreignLine).toContain("1 API key(s)");
    expect(foreignLine).toContain("NOT owned");
    expect(foreignLine).toContain("CANNOT be restored");
    expect(foreignLine).not.toContain("sk_mt_foreign_secret"); // names, never values

    // Only the owned key is restored; the foreign-bound one never is.
    const apiKeyInserts = statementLog.filter(
      (s) => s.op === "insert" && s.table === apiKeysTable,
    );
    expect(apiKeyInserts).toHaveLength(1);
    expect(apiKeyInserts[0].values).toMatchObject({ name: "consumer-scoped" });
  });
});

describe("registration controls — fail-closed defaults and audited boot-time flips", () => {
  /** Index of the `upsertConfig` write issued for one config key, or -1. */
  function configWriteIndex(key: string): number {
    return statementLog.findIndex(
      (s) =>
        s.op === "insert" && s.table === configTable && s.values?.id === key,
    );
  }

  function configWrite(key: string): Record<string, unknown> | undefined {
    const index = configWriteIndex(key);
    return index === -1 ? undefined : statementLog[index].values;
  }

  function warnLines(): string[] {
    return (console.warn as unknown as ReturnType<typeof vi.fn>).mock.calls.map(
      (call) => String(call[0]),
    );
  }

  function logLines(): string[] {
    return (console.log as unknown as ReturnType<typeof vi.fn>).mock.calls.map(
      (call) => String(call[0]),
    );
  }

  it("resolves BOTH controls to DISABLED when neither env var is set", async () => {
    // `beforeEach` deletes every BOOTSTRAP_* key, so this is the deploy that
    // never mentioned the variables at all — the case upstream leaves open.
    await initializeEnvironmentConfiguration();

    expect(configWrite("DISABLE_SIGNUP")).toMatchObject({ value: "true" });
    expect(configWrite("DISABLE_SSO_SIGNUP")).toMatchObject({ value: "true" });
  });

  it("still honours an explicit false — the default is a default, not an override", async () => {
    process.env.BOOTSTRAP_DISABLE_REGISTRATION_UI = "false";
    process.env.BOOTSTRAP_DISABLE_REGISTRATION_SSO = "false";

    await initializeEnvironmentConfiguration();

    expect(configWrite("DISABLE_SIGNUP")).toMatchObject({ value: "false" });
    expect(configWrite("DISABLE_SSO_SIGNUP")).toMatchObject({ value: "false" });
  });

  it("falls closed on an unparseable value — a typo must not reopen registration", async () => {
    process.env.BOOTSTRAP_DISABLE_REGISTRATION_UI = "flase";

    await initializeEnvironmentConfiguration();

    expect(configWrite("DISABLE_SIGNUP")).toMatchObject({ value: "true" });
  });

  it("emits one attributed row per flag that actually CHANGED, after the write", async () => {
    // Pre-existing rows say registration is OPEN; the unset env now resolves
    // to DISABLED, so both flags move. Queue order is the entrypoint's read
    // order: DISABLE_SIGNUP first, then DISABLE_SSO_SIGNUP.
    readFixtures.configFindFirstQueue = [
      { value: "false" },
      { value: "false" },
    ];

    await initializeEnvironmentConfiguration();

    expect(emitLog).toHaveLength(2);
    const [signup, ssoSignup] = emitLog;

    // No actor bundle: `admin-event.ts` stamps that `actor_type: "system"`,
    // which is the truth — no administrator is behind a container restart.
    expect(signup.actor).toBeUndefined();
    expect(signup.event).toEqual({
      action: "config.signup_disabled.set",
      target_type: "config_key",
      target_id: "DISABLE_SIGNUP",
      detail: { old_value: false, new_value: true, source: "bootstrap_env" },
    });
    expect(ssoSignup.actor).toBeUndefined();
    expect(ssoSignup.event).toEqual({
      action: "config.sso_signup_disabled.set",
      target_type: "config_key",
      target_id: "DISABLE_SSO_SIGNUP",
      detail: { old_value: false, new_value: true, source: "bootstrap_env" },
    });

    // Emitted AFTER the write it describes — a row claiming a flag moved, from
    // a boot whose write then threw, would be worse than no row at all.
    const writeIndex = configWriteIndex("DISABLE_SIGNUP");
    expect(writeIndex).toBeGreaterThanOrEqual(0);
    expect(signup.statementsAtEmit).toBeGreaterThan(writeIndex);
  });

  it("emits nothing when a restart re-asserts what is already stored", async () => {
    readFixtures.configFindFirstQueue = [{ value: "true" }, { value: "true" }];

    await initializeEnvironmentConfiguration();

    // The writes still happen — bootstrap re-asserts both flags every run ...
    expect(configWrite("DISABLE_SIGNUP")).toMatchObject({ value: "true" });
    expect(configWrite("DISABLE_SSO_SIGNUP")).toMatchObject({ value: "true" });
    // ... but they leave no rows, so the one restart that DID move a flag is
    // not buried under a row for every restart that did not.
    expect(emitAdminEventMock).not.toHaveBeenCalled();
    expect(emitLog).toHaveLength(0);
  });

  it("emits for the flag that moved and stays silent on the one that did not", async () => {
    // SSO already disabled, UI still open: exactly one flag changes.
    readFixtures.configFindFirstQueue = [{ value: "false" }, { value: "true" }];

    await initializeEnvironmentConfiguration();

    expect(emitLog.map((e) => e.event.action)).toEqual([
      "config.signup_disabled.set",
    ]);
  });

  it("creates the configured user BEFORE writing the lock, so a fresh boot still gets its admin", async () => {
    // The first boot the reordering exists for: fresh database, fail-closed
    // defaults, one configured administrator. `ensureUser` onboards through
    // Better Auth's `/api/auth/sign-up/email`, and `auth.ts`'s
    // `user.create.before` hook THROWS once DISABLE_SIGNUP is stored, so a
    // lock written first leaves this deploy with no administrator at all.
    process.env.BOOTSTRAP_USER_EMAIL = "admin@example.com";
    process.env.BOOTSTRAP_USER_PASSWORD = "hunter2hunter2";
    // ensureUser: the existing-user probe (nothing there), then the
    // post-sign-up re-read.
    readFixtures.usersFindFirstQueue = [
      undefined,
      { id: "new-user-id", email: "admin@example.com" },
    ];

    await initializeEnvironmentConfiguration();

    // The lock still lands — this is a fail-closed boot, not an exemption.
    expect(configWrite("DISABLE_SIGNUP")).toMatchObject({ value: "true" });
    expect(configWrite("DISABLE_SSO_SIGNUP")).toMatchObject({ value: "true" });

    // And the sign-up POST was issued while both locks were still absent: it
    // saw a statement log shorter than the index either write landed at.
    expect(authCallLog).toHaveLength(1);
    expect(authCallLog[0].statementsAtCall).toBeLessThanOrEqual(
      configWriteIndex("DISABLE_SIGNUP"),
    );
    expect(authCallLog[0].statementsAtCall).toBeLessThanOrEqual(
      configWriteIndex("DISABLE_SSO_SIGNUP"),
    );
  });

  it("still asserts both controls on a guarded (BOOTSTRAP_ONLY_FIRST_RUN) boot", async () => {
    process.env.BOOTSTRAP_ONLY_FIRST_RUN = "true";
    process.env.BOOTSTRAP_USER_EMAIL = "admin@example.com";
    process.env.BOOTSTRAP_USER_PASSWORD = "hunter2hunter2";
    // The completion-marker read comes first on this path, ahead of the two
    // registration reads; "true" sends the entrypoint down the early return.
    readFixtures.configFindFirstQueue = [{ value: "true" }];

    await initializeEnvironmentConfiguration();

    // Genuinely the guarded path: a user WAS configured and was not created.
    expect(authCallLog).toHaveLength(0);
    expect(logLines()).toContain(
      "✅ Environment-based configuration initialized (guarded)",
    );

    // The controls are "applied every run" controls, and a guarded boot is
    // still a run: skipping them would leave registration wherever the last
    // unguarded boot (or an administrator) left it.
    expect(configWrite("DISABLE_SIGNUP")).toMatchObject({ value: "true" });
    expect(configWrite("DISABLE_SSO_SIGNUP")).toMatchObject({ value: "true" });
    // The audit half runs here too (no stored rows, so both flags moved).
    expect(emitLog.map((e) => e.event.action)).toEqual([
      "config.signup_disabled.set",
      "config.sso_signup_disabled.set",
    ]);
  });

  it("survives a failed read of the current value and records old_value: null", async () => {
    // The DISABLE_SIGNUP read throws; the DISABLE_SSO_SIGNUP read succeeds and
    // matches what this boot wants, so only the unreadable flag emits.
    readFixtures.configFindFirstQueue = [
      new Error("connection terminated unexpectedly"),
      { value: "true" },
    ];

    await initializeEnvironmentConfiguration();

    // The boot completed and the write still happened ...
    expect(logLines()).toContain(
      "✅ Environment-based configuration initialized successfully",
    );
    expect(configWrite("DISABLE_SIGNUP")).toMatchObject({ value: "true" });

    // ... the failed read was said out loud, because the row it produces is
    // degraded and the log line is what says why ...
    const warnLine = warnLines().find((line) =>
      line.includes("registration-control audit"),
    );
    expect(warnLine).toBeDefined();
    expect(warnLine).toContain("DISABLE_SIGNUP");

    // ... and exactly one row was emitted: `null` compares unequal to any
    // boolean, so an unreadable flag is assumed changed (over-reporting beats
    // losing the row that says registration reopened), while the flag that
    // read cleanly as already-true stayed silent.
    expect(emitLog).toHaveLength(1);
    expect(emitLog[0].event).toMatchObject({
      action: "config.signup_disabled.set",
      target_id: "DISABLE_SIGNUP",
      detail: { old_value: null, new_value: true, source: "bootstrap_env" },
    });
  });
});
