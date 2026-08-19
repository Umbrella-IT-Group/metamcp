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
 *  - the registration lock is written AFTER the configured users are created
 *    (the cheap second line behind the exemption below);
 *  - the BOOTSTRAP SIGNUP EXEMPTION is opened around the user pass and closed
 *    in a `finally` after it, including when that pass throws. This is what
 *    actually keeps a closed gateway able to recreate its own administrator:
 *    `ensureUser` signs users up through the very route DISABLE_SIGNUP closes,
 *    and the flag PERSISTS, so on every boot after the first the stored `true`
 *    is what refuses and no ordering inside a boot can help. Only the
 *    entrypoint can show the flag's lifetime.
 *
 * Env-driven config: each test writes the BOOTSTRAP_* vars it needs and the
 * suite restores the original environment afterwards.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// auth.ts throws without BETTER_AUTH_SECRET and connects to postgres.
//
// `authCallLog` records, per sign-up call, the length of `statementLog` and
// whether the bootstrap exemption was open. Neither is visible in the
// statement log (`ensureUser` creates users through `auth.handler`, not
// through a logged insert), and both are safety properties: the first answers
// "which came first, the sign-up or the config write", the second answers
// "was bootstrap allowed through the gate that refuses everyone else".
const { authHandlerMock, authCallLog } = vi.hoisted(() => ({
  authHandlerMock: vi.fn(),
  authCallLog: [] as {
    statementsAtCall: number;
    bootstrapSignupAllowed: boolean;
  }[],
}));
vi.mock("../auth", () => ({ auth: { handler: authHandlerMock } }));

/**
 * Chain-stub db. Every `insert(table)` is recorded (with its values) into
 * `statementLog` in issue order — the assertion surface. Reads are routed
 * by TABLE IDENTITY (the real schema module is imported below; it is pure
 * drizzle-orm table definitions, no connection).
 */
type LoggedStatement = {
  op: "insert" | "delete" | "update";
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
    /**
     * What `DISABLE_SIGNUP` ALREADY holds in the database when this boot
     * starts. Distinct from `configFindFirstQueue`, which models the audit
     * comparison read: this one drives the signup GATE inside the stand-in
     * `auth.handler` below, and `true` is the boot-2+ state every restart of a
     * deployed gateway is in.
     */
    storedSignupDisabled: false,
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
    // Logged like inserts and deletes: the config-supplied-key path REWRITES
    // an existing row's hash rather than inserting, so without this the only
    // observable of that branch would be its log line.
    update: vi.fn((table: unknown) => ({
      set: (values: Record<string, unknown>) => ({
        where: () => {
          statementLog.push({ op: "update", table, values });
          return Promise.resolve(undefined);
        },
      }),
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
import { apiKeyLast4, hashApiKey } from "./api-key-hash";
import { initializeEnvironmentConfiguration } from "./bootstrap.service";
// NOT mocked, deliberately: this module is half the fix under test, and the
// entrypoint's use of it is what these tests observe.
import {
  isBootstrapSignupAllowed,
  setBootstrapSignupAllowed,
} from "./bootstrap-signup-override";

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
  //
  // The `storedSignupDisabled` branch is a STAND-IN for `auth.ts`'s
  // `databaseHooks.user.create.before` gate, which cannot run here (`../auth`
  // is mocked wholesale — bootstrap will not drive a live better-auth
  // instance). It reproduces the one decision that matters, `refuse unless the
  // bootstrap exemption is open`, against the REAL exemption module, so these
  // tests bite on bootstrap's half of the fix: forget to open the exemption and
  // the recreate scenarios below fail exactly as production would.
  //
  // What it deliberately does NOT prove is that the real hook honours the
  // exemption. That is `src/auth-signup-gate.test.ts`, which drives the
  // configured hook itself. Change one file and change the other.
  authHandlerMock.mockImplementation(async () => {
    const bootstrapSignupAllowed = isBootstrapSignupAllowed();
    authCallLog.push({
      statementsAtCall: statementLog.length,
      bootstrapSignupAllowed,
    });
    if (readFixtures.storedSignupDisabled && !bootstrapSignupAllowed) {
      return {
        ok: false,
        status: 403,
        text: async () => "New user registration is currently disabled.",
      };
    }
    return readFixtures.authHandlerResponse;
  });
  readFixtures.authHandlerResponse = { ok: true, text: async () => "" };
  readFixtures.storedSignupDisabled = false;
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
  // The exemption is process-global, so a regression that leaks it `true` would
  // otherwise disarm every gate assertion in the tests that follow. Each test
  // asserts the flag's final state itself, BEFORE this runs.
  setBootstrapSignupAllowed(false);
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
      key_hash: hashApiKey("sk_mt_preserved_secret"),
      last4: apiKeyLast4("sk_mt_preserved_secret"),
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
      key_hash: hashApiKey("sk_mt_preserved_secret"),
      last4: apiKeyLast4("sk_mt_preserved_secret"),
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

/**
 * A well-formed operator-supplied key: 70 characters, the same shape the
 * repository mint emits.
 */
const CONFIGURED_KEY = `sk_mt_${"c3D4".repeat(16)}`;

describe("bootstrapApiKeys log truth — pending restore for the same (user_id, name)", () => {
  it("amends the 'Created ... API key' line instead of presenting the doomed fresh value as live", async () => {
    // The config declares a key with the SAME name as the preserved key
    // ("consumer-scoped", owned by the recreated user): bootstrapApiKeys
    // writes the configured value, then the deferred restore's
    // onConflictDoUpdate overwrites it. The configured value never survives
    // startup, so the log must not present its mask as the live credential.
    arrangeRecreateScenario({
      apiKeysEnv: JSON.stringify([
        {
          name: "consumer-scoped",
          user_email: "admin@example.com",
          key: CONFIGURED_KEY,
        },
      ]),
    });
    // bootstrapApiKeys' existence probe: the key is gone (the recreate
    // deleted it), so the create path runs.
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

    // Both writes still happened: the config write AND the restore upsert —
    // net DB state is unchanged by the log fix.
    const apiKeyInserts = statementLog.filter(
      (s) => s.op === "insert" && s.table === apiKeysTable,
    );
    expect(apiKeyInserts).toHaveLength(2);
    // Last write wins and it is the restore (the preserved value).
    expect(apiKeyInserts[apiKeyInserts.length - 1].values).toMatchObject({
      key_hash: hashApiKey("sk_mt_preserved_secret"),
      last4: apiKeyLast4("sk_mt_preserved_secret"),
    });
  });

  it("a non-colliding config key keeps the normal masked-value log line", async () => {
    arrangeRecreateScenario({
      apiKeysEnv: JSON.stringify([
        {
          name: "unrelated-key",
          user_email: "admin@example.com",
          key: CONFIGURED_KEY,
        },
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
    // Masked, never whole — the boot log must not carry a live credential.
    expect(createdLine).not.toContain(CONFIGURED_KEY);
  });
});

/**
 * `BOOTSTRAP_API_KEYS[].key` — the operator-supplied value, and the refusal
 * to invent one.
 *
 * Migration 0034 stores only a hash and the product has no rotate endpoint,
 * so a key bootstrap generates for itself is written to a row that no
 * surface can ever read back: the boot log would say "✓ Created" over a
 * credential that is unusable and unrepairable. These cases pin that
 * bootstrap refuses that outcome out loud, and that a supplied value reaches
 * the database through the SHARED hash helper (a local encoding here would
 * store a digest the authentication lookup never matches — a silent 401).
 */
describe("bootstrapApiKeys — operator-supplied key values", () => {
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

  /**
   * A plain boot: the configured user already exists, nothing is recreated,
   * no keys are preserved. Two `usersTable.findFirst` responses — the
   * existing-user probe, then the re-read `ensureUser` issues on every path
   * before it can return the id `userMap` is keyed on.
   */
  function arrangePlainBoot(apiKeysEnv: unknown[]) {
    process.env.BOOTSTRAP_USER_EMAIL = "admin@example.com";
    process.env.BOOTSTRAP_USER_PASSWORD = "hunter2hunter2";
    process.env.BOOTSTRAP_API_KEYS = JSON.stringify(apiKeysEnv);
    readFixtures.usersFindFirstQueue = [
      { id: "user-1", email: "admin@example.com" },
      { id: "user-1", email: "admin@example.com" },
    ];
  }

  function apiKeyInserts() {
    return statementLog.filter(
      (s) => s.op === "insert" && s.table === apiKeysTable,
    );
  }

  function apiKeyUpdates() {
    return statementLog.filter(
      (s) => s.op === "update" && s.table === apiKeysTable,
    );
  }

  it("writes the SUPPLIED value's hash and last4 — never a value of its own", async () => {
    arrangePlainBoot([
      {
        name: "connector",
        user_email: "admin@example.com",
        key: CONFIGURED_KEY,
      },
    ]);
    readFixtures.apiKeysFindFirstQueue = [undefined];

    await initializeEnvironmentConfiguration();

    expect(apiKeyInserts()).toHaveLength(1);
    // Through the shared helper, so the row this writes is the row
    // `validateApiKey` finds when the operator presents CONFIGURED_KEY.
    expect(apiKeyInserts()[0].values).toMatchObject({
      name: "connector",
      key_hash: hashApiKey(CONFIGURED_KEY),
      last4: apiKeyLast4(CONFIGURED_KEY),
      user_id: "user-1",
      is_active: true,
    });
  });

  it("SKIPS an entry with no key, loudly and with the remedy, writing nothing", async () => {
    // The regression: before this, bootstrap generated a value, stored its
    // hash, logged "✓ Created ... : sk_mt_abcd…wxyz", and the operator was
    // left holding a masked prefix of a credential no surface could return.
    arrangePlainBoot([{ name: "connector", user_email: "admin@example.com" }]);
    readFixtures.apiKeysFindFirstQueue = [undefined];

    await initializeEnvironmentConfiguration();

    expect(apiKeyInserts()).toHaveLength(0);
    const skipLine = warnLines().find((line) =>
      line.includes('Skipping API key "connector"'),
    );
    expect(skipLine).toBeDefined();
    expect(skipLine).toContain('must carry a "key" value');
    // Names the way out, both of them — a warning that only says "no" costs
    // the operator the same discovery this test exists to prevent.
    expect(skipLine).toContain('Add "key"');
    expect(skipLine).toContain("UI");
    // And nothing claimed success for it.
    expect(
      logLines().find((line) => line.includes('API key "connector"')),
    ).toBeUndefined();
  });

  it.each([
    ["empty", "", 'its "key" is empty'],
    ["too short", "sk_mt_tooshort", "shorter than 32 characters"],
    [
      "whitespace-padded",
      ` ${CONFIGURED_KEY} `,
      "leading or trailing whitespace",
    ],
  ])(
    "SKIPS a %s key rather than falling back to a generated one",
    async (_label, key, expectedReason) => {
      arrangePlainBoot([
        { name: "connector", user_email: "admin@example.com", key },
      ]);
      readFixtures.apiKeysFindFirstQueue = [undefined];

      await initializeEnvironmentConfiguration();

      // The fallback is the danger: a generated value would look like a
      // success while being unreadable, and the operator would never learn
      // their configured key was rejected.
      expect(apiKeyInserts()).toHaveLength(0);
      const skipLine = warnLines().find((line) =>
        line.includes('Skipping API key "connector"'),
      );
      expect(skipLine).toBeDefined();
      expect(skipLine).toContain(expectedReason);
    },
  );

  it("rewrites an EXISTING row when the configured value disagrees with the stored hash", async () => {
    // The only route back from a key nobody can read: rows minted before the
    // field existed hold an unreadable value, and there is no rotate
    // endpoint. Ignoring the config here would leave that row dead forever.
    arrangePlainBoot([
      {
        name: "connector",
        user_email: "admin@example.com",
        key: CONFIGURED_KEY,
      },
    ]);
    readFixtures.apiKeysFindFirstQueue = [
      {
        uuid: "key-uuid-1",
        name: "connector",
        key_hash: hashApiKey("sk_mt_some_older_unreadable_value"),
        last4: "alue",
        user_id: "user-1",
      },
    ];

    await initializeEnvironmentConfiguration();

    expect(apiKeyInserts()).toHaveLength(0);
    expect(apiKeyUpdates()).toHaveLength(1);
    expect(apiKeyUpdates()[0].values).toEqual({
      key_hash: hashApiKey(CONFIGURED_KEY),
      last4: apiKeyLast4(CONFIGURED_KEY),
    });
    const updatedLine = logLines().find((line) =>
      line.includes('API key "connector"'),
    );
    expect(updatedLine).toContain("updated to the value configured");
    expect(updatedLine).not.toContain(CONFIGURED_KEY); // masked, never whole
  });

  it("leaves an existing row alone when the configured value already matches", async () => {
    // Every restart re-reads the same config; a write per boot would churn
    // the row and make the audit trail lie about when the key last changed.
    arrangePlainBoot([
      {
        name: "connector",
        user_email: "admin@example.com",
        key: CONFIGURED_KEY,
      },
    ]);
    readFixtures.apiKeysFindFirstQueue = [
      {
        uuid: "key-uuid-1",
        name: "connector",
        key_hash: hashApiKey(CONFIGURED_KEY),
        last4: apiKeyLast4(CONFIGURED_KEY),
        user_id: "user-1",
      },
    ];

    await initializeEnvironmentConfiguration();

    expect(apiKeyInserts()).toHaveLength(0);
    expect(apiKeyUpdates()).toHaveLength(0);
    expect(
      logLines().find((line) => line.includes('API key "connector"')),
    ).toContain("already exists: sk_mt_…");
  });

  it("leaves an existing row alone when the entry declares no key at all", async () => {
    // The no-key refusal is about CREATING an unreadable credential. A key
    // that already exists is already working for whoever holds it, so an
    // entry that merely names it must not be treated as a request to
    // replace it.
    arrangePlainBoot([{ name: "connector", user_email: "admin@example.com" }]);
    readFixtures.apiKeysFindFirstQueue = [
      {
        uuid: "key-uuid-1",
        name: "connector",
        key_hash: hashApiKey(CONFIGURED_KEY),
        last4: apiKeyLast4(CONFIGURED_KEY),
        user_id: "user-1",
      },
    ];

    await initializeEnvironmentConfiguration();

    expect(apiKeyInserts()).toHaveLength(0);
    expect(apiKeyUpdates()).toHaveLength(0);
    expect(
      warnLines().find((line) => line.includes('Skipping API key "connector"')),
    ).toBeUndefined();
    expect(
      logLines().find((line) => line.includes('API key "connector"')),
    ).toContain("already exists: sk_mt_…");
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
        key_hash: hashApiKey("sk_mt_bound_secret"),
        last4: apiKeyLast4("sk_mt_bound_secret"),
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
      key_hash: hashApiKey("sk_mt_bound_secret"),
      last4: apiKeyLast4("sk_mt_bound_secret"),
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
        key_hash: hashApiKey("sk_mt_departed_secret"),
        last4: apiKeyLast4("sk_mt_departed_secret"),
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
        key_hash: hashApiKey("sk_mt_preserved_secret"),
        last4: apiKeyLast4("sk_mt_preserved_secret"),
        is_active: true,
        user_id: "old-user-id",
        endpoint_uuid: "stale-ep-uuid",
        endpoint_name: "ep-a",
        acts_as_user_id: null,
        acts_as_email: null,
      },
      {
        name: "foreign-bound-key",
        key_hash: hashApiKey("sk_mt_foreign_secret"),
        last4: apiKeyLast4("sk_mt_foreign_secret"),
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

describe("bootstrap signup exemption — the boot-2+ recreate lockout", () => {
  function warnLines(): string[] {
    return (console.warn as unknown as ReturnType<typeof vi.fn>).mock.calls.map(
      (call) => String(call[0]),
    );
  }

  it("recreates the administrator on a boot where DISABLE_SIGNUP is ALREADY stored true", async () => {
    // The regression this exemption exists for, and the reason ordering alone
    // was not a fix. This is not a fresh database: a previous boot already
    // wrote DISABLE_SIGNUP=true, so the gate is closed before the entrypoint
    // runs a single statement. BOOTSTRAP_RECREATE_USER=true (what example.env
    // ships) means `ensureUser` DELETES the administrator and its user-scoped
    // API keys FIRST. Without the exemption the re-signup that follows is
    // refused and the deploy comes up with no administrator, registration
    // closed, and the connector keys unrecoverable, on an ordinary restart.
    arrangeRecreateScenario();
    readFixtures.storedSignupDisabled = true;
    // The audit comparison read agrees: this boot re-asserts what is stored.
    readFixtures.configFindFirstQueue = [{ value: "true" }, { value: "true" }];

    await initializeEnvironmentConfiguration();

    // The destructive half genuinely ran, so this is the real hazard path.
    expect(
      statementLog.some((s) => s.op === "delete" && s.table === apiKeysTable),
    ).toBe(true);

    // The sign-up POST was issued and was NOT refused: no sign-up failure, and
    // no credential-loss warning. These two lines ARE the lockout when the
    // exemption is missing, so they come first, ahead of any assertion about
    // the mechanism.
    expect(authCallLog).toHaveLength(1);
    expect(warnLines().find((line) => line.includes("sign-up failed"))).toBe(
      undefined,
    );
    expect(
      warnLines().find((line) => line.includes("CANNOT be restored")),
    ).toBe(undefined);

    // The administrator came back, and so did the preserved key, carrying its
    // original secret and the fresh ids.
    const apiKeyInserts = statementLog.filter(
      (s) => s.op === "insert" && s.table === apiKeysTable,
    );
    expect(apiKeyInserts).toHaveLength(1);
    expect(apiKeyInserts[0].values).toMatchObject({
      name: "consumer-scoped",
      key_hash: hashApiKey("sk_mt_preserved_secret"),
      last4: apiKeyLast4("sk_mt_preserved_secret"),
      user_id: "new-user-id",
      endpoint_uuid: "fresh-ep-uuid",
    });

    // ... and it got through because the exemption was open, not by accident.
    expect(authCallLog[0].bootstrapSignupAllowed).toBe(true);

    // And the boot still leaves registration closed. The exemption is for
    // bootstrap's own accounts, not a reopening.
    const signupWrite = statementLog.find(
      (s) =>
        s.op === "insert" &&
        s.table === configTable &&
        s.values?.id === "DISABLE_SIGNUP",
    );
    expect(signupWrite?.values).toMatchObject({ value: "true" });
  });

  it("closes the exemption once the user pass is done", async () => {
    // The flag must not outlive the pass. `index.ts` awaits this entrypoint
    // before `app.listen()`, so `false` here means no request can ever meet an
    // open exemption.
    arrangeRecreateScenario();
    readFixtures.storedSignupDisabled = true;

    await initializeEnvironmentConfiguration();

    expect(authCallLog[0].bootstrapSignupAllowed).toBe(true);
    expect(isBootstrapSignupAllowed()).toBe(false);
  });

  /**
   * `bootstrapUsers` guards each user individually, so the only way to make the
   * pass itself throw is to fail something ABOVE that guard: the banner it logs
   * before the loop. Contrived as an injection site, exact as a code path.
   */
  function throwOutOfBootstrapUsers() {
    process.env.BOOTSTRAP_USER_EMAIL = "admin@example.com";
    process.env.BOOTSTRAP_USER_PASSWORD = "hunter2hunter2";
    (console.log as unknown as ReturnType<typeof vi.fn>).mockImplementation(
      (line: unknown) => {
        if (String(line).includes("Bootstrapping")) {
          throw new Error("user pass exploded");
        }
      },
    );
  }

  it("closes the exemption even when the user pass THROWS", async () => {
    throwOutOfBootstrapUsers();

    // The entrypoint swallows it (bootstrap never fails a boot by itself) ...
    await expect(initializeEnvironmentConfiguration()).resolves.toBeUndefined();

    // ... having genuinely gone through the catch, so this is the throw path
    // and not a quiet success ...
    expect(
      warnLines().find((line) => line.includes("Users bootstrap failed")),
    ).toBeDefined();
    // ... before any sign-up was attempted ...
    expect(authCallLog).toHaveLength(0);
    // ... and the exemption is shut. A clear at the tail of the `try` leaves it
    // OPEN here, which is the regression this case is for.
    expect(isBootstrapSignupAllowed()).toBe(false);
  });

  it("closes the exemption even when the ERROR HANDLING itself throws", async () => {
    // This is what `finally` buys over a clear placed after the whole
    // try/catch. Today's catch swallows, so a trailing clear would still run on
    // the case above and the two placements look interchangeable. They are not:
    // let the catch's own logging fail (or let a future change rethrow) and a
    // trailing clear is skipped, leaving the gateway listening with the signup
    // gate held open for the life of the process.
    throwOutOfBootstrapUsers();
    (console.warn as unknown as ReturnType<typeof vi.fn>).mockImplementation(
      (line: unknown) => {
        if (String(line).includes("Users bootstrap failed")) {
          throw new Error("logging exploded");
        }
      },
    );

    // The boot fails outright here, which is allowed: `startup.ts` is what
    // decides whether a failed bootstrap stops the process (BOOTSTRAP_FAIL_HARD).
    await expect(initializeEnvironmentConfiguration()).rejects.toThrow(
      "logging exploded",
    );

    // What is NOT allowed is failing with the gate left open.
    expect(isBootstrapSignupAllowed()).toBe(false);
  });

  it("never opens the exemption on a guarded (BOOTSTRAP_ONLY_FIRST_RUN) boot", async () => {
    // The early return creates no users, so it must not touch the flag either.
    process.env.BOOTSTRAP_ONLY_FIRST_RUN = "true";
    process.env.BOOTSTRAP_USER_EMAIL = "admin@example.com";
    process.env.BOOTSTRAP_USER_PASSWORD = "hunter2hunter2";
    readFixtures.configFindFirstQueue = [{ value: "true" }];

    await initializeEnvironmentConfiguration();

    expect(authCallLog).toHaveLength(0);
    expect(isBootstrapSignupAllowed()).toBe(false);
  });
});
