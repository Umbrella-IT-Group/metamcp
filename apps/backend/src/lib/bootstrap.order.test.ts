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
 *    deferred one.
 *
 * Env-driven config: each test writes the BOOTSTRAP_* vars it needs and the
 * suite restores the original environment afterwards.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// auth.ts throws without BETTER_AUTH_SECRET and connects to postgres.
const { authHandlerMock } = vi.hoisted(() => ({
  authHandlerMock: vi.fn(),
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
    /** rows returned by select().from(apiKeysTable).leftJoin().where() — the preserve capture */
    preservedKeyRows: [] as Record<string, unknown>[],
    /** rows returned by select().from(endpointsTable) — the restore's re-resolution load */
    endpointRows: [] as Record<string, unknown>[],
    /** FIFO responses for db.query.usersTable.findFirst */
    usersFindFirstQueue: [] as (Record<string, unknown> | undefined)[],
    /** FIFO responses for db.query.apiKeysTable.findFirst */
    apiKeysFindFirstQueue: [] as (Record<string, unknown> | undefined)[],
  };

  // Import the real tables lazily inside the factory-safe closure — the
  // mock factory itself must not touch them, only the runtime calls do.
  const tableIs = (table: unknown, name: string) =>
    // drizzle stores the SQL name under a symbol; compare via the table's
    // own Symbol.for key to avoid importing drizzle internals here.
    (
      table as { [key: symbol]: unknown }
    )?.[Symbol.for("drizzle:Name")] === name;

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
          : [];
        const joined = {
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
      configTable: { findFirst: vi.fn(() => Promise.resolve(undefined)) },
    },
  };

  return { dbMock, statementLog, readFixtures };
});
vi.mock("../db", () => ({ db: dbMock }));

import {
  apiKeysTable,
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
  readFixtures.preservedKeyRows = [];
  readFixtures.endpointRows = [];
  readFixtures.usersFindFirstQueue = [];
  readFixtures.apiKeysFindFirstQueue = [];
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
  // The preserve capture: one key scoped (by name) to the endpoint that the
  // recreate cascade will destroy and bootstrapEndpoints will recreate.
  readFixtures.preservedKeyRows = [
    {
      name: "tara-scoped",
      key: "sk_mt_preserved_secret",
      is_active: true,
      endpoint_uuid: "stale-ep-uuid",
      endpoint_name: "ep-a",
    },
  ];
  // The restore pass's endpoint load — post-bootstrapEndpoints state with a
  // FRESH uuid for the recreated endpoint.
  readFixtures.endpointRows = [{ uuid: "fresh-ep-uuid", name: "ep-a" }];

  authHandlerMock.mockResolvedValue({ ok: true, text: async () => "" });
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
      name: "tara-scoped",
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
