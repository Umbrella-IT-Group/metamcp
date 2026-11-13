/**
 * Authorization-code replay handling: migration 0045, its repository methods and
 * the token endpoint that uses them, against a REAL Postgres.
 *
 * RFC 6749 section 4.1.2: a reused authorization code MUST be denied and the
 * tokens issued from it SHOULD be revoked. The token endpoint already denied a
 * second redemption (the first deletes the code), but nothing recorded which
 * tokens the code had produced. Migration 0045 adds `oauth_spent_authorization_codes`,
 * written in the SAME transaction as the token pair.
 *
 * Layer 1 (always runs): the migration SQL and the drizzle journal are asserted
 * directly. A migration whose journal `when` does not out-rank the previous max
 * is SILENTLY skipped by drizzle, so the ordering is checked as a test.
 *
 * Layer 2 (opt-in via TEST_DATABASE_URL): the claims only a database can make.
 *  - the SQL layer: the table exists, a record is keyed on the hash and never the
 *    code, `get` and `consume` respect expiry, of two concurrent consumes exactly
 *    one gets the row, both foreign keys cascade, the reaper takes only expired
 *    rows, and the migration applied a second time changes nothing;
 *  - through the real token router over HTTP (the user, client and code are
 *    seeded by repository calls): a first redemption leaves one record tied to
 *    the pair's family; a validated replay is audited, and under `revoke` ends
 *    the family while a neighbouring family of the same user survives; a
 *    replay that does not prove possession changes nothing; a replay after
 *    users.revokeAccess records that nothing was live;
 *  - ATOMICITY: a record write that throws after inserting, and a pair insert
 *    that throws, both leave no pair, no record and a code that can still be
 *    redeemed;
 *  - ORDER: a replay that arrives while the original redemption is still inside
 *    its lock queues behind it, then finds the record and revokes the pair the
 *    first caller was already sent; a replay arriving after the first
 *    redemption committed takes the same lock.
 *
 * Lock order is forced with explicit barriers and pg_locks, never timing.
 *
 *   cd apps/backend
 *   DATABASE_URL=<url> npx drizzle-kit migrate
 *   TEST_DATABASE_URL=<url> npx vitest run \
 *     src/db/repositories/oauth-code-replay.integration.test.ts
 *
 * Point it at a disposable database.
 */

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import path from "node:path";

import express from "express";
import { Client } from "pg";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import { INTEGRATION_DB_LOCK_KEY } from "./integration-db-lock";

const MIGRATION_PATH = path.resolve(
  __dirname,
  "../../../drizzle/0045_oauth_spent_authorization_codes.sql",
);
const JOURNAL_PATH = path.resolve(
  __dirname,
  "../../../drizzle/meta/_journal.json",
);
const RAW = readFileSync(MIGRATION_PATH, "utf8");

describe("migration 0045: the spent-authorization-code table", () => {
  // Assert against the STATEMENTS, not the file: the header prose names the
  // columns and the table, so a naive whole-file match would read comments as
  // schema.
  const sql = RAW.split("\n")
    .filter((line) => !line.trimStart().startsWith("--"))
    .join("\n");

  it("creates the table keyed on the code hash, with cascading owner foreign keys", () => {
    expect(sql).toContain(
      'CREATE TABLE IF NOT EXISTS "oauth_spent_authorization_codes"',
    );
    expect(sql).toContain('"code_hash" text PRIMARY KEY NOT NULL');
    expect(sql).toContain('"family_id" uuid NOT NULL');
    expect(sql).toContain('"redirect_uri" text NOT NULL');
    expect(sql).toContain('"code_challenge" text NOT NULL');
    expect(sql).toContain('"expires_at" timestamp with time zone NOT NULL');
    // Both owner columns cascade with their parent, so a deleted client or user
    // leaves no orphan record.
    expect(sql).toMatch(
      /"client_id" text NOT NULL REFERENCES "oauth_clients" \("client_id"\) ON DELETE CASCADE/,
    );
    expect(sql).toMatch(
      /"user_id" text NOT NULL REFERENCES "users" \("id"\) ON DELETE CASCADE/,
    );
  });

  it("indexes expiry for the reaper", () => {
    expect(sql).toContain(
      'CREATE INDEX IF NOT EXISTS "oauth_spent_authorization_codes_expires_at_idx"',
    );
  });

  it("makes every CREATE idempotent, so a re-run after a partial apply is a no-op", () => {
    const bareCreates = [...sql.matchAll(/CREATE (TABLE|INDEX)\s+"/g)];
    expect(bareCreates).toHaveLength(0);
  });
});

describe("drizzle journal entry for 0045", () => {
  const journal = JSON.parse(readFileSync(JOURNAL_PATH, "utf8")) as {
    entries: { idx: number; when: number; tag: string }[];
  };

  it("registers 0045 with a `when` STRICTLY GREATER than every earlier entry", () => {
    const [entry] = journal.entries.filter(
      (e) => e.tag === "0045_oauth_spent_authorization_codes",
    );
    expect(entry).toBeDefined();
    expect(entry.idx).toBe(45);

    // drizzle applies only entries whose `when` exceeds the max already
    // applied, so a stale `when` is skipped WITHOUT an error and the table is
    // never created.
    const earlier = journal.entries.filter((e) => e.idx < entry.idx);
    expect(entry.when).toBeGreaterThan(Math.max(...earlier.map((e) => e.when)));
  });
});

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;

// `describe.skipIf` rather than a silent early return: a skipped suite is
// visible in the vitest output, so "the integration test didn't run" can never
// be mistaken for "the integration test passed".
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

const quiet = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
vi.mock("@/utils/logger", () => ({ default: quiet }));

const RUN = Date.now().toString(36);
const USER_ID = `itest-spent-user-${RUN}`;
const OTHER_USER_ID = `itest-spent-other-${RUN}`;
const REDIRECT = "https://claude.ai/api/mcp/auth_callback";
const MODE_ENV = "OAUTH_CODE_REPLAY";
// RFC 7636 Appendix B: the published verifier and challenge, so the fixtures do
// not derive one from the code under test.
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const LEGACY_REPLAY_BODY = {
  error: "invalid_grant",
  error_description: "Invalid or expired authorization code",
};
const CODE_TTL_MS = 10 * 60 * 1000;
const MARGIN_MS = 5 * 60 * 1000;

type Db = typeof import("../index").db;
type Schema = typeof import("../schema");

describeIfDb("authorization-code replay (real Postgres)", () => {
  let db: Db;
  let schema: Schema;
  let drizzle: typeof import("drizzle-orm");
  let oauthRepository: typeof import("./oauth.repo").oauthRepository;
  let usersRepository: typeof import("./users.repo").usersRepository;
  let hashApiKey: typeof import("../../lib/api-key-hash").hashApiKey;
  let lockNamespace: string;
  let server: import("node:http").Server;
  let base: string;
  // A dedicated connection for the cross-suite serialization lock (a session
  // lock must be released on the connection that took it) and one that only
  // observes pg_locks and runs the migration text.
  let suiteLock: Client;
  let observer: Client;
  let ipCounter = 0;
  const createdClients: string[] = [];
  const createdUsers: string[] = [];

  const nextIp = () => `2001:db8:5d::${(++ipCounter).toString(16)}`;
  const sha256 = (value: string) =>
    createHash("sha256").update(value).digest("hex");

  // ----------------------------------------------------------- audit capture
  // The audit writer is detached from the request (fire-and-forget). This sink
  // writes the real audit_log row exactly as the production sink does, and
  // counts writes in flight, so a test waits for "every row emitted so far is
  // stored" instead of sleeping, and a second row would be seen.
  let auditInFlight = 0;
  let auditIdle: Array<() => void> = [];
  const drainAudit = () =>
    auditInFlight === 0
      ? Promise.resolve()
      : new Promise<void>((resolve) => auditIdle.push(resolve));

  // ---------------------------------------------------------------- helpers

  async function newClient(): Promise<string> {
    const clientId = `mcp_client_itest_spent_${randomBytes(6).toString("hex")}`;
    await db.insert(schema.oauthClientsTable).values({
      client_id: clientId,
      client_name: clientId,
      redirect_uris: [REDIRECT],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      registration_source: "admin",
      approval_status: "approved",
    });
    createdClients.push(clientId);
    return clientId;
  }

  async function newUser(id: string): Promise<void> {
    await db.insert(schema.usersTable).values({
      id,
      name: id,
      email: `${id}@example.test`,
    });
    createdUsers.push(id);
  }

  async function seedCode(
    clientId: string,
    userId = USER_ID,
  ): Promise<{ code: string }> {
    const code = `mcp_code_itest_${randomBytes(12).toString("hex")}`;
    await oauthRepository.setAuthCode(code, {
      client_id: clientId,
      redirect_uri: REDIRECT,
      scope: "mcp",
      user_id: userId,
      code_challenge: CHALLENGE,
      code_challenge_method: "S256",
      expires_at: Date.now() + CODE_TTL_MS,
    });
    return { code };
  }

  async function seedPair(clientId: string, familyId: string = randomUUID()) {
    const access = `mcp_token_itest_${randomBytes(12).toString("hex")}`;
    const refreshToken = `mcp_refresh_itest_${randomBytes(12).toString("hex")}`;
    await oauthRepository.setAccessToken(access, {
      client_id: clientId,
      user_id: USER_ID,
      scope: "mcp",
      expires_at: Date.now() + 3600_000,
      family_id: familyId,
      refresh: { token: refreshToken, expires_at: Date.now() + 86_400_000 },
    });
    return { access, refreshToken, familyId };
  }

  async function redeem(
    clientId: string,
    code: string,
    overrides: Record<string, string> = {},
  ) {
    const res = await fetch(`${base}/oauth/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "cf-connecting-ip": nextIp(),
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: clientId,
        redirect_uri: REDIRECT,
        code_verifier: VERIFIER,
        ...overrides,
      }).toString(),
    });
    return {
      status: res.status,
      body: (await res.json()) as Record<string, string | undefined>,
    };
  }

  async function tombstonesOf(code: string) {
    return db
      .select()
      .from(schema.oauthSpentAuthorizationCodesTable)
      .where(
        drizzle.eq(
          schema.oauthSpentAuthorizationCodesTable.code_hash,
          hashApiKey(code),
        ),
      );
  }

  async function familyRows(familyId: string) {
    return db
      .select({ access_token: schema.oauthAccessTokensTable.access_token })
      .from(schema.oauthAccessTokensTable)
      .where(drizzle.eq(schema.oauthAccessTokensTable.family_id, familyId));
  }

  async function familyOfAccessToken(accessToken: string): Promise<string> {
    const row = await oauthRepository.getAccessToken(accessToken);
    if (!row) throw new Error("the issued access token is not stored");
    return row.family_id;
  }

  async function reuseRows(clientId: string) {
    await drainAudit();
    return db
      .select()
      .from(schema.auditLogTable)
      .where(
        drizzle.and(
          drizzle.eq(schema.auditLogTable.action, "oauth.token.reuse"),
          drizzle.eq(schema.auditLogTable.target_id, clientId),
        ),
      );
  }

  /** Poll pg_locks until `count` waiters on the OAuth user lock are queued. */
  async function waitForUserLockWaiters(count: number): Promise<void> {
    // Two-key advisory locks (objsubid 2) are the OAuth user lock; the suite
    // serialization lock is a one-key lock (objsubid 1). Polling an observed
    // condition, not a fixed wait.
    const query = `SELECT count(*)::int AS n FROM pg_locks WHERE locktype = 'advisory' AND objsubid = 2 AND NOT granted`;
    const deadline = Date.now() + 15_000;
    for (;;) {
      const { rows } = await observer.query<{ n: number }>(query);
      if ((rows[0]?.n ?? 0) >= count) return;
      if (Date.now() > deadline) {
        throw new Error("timed out waiting for a user-lock waiter");
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }

  /** Resolve true once `count` requests queue on the user lock, false if every competitor settled without queueing. */
  async function queuedBehind(
    competitors: Promise<unknown>[],
    count: number,
  ): Promise<boolean> {
    const settled = Promise.allSettled(competitors).then(() => false);
    const queued = waitForUserLockWaiters(count).then(
      () => true,
      () => false,
    );
    return Promise.race([queued, settled]);
  }

  beforeAll(async () => {
    process.env.DATABASE_URL = TEST_DATABASE_URL;
    process.env.BETTER_AUTH_SECRET = `itest-throwaway-secret-${RUN}`;
    process.env.APP_URL = "http://127.0.0.1:1";
    delete process.env[MODE_ENV];

    suiteLock = new Client({ connectionString: TEST_DATABASE_URL });
    await suiteLock.connect();
    // Serialize against every other TEST_DATABASE_URL suite: cleanupExpired is
    // a GLOBAL delete, and this lock keeps a parallel suite's fixtures out of
    // its blast radius.
    await suiteLock.query(
      `SELECT pg_advisory_lock(${INTEGRATION_DB_LOCK_KEY})`,
    );
    observer = new Client({ connectionString: TEST_DATABASE_URL });
    await observer.connect();

    ({ db } = await import("../index"));
    schema = await import("../schema");
    drizzle = await import("drizzle-orm");
    ({ oauthRepository } = await import("./oauth.repo"));
    ({ usersRepository } = await import("./users.repo"));
    ({ hashApiKey } = await import("../../lib/api-key-hash"));
    ({ OAUTH_USER_LOCK_NAMESPACE: lockNamespace } = await import(
      "./oauth-user-lock"
    ));
    const { auditLogRepository } = await import("./audit-log.repo");
    const { setAuditSinkForTesting } = await import(
      "../../lib/audit/audit-emitter"
    );
    setAuditSinkForTesting(async (event) => {
      auditInFlight += 1;
      try {
        await auditLogRepository.record({
          actor_type: event.actor_type,
          actor_id: event.actor_id ?? null,
          actor_label: event.actor_label ?? null,
          actor_ip: event.actor_ip ?? null,
          actor_user_agent: event.actor_user_agent ?? null,
          action: event.action,
          target_type: event.target_type ?? null,
          target_id: event.target_id ?? null,
          outcome: event.outcome,
          request_id: event.request_id ?? null,
          http_status: event.http_status ?? null,
          detail: event.detail ?? {},
        });
      } finally {
        auditInFlight -= 1;
        if (auditInFlight === 0) {
          const waiting = auditIdle;
          auditIdle = [];
          for (const resolve of waiting) resolve();
        }
      }
    });

    const utils = await import("../../routers/oauth/utils");
    const { auditContextMiddleware } = await import(
      "../../middleware/audit-context.middleware"
    );
    const { errorHandler } = await import(
      "../../middleware/error-handler.middleware"
    );
    const { default: tokenRouter } = await import("../../routers/oauth/token");

    await db
      .delete(schema.usersTable)
      .where(drizzle.inArray(schema.usersTable.id, [USER_ID, OTHER_USER_ID]));
    await newUser(USER_ID);
    await newUser(OTHER_USER_ID);

    const app = express();
    // Same order as apps/backend/src/index.ts and routers/oauth/index.ts, with
    // the terminal error handler last, as in production.
    app.use(auditContextMiddleware);
    app.use(utils.securityHeaders);
    app.use(utils.jsonParsingMiddleware);
    app.use(utils.urlencodedParsingMiddleware);
    app.use(tokenRouter);
    app.use(errorHandler);
    await new Promise<void>((resolve) => {
      server = app.listen(0, "127.0.0.1", resolve);
    });
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }, 60_000);

  afterEach(() => {
    delete process.env[MODE_ENV];
    vi.restoreAllMocks();
  });

  afterAll(async () => {
    await new Promise((resolve) => server?.close(resolve));
    if (db) {
      for (const id of createdClients) {
        await db
          .delete(schema.oauthClientsTable)
          .where(drizzle.eq(schema.oauthClientsTable.client_id, id));
      }
      for (const id of createdUsers) {
        await db
          .delete(schema.usersTable)
          .where(drizzle.eq(schema.usersTable.id, id));
      }
      const { pool } = await import("../index");
      await pool.end();
    }
    await observer?.end();
    await suiteLock?.query(
      `SELECT pg_advisory_unlock(${INTEGRATION_DB_LOCK_KEY})`,
    );
    await suiteLock?.end();
  });

  // ======================================================== the SQL layer

  describe("the table and its repository methods", () => {
    it("exists after migration", async () => {
      const { rows } = await observer.query<{ rel: string | null }>(
        `SELECT to_regclass('public.oauth_spent_authorization_codes')::text AS rel`,
      );
      expect(rows[0].rel).toBe("oauth_spent_authorization_codes");
    });

    it("has the primary key, both cascading foreign keys and the expiry index", async () => {
      const fks = await observer.query<{
        conname: string;
        confdeltype: string;
      }>(
        `SELECT conname, confdeltype FROM pg_constraint
         WHERE conrelid = 'oauth_spent_authorization_codes'::regclass AND contype = 'f'`,
      );
      expect(fks.rows).toHaveLength(2);
      // 'c' is ON DELETE CASCADE.
      expect(fks.rows.map((r) => r.confdeltype)).toEqual(["c", "c"]);
      const pk = await observer.query(
        `SELECT 1 FROM pg_constraint
         WHERE conrelid = 'oauth_spent_authorization_codes'::regclass AND contype = 'p'`,
      );
      expect(pk.rowCount).toBe(1);
      const idx = await observer.query(
        `SELECT 1 FROM pg_indexes
         WHERE tablename = 'oauth_spent_authorization_codes'
           AND indexname = 'oauth_spent_authorization_codes_expires_at_idx'`,
      );
      expect(idx.rowCount).toBe(1);
    });

    it("applying the migration text a second time changes nothing", async () => {
      const clientId = await newClient();
      const { code } = await seedCode(clientId);
      await db.transaction((tx) =>
        oauthRepository.recordSpentCode(
          code,
          {
            family_id: randomUUID(),
            client_id: clientId,
            user_id: USER_ID,
            redirect_uri: REDIRECT,
            code_challenge: CHALLENGE,
            expires_at: new Date(Date.now() + MARGIN_MS),
          },
          tx,
        ),
      );

      for (const statement of RAW.split("--> statement-breakpoint")) {
        await observer.query(statement);
      }

      expect(await tombstonesOf(code)).toHaveLength(1);
    });

    it("stores the hash of the code, never the code, and refuses a second record for one code", async () => {
      const clientId = await newClient();
      const { code } = await seedCode(clientId);
      const record = () =>
        db.transaction((tx) =>
          oauthRepository.recordSpentCode(
            code,
            {
              family_id: randomUUID(),
              client_id: clientId,
              user_id: USER_ID,
              redirect_uri: REDIRECT,
              code_challenge: CHALLENGE,
              expires_at: new Date(Date.now() + MARGIN_MS),
            },
            tx,
          ),
        );
      await record();

      const [row] = await tombstonesOf(code);
      expect(row.code_hash).toBe(sha256(code));
      expect(JSON.stringify(row)).not.toContain(code);
      // A plain insert on purpose: a conflict fails the grant loudly rather
      // than being swallowed.
      await expect(record()).rejects.toThrow();
    });

    it("get and consume respect expiry, and consume returns the row to exactly one caller", async () => {
      const clientId = await newClient();
      const { code } = await seedCode(clientId);
      const familyId = randomUUID();
      const expiresAt = new Date(Date.now() + MARGIN_MS);
      await db.transaction((tx) =>
        oauthRepository.recordSpentCode(
          code,
          {
            family_id: familyId,
            client_id: clientId,
            user_id: USER_ID,
            redirect_uri: REDIRECT,
            code_challenge: CHALLENGE,
            expires_at: expiresAt,
          },
          tx,
        ),
      );

      expect(await oauthRepository.getSpentCode(code)).toMatchObject({
        family_id: familyId,
        client_id: clientId,
        user_id: USER_ID,
        redirect_uri: REDIRECT,
        code_challenge: CHALLENGE,
      });
      // Expired is judged against the `now` it is given, not the wall clock.
      const afterExpiry = new Date(expiresAt.getTime() + 1);
      expect(
        await oauthRepository.getSpentCode(code, db, afterExpiry),
      ).toBeNull();
      expect(
        await db.transaction((tx) =>
          oauthRepository.consumeSpentCode(code, tx, afterExpiry),
        ),
      ).toBeNull();
      // The refused consume left the row where it was.
      expect(await tombstonesOf(code)).toHaveLength(1);

      const results = await Promise.all([
        db.transaction((tx) => oauthRepository.consumeSpentCode(code, tx)),
        db.transaction((tx) => oauthRepository.consumeSpentCode(code, tx)),
      ]);
      expect(results.filter((r) => r !== null)).toHaveLength(1);
      expect(results.find((r) => r !== null)).toMatchObject({
        family_id: familyId,
        client_id: clientId,
        user_id: USER_ID,
      });
      expect(await tombstonesOf(code)).toHaveLength(0);
    });

    it("countFamilyAccessTokens counts only the named family's rows", async () => {
      const clientId = await newClient();
      const family = randomUUID();
      await seedPair(clientId, family);
      await seedPair(clientId, family);
      await seedPair(clientId);

      expect(await oauthRepository.countFamilyAccessTokens(family)).toBe(2);
      expect(await oauthRepository.countFamilyAccessTokens(randomUUID())).toBe(
        0,
      );
    });

    it("cascades when the client or the user is deleted", async () => {
      const clientId = await newClient();
      const throwawayUser = `itest-spent-cascade-${randomBytes(4).toString("hex")}`;
      await newUser(throwawayUser);
      const first = await seedCode(clientId);
      const second = await seedCode(clientId, throwawayUser);
      const record = (code: string, userId: string) =>
        db.transaction((tx) =>
          oauthRepository.recordSpentCode(
            code,
            {
              family_id: randomUUID(),
              client_id: clientId,
              user_id: userId,
              redirect_uri: REDIRECT,
              code_challenge: CHALLENGE,
              expires_at: new Date(Date.now() + MARGIN_MS),
            },
            tx,
          ),
        );
      await record(first.code, USER_ID);
      await record(second.code, throwawayUser);

      await db
        .delete(schema.usersTable)
        .where(drizzle.eq(schema.usersTable.id, throwawayUser));
      expect(await tombstonesOf(second.code)).toHaveLength(0);
      expect(await tombstonesOf(first.code)).toHaveLength(1);

      await db
        .delete(schema.oauthClientsTable)
        .where(drizzle.eq(schema.oauthClientsTable.client_id, clientId));
      expect(await tombstonesOf(first.code)).toHaveLength(0);
    });

    it("cleanupExpired reaps only expired records", async () => {
      const clientId = await newClient();
      const expired = await seedCode(clientId);
      const live = await seedCode(clientId);
      const record = (code: string, expiresAt: Date) =>
        db.transaction((tx) =>
          oauthRepository.recordSpentCode(
            code,
            {
              family_id: randomUUID(),
              client_id: clientId,
              user_id: USER_ID,
              redirect_uri: REDIRECT,
              code_challenge: CHALLENGE,
              expires_at: expiresAt,
            },
            tx,
          ),
        );
      await record(expired.code, new Date(Date.now() - 60_000));
      await record(live.code, new Date(Date.now() + MARGIN_MS));

      await oauthRepository.cleanupExpired();

      expect(await tombstonesOf(expired.code)).toHaveLength(0);
      expect(await tombstonesOf(live.code)).toHaveLength(1);
    });
  });

  // ============================================ through the real token router

  describe("a first redemption", () => {
    it("leaves one record tied to the pair's family, in the default mode", async () => {
      const clientId = await newClient();
      const { code } = await seedCode(clientId);

      const res = await redeem(clientId, code);

      expect(res.status).toBe(200);
      expect(res.body.access_token).toMatch(/^mcp_token_/);
      const familyId = await familyOfAccessToken(
        res.body.access_token as string,
      );
      const [row] = await tombstonesOf(code);
      expect(row).toMatchObject({
        family_id: familyId,
        client_id: clientId,
        user_id: USER_ID,
        redirect_uri: REDIRECT,
        code_challenge: CHALLENGE,
      });
      expect(await familyRows(familyId)).toHaveLength(1);
      // The code itself is gone, as before.
      expect(await oauthRepository.getAuthCode(code)).toBeNull();
    });

    it("OAUTH_CODE_REPLAY=off writes no record", async () => {
      process.env[MODE_ENV] = "off";
      const clientId = await newClient();
      const { code } = await seedCode(clientId);

      const res = await redeem(clientId, code);

      expect(res.status).toBe(200);
      expect(await tombstonesOf(code)).toHaveLength(0);
    });
  });

  describe("a validated replay", () => {
    it("in the default mode is audited with the live count, and revokes nothing", async () => {
      const clientId = await newClient();
      const { code } = await seedCode(clientId);
      const first = await redeem(clientId, code);
      const familyId = await familyOfAccessToken(
        first.body.access_token as string,
      );

      const replay = await redeem(clientId, code);

      // Oracle: RFC 6749 section 5.2, and the body an unknown code has always
      // got, so the replay is indistinguishable from a plain miss.
      expect(replay.status).toBe(400);
      expect(replay.body).toEqual(LEGACY_REPLAY_BODY);
      expect(await familyRows(familyId)).toHaveLength(1);
      expect(await tombstonesOf(code)).toHaveLength(0);
      const rows = await reuseRows(clientId);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        outcome: "denied",
        http_status: 400,
        actor_id: USER_ID,
      });
      expect(rows[0].detail).toMatchObject({
        reason: "authorization_code_reuse",
        token_type: "authorization_code",
        family_id: familyId,
        mode: "log",
        tokens_live: 1,
        family_revoked: false,
        token_sha256: sha256(code),
      });
      expect(JSON.stringify(rows[0])).not.toContain(code);
    });

    it("in revoke mode ends the family, leaves the user's other family alone, and audits once however often it is replayed", async () => {
      process.env[MODE_ENV] = "revoke";
      const clientId = await newClient();
      const neighbour = await seedPair(clientId);
      const { code } = await seedCode(clientId);
      const first = await redeem(clientId, code);
      const access = first.body.access_token as string;
      const refreshToken = first.body.refresh_token as string;
      const familyId = await familyOfAccessToken(access);

      const replay = await redeem(clientId, code);
      const again = await redeem(clientId, code);

      expect(replay.status).toBe(400);
      expect(replay.body).toEqual(LEGACY_REPLAY_BODY);
      expect(again.body).toEqual(LEGACY_REPLAY_BODY);
      // The session the first caller was given is gone, access and refresh.
      expect(await familyRows(familyId)).toHaveLength(0);
      expect(await oauthRepository.getAccessToken(access)).toBeNull();
      expect(await oauthRepository.getByRefreshToken(refreshToken)).toBeNull();
      // The same user's unrelated session is untouched.
      expect(await familyRows(neighbour.familyId)).toHaveLength(1);
      // Two replays, one row.
      const rows = await reuseRows(clientId);
      expect(rows).toHaveLength(1);
      expect(rows[0].detail).toMatchObject({
        mode: "revoke",
        tokens_live: 1,
        family_revoked: true,
      });
    });

    it("does not act when the verifier is wrong, and the record stays for the real holder", async () => {
      process.env[MODE_ENV] = "revoke";
      const clientId = await newClient();
      const { code } = await seedCode(clientId);
      const first = await redeem(clientId, code);
      const familyId = await familyOfAccessToken(
        first.body.access_token as string,
      );

      const forged = await redeem(clientId, code, {
        code_verifier: randomBytes(32).toString("base64url"),
      });

      expect(forged.body).toEqual(LEGACY_REPLAY_BODY);
      expect(await familyRows(familyId)).toHaveLength(1);
      expect(await tombstonesOf(code)).toHaveLength(1);
      expect(await reuseRows(clientId)).toHaveLength(0);

      // The holder of the verifier still triggers it afterwards.
      await redeem(clientId, code);
      expect(await familyRows(familyId)).toHaveLength(0);
      expect(await reuseRows(clientId)).toHaveLength(1);
    });

    it("ignores an expired record", async () => {
      process.env[MODE_ENV] = "revoke";
      const clientId = await newClient();
      const pair = await seedPair(clientId);
      const { code } = await seedCode(clientId);
      await oauthRepository.consumeAuthCode(code);
      await db.transaction((tx) =>
        oauthRepository.recordSpentCode(
          code,
          {
            family_id: pair.familyId,
            client_id: clientId,
            user_id: USER_ID,
            redirect_uri: REDIRECT,
            code_challenge: CHALLENGE,
            expires_at: new Date(Date.now() - 60_000),
          },
          tx,
        ),
      );

      const replay = await redeem(clientId, code);

      expect(replay.body).toEqual(LEGACY_REPLAY_BODY);
      expect(await familyRows(pair.familyId)).toHaveLength(1);
      expect(await reuseRows(clientId)).toHaveLength(0);
    });

    it("an unknown code writes nothing", async () => {
      process.env[MODE_ENV] = "revoke";
      const clientId = await newClient();

      const res = await redeem(
        clientId,
        `mcp_code_itest_never_issued_${randomBytes(6).toString("hex")}`,
      );

      expect(res.body).toEqual(LEGACY_REPLAY_BODY);
      expect(await reuseRows(clientId)).toHaveLength(0);
    });

    it("after users.revokeAccess records that nothing was live, and claims no revoke", async () => {
      process.env[MODE_ENV] = "revoke";
      const clientId = await newClient();
      const { code } = await seedCode(clientId);
      const first = await redeem(clientId, code);
      const familyId = await familyOfAccessToken(
        first.body.access_token as string,
      );
      // revokeAccess deletes the family's tokens but leaves the record.
      await usersRepository.revokeAccess(USER_ID);
      expect(await familyRows(familyId)).toHaveLength(0);
      expect(await tombstonesOf(code)).toHaveLength(1);

      const replay = await redeem(clientId, code);

      expect(replay.body).toEqual(LEGACY_REPLAY_BODY);
      const rows = await reuseRows(clientId);
      expect(rows).toHaveLength(1);
      expect(rows[0].detail).toMatchObject({
        tokens_live: 0,
        family_revoked: false,
      });
    });
  });

  describe("atomicity", () => {
    it("a record write that inserts and then throws leaves no pair, no record and a redeemable code", async () => {
      const clientId = await newClient();
      const { code } = await seedCode(clientId);
      const original = oauthRepository.recordSpentCode.bind(oauthRepository);
      vi.spyOn(oauthRepository, "recordSpentCode").mockImplementation(
        async (...args) => {
          // The real insert, through the executor the router passed. If the
          // router passed anything but its own transaction, this row would
          // survive the throw below.
          await original(...args);
          throw new Error("record failed after inserting");
        },
      );

      const res = await redeem(clientId, code);

      expect(res.status).toBe(500);
      expect(res.body.access_token).toBeUndefined();
      expect(await tombstonesOf(code)).toHaveLength(0);
      const pairs = await db
        .select()
        .from(schema.oauthAccessTokensTable)
        .where(drizzle.eq(schema.oauthAccessTokensTable.client_id, clientId));
      expect(pairs).toHaveLength(0);
      // The consume rolled back with it: the code is still there.
      expect(await oauthRepository.getAuthCode(code)).not.toBeNull();

      vi.restoreAllMocks();
      const retry = await redeem(clientId, code);
      expect(retry.status).toBe(200);
      expect(await tombstonesOf(code)).toHaveLength(1);
    });

    it("a pair insert that throws leaves no record and a redeemable code", async () => {
      const clientId = await newClient();
      const { code } = await seedCode(clientId);
      vi.spyOn(oauthRepository, "setAccessToken").mockRejectedValueOnce(
        new Error("pair insert failed"),
      );

      const res = await redeem(clientId, code);

      expect(res.status).toBe(500);
      expect(await tombstonesOf(code)).toHaveLength(0);
      expect(await oauthRepository.getAuthCode(code)).not.toBeNull();
    });
  });

  describe("ordering under the user's credential lock", () => {
    it("a replay that arrives while the original is still inside its lock queues, then revokes the pair already sent", async () => {
      process.env[MODE_ENV] = "revoke";
      const clientId = await newClient();
      const { code } = await seedCode(clientId);
      const original = oauthRepository.recordSpentCode.bind(oauthRepository);
      let arrive!: () => void;
      let release!: () => void;
      const arrived = new Promise<void>((resolve) => {
        arrive = resolve;
      });
      const released = new Promise<void>((resolve) => {
        release = resolve;
      });
      // Pause the first redemption inside its lock, after its pair and record
      // are inserted and before they commit.
      vi.spyOn(oauthRepository, "recordSpentCode").mockImplementation(
        async (...args) => {
          await original(...args);
          arrive();
          await released;
        },
      );

      const first = redeem(clientId, code);
      let replay: ReturnType<typeof redeem> | undefined;
      try {
        // Reaching the pause is the precondition; a first redemption that
        // finishes without reaching it is a broken setup, not a pass.
        await Promise.race([
          arrived,
          first.then(() => {
            throw new Error("the first redemption never reached the pause");
          }),
        ]);
        // The original's delete of the live code is uncommitted, so the replay
        // still reads the live code, passes every check, and queues for the lock.
        replay = redeem(clientId, code);
        const queued = await queuedBehind([replay], 1);
        release();
        const [firstRes, replayRes] = await Promise.all([first, replay]);

        expect(replayRes.status).toBe(400);
        expect(replayRes.body).toEqual(LEGACY_REPLAY_BODY);
        expect(firstRes.status).toBe(200);
        // The pair the first caller was already sent is dead.
        expect(
          await oauthRepository.getAccessToken(
            firstRes.body.access_token as string,
          ),
        ).toBeNull();
        const rows = await reuseRows(clientId);
        expect(rows).toHaveLength(1);
        expect(rows[0].detail).toMatchObject({
          tokens_live: 1,
          family_revoked: true,
        });
        // Asserted last, so code without the lock fails on the assertion that
        // matters rather than on a timeout.
        expect(queued).toBe(true);
      } finally {
        release();
        await Promise.allSettled([first, replay]);
      }
    });

    it("a replay that arrives after the first redemption committed takes the same lock", async () => {
      process.env[MODE_ENV] = "revoke";
      const clientId = await newClient();
      const { code } = await seedCode(clientId);
      const first = await redeem(clientId, code);
      const familyId = await familyOfAccessToken(
        first.body.access_token as string,
      );

      // Hold the user's credential lock on another connection, so the revoke
      // can only run once it is released.
      const holder = new Client({ connectionString: TEST_DATABASE_URL });
      await holder.connect();
      await holder.query("BEGIN");
      await holder.query(
        `SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`,
        [lockNamespace, USER_ID],
      );
      let replay: ReturnType<typeof redeem> | undefined;
      try {
        replay = redeem(clientId, code);
        const queued = await queuedBehind([replay], 1);
        // Nothing is revoked while the lock is held elsewhere.
        const duringHold = await familyRows(familyId);
        await holder.query("COMMIT");
        const res = await replay;

        expect(res.body).toEqual(LEGACY_REPLAY_BODY);
        expect(await familyRows(familyId)).toHaveLength(0);
        expect(duringHold).toHaveLength(1);
        expect(queued).toBe(true);
      } finally {
        await holder.query("ROLLBACK").catch(() => undefined);
        await holder.end();
        await Promise.allSettled([replay]);
      }
    });
  });
});
