/**
 * Shared setup for the admin-plane integration suites that run the real /trpc
 * stack against a real Postgres (api-key-mint.integration.test.ts,
 * admin-write.integration.test.ts and key-owner-groups.integration.test.ts):
 * users, admin-plane keys of both scopes, the express app around the real tRPC
 * router, access groups, data-plane keys of a chosen owner and scope, the
 * audit-fault trigger, and the readers that find a detached audit row (see
 * `auditEventually`).
 *
 * Test support only: nothing in the shipped backend imports it, and tsup's
 * only entry is `src/index.ts`. The two suites call `vi.mock` for the logger
 * and the MCP connection pools themselves (mock registration is per file),
 * then call `createFixture` from `beforeAll`.
 *
 * Addresses are RFC 5737 documentation ranges, emails use .test, ids and
 * names are synthetic.
 */

import type { AddressInfo } from "node:net";

import express from "express";
import { Client } from "pg";
import { expect } from "vitest";

import { INTEGRATION_DB_LOCK_KEY } from "../db/repositories/integration-db-lock";

export type TrpcReply = {
  status: number;
  data: unknown;
  code: string | undefined;
  message: string | undefined;
};

export interface Fixture {
  base: string;
  run: string;
  suiteLock: Client;
  db: typeof import("../db/index").db;
  schema: typeof import("../db/schema");
  eq: typeof import("drizzle-orm").eq;
  ownerId: string;
  memberId: string;
  otherMemberId: string;
  ownerCookie: string;
  memberCookie: string;
  operator: { key: string; uuid: string };
  sync: { key: string; uuid: string };
  publicNamespaceUuid: string;
  trpc: (
    procedure: string,
    input: unknown,
    kind: "query" | "mutation",
    options?: {
      key?: string;
      cookie?: string;
      ip?: string | null;
    },
  ) => Promise<TrpcReply>;
  /** Rows of audit_log matching `where`, read straight away (no polling). */
  auditNow: (
    where: string,
    params: unknown[],
  ) => Promise<Array<Record<string, unknown>>>;
  /**
   * Same, polling briefly for a row `emit()` writes after the response, then
   * letting every audit write still in flight land and reading once more, so a
   * request that wrote its row twice reads as two rows, not one.
   *
   * SCOPE `where` BY SOMETHING ONLY THE REQUEST UNDER TEST CARRIES (its own
   * `uniqueIp()`, a uuid it created), NEVER BY A TIME WINDOW. A detached write
   * is stamped by the database when it STARTS, which can be after the response
   * and after any timestamp a test takes next, so `occurred_at >= <now>` also
   * matches the late rows of earlier requests (and can pass on one of them).
   */
  auditEventually: (
    where: string,
    params: unknown[],
  ) => Promise<Array<Record<string, unknown>>>;
  /**
   * Resolve once every audit write emitted so far has landed: the audit pool
   * has no checked-out connection and nobody waiting for one. After it, a row
   * the request wrote is visible to `auditNow` with no polling. Throws if the
   * writes are still in flight after 5 s.
   */
  auditSettled: () => Promise<void>;
  /**
   * An address, from the RFC 5737 documentation range 192.0.2.0/24, that no
   * other request of the suite sends (`ip` option of `trpc`), so the audit rows
   * it writes are identified by `actor_ip`.
   */
  uniqueIp: () => string;
  /**
   * Hold every audit_log INSERT until the returned `release` is called, so a
   * test can stage the case the detached writer makes possible: the response
   * is back and the row is not. Keep it short: a write that waits for an audit
   * pool connection (two of them, 1 s checkout timeout) for longer than a
   * second is dropped, so stall one request's writes, not a burst. `close()`
   * releases it if the test did not.
   */
  stallAuditWrites: () => Promise<() => Promise<void>>;
  endpoint: (over: {
    name: string;
    userId?: string | null;
    restricted?: boolean;
    requireScoped?: boolean;
    oauth?: boolean;
    apiKeyAuth?: boolean;
  }) => Promise<string>;
  /**
   * An access group written straight to the tables (as a human administrator's
   * UI would), with members and mapped endpoints; removed with the fixture.
   * Returns its uuid.
   */
  group: (over: {
    name: string;
    members?: string[];
    endpoints?: string[];
  }) => Promise<string>;
  /**
   * A data-plane key of any owner and scope written through the repository
   * (what an administrator creating a key in the UI produces): none of the
   * agent mint rules apply. `ownerId` null is a public key.
   */
  dataKey: (over: {
    name: string;
    ownerId: string | null;
    endpointUuid?: string | null;
  }) => Promise<{ key: string; uuid: string }>;
  /** Set a user's role directly, for a demotion or promotion mid-test. */
  setRole: (userId: string, role: "admin" | "member") => Promise<void>;
  /**
   * Present `token` to the real data-plane middleware (`authenticateApiKey`,
   * both API-key branches, real repositories) for the endpoint row as stored
   * now. `next` is whether the request would have been served.
   */
  authenticateKey: (options: {
    endpointUuid: string;
    token: string;
    via?: "bearer" | "x-api-key";
    ip?: string | null;
  }) => Promise<{ next: boolean; status: number; body: unknown }>;
  /** Make audit_log refuse an INSERT for `action` until `clearAuditFault`. */
  failAuditFor: (action: string) => Promise<void>;
  clearAuditFault: (action: string) => Promise<void>;
  /** Make api_keys refuse an INSERT of a key with this name. */
  failKeyInsertFor: (name: string) => Promise<void>;
  clearKeyInsertFault: () => Promise<void>;
  close: () => Promise<void>;
}

const APP_ORIGIN = "http://127.0.0.1:1";

/** How long `auditSettled` waits for the audit writes in flight before it throws. */
const AUDIT_SETTLE_TIMEOUT_MS = 5_000;

/**
 * Advisory-lock key of the audit stall (`stallAuditWrites`). A second key,
 * distinct from INTEGRATION_DB_LOCK_KEY, held only by the suite's own session
 * and only while a test has the stall closed.
 */
const AUDIT_STALL_LOCK_KEY = 987_201_432;

export async function createFixture(
  databaseUrl: string,
  label: string,
): Promise<Fixture> {
  const run = `${label}${Date.now().toString(36)}`;
  const PASSWORD = `itest-throwaway-password-${run}`;
  process.env.DATABASE_URL = databaseUrl;
  process.env.BETTER_AUTH_SECRET = `itest-throwaway-secret-${run}`;
  process.env.APP_URL = APP_ORIGIN;

  const suiteLock = new Client({ connectionString: databaseUrl });
  await suiteLock.connect();
  await suiteLock.query(`SELECT pg_advisory_lock(${INTEGRATION_DB_LOCK_KEY})`);

  const { db } = await import("../db/index");
  // The pool every `emit()` write goes through (db/audit-db), the one this
  // process shares with the app under test, read by `auditSettled`.
  const { auditPool } = await import("../db/audit-db");
  const schema = await import("../db/schema");
  const { eq } = await import("drizzle-orm");
  const { ApiKeysRepository } = await import(
    "../db/repositories/api-keys.repo"
  );
  const { auth } = await import("../auth");

  const emails = {
    owner: `itest-${run}-owner@example.test`,
    member: `itest-${run}-member@example.test`,
    other: `itest-${run}-other@example.test`,
  };
  for (const email of Object.values(emails)) {
    await db
      .delete(schema.usersTable)
      .where(eq(schema.usersTable.email, email));
  }

  async function signUp(email: string) {
    const res = await auth.handler(
      new Request(`${APP_ORIGIN}/api/auth/sign-up/email`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: APP_ORIGIN },
        body: JSON.stringify({ email, password: PASSWORD, name: "itest" }),
      }),
    );
    expect(res.status).toBe(200);
    const id = ((await res.json()) as { user: { id: string } }).user.id;
    const cookie = (res.headers.getSetCookie?.() ?? [])
      .map((c) => c.split(";")[0])
      .join("; ");
    return { id, cookie };
  }

  const owner = await signUp(emails.owner);
  const member = await signUp(emails.member);
  const other = await signUp(emails.other);
  await db
    .update(schema.usersTable)
    .set({ role: "admin" })
    .where(eq(schema.usersTable.id, owner.id));
  // A cookie minted before the promotion carries the old role; sign in again.
  const signedIn = await auth.handler(
    new Request(`${APP_ORIGIN}/api/auth/sign-in/email`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: APP_ORIGIN },
      body: JSON.stringify({ email: emails.owner, password: PASSWORD }),
    }),
  );
  expect(signedIn.status).toBe(200);
  const ownerCookie = (signedIn.headers.getSetCookie?.() ?? [])
    .map((c) => c.split(";")[0])
    .join("; ");

  const repo = new ApiKeysRepository();
  const syncKey = await repo.create({
    name: `itest ${run} sync`,
    user_id: owner.id,
    admin_plane: true,
    is_active: true,
  });
  const operatorKey = await repo.create({
    name: `itest ${run} operator`,
    user_id: owner.id,
    admin_plane: true,
    admin_plane_scope: "operator",
    is_active: true,
  });

  const [namespace] = await db
    .insert(schema.namespacesTable)
    .values({ name: `itest-${run}-ns`, user_id: null })
    .returning();

  const { default: trpcRouter } = await import("../routers/trpc");
  const { auditContextMiddleware } = await import(
    "../middleware/audit-context.middleware"
  );
  const app = express();
  // Mounted first in the real server (index.ts): it stamps the request id and
  // the Cloudflare-supplied client address the self-lockout rails and the audit
  // rows read.
  app.use(auditContextMiddleware);
  app.use("/trpc", trpcRouter);
  let server!: import("node:http").Server;
  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", resolve);
  });
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  let ipCounter = 0;
  const nextIp = () => `198.51.100.${(++ipCounter % 250) + 1}`;

  // A separate range from `nextIp` (which wraps and so repeats), and a throw
  // rather than a wrap: an address that is not unique is the bug it prevents.
  let uniqueIpCounter = 0;
  const uniqueIp = () => {
    if (uniqueIpCounter >= 254) throw new Error("uniqueIp: range exhausted");
    return `192.0.2.${++uniqueIpCounter}`;
  };

  async function trpc(
    procedure: string,
    input: unknown,
    kind: "query" | "mutation",
    options: { key?: string; cookie?: string; ip?: string | null } = {},
  ): Promise<TrpcReply> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
    };
    if (options.ip !== null) {
      headers["cf-connecting-ip"] = options.ip ?? nextIp();
    }
    if (options.cookie) {
      headers.cookie = options.cookie;
      headers.origin = APP_ORIGIN;
    } else {
      headers.authorization = `Bearer ${options.key ?? operatorKey.key}`;
    }
    const url =
      kind === "query"
        ? `${base}/trpc/frontend/${procedure}${
            input === undefined
              ? ""
              : `?input=${encodeURIComponent(JSON.stringify(input))}`
          }`
        : `${base}/trpc/frontend/${procedure}`;
    const res = await fetch(url, {
      method: kind === "query" ? "GET" : "POST",
      headers,
      body: kind === "mutation" ? JSON.stringify(input ?? {}) : undefined,
    });
    const body = (await res.json()) as {
      result?: { data?: unknown };
      error?: { message?: string; data?: { code?: string } };
    };
    return {
      status: res.status,
      data: body.result?.data,
      code: body.error?.data?.code,
      message: body.error?.message,
    };
  }

  const auditSql = (where: string) =>
    `SELECT actor_type, actor_id, actor_label, action, target_type, target_id,
            outcome, detail
       FROM audit_log WHERE ${where} ORDER BY occurred_at`;

  async function auditNow(where: string, params: unknown[]) {
    const { rows } = await suiteLock.query(auditSql(where), params);
    return rows;
  }

  // `emit()` hands its write to the audit pool and returns, so a request is
  // answered before its audit rows exist. Every write it started is, from the
  // moment the response reaches the test, either holding one of the pool's
  // connections or waiting for one (the code between `emit()` and the pool
  // checkout is microtasks, which finish before the response is delivered), so
  // a pool that is entirely idle means every row emitted so far is committed.
  // The sink is resolved by the suite's first request, long before any test
  // calls this.
  async function auditSettled() {
    const deadline = Date.now() + AUDIT_SETTLE_TIMEOUT_MS;
    while (
      auditPool.waitingCount > 0 ||
      auditPool.idleCount < auditPool.totalCount
    ) {
      if (Date.now() > deadline) {
        throw new Error(
          `audit writes still in flight after ${AUDIT_SETTLE_TIMEOUT_MS} ms`,
        );
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }

  async function auditEventually(where: string, params: unknown[]) {
    const deadline = Date.now() + 5_000;
    for (;;) {
      const rows = await auditNow(where, params);
      if (rows.length > 0 || Date.now() > deadline) break;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    // The first row is in. Read again once nothing is in flight: a request
    // that wrote the row twice must read as two, and a poll that returns at
    // the first row would not see the second.
    await auditSettled();
    return auditNow(where, params);
  }

  async function endpoint(over: {
    name: string;
    userId?: string | null;
    restricted?: boolean;
    requireScoped?: boolean;
    oauth?: boolean;
    apiKeyAuth?: boolean;
  }) {
    const [row] = await db
      .insert(schema.endpointsTable)
      .values({
        name: `${over.name}-${run}`,
        namespace_uuid: namespace.uuid,
        user_id: over.userId ?? null,
        restricted: over.restricted ?? false,
        // Independent of `restricted`: restricting an endpoint no longer turns
        // the scoped-key requirement on, so neither does this helper.
        require_scoped_api_key: over.requireScoped ?? false,
        enable_oauth: over.oauth ?? false,
        enable_api_key_auth: over.apiKeyAuth ?? true,
      })
      .returning({ uuid: schema.endpointsTable.uuid });
    return row.uuid;
  }

  const groupUuids: string[] = [];

  async function group(over: {
    name: string;
    members?: string[];
    endpoints?: string[];
  }) {
    const [row] = await db
      .insert(schema.accessGroupsTable)
      .values({ name: `${over.name}-${run}` })
      .returning({ uuid: schema.accessGroupsTable.uuid });
    groupUuids.push(row.uuid);
    for (const userId of over.members ?? []) {
      await db
        .insert(schema.accessGroupMembersTable)
        .values({ group_uuid: row.uuid, user_id: userId });
    }
    for (const endpointUuid of over.endpoints ?? []) {
      await db
        .insert(schema.accessGroupEndpointsTable)
        .values({ group_uuid: row.uuid, endpoint_uuid: endpointUuid });
    }
    return row.uuid;
  }

  async function dataKey(over: {
    name: string;
    ownerId: string | null;
    endpointUuid?: string | null;
  }) {
    const created = await repo.create({
      name: `${over.name}-${run}`,
      user_id: over.ownerId,
      endpoint_uuid: over.endpointUuid ?? null,
      is_active: true,
    });
    return { key: created.key, uuid: created.uuid };
  }

  async function setRole(userId: string, role: "admin" | "member") {
    await db
      .update(schema.usersTable)
      .set({ role })
      .where(eq(schema.usersTable.id, userId));
  }

  async function authenticateKey(options: {
    endpointUuid: string;
    token: string;
    via?: "bearer" | "x-api-key";
    ip?: string | null;
  }) {
    const { authenticateApiKey } = await import(
      "../middleware/api-key-oauth.middleware"
    );
    const { endpointsRepository } = await import("../db/repositories");
    const stored = await endpointsRepository.findByUuid(options.endpointUuid);
    const headers: Record<string, string> = {};
    if (options.via === "bearer") {
      headers.authorization = `Bearer ${options.token}`;
    } else {
      headers["x-api-key"] = options.token;
    }
    if (options.ip) headers["cf-connecting-ip"] = options.ip;
    const req = {
      headers,
      query: {},
      ip: "127.0.0.1",
      endpoint: stored,
      protocol: "http",
      originalUrl: "/metamcp/x/mcp",
      path: "/mcp",
      method: "POST",
      get: () => undefined,
    } as unknown as express.Request;
    const result = { next: false, status: 0, body: undefined as unknown };
    const res = {
      status(code: number) {
        result.status = code;
        return res;
      },
      json(body: unknown) {
        result.body = body;
        return res;
      },
      send(body: unknown) {
        result.body = body;
        return res;
      },
      set: () => res,
      setHeader: () => res,
      header: () => res,
      end: () => res,
    } as unknown as express.Response;
    await authenticateApiKey(req, res, () => {
      result.next = true;
    });
    return result;
  }

  // Fault injection at the database: a trigger that raises on a marked INSERT
  // is a real statement failure inside the transaction, which is what the
  // atomicity claims are about (a mocked failure would prove only the mock).
  async function failAuditFor(action: string) {
    await suiteLock.query(
      `CREATE TABLE IF NOT EXISTS itest_fail_audit_actions (action text PRIMARY KEY)`,
    );
    await suiteLock.query(`
      CREATE OR REPLACE FUNCTION itest_fail_audit() RETURNS trigger AS $$
      BEGIN
        IF EXISTS (SELECT 1 FROM itest_fail_audit_actions WHERE action = NEW.action) THEN
          RAISE EXCEPTION 'itest: audit insert refused';
        END IF;
        RETURN NEW;
      END $$ LANGUAGE plpgsql`);
    await suiteLock.query(
      `DROP TRIGGER IF EXISTS itest_fail_audit_trg ON audit_log`,
    );
    await suiteLock.query(
      `CREATE TRIGGER itest_fail_audit_trg BEFORE INSERT ON audit_log
         FOR EACH ROW EXECUTE FUNCTION itest_fail_audit()`,
    );
    await suiteLock.query(
      `INSERT INTO itest_fail_audit_actions (action) VALUES ($1) ON CONFLICT DO NOTHING`,
      [action],
    );
  }

  async function clearAuditFault(action: string) {
    await suiteLock.query(
      `DELETE FROM itest_fail_audit_actions WHERE action = $1`,
      [action],
    );
  }

  async function failKeyInsertFor(name: string) {
    // The trigger reads a table, not a session setting, because the app's
    // connection is not the test's.
    await suiteLock.query(
      `CREATE TABLE IF NOT EXISTS itest_fail_key_names (name text PRIMARY KEY)`,
    );
    await suiteLock.query(`
      CREATE OR REPLACE FUNCTION itest_fail_key_insert() RETURNS trigger AS $$
      BEGIN
        IF EXISTS (SELECT 1 FROM itest_fail_key_names WHERE name = NEW.name) THEN
          RAISE EXCEPTION 'itest: key insert refused';
        END IF;
        RETURN NEW;
      END $$ LANGUAGE plpgsql`);
    await suiteLock.query(
      `DROP TRIGGER IF EXISTS itest_fail_key_trg ON api_keys`,
    );
    await suiteLock.query(
      `CREATE TRIGGER itest_fail_key_trg BEFORE INSERT ON api_keys
         FOR EACH ROW EXECUTE FUNCTION itest_fail_key_insert()`,
    );
    await suiteLock.query(
      `INSERT INTO itest_fail_key_names (name) VALUES ($1) ON CONFLICT DO NOTHING`,
      [name],
    );
  }

  async function clearKeyInsertFault() {
    await suiteLock.query(
      `DROP TRIGGER IF EXISTS itest_fail_key_trg ON api_keys`,
    );
    await suiteLock.query(`DROP TABLE IF EXISTS itest_fail_key_names`);
  }

  // A BEFORE INSERT trigger that waits for a shared advisory lock this
  // session holds exclusively while the stall is closed. The wait is in the
  // database, not the app, so the app under test is untouched, and a test that
  // dies with the stall closed frees it by ending the session. The lock is
  // taken and dropped again at once, so the writes pass the moment it is
  // released. `occurred_at` is not delayed by it (the default is evaluated when
  // the statement starts), which is why the tests that use it identify rows by
  // address and not by time.
  let releaseStall: (() => Promise<void>) | null = null;

  async function stallAuditWrites() {
    if (releaseStall) throw new Error("audit writes are already stalled");
    await suiteLock.query(`
      CREATE OR REPLACE FUNCTION itest_stall_audit() RETURNS trigger AS $$
      BEGIN
        PERFORM pg_advisory_lock_shared(${AUDIT_STALL_LOCK_KEY});
        PERFORM pg_advisory_unlock_shared(${AUDIT_STALL_LOCK_KEY});
        RETURN NEW;
      END $$ LANGUAGE plpgsql`);
    await suiteLock.query(
      `DROP TRIGGER IF EXISTS itest_stall_audit_trg ON audit_log`,
    );
    await suiteLock.query(
      `CREATE TRIGGER itest_stall_audit_trg BEFORE INSERT ON audit_log
         FOR EACH ROW EXECUTE FUNCTION itest_stall_audit()`,
    );
    await suiteLock.query(`SELECT pg_advisory_lock(${AUDIT_STALL_LOCK_KEY})`);
    const release = async () => {
      if (releaseStall !== release) return;
      releaseStall = null;
      // Unlock first: DROP TRIGGER needs a lock the stalled INSERTs hold.
      await suiteLock.query(
        `SELECT pg_advisory_unlock(${AUDIT_STALL_LOCK_KEY})`,
      );
      await suiteLock.query(
        `DROP TRIGGER IF EXISTS itest_stall_audit_trg ON audit_log`,
      );
      await suiteLock.query(`DROP FUNCTION IF EXISTS itest_stall_audit()`);
    };
    releaseStall = release;
    return release;
  }

  async function close() {
    await new Promise((resolve) => server?.close(resolve));
    await releaseStall?.();
    await suiteLock.query(
      `DROP TRIGGER IF EXISTS itest_fail_audit_trg ON audit_log`,
    );
    await suiteLock.query(`DROP TABLE IF EXISTS itest_fail_audit_actions`);
    await clearKeyInsertFault();
    for (const uuid of groupUuids) {
      await db
        .delete(schema.accessGroupsTable)
        .where(eq(schema.accessGroupsTable.uuid, uuid));
    }
    // Groups a test made through the operator procedures, named with the run.
    await suiteLock.query(`DELETE FROM access_groups WHERE name LIKE $1`, [
      `%${run}`,
    ]);
    await db
      .delete(schema.namespacesTable)
      .where(eq(schema.namespacesTable.uuid, namespace.uuid));
    for (const email of Object.values(emails)) {
      await db
        .delete(schema.usersTable)
        .where(eq(schema.usersTable.email, email));
    }
    const { pool } = await import("../db/index");
    await pool.end();
    await suiteLock.query(
      `SELECT pg_advisory_unlock(${INTEGRATION_DB_LOCK_KEY})`,
    );
    await suiteLock.end();
  }

  return {
    base,
    run,
    suiteLock,
    db,
    schema,
    eq,
    ownerId: owner.id,
    memberId: member.id,
    otherMemberId: other.id,
    ownerCookie,
    memberCookie: member.cookie,
    operator: { key: operatorKey.key, uuid: operatorKey.uuid },
    sync: { key: syncKey.key, uuid: syncKey.uuid },
    publicNamespaceUuid: namespace.uuid,
    trpc,
    auditNow,
    auditEventually,
    auditSettled,
    uniqueIp,
    stallAuditWrites,
    endpoint,
    group,
    dataKey,
    setRole,
    authenticateKey,
    failAuditFor,
    clearAuditFault,
    failKeyInsertFor,
    clearKeyInsertFault,
    close,
  };
}
