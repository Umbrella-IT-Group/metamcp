/**
 * Every OAuth credential mint and revoke for one user is serialized by the
 * per-user advisory lock (./oauth-user-lock), against a REAL Postgres.
 *
 * What is pinned, end to end through the real token and authorization
 * routers, the real repositories and the real better-auth instance:
 *
 *  - one refresh token presented twice at once mints exactly once, and the
 *    duplicate takes the strict reuse path, so no row of the family survives;
 *  - users.revokeAccess, reuse detection's family revoke and /oauth/revoke
 *    are never undone by a refresh that was in flight, in either lock order
 *    and across several families of one user;
 *  - authorization-code redemption and consent approval are serialized the
 *    same way, and a fresh sign-in after a revoke still works;
 *  - a failed insert rolls the claim, the marker and the consumed code back;
 *  - refusals that must not consume a credential still do not.
 *
 * Lock order is forced with explicit barriers, never timing: a repository call
 * that runs INSIDE the lock is paused until the competing request is seen
 * waiting in pg_locks, or a separate connection holds a row lock that keeps
 * revokeAccess inside its locked transaction while the competitor queues.
 * Nothing awaits a competing revoke from inside a request that holds the lock;
 * that would wait for itself.
 *
 * Opt-in via TEST_DATABASE_URL, pointed at a disposable, migrated database:
 *
 *   cd apps/backend
 *   DATABASE_URL=<url> npx drizzle-kit migrate
 *   TEST_DATABASE_URL=<url> npx vitest run \
 *     src/db/repositories/oauth-user-lock.integration.test.ts
 */

import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { AddressInfo } from "node:net";

import express from "express";
import { Client } from "pg";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import { INTEGRATION_DB_LOCK_KEY } from "./integration-db-lock";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

const quiet = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
vi.mock("@/utils/logger", () => ({ default: quiet }));

const RUN = Date.now().toString(36);
// The better-auth account created in beforeAll; its id is assigned there.
let USER_ID = "";
const EMAIL = `itest-oauth-lock-${RUN}@example.test`;
const PASSWORD = `itest-throwaway-password-${RUN}`;
const CLIENT_ID = `mcp_client_itest_lock_${RUN}`;
const SECRET_CLIENT_ID = `mcp_client_itest_lock_secret_${RUN}`;
const CLIENT_SECRET = `itest-client-secret-${RUN}`;
const REDIRECT_URI = "http://127.0.0.1:53682/callback";
const APP_ORIGIN = "http://127.0.0.1:1";
// The refresh grant's client-authentication mode (routers/oauth/token.ts
// OAUTH_REFRESH_CLIENT_AUTH_ENV), read per request.
const REFRESH_CLIENT_AUTH_ENV = "OAUTH_REFRESH_CLIENT_AUTH";

type Db = typeof import("../index").db;
type Schema = typeof import("../schema");

describeIfDb("per-user OAuth credential lock (real Postgres)", () => {
  let db: Db;
  let schema: Schema;
  let eq: typeof import("drizzle-orm").eq;
  let and: typeof import("drizzle-orm").and;
  let oauthRepository: typeof import("./oauth.repo").oauthRepository;
  let usersRepository: typeof import("./users.repo").usersRepository;
  let auth: typeof import("../../auth").auth;
  let hashClientSecret: typeof import("../../routers/oauth/utils").hashClientSecret;
  let server: import("node:http").Server;
  let base: string;
  // A dedicated connection for the cross-suite serialization lock (a session
  // lock must be released on the connection that took it) and one that only
  // observes pg_locks.
  let suiteLock: Client;
  let observer: Client;
  let ipCounter = 0;

  const nextIp = () => `2001:db8:4c::${(++ipCounter).toString(16)}`;

  // ---------------------------------------------------------------- helpers

  async function refresh(refreshToken: string, extra: object = {}) {
    const res = await fetch(`${base}/oauth/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "cf-connecting-ip": nextIp(),
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: CLIENT_ID,
        ...extra,
      }).toString(),
    });
    return {
      status: res.status,
      body: (await res.json()) as Record<string, string | undefined>,
    };
  }

  async function revoke(token: string, extra: object = {}) {
    const res = await fetch(`${base}/oauth/revoke`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "cf-connecting-ip": nextIp(),
      },
      body: new URLSearchParams({ token, ...extra }).toString(),
    });
    return { status: res.status };
  }

  async function redeemCode(code: string, verifier: string) {
    const res = await fetch(`${base}/oauth/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "cf-connecting-ip": nextIp(),
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        code_verifier: verifier,
      }).toString(),
    });
    return {
      status: res.status,
      body: (await res.json()) as Record<string, string | undefined>,
    };
  }

  async function seedPair(familyId: string = randomUUID()) {
    const access = `mcp_token_itest_${randomBytes(12).toString("hex")}`;
    const refreshToken = `mcp_refresh_itest_${randomBytes(12).toString("hex")}`;
    await oauthRepository.setAccessToken(access, {
      client_id: CLIENT_ID,
      user_id: USER_ID,
      scope: "mcp",
      expires_at: Date.now() + 3600_000,
      family_id: familyId,
      refresh: { token: refreshToken, expires_at: Date.now() + 86_400_000 },
    });
    return { access, refreshToken, familyId };
  }

  async function seedCode() {
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const code = `mcp_code_itest_${randomBytes(12).toString("hex")}`;
    await oauthRepository.setAuthCode(code, {
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: "mcp",
      user_id: USER_ID,
      code_challenge: challenge,
      code_challenge_method: "S256",
      expires_at: Date.now() + 5 * 60 * 1000,
    });
    return { code, verifier };
  }

  async function seedSession() {
    const id = `itest-session-${randomBytes(8).toString("hex")}`;
    await db.insert(schema.sessionsTable).values({
      id,
      token: `itest-session-token-${randomBytes(8).toString("hex")}`,
      userId: USER_ID,
      expiresAt: new Date(Date.now() + 3600_000),
    });
    return id;
  }

  async function liveRows(familyId?: string) {
    const rows = await db
      .select({ family_id: schema.oauthAccessTokensTable.family_id })
      .from(schema.oauthAccessTokensTable)
      .where(eq(schema.oauthAccessTokensTable.user_id, USER_ID));
    return familyId ? rows.filter((r) => r.family_id === familyId) : rows;
  }

  async function markers(familyId: string) {
    return db
      .select({
        hash: schema.oauthRotatedRefreshTokensTable.refresh_token_hash,
      })
      .from(schema.oauthRotatedRefreshTokensTable)
      .where(
        and(
          eq(schema.oauthRotatedRefreshTokensTable.user_id, USER_ID),
          eq(schema.oauthRotatedRefreshTokensTable.family_id, familyId),
        ),
      );
  }

  async function codesForUser() {
    return db
      .select({ code: schema.oauthAuthorizationCodesTable.code })
      .from(schema.oauthAuthorizationCodesTable)
      .where(eq(schema.oauthAuthorizationCodesTable.user_id, USER_ID));
  }

  /** Poll pg_locks until `count` waiters of the given kind are queued. */
  async function waitForWaiters(
    kind: "advisory" | "row",
    count: number,
  ): Promise<void> {
    const query =
      kind === "advisory"
        ? // Two-key advisory locks (objsubid 2) are the OAuth user lock; the
          // suite serialization lock is a one-key lock (objsubid 1).
          `SELECT count(*)::int AS n FROM pg_locks WHERE locktype = 'advisory' AND objsubid = 2 AND NOT granted`
        : `SELECT count(*)::int AS n FROM pg_locks WHERE locktype = 'transactionid' AND NOT granted`;
    const deadline = Date.now() + 15_000;
    for (;;) {
      const { rows } = await observer.query<{ n: number }>(query);
      if ((rows[0]?.n ?? 0) >= count) return;
      if (Date.now() > deadline) {
        throw new Error(
          `timed out waiting for ${count} ${kind} lock waiter(s)`,
        );
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }

  /**
   * Resolve true once `count` requests are queued on the OAuth user lock, or
   * false once every competitor has settled without queueing. The second can
   * only happen when nothing serializes them. Each test asserts the queue
   * after its security assertions, so code without the lock fails on the
   * assertion that matters instead of on a timeout.
   */
  async function queuedBehind(
    competitors: Promise<unknown>[],
    count: number,
  ): Promise<boolean> {
    const settled = Promise.allSettled(competitors).then(() => false);
    const queued = waitForWaiters("advisory", count).then(
      () => true,
      () => false,
    );
    return Promise.race([queued, settled]);
  }

  /**
   * Pause the first call of `method` until `release()` is called. Every method
   * paused here runs inside the user's lock, so the caller holds the lock
   * while it waits. `onlyWithTxAt` skips calls without a transaction at that
   * argument (for a method also called before the lock is taken). Pausing on
   * the first call keeps each test meaningful against code without the lock:
   * there it pauses between the read and the write, the window the race
   * needs, and the test fails on its assertions.
   */
  function pauseInsideLock<T extends object>(
    target: T,
    method: keyof T & string,
    onlyWithTxAt?: number,
  ) {
    const original = (target[method] as (...a: unknown[]) => unknown).bind(
      target,
    );
    let arrive!: () => void;
    let release!: () => void;
    const arrived = new Promise<void>((resolve) => {
      arrive = resolve;
    });
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    let paused = false;
    const spy = vi.spyOn(target, method as never).mockImplementation((async (
      ...args: unknown[]
    ) => {
      if (
        !paused &&
        (onlyWithTxAt === undefined || args[onlyWithTxAt] !== undefined)
      ) {
        paused = true;
        arrive();
        await released;
      }
      return original(...args);
    }) as never);
    return { arrived, release, restore: () => spy.mockRestore() };
  }

  /** Hold a row lock on the user's sessions so revokeAccess, once inside its
   * locked transaction, waits at its first delete. */
  async function holdSessionRowLock() {
    const holder = new Client({ connectionString: TEST_DATABASE_URL });
    await holder.connect();
    await holder.query("BEGIN");
    await holder.query(
      `SELECT id FROM "sessions" WHERE "user_id" = $1 FOR UPDATE`,
      [USER_ID],
    );
    return {
      async release() {
        await holder.query("COMMIT");
        await holder.end();
      },
    };
  }

  async function signUpAndAuthorize() {
    const signup = await auth.handler(
      new Request(`${APP_ORIGIN}/api/auth/sign-in/email`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: APP_ORIGIN },
        body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
      }),
    );
    expect(signup.status).toBe(200);
    const sessionCookie = (signup.headers.getSetCookie?.() ?? [])
      .map((c) => c.split(";")[0])
      .join("; ");
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const authorize = await fetch(
      `${base}/oauth/authorize?response_type=code&client_id=${CLIENT_ID}` +
        `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
        `&code_challenge=${challenge}&code_challenge_method=S256&state=s`,
      {
        redirect: "manual",
        headers: { cookie: sessionCookie, "cf-connecting-ip": nextIp() },
      },
    );
    expect(authorize.status).toBe(302);
    const areq = new URL(
      authorize.headers.get("location") as string,
    ).searchParams.get("areq") as string;
    const csrfCookie = (authorize.headers.getSetCookie?.() ?? [])
      .map((c) => c.split(";")[0])
      .join("; ");
    return { sessionCookie, csrfCookie, areq, verifier };
  }

  async function approve(flow: Awaited<ReturnType<typeof signUpAndAuthorize>>) {
    const res = await fetch(`${base}/oauth/authorize/decision`, {
      method: "POST",
      redirect: "manual",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie: `${flow.sessionCookie}; ${flow.csrfCookie}`,
        "cf-connecting-ip": nextIp(),
      },
      body: new URLSearchParams({
        areq: flow.areq,
        decision: "approve",
      }).toString(),
    });
    const html = await res.text();
    const code = /<code>(mcp_code_[A-Za-z0-9_-]+)<\/code>/.exec(html)?.[1];
    return { status: res.status, code };
  }

  // ------------------------------------------------------------ lifecycle

  beforeAll(async () => {
    process.env.DATABASE_URL = TEST_DATABASE_URL;
    process.env.BETTER_AUTH_SECRET = `itest-throwaway-secret-${RUN}`;
    process.env.APP_URL = APP_ORIGIN;

    suiteLock = new Client({ connectionString: TEST_DATABASE_URL });
    await suiteLock.connect();
    await suiteLock.query(
      `SELECT pg_advisory_lock(${INTEGRATION_DB_LOCK_KEY})`,
    );
    observer = new Client({ connectionString: TEST_DATABASE_URL });
    await observer.connect();

    ({ db } = await import("../index"));
    schema = await import("../schema");
    ({ eq, and } = await import("drizzle-orm"));
    ({ oauthRepository } = await import("./oauth.repo"));
    ({ usersRepository } = await import("./users.repo"));
    ({ auth } = await import("../../auth"));
    ({ hashClientSecret } = await import("../../routers/oauth/utils"));
    const utils = await import("../../routers/oauth/utils");
    const { default: tokenRouter } = await import("../../routers/oauth/token");
    const { default: authorizationRouter } = await import(
      "../../routers/oauth/authorization"
    );

    await db
      .delete(schema.usersTable)
      .where(eq(schema.usersTable.email, EMAIL));
    for (const id of [CLIENT_ID, SECRET_CLIENT_ID]) {
      await db
        .delete(schema.oauthClientsTable)
        .where(eq(schema.oauthClientsTable.client_id, id));
    }

    // The user through better-auth itself, so the consent tests can sign in.
    const signup = await auth.handler(
      new Request(`${APP_ORIGIN}/api/auth/sign-up/email`, {
        method: "POST",
        headers: { "content-type": "application/json", origin: APP_ORIGIN },
        body: JSON.stringify({
          email: EMAIL,
          password: PASSWORD,
          name: "itest",
        }),
      }),
    );
    expect(signup.status).toBe(200);
    USER_ID = ((await signup.json()) as { user: { id: string } }).user.id;
    expect(USER_ID).not.toBe("");

    await db.insert(schema.oauthClientsTable).values({
      client_id: CLIENT_ID,
      client_name: "itest public client",
      redirect_uris: [REDIRECT_URI],
      token_endpoint_auth_method: "none",
      // Approved (migration 0042): this suite is about the credential lock,
      // and only an approved client can be authorized or refreshed.
      approval_status: "approved",
    } as typeof schema.oauthClientsTable.$inferInsert);
    const hashed = hashClientSecret(CLIENT_SECRET);
    await db.insert(schema.oauthClientsTable).values({
      client_id: SECRET_CLIENT_ID,
      client_name: "itest confidential client",
      redirect_uris: [REDIRECT_URI],
      token_endpoint_auth_method: "client_secret_post",
      client_secret: hashed.hash,
      client_secret_salt: hashed.salt,
      approval_status: "approved",
    } as typeof schema.oauthClientsTable.$inferInsert);

    const app = express();
    app.use(utils.jsonParsingMiddleware);
    app.use(utils.urlencodedParsingMiddleware);
    app.use(authorizationRouter);
    app.use(tokenRouter);
    // Express 5 hands a rejected handler to the error middleware.
    app.use(
      (
        _err: unknown,
        _req: express.Request,
        res: express.Response,
        _next: express.NextFunction,
      ) => {
        res.status(500).json({ error: "server_error" });
      },
    );
    await new Promise<void>((resolve) => {
      server = app.listen(0, "127.0.0.1", resolve);
    });
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }, 60_000);

  beforeEach(async () => {
    await db
      .delete(schema.oauthAccessTokensTable)
      .where(eq(schema.oauthAccessTokensTable.user_id, USER_ID));
    await db
      .delete(schema.oauthRotatedRefreshTokensTable)
      .where(eq(schema.oauthRotatedRefreshTokensTable.user_id, USER_ID));
    await db
      .delete(schema.oauthAuthorizationCodesTable)
      .where(eq(schema.oauthAuthorizationCodesTable.user_id, USER_ID));
    await db
      .update(schema.usersTable)
      .set({ disabled: false })
      .where(eq(schema.usersTable.id, USER_ID));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env[REFRESH_CLIENT_AUTH_ENV];
  });

  afterAll(async () => {
    await new Promise((resolve) => server?.close(resolve));
    if (db) {
      await db
        .delete(schema.usersTable)
        .where(eq(schema.usersTable.email, EMAIL));
      for (const id of [CLIENT_ID, SECRET_CLIENT_ID]) {
        await db
          .delete(schema.oauthClientsTable)
          .where(eq(schema.oauthClientsTable.client_id, id));
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

  // ------------------------------------------------- refresh compatibility

  describe("refresh rotation", () => {
    it("still rotates serially: each token works once and the chain continues", async () => {
      const { refreshToken, familyId } = await seedPair();

      const first = await refresh(refreshToken);
      expect(first.status).toBe(200);
      const second = await refresh(first.body.refresh_token as string);
      expect(second.status).toBe(200);

      expect(await liveRows(familyId)).toHaveLength(1);
      expect(await markers(familyId)).toHaveLength(2);
    });

    it("mints once for a double presentation, and the duplicate's reuse revocation leaves no row", async () => {
      // Forced order: request A holds the lock (paused inside it) while B has
      // read the same live row and queued on the lock.
      const { refreshToken, familyId } = await seedPair();
      const pause = pauseInsideLock(usersRepository, "isDisabled");

      const a = refresh(refreshToken);
      await pause.arrived;
      const b = refresh(refreshToken);
      const queued = await queuedBehind([b], 1);
      pause.release();
      const results = await Promise.all([a, b]);

      expect(results.map((r) => r.status)).toEqual([200, 400]);
      expect(results[1]?.body).toEqual({
        error: "invalid_grant",
        error_description: "Invalid refresh token",
      });
      // The strict reuse policy, pinned: the duplicate revoked the family,
      // including the pair A received, so a client whose reply was lost must
      // sign in again rather than getting a replay window.
      expect(await liveRows(familyId)).toEqual([]);
      expect(await markers(familyId)).toEqual([]);
      expect(
        (await refresh(results[0]?.body.refresh_token as string)).status,
      ).toBe(400);
      expect(queued).toBe(true);
    });

    it("never yields two successes across repeated unforced double presentations", async () => {
      const TRIALS = 15;
      for (let trial = 0; trial < TRIALS; trial += 1) {
        const { refreshToken, familyId } = await seedPair();
        const results = await Promise.all([
          refresh(refreshToken),
          refresh(refreshToken),
        ]);
        const ok = results.filter((r) => r.status === 200);
        expect({ trial, ok: ok.length }).toEqual({ trial, ok: 1 });
        expect({ trial, live: (await liveRows(familyId)).length }).toEqual({
          trial,
          live: 0,
        });
      }
    });
  });

  // ------------------------------------------------- revokeAccess vs refresh

  describe("users.revokeAccess against a refresh in flight", () => {
    it("refresh holds the lock first: its new pair is deleted by the revoke that waited", async () => {
      const { refreshToken } = await seedPair();
      const pause = pauseInsideLock(usersRepository, "isDisabled");

      const inFlight = refresh(refreshToken);
      await pause.arrived;
      const revoked = usersRepository.revokeAccess(USER_ID);
      const queued = await queuedBehind([revoked], 1);
      pause.release();

      const [res, counts] = await Promise.all([inFlight, revoked]);
      expect(res.status).toBe(200);
      expect(await liveRows()).toEqual([]);
      expect((await refresh(res.body.refresh_token as string)).status).toBe(
        400,
      );
      expect(counts.oauth_tokens_deleted).toBe(1);
      expect(queued).toBe(true);
    });

    it("revoke holds the lock first: the waiting refresh finds nothing to rotate", async () => {
      const { refreshToken } = await seedPair();
      await seedSession();
      const rowLock = await holdSessionRowLock();

      // revokeAccess takes the user lock, then waits at its session delete.
      const revoked = usersRepository.revokeAccess(USER_ID);
      await waitForWaiters("row", 1);
      // The refresh reads the still-live row, then queues on the user lock.
      const inFlight = refresh(refreshToken);
      const queued = await queuedBehind([inFlight], 1);
      await rowLock.release();

      const [counts, res] = await Promise.all([revoked, inFlight]);
      expect(await liveRows()).toEqual([]);
      expect(res.status).toBe(400);
      expect(counts.oauth_tokens_deleted).toBe(1);
      expect(queued).toBe(true);
    });

    it("leaves no row in any of several families refreshing while the revoke runs", async () => {
      const [one, two, three] = await Promise.all([
        seedPair(),
        seedPair(),
        seedPair(),
      ]);
      const pause = pauseInsideLock(usersRepository, "isDisabled");

      const first = refresh(one.refreshToken);
      await pause.arrived;
      const others = [refresh(two.refreshToken), refresh(three.refreshToken)];
      const othersQueued = await queuedBehind(others, 2);
      const revoked = usersRepository.revokeAccess(USER_ID);
      const revokeQueued = await queuedBehind([revoked], 3);
      pause.release();

      await Promise.all([first, ...others, revoked]);
      expect(await liveRows()).toEqual([]);
      expect([othersQueued, revokeQueued]).toEqual([true, true]);
    });

    it("leaves no surviving row while chains refresh back to back (no timing device)", async () => {
      const TRIALS = 12;
      const CHAINS = 4;
      let refreshes = 0;
      for (let trial = 0; trial < TRIALS; trial += 1) {
        const seeds = await Promise.all(
          Array.from({ length: CHAINS }, () => seedPair()),
        );
        let stop = false;
        const chains = seeds.map(async (seed) => {
          let token = seed.refreshToken;
          while (!stop) {
            const res = await refresh(token);
            refreshes += 1;
            if (res.status !== 200) return;
            token = res.body.refresh_token as string;
          }
        });
        await new Promise((resolve) => setTimeout(resolve, 20 + trial * 5));
        await usersRepository.revokeAccess(USER_ID);
        stop = true;
        await Promise.all(chains);
        expect({ trial, live: (await liveRows()).length }).toEqual({
          trial,
          live: 0,
        });
      }
      expect(refreshes).toBeGreaterThan(TRIALS * CHAINS);
    }, 120_000);
  });

  // ----------------------------------------- reuse detection vs refresh

  describe("reuse detection's family revoke against a refresh in flight", () => {
    it("the live refresh holds the lock first: the reuse revoke deletes what it minted", async () => {
      const { refreshToken: rt0, familyId } = await seedPair();
      const rt1 = (await refresh(rt0)).body.refresh_token as string;
      const pause = pauseInsideLock(usersRepository, "isDisabled");

      const live = refresh(rt1);
      await pause.arrived;
      const reuse = refresh(rt0);
      const queued = await queuedBehind([reuse], 1);
      pause.release();

      const [liveRes, reuseRes] = await Promise.all([live, reuse]);
      expect(await liveRows(familyId)).toEqual([]);
      expect(liveRes.status).toBe(200);
      expect(reuseRes.status).toBe(400);
      expect(queued).toBe(true);
    });

    it("the reuse revoke holds the lock first: the waiting refresh finds nothing", async () => {
      const { refreshToken: rt0, familyId } = await seedPair();
      const rt1 = (await refresh(rt0)).body.refresh_token as string;
      // The reuse path re-reads its marker inside the lock.
      const pause = pauseInsideLock(
        oauthRepository,
        "getRotatedRefreshToken",
        1,
      );

      const reuse = refresh(rt0);
      // Without the lock the reuse request never pauses; it settles instead.
      await Promise.race([pause.arrived, reuse]);
      const live = refresh(rt1);
      const queued = await queuedBehind([live], 1);
      pause.release();

      const [reuseRes, liveRes] = await Promise.all([reuse, live]);
      expect(await liveRows(familyId)).toEqual([]);
      expect(reuseRes.status).toBe(400);
      expect(liveRes.status).toBe(400);
      expect(queued).toBe(true);
    });
  });

  // ------------------------------------------------------ /oauth/revoke

  describe("/oauth/revoke against a refresh in flight", () => {
    it("a live refresh token: the rotation that won is revoked with its family", async () => {
      const { refreshToken, familyId } = await seedPair();
      const pause = pauseInsideLock(usersRepository, "isDisabled");

      const inFlight = refresh(refreshToken);
      await pause.arrived;
      const revoking = revoke(refreshToken);
      const queued = await queuedBehind([revoking], 1);
      pause.release();

      const [res, revokeRes] = await Promise.all([inFlight, revoking]);
      expect(await liveRows(familyId)).toEqual([]);
      expect((await refresh(res.body.refresh_token as string)).status).toBe(
        400,
      );
      expect(res.status).toBe(200);
      expect(revokeRes.status).toBe(200);
      expect(queued).toBe(true);
    });

    it("a live access token: the same, through the access-token branch", async () => {
      const { access, refreshToken, familyId } = await seedPair();
      const pause = pauseInsideLock(usersRepository, "isDisabled");

      const inFlight = refresh(refreshToken);
      await pause.arrived;
      const revoking = revoke(access);
      const queued = await queuedBehind([revoking], 1);
      pause.release();

      const [res, revokeRes] = await Promise.all([inFlight, revoking]);
      expect(await liveRows(familyId)).toEqual([]);
      expect(res.status).toBe(200);
      expect(revokeRes.status).toBe(200);
      expect(queued).toBe(true);
    });

    it("the revoke holds the lock first: the waiting refresh finds nothing", async () => {
      const { refreshToken, familyId } = await seedPair();
      const pause = pauseInsideLock(oauthRepository, "deleteByRefreshToken");

      const revoking = revoke(refreshToken);
      await pause.arrived;
      const inFlight = refresh(refreshToken);
      const queued = await queuedBehind([inFlight], 1);
      pause.release();

      const [revokeRes, res] = await Promise.all([revoking, inFlight]);
      expect(await liveRows(familyId)).toEqual([]);
      expect(revokeRes.status).toBe(200);
      expect(res.status).toBe(400);
      expect(queued).toBe(true);
    });

    it("a refresh token that was already rotated out revokes the family through its marker", async () => {
      const { refreshToken: rt0, familyId } = await seedPair();
      const rt1 = (await refresh(rt0)).body.refresh_token as string;

      expect((await revoke(rt0)).status).toBe(200);

      expect(await liveRows(familyId)).toEqual([]);
      expect(await markers(familyId)).toEqual([]);
      expect((await refresh(rt1)).status).toBe(400);
      // A replay now resolves to nothing and is still answered 200.
      expect((await revoke(rt0)).status).toBe(200);
    });

    it("still refuses a client_id the token was not issued to, and leaves the token", async () => {
      const { refreshToken, familyId } = await seedPair();

      const res = await revoke(refreshToken, { client_id: SECRET_CLIENT_ID });

      expect(res.status).toBe(400);
      expect(await liveRows(familyId)).toHaveLength(1);
      expect((await refresh(refreshToken)).status).toBe(200);
    });
  });

  // --------------------------------------------- code redemption vs revoke

  describe("authorization-code redemption against users.revokeAccess", () => {
    it("redemption holds the lock first: the revoke deletes the pair it minted", async () => {
      const { code, verifier } = await seedCode();
      // Paused after the code is consumed, at the insert of the new pair.
      const pause = pauseInsideLock(oauthRepository, "setAccessToken");

      const redeeming = redeemCode(code, verifier);
      await pause.arrived;
      const revoked = usersRepository.revokeAccess(USER_ID);
      const queued = await queuedBehind([revoked], 1);
      pause.release();

      const [res, counts] = await Promise.all([redeeming, revoked]);
      expect(await liveRows()).toEqual([]);
      expect(res.status).toBe(200);
      expect(counts.oauth_tokens_deleted).toBe(1);
      expect(queued).toBe(true);
    });

    it("revoke holds the lock first: the waiting redemption finds the code gone", async () => {
      const { code, verifier } = await seedCode();
      await seedSession();
      const rowLock = await holdSessionRowLock();

      const revoked = usersRepository.revokeAccess(USER_ID);
      await waitForWaiters("row", 1);
      const redeeming = redeemCode(code, verifier);
      const queued = await queuedBehind([redeeming], 1);
      await rowLock.release();

      const [counts, res] = await Promise.all([revoked, redeeming]);
      expect(await liveRows()).toEqual([]);
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("invalid_grant");
      expect(counts.authorization_codes_deleted).toBe(1);
      expect(queued).toBe(true);
    });
  });

  // ------------------------------------------------ consent vs revoke

  describe("consent approval against users.revokeAccess", () => {
    it("refuses a session that expires while approval waits for the user lock", async () => {
      const flow = await signUpAndAuthorize();
      let release!: () => void;
      let entered!: () => void;
      const held = new Promise<void>((resolve) => {
        entered = resolve;
      });
      const released = new Promise<void>((resolve) => {
        release = resolve;
      });
      const holder = oauthRepository.withUserLock(USER_ID, async () => {
        entered();
        await released;
      });
      await held;
      const approving = approve(flow);
      let queued: boolean;
      try {
        queued = await queuedBehind([approving], 1);
        // The approval transaction has started and is waiting. Expire its
        // session after that start, so SQL now() would still see it as live.
        await observer.query(
          `UPDATE sessions SET expires_at = clock_timestamp() WHERE user_id = $1`,
          [USER_ID],
        );
      } finally {
        release();
        await holder;
      }
      const decision = await approving;

      expect(queued).toBe(true);
      expect(decision.status).toBe(403);
      expect(decision.code).toBeUndefined();
      expect(await codesForUser()).toEqual([]);
    });

    it("approval holds the lock first: the revoke deletes the code it stored", async () => {
      const flow = await signUpAndAuthorize();
      // Paused at the code insert, after every consent check passed.
      const pause = pauseInsideLock(oauthRepository, "setAuthCode");

      const approving = approve(flow);
      await pause.arrived;
      const revoked = usersRepository.revokeAccess(USER_ID);
      const queued = await queuedBehind([revoked], 1);
      pause.release();

      const [decision, counts] = await Promise.all([approving, revoked]);
      expect(await codesForUser()).toEqual([]);
      const redeemed = await redeemCode(decision.code as string, flow.verifier);
      expect(redeemed.status).toBe(400);
      expect(decision.status).toBe(200);
      expect(counts.authorization_codes_deleted).toBe(1);
      expect(queued).toBe(true);
    });

    it("revoke holds the lock first: the waiting approval stores no code", async () => {
      const flow = await signUpAndAuthorize();
      const rowLock = await holdSessionRowLock();

      const revoked = usersRepository.revokeAccess(USER_ID);
      await waitForWaiters("row", 1);
      const approving = approve(flow);
      const queued = await queuedBehind([approving], 1);
      await rowLock.release();

      const [counts, decision] = await Promise.all([revoked, approving]);
      expect(await codesForUser()).toEqual([]);
      expect(decision.status).toBe(403);
      expect(decision.code).toBeUndefined();
      expect(counts.sessions_deleted).toBeGreaterThanOrEqual(1);
      expect(queued).toBe(true);
    });

    it("a fresh sign-in after the revoke approves and redeems normally", async () => {
      await usersRepository.revokeAccess(USER_ID);
      const flow = await signUpAndAuthorize();

      const decision = await approve(flow);
      expect(decision.status).toBe(200);
      const redeemed = await redeemCode(decision.code as string, flow.verifier);
      expect(redeemed.status).toBe(200);
    });
  });

  // ------------------------------------------------------------ rollback

  describe("a failed insert rolls everything in its transaction back", () => {
    it("refresh: the claim and the rotated marker are undone and the token still works", async () => {
      const { refreshToken, familyId } = await seedPair();
      vi.spyOn(oauthRepository, "setAccessToken").mockRejectedValueOnce(
        new Error("simulated insert failure"),
      );

      const failed = await refresh(refreshToken);
      expect(failed.status).toBe(500);
      expect(await liveRows(familyId)).toHaveLength(1);
      expect(await markers(familyId)).toEqual([]);

      vi.restoreAllMocks();
      expect((await refresh(refreshToken)).status).toBe(200);
    });

    it("code redemption: the consumed code is restored and redeems on retry", async () => {
      const { code, verifier } = await seedCode();
      vi.spyOn(oauthRepository, "setAccessToken").mockRejectedValueOnce(
        new Error("simulated insert failure"),
      );

      expect((await redeemCode(code, verifier)).status).toBe(500);
      expect(await codesForUser()).toHaveLength(1);
      expect(await liveRows()).toEqual([]);

      vi.restoreAllMocks();
      expect((await redeemCode(code, verifier)).status).toBe(200);
    });
  });

  // ------------------------------------------- refusals that consume nothing

  describe("refusals still leave the token in place", () => {
    it("a disabled account is refused and refreshes again once re-enabled", async () => {
      const { refreshToken, familyId } = await seedPair();
      await usersRepository.setDisabled(USER_ID, true, USER_ID);

      expect((await refresh(refreshToken)).status).toBe(400);
      expect(await liveRows(familyId)).toHaveLength(1);

      await usersRepository.setDisabled(USER_ID, false, USER_ID);
      expect((await refresh(refreshToken)).status).toBe(200);
    });

    it("a client_id the token was not issued to is refused without rotating", async () => {
      const { refreshToken, familyId } = await seedPair();

      const res = await refresh(refreshToken, { client_id: SECRET_CLIENT_ID });

      expect(res.status).toBe(400);
      expect(res.body.error).toBe("invalid_client");
      expect(await liveRows(familyId)).toHaveLength(1);
      expect(await markers(familyId)).toEqual([]);
    });

    it("an enforced confidential client without its secret is refused without rotating", async () => {
      process.env[REFRESH_CLIENT_AUTH_ENV] = "enforce";
      const access = `mcp_token_itest_${randomBytes(12).toString("hex")}`;
      const refreshToken = `mcp_refresh_itest_${randomBytes(12).toString("hex")}`;
      const familyId = randomUUID();
      await oauthRepository.setAccessToken(access, {
        client_id: SECRET_CLIENT_ID,
        user_id: USER_ID,
        scope: "mcp",
        expires_at: Date.now() + 3600_000,
        family_id: familyId,
        refresh: { token: refreshToken, expires_at: Date.now() + 86_400_000 },
      });

      const refused = await refresh(refreshToken, {
        client_id: SECRET_CLIENT_ID,
      });
      expect(refused.status).toBe(401);
      expect(await liveRows(familyId)).toHaveLength(1);

      const ok = await refresh(refreshToken, {
        client_id: SECRET_CLIENT_ID,
        client_secret: CLIENT_SECRET,
      });
      expect(ok.status).toBe(200);
    });
  });
});
