/**
 * The M365 refresh-token rotation and reauth mark are compare-and-swap
 * statements, and the only honest test of that is a REAL Postgres: with the
 * database removed every case here would pass against a stub that agrees with
 * itself.
 *
 * What is pinned:
 *  - a rotation applies only while the row still holds the ciphertext the mint
 *    read AND is active, so a re-enrollment, an operator reauth mark, a real
 *    `usersRepository.revokeAccess`, a delete or another writer's rotation all
 *    beat a mint that was in flight, and a rotation never reactivates a row;
 *  - the reauth mark applies only against the ciphertext that was rejected, so a
 *    rejection of an old grant cannot mark a re-enrolled row;
 *  - the rewrap swap changes nothing but the ciphertext and key id;
 *  - two rotations built from one read cannot both apply, shown with a writer
 *    that is held open inside its transaction (Read Committed re-evaluates the
 *    WHERE clause against the committed row, PostgreSQL documentation 13.2.1);
 *  - the mint service, driven end to end against this real repository,
 *    reconciles a write that committed before throwing, a rewrap that landed
 *    during the mint, and an old grant's late terminal failure after a
 *    re-enrollment.
 *
 * Lock order is forced by watching pg_locks, never by timing: the second writer
 * is released only after it is seen queued behind the open transaction.
 *
 * Opt-in via TEST_DATABASE_URL, pointed at a disposable, migrated database:
 *
 *   cd apps/backend
 *   DATABASE_URL=<url> npx drizzle-kit migrate
 *   TEST_DATABASE_URL=<url> npx vitest run \
 *     src/db/repositories/m365-tokens.cas.integration.test.ts
 */
import { randomBytes, randomUUID } from "node:crypto";

import { eq, inArray } from "drizzle-orm";
import { Client, type PoolClient } from "pg";
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

import {
  decryptRefreshToken,
  encryptRefreshToken,
} from "../../lib/m365/crypto";
import { M365MintService } from "../../lib/m365/mint-service";
import logger from "../../utils/logger";
import { INTEGRATION_DB_LOCK_KEY } from "./integration-db-lock";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
type Db = (typeof import("../index"))["db"];
type Pool = (typeof import("../index"))["pool"];
type Schema = typeof import("../schema");
type TokensRepo = (typeof import("./m365-tokens.repo"))["m365TokensRepository"];
type UsersRepo = (typeof import("./users.repo"))["usersRepository"];

const KEK = randomBytes(32);
const ctxFor = (userId: string) => `m365-refresh-token:${userId}`;

describe.skipIf(!TEST_DATABASE_URL)(
  "m365_user_tokens compare-and-swap against a real Postgres",
  () => {
    let db: Db;
    let pool: Pool;
    let schema: Schema;
    let repo: TokensRepo;
    let usersRepo: UsersRepo;
    let suiteLock: PoolClient;
    let observer: Client;
    let holder: Client;
    let userId: string;
    const created: string[] = [];

    /** A fresh user row and an enrollment holding `plaintext`, as `version`. */
    async function enrolled(
      plaintext: string,
      version: "v1" | "v2" = "v1",
      forUser = userId,
    ) {
      const rt_ciphertext = encryptRefreshToken(
        plaintext,
        KEK,
        "k1",
        version === "v2" ? ctxFor(forUser) : undefined,
      );
      await repo.upsertEnrollment({
        user_id: forUser,
        entra_oid: "oid-1",
        tenant_id: "tid-1",
        entra_upn: "fixture@example.com",
        rt_ciphertext,
        kek_id: "k1",
        scopes_granted: "User.Read",
      });
      return rt_ciphertext;
    }

    async function createUser(): Promise<string> {
      const id = randomUUID();
      await db.insert(schema.usersTable).values({
        id,
        name: "m365 CAS fixture",
        email: `m365-cas-${id}@example.com`,
        role: "member",
      });
      created.push(id);
      return id;
    }

    async function rowOf(forUser = userId) {
      const [row] = await db
        .select()
        .from(schema.m365UserTokensTable)
        .where(eq(schema.m365UserTokensTable.user_id, forUser));
      return row;
    }

    /** Wait (no sleep) until some writer is queued on a row lock for our table. */
    async function waitForQueuedWriter(): Promise<void> {
      for (let attempt = 0; attempt < 200_000; attempt++) {
        const { rows } = await observer.query<{ n: number }>(
          `SELECT count(*)::int AS n
             FROM pg_locks l
             JOIN pg_stat_activity a ON a.pid = l.pid
            WHERE l.locktype = 'transactionid'
              AND NOT l.granted
              AND a.query ILIKE '%m365_user_tokens%'
              AND a.pid <> pg_backend_pid()`,
        );
        if ((rows[0]?.n ?? 0) >= 1) return;
      }
      throw new Error(
        "the second rotation never queued behind the open transaction",
      );
    }

    beforeAll(async () => {
      process.env.DATABASE_URL = TEST_DATABASE_URL;
      ({ db, pool } = await import("../index"));
      schema = await import("../schema");
      ({ m365TokensRepository: repo } = await import("./m365-tokens.repo"));
      ({ usersRepository: usersRepo } = await import("./users.repo"));
      // Other integration files truncate shared tables: hold their common
      // session lock on a dedicated connection until cleanup finishes.
      suiteLock = await pool.connect();
      await suiteLock.query("SELECT pg_advisory_lock($1)", [
        INTEGRATION_DB_LOCK_KEY,
      ]);
      observer = new Client({ connectionString: TEST_DATABASE_URL });
      await observer.connect();
      holder = new Client({ connectionString: TEST_DATABASE_URL });
      await holder.connect();
    });

    beforeEach(async () => {
      userId = await createUser();
      vi.stubEnv("M365_TENANT_ID", "tid-1");
      vi.stubEnv("M365_CLIENT_ID", "cid-1");
      vi.stubEnv("M365_CLIENT_SECRET", "secret-1");
      vi.stubEnv("M365_TOKEN_KEK", KEK.toString("base64"));
      vi.stubEnv("APP_URL", "https://mcp.example.com");
      vi.stubEnv("M365_ENVELOPE_WRITE_VERSION", "");
      vi.stubEnv("M365_ENVELOPE_STRICT", "");
      // The mint service logs every mint; keep the test output readable.
      for (const level of ["info", "warn", "error"] as const) {
        vi.spyOn(logger, level).mockImplementation(() => undefined);
      }
    });

    afterEach(async () => {
      vi.unstubAllEnvs();
      vi.restoreAllMocks();
      try {
        await holder.query("ROLLBACK");
      } catch {
        // No open transaction: nothing to roll back.
      }
      // The token rows cascade with their user.
      if (created.length > 0) {
        await db
          .delete(schema.usersTable)
          .where(inArray(schema.usersTable.id, created.splice(0)));
      }
    });

    afterAll(async () => {
      try {
        await suiteLock?.query("SELECT pg_advisory_unlock($1)", [
          INTEGRATION_DB_LOCK_KEY,
        ]);
      } finally {
        suiteLock?.release();
        await observer?.end();
        await holder?.end();
        await pool?.end();
      }
    });

    // ------------------------------------------------------------ rotation

    it("rotates when the stored ciphertext matches and the row is active", async () => {
      const x = await enrolled("rt-x");
      const before = await rowOf();

      expect(await repo.rotateRefreshToken(userId, "ct-y", "k2", x)).toBe(true);

      const after = await rowOf();
      expect(after.rt_ciphertext).toBe("ct-y");
      expect(after.kek_id).toBe("k2");
      expect(after.status).toBe("active");
      expect(after.rotated_at).not.toBeNull();
      expect(after.last_used_at).not.toBeNull();
      expect(after.uuid).toBe(before.uuid);
    });

    it("does not overwrite a re-enrollment that landed between the read and the write", async () => {
      const x = await enrolled("rt-x");
      // The mint read X; the user re-enrolls; the mint then tries to write.
      const y = await enrolled("rt-y");

      expect(await repo.rotateRefreshToken(userId, "ct-z", "k1", x)).toBe(
        false,
      );
      expect((await rowOf()).rt_ciphertext).toBe(y);
    });

    it("does not reactivate a row an operator marked reauth_required", async () => {
      const x = await enrolled("rt-x");
      await repo.markReauthRequired(userId, x);

      expect(await repo.rotateRefreshToken(userId, "ct-y", "k1", x)).toBe(
        false,
      );
      const after = await rowOf();
      expect(after.status).toBe("reauth_required");
      expect(after.rt_ciphertext).toBe(x);
    });

    it("does not undo the real usersRepository.revokeAccess", async () => {
      const x = await enrolled("rt-x");
      // The third writer of this table, driven through the real method inside
      // its own locked transaction, not re-implemented here.
      const summary = await usersRepo.revokeAccess(userId);
      expect(summary.m365_tokens_revoked).toBe(1);

      expect(await repo.rotateRefreshToken(userId, "ct-y", "k1", x)).toBe(
        false,
      );
      const after = await rowOf();
      expect(after.status).toBe("reauth_required");
      expect(after.rt_ciphertext).toBe(x);
    });

    it("returns false for a row that was deleted", async () => {
      const x = await enrolled("rt-x");
      await repo.deleteByUserId(userId);

      expect(await repo.rotateRefreshToken(userId, "ct-y", "k1", x)).toBe(
        false,
      );
      expect(await rowOf()).toBeUndefined();
    });

    // ----------------------------------------------------------- reauth mark

    it("marks reauth_required only against the ciphertext that was rejected", async () => {
      const x = await enrolled("rt-x");
      const y = await enrolled("rt-y"); // re-enrolled after X was read

      await repo.markReauthRequired(userId, x);
      expect((await rowOf()).status).toBe("active");

      await repo.markReauthRequired(userId, y);
      expect((await rowOf()).status).toBe("reauth_required");
    });

    // ---------------------------------------------------------------- rewrap

    it("replaceCiphertextIfUnchanged applies only on a match and changes nothing but the ciphertext and key id", async () => {
      const x = await enrolled("rt-x");
      await repo.rotateRefreshToken(userId, x, "k1", x); // stamps the timestamps
      await repo.markReauthRequired(userId, x); // a non-default status
      const before = await rowOf();

      expect(
        await repo.replaceCiphertextIfUnchanged(userId, "stale", "ct-n", "k9"),
      ).toBe(false);
      expect((await rowOf()).rt_ciphertext).toBe(x);

      expect(
        await repo.replaceCiphertextIfUnchanged(userId, x, "ct-n", "k9"),
      ).toBe(true);
      const after = await rowOf();
      expect(after.rt_ciphertext).toBe("ct-n");
      expect(after.kek_id).toBe("k9");
      // Not a rotation, and not its job to change the row's lifecycle.
      expect(after.status).toBe("reauth_required");
      expect(after.rotated_at?.getTime()).toBe(before.rotated_at?.getTime());
      expect(after.last_used_at?.getTime()).toBe(
        before.last_used_at?.getTime(),
      );
    });

    it("listEnvelopes returns every row in any status, with two columns only", async () => {
      const other = await createUser();
      const third = await createUser();
      const a = await enrolled("rt-a");
      const b = await enrolled("rt-b", "v2", other);
      const c = await enrolled("rt-c", "v1", third);
      await repo.markReauthRequired(other, b);

      const listed = (await repo.listEnvelopes()).filter((row) =>
        [userId, other, third].includes(row.user_id),
      );

      expect(
        Object.fromEntries(listed.map((r) => [r.user_id, r.rt_ciphertext])),
      ).toEqual({ [userId]: a, [other]: b, [third]: c });
      for (const row of listed) {
        expect(Object.keys(row).sort()).toEqual(["rt_ciphertext", "user_id"]);
      }
    });

    // ----------------------------------------------------------- concurrency

    it("a second rotation built from the same read loses to a writer held open inside its transaction", async () => {
      const x = await enrolled("rt-x");

      // The first writer's UPDATE (X to Y) runs and stays uncommitted.
      await holder.query("BEGIN");
      const first = await holder.query(
        `UPDATE m365_user_tokens
            SET rt_ciphertext = $1
          WHERE user_id = $2 AND rt_ciphertext = $3 AND status = 'active'`,
        ["ct-y", userId, x],
      );
      expect(first.rowCount).toBe(1);

      // The second rotation, from the same read, blocks on that row.
      const second = repo.rotateRefreshToken(userId, "ct-z", "k1", x);
      await waitForQueuedWriter();
      await holder.query("COMMIT");

      // Read Committed re-evaluates the WHERE clause against the committed row
      // (ciphertext now Y), so the second rotation matches nothing.
      expect(await second).toBe(false);
      expect((await rowOf()).rt_ciphertext).toBe("ct-y");
    });

    it("exactly one of two simultaneous rotations from one read applies", async () => {
      const x = await enrolled("rt-x");

      const results = await Promise.all([
        repo.rotateRefreshToken(userId, "ct-1", "k1", x),
        repo.rotateRefreshToken(userId, "ct-2", "k1", x),
      ]);

      expect(results.filter(Boolean)).toHaveLength(1);
      const winner = results[0] ? "ct-1" : "ct-2";
      expect((await rowOf()).rt_ciphertext).toBe(winner);
    });

    // ---------------------------------- the mint service over the real repo

    function tokenResponse(body: Record<string, unknown>, status = 200) {
      return new Response(JSON.stringify(body), {
        status,
        headers: { "Content-Type": "application/json" },
      });
    }
    const presentedRt = (init?: RequestInit) =>
      new URLSearchParams(String(init?.body)).get("refresh_token") ?? "";
    const stored = async () => {
      const row = await rowOf();
      return decryptRefreshToken(row.rt_ciphertext, KEK, ctxFor(row.user_id));
    };

    it("reconciles a write that committed before the connection failed (real SQL miss, then re-read)", async () => {
      await enrolled("A");
      // The real write commits, then the caller sees an error: the retry then
      // misses against the real row and must be recognised as already applied.
      let thrown = false;
      const flaky = new Proxy(repo, {
        get(target, prop, receiver) {
          if (prop !== "rotateRefreshToken") {
            return Reflect.get(target, prop, receiver);
          }
          return async (
            ...args: Parameters<TokensRepo["rotateRefreshToken"]>
          ) => {
            const applied = await target.rotateRefreshToken(...args);
            if (applied && !thrown) {
              thrown = true;
              throw new Error("connection reset after commit");
            }
            return applied;
          };
        },
      });
      const fetchStub = vi.fn(async (_url: string | URL, init?: RequestInit) =>
        tokenResponse({
          access_token: `at:${presentedRt(init)}`,
          refresh_token: `${presentedRt(init)}>`,
          expires_in: 3600,
        }),
      );
      const service = new M365MintService(flaky, fetchStub as typeof fetch);

      expect(await service.getAccessToken(userId)).toBe("at:A");

      expect(thrown).toBe(true);
      expect(await stored()).toBe("A>");
      expect((await rowOf()).status).toBe("active");
    });

    it("re-seals and applies when a rewrap of the same grant lands during the mint", async () => {
      const original = await enrolled("A");
      const rewrapped = encryptRefreshToken("A", KEK, "k1", ctxFor(userId));
      const fetchStub = vi.fn(
        async (_url: string | URL, init?: RequestInit) => {
          // The boot converge of another process, through the real repository.
          expect(
            await repo.replaceCiphertextIfUnchanged(
              userId,
              original,
              rewrapped,
              "k1",
            ),
          ).toBe(true);
          return tokenResponse({
            access_token: `at:${presentedRt(init)}`,
            refresh_token: `${presentedRt(init)}>`,
            expires_in: 3600,
          });
        },
      );
      const service = new M365MintService(repo, fetchStub as typeof fetch);

      expect(await service.getAccessToken(userId)).toBe("at:A");

      const after = await rowOf();
      expect(after.rt_ciphertext.startsWith("v2.")).toBe(true);
      expect(await stored()).toBe("A>");
      expect(after.status).toBe("active");
    });

    it("an old grant's late terminal failure after a re-enrollment leaves the re-enrolled row active", async () => {
      await enrolled("A");
      let releaseOld!: (response: Response) => void;
      const gate = new Promise<Response>((resolve) => {
        releaseOld = resolve;
      });
      let arrived!: () => void;
      const reachedEntra = new Promise<void>((resolve) => {
        arrived = resolve;
      });
      const fetchStub = vi.fn(async () => {
        arrived();
        return gate;
      });
      // Observe the fire-and-forget conditional mark so the test can wait for
      // the real UPDATE to finish instead of guessing when it has.
      let markDone: Promise<void> | undefined;
      const observed = new Proxy(repo, {
        get(target, prop, receiver) {
          if (prop !== "markReauthRequired") {
            return Reflect.get(target, prop, receiver);
          }
          return (...args: Parameters<TokensRepo["markReauthRequired"]>) => {
            markDone = target.markReauthRequired(...args);
            return markDone;
          };
        },
      });
      const service = new M365MintService(observed, fetchStub as typeof fetch);

      const oldCaller = service.getAccessToken(userId);
      const oldOutcome = oldCaller.then(
        () => "resolved",
        (error: { code: string }) => error.code,
      );
      await reachedEntra;

      // Re-enrollment lands while the old grant's redemption is in flight.
      const fresh = await enrolled("NEW");
      service.invalidateUser(userId);

      // Entra now rejects the OLD grant.
      releaseOld(
        tokenResponse(
          {
            error: "invalid_grant",
            error_description: "AADSTS700082: expired",
            error_codes: [700082],
          },
          400,
        ),
      );
      expect(await oldOutcome).toBe("credential_expired");
      // The mark is fire-and-forget: let its scheduling run, then wait for the
      // real UPDATE itself. A mark that was never issued fails here, rather
      // than the row check below passing for the wrong reason.
      for (let i = 0; i < 25; i++) await Promise.resolve();
      expect(markDone).toBeDefined();
      await markDone;

      const after = await rowOf();
      expect(after.status).toBe("active");
      expect(after.rt_ciphertext).toBe(fresh);
    });
  },
);
