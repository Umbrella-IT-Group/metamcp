/**
 * Boot promotion must still name the account at the write, not only at the
 * preceding lookup. Opt-in TEST_DATABASE_URL uses a throwaway database; these
 * tests insert and remove only their own uniquely named fixture accounts.
 */
import { randomUUID } from "node:crypto";

import { eq } from "drizzle-orm";
import type { PoolClient } from "pg";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
} from "vitest";

import { INTEGRATION_DB_LOCK_KEY } from "./integration-db-lock";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
type Db = (typeof import("../index"))["db"];
type Pool = (typeof import("../index"))["pool"];
type UsersTable = (typeof import("../schema"))["usersTable"];
type Repo = (typeof import("./users.repo"))["usersRepository"];

let db: Db;
let pool: Pool;
let usersTable: UsersTable;
let repo: Repo;
let id: string;
let configuredEmail: string;
let lockClient: PoolClient | undefined;

describe.skipIf(!TEST_DATABASE_URL)(
  "boot admin promotion checks its named address at write time",
  () => {
    beforeAll(async () => {
      process.env.DATABASE_URL = TEST_DATABASE_URL;
      ({ db, pool } = await import("../index"));
      ({ usersTable } = await import("../schema"));
      ({ usersRepository: repo } = await import("./users.repo"));
      // Other integration files truncate shared tables. Hold their common
      // session lock on a dedicated connection until fixture cleanup finishes.
      lockClient = await pool.connect();
      await lockClient.query("SELECT pg_advisory_lock($1)", [
        INTEGRATION_DB_LOCK_KEY,
      ]);
    });

    beforeEach(async () => {
      id = randomUUID();
      configuredEmail = `admin-converge-${id}@example.com`;
      await db.insert(usersTable).values({
        id,
        name: "Admin converge fixture",
        email: configuredEmail,
        role: "member",
      });
    });

    afterEach(async () => {
      await db.delete(usersTable).where(eq(usersTable.id, id));
    });

    afterAll(async () => {
      try {
        if (lockClient) {
          await lockClient.query("SELECT pg_advisory_unlock($1)", [
            INTEGRATION_DB_LOCK_KEY,
          ]);
        }
      } finally {
        lockClient?.release();
        await pool?.end();
      }
    });

    it("does not promote an account whose email changed after the lookup", async () => {
      const [account] = await repo.findByEmailsIgnoringCase([configuredEmail]);
      expect(account.id).toBe(id);
      await db
        .update(usersTable)
        .set({ email: `renamed-${configuredEmail}` })
        .where(eq(usersTable.id, id));

      expect(
        await repo.promoteToAdmin(account.id, configuredEmail),
      ).toBeUndefined();
      const [after] = await db
        .select()
        .from(usersTable)
        .where(eq(usersTable.id, id));
      expect(after.role).toBe("member");
    });

    it("promotes the still-named account ignoring email case, once", async () => {
      await db
        .update(usersTable)
        .set({ email: configuredEmail.toUpperCase() })
        .where(eq(usersTable.id, id));

      expect(await repo.promoteToAdmin(id, configuredEmail)).toEqual({
        id,
        email: configuredEmail.toUpperCase(),
      });
      expect(await repo.promoteToAdmin(id, configuredEmail)).toBeUndefined();
      const [after] = await db
        .select()
        .from(usersTable)
        .where(eq(usersTable.id, id));
      expect(after.role).toBe("admin");
    });
  },
);
