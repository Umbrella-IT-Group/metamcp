/**
 * A signed-in user cannot set their own `emailVerified`, through the real
 * better-auth instance from ./auth against a REAL Postgres; an ordinary
 * profile update still works.
 *
 * `role` and `disabled` were already not settable; this pins all three so the
 * boundary is tested where better-auth enforces it, not assumed from config.
 *
 * Opt-in via TEST_DATABASE_URL, pointed at a disposable, migrated database:
 *
 *   cd apps/backend
 *   DATABASE_URL=<url> npx drizzle-kit migrate
 *   TEST_DATABASE_URL=<url> npx vitest run src/auth.email-verified.integration.test.ts
 */

import { Client } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { INTEGRATION_DB_LOCK_KEY } from "./db/repositories/integration-db-lock";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

const quiet = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
vi.mock("@/utils/logger", () => ({ default: quiet }));

const RUN = Date.now().toString(36);
const EMAIL = `itest-email-verified-${RUN}@example.test`;
const ORIGIN = "http://127.0.0.1:1";

describeIfDb(
  "better-auth user fields a user cannot set (real Postgres)",
  () => {
    let auth: typeof import("./auth").auth;
    let db: typeof import("./db/index").db;
    let schema: typeof import("./db/schema");
    let eq: typeof import("drizzle-orm").eq;
    let suiteLock: Client;
    let cookie = "";

    async function call(path: string, body: unknown) {
      const headers = new Headers({
        "content-type": "application/json",
        origin: ORIGIN,
      });
      if (cookie) headers.set("cookie", cookie);
      const res = await auth.handler(
        new Request(`${ORIGIN}/api/auth${path}`, {
          method: "POST",
          headers,
          body: JSON.stringify(body),
        }),
      );
      const setCookie = (res.headers.getSetCookie?.() ?? [])
        .map((c) => c.split(";")[0])
        .join("; ");
      return { status: res.status, setCookie };
    }

    async function row() {
      const [user] = await db
        .select({
          name: schema.usersTable.name,
          role: schema.usersTable.role,
          disabled: schema.usersTable.disabled,
          emailVerified: schema.usersTable.emailVerified,
        })
        .from(schema.usersTable)
        .where(eq(schema.usersTable.email, EMAIL));
      return user;
    }

    beforeAll(async () => {
      process.env.DATABASE_URL = TEST_DATABASE_URL;
      process.env.BETTER_AUTH_SECRET = `itest-throwaway-secret-${RUN}`;
      process.env.APP_URL = ORIGIN;
      suiteLock = new Client({ connectionString: TEST_DATABASE_URL });
      await suiteLock.connect();
      await suiteLock.query(
        `SELECT pg_advisory_lock(${INTEGRATION_DB_LOCK_KEY})`,
      );

      ({ db } = await import("./db/index"));
      schema = await import("./db/schema");
      ({ eq } = await import("drizzle-orm"));
      ({ auth } = await import("./auth"));
      await db
        .delete(schema.usersTable)
        .where(eq(schema.usersTable.email, EMAIL));
    }, 60_000);

    afterAll(async () => {
      if (db) {
        await db
          .delete(schema.usersTable)
          .where(eq(schema.usersTable.email, EMAIL));
        const { pool } = await import("./db/index");
        await pool.end();
      }
      await suiteLock?.query(
        `SELECT pg_advisory_unlock(${INTEGRATION_DB_LOCK_KEY})`,
      );
      await suiteLock?.end();
    });

    it("ignores emailVerified on sign-up", async () => {
      const res = await call("/sign-up/email", {
        email: EMAIL,
        password: `itest-throwaway-password-${RUN}`,
        name: "itest user",
        emailVerified: true,
      });
      expect(res.status).toBe(200);
      cookie = res.setCookie;

      expect(await row()).toMatchObject({
        emailVerified: false,
        role: "member",
        disabled: false,
      });
    });

    it("refuses emailVerified on update-user and leaves the stored value", async () => {
      const res = await call("/update-user", { emailVerified: true });

      expect(res.status).toBe(400);
      expect((await row())?.emailVerified).toBe(false);
    });

    it("refuses role and disabled on update-user as before", async () => {
      expect((await call("/update-user", { role: "admin" })).status).toBe(400);
      expect((await call("/update-user", { disabled: true })).status).toBe(400);
      expect(await row()).toMatchObject({ role: "member", disabled: false });
    });

    it("still applies an ordinary profile update", async () => {
      const res = await call("/update-user", { name: "itest renamed" });

      expect(res.status).toBe(200);
      expect((await row())?.name).toBe("itest renamed");
    });
  },
);
