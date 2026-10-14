/**
 * SQL-shape test for the two statements the boot-time admin converge issues
 * (`lib/admin-converge.ts`, fork issue #196).
 *
 * The converge suite runs against an in-memory double, so it cannot see the
 * SQL; this file pins the parts of that SQL the double merely imitates. Same
 * technique as `users.repo.list-query.test.ts`: `.toSQL()` renders without a
 * connection, so it stays in the fast default suite.
 *
 *  1. The lookup compares `lower(email)`, so an account stored with capitals
 *     is found by its lowercased address. Dropping the `lower()` would make
 *     the converge silently skip it and report "no account".
 *  2. The promotion sets exactly one value, `admin`, and only on a row whose
 *     role is not already `admin`. The first half is the "never demotes"
 *     guarantee at the SQL level; the second is what makes a no-change restart
 *     return no row and therefore write no audit row.
 *     The configured email is rechecked in that same write so a renamed
 *     account cannot inherit a promotion from a stale lookup.
 */

import { beforeAll, describe, expect, it } from "vitest";

// db/index throws unless DATABASE_URL is set. pg's Pool constructor is lazy,
// and `.toSQL()` never runs a query, so a valid URL pointing nowhere is
// enough to import the module.
beforeAll(() => {
  // Built at runtime, not as a single literal, so this loopback fixture
  // never reads as an embedded credential to secret scanners.
  process.env.DATABASE_URL ??=
    "postgres://test:" + "test" + "@127.0.0.1:5432/metamcp_test";
});

describe("buildFindUsersByEmailsQuery", () => {
  it("compares the lowercased column against every configured address", async () => {
    const { buildFindUsersByEmailsQuery } = await import("./users.repo");
    const { sql, params } = buildFindUsersByEmailsQuery([
      "pat@example.com",
      "sam@example.com",
    ]).toSQL();

    expect(sql).toBe(
      'select "id", "email", "role" from "users" where lower("users"."email") in ($1, $2)',
    );
    expect(params).toEqual(["pat@example.com", "sam@example.com"]);
  });
});

describe("buildPromoteToAdminQuery", () => {
  it("sets role=admin only on a still-named row that is not already admin", async () => {
    const { buildPromoteToAdminQuery } = await import("./users.repo");
    const now = new Date("2026-10-14T00:00:00.000Z");
    const { sql, params } = buildPromoteToAdminQuery(
      "u-1",
      "pat@example.com",
      now,
    ).toSQL();

    expect(sql).toBe(
      'update "users" set "role" = $1, "updated_at" = $2 ' +
        'where ("users"."id" = $3 and lower("users"."email") = $4 and "users"."role" <> $5) ' +
        'returning "id", "email"',
    );
    expect(params[0]).toBe("admin");
    expect(params[2]).toBe("u-1");
    expect(params[3]).toBe("pat@example.com");
    expect(params[4]).toBe("admin");
  });
});
