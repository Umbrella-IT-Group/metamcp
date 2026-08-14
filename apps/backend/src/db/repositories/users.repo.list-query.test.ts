/**
 * SQL-shape test for the admin user listing.
 *
 * This fork has no live-DB test harness (see the note in
 * api-keys.repo.member-scope.test.ts), and `buildUserListQuery` hand-builds
 * three CORRELATED SUBQUERIES via drizzle's `sql` template — a construction
 * that type-checks whatever it emits. So the SQL text itself is the thing
 * worth pinning: `.toSQL()` renders the statement without opening a
 * connection.
 *
 * Two properties are asserted, and each maps to a way this query has a
 * realistic chance of going wrong:
 *
 *  1. The counts are SUBQUERIES, not joins. Three one-to-many LEFT JOINs off
 *     the same driving table multiply each other's rows — a user with 2
 *     sessions and 3 keys would report 6 of each. A future "simplification"
 *     to joins is the likely regression, and it produces plausible-looking
 *     wrong numbers on a security screen rather than an error.
 *  2. Every subquery is CORRELATED to the outer user row. Losing the
 *     `"users"."id"` correlation turns each count into a deployment-wide
 *     total, so every account would show the same (large) live-access counts
 *     and an idle attacker account would look busy.
 */

import { beforeAll, describe, expect, it } from "vitest";

// db/index throws unless DATABASE_URL is set. pg's Pool constructor is lazy —
// it opens no socket until a query runs, and `.toSQL()` never runs one — so a
// syntactically valid URL pointing nowhere is enough to import the module.
beforeAll(() => {
  process.env.DATABASE_URL ??=
    "postgres://test:test@127.0.0.1:5432/metamcp_test";
});

const NOW = new Date("2026-08-14T00:00:00.000Z");

describe("buildUserListQuery", () => {
  it("counts each access path with a correlated subquery, not a join", async () => {
    const { buildUserListQuery } = await import("./users.repo");
    const { sql } = buildUserListQuery(NOW).toSQL();

    // Three independent counts + the last-active max, each parenthesised as
    // its own scalar subselect in the projection.
    expect(sql).toContain(
      `(select count(*) from "sessions" where ("sessions"."user_id" = "users"."id"`,
    );
    expect(sql).toContain(
      `(select count(*) from "oauth_access_tokens" where ("oauth_access_tokens"."user_id" = "users"."id"`,
    );
    expect(sql).toContain(
      `(select count(*) from "api_keys" where ("api_keys"."user_id" = "users"."id"`,
    );
    expect(sql).toContain(
      `(select max("updated_at") from "sessions" where "sessions"."user_id" = "users"."id")`,
    );

    // No join anywhere: `from "users"` is the only table in the outer query.
    expect(sql).not.toMatch(/\bjoin\b/i);
  });

  it("filters the counts to LIVE access and orders newest account first", async () => {
    const { buildUserListQuery } = await import("./users.repo");
    const { sql, params } = buildUserListQuery(NOW).toSQL();

    // Liveness predicates: unexpired sessions, unexpired tokens, active keys.
    expect(sql).toContain(`"sessions"."expires_at" > $`);
    expect(sql).toContain(`"oauth_access_tokens"."expires_at" > $`);
    expect(sql).toContain(`"api_keys"."is_active" = $`);
    expect(sql).toContain(`order by "users"."created_at" desc`);

    // ONE `now`, bound twice — both expiry predicates are judged against the
    // same instant, so a user's session and token counts cannot disagree
    // about what "expired" means. (drizzle renders a Date parameter as a
    // string in the bound-parameter list, hence the parse rather than an
    // identity comparison.)
    const timestamps = params.filter(
      (p) => p instanceof Date || typeof p === "string",
    );
    expect(timestamps).toHaveLength(2);
    expect(new Date(timestamps[0] as string | Date).getTime()).toBe(
      NOW.getTime(),
    );
    expect(timestamps[1]).toEqual(timestamps[0]);
  });

  it("selects no credential column", async () => {
    const { buildUserListQuery } = await import("./users.repo");
    const { sql } = buildUserListQuery(NOW).toSQL();

    // `users` carries no secret today, but the projection is an explicit
    // allow-list precisely so that stays true as columns are added. A bare
    // `select *` would silently pick up whatever lands there next.
    expect(sql).not.toContain("select *");
    expect(sql).not.toMatch(/"password"|"token"|"secret"/);
  });
});
