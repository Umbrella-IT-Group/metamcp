/**
 * No-secret-leak AND driver-decode contract for the two Access-dashboard
 * listings.
 *
 * Redaction half: the 2026-08-13 pentest recovered three live gateway API
 * keys from a list route that returned `key` raw (see api-keys.serializer.ts).
 * These two listings are new surfaces of the same shape — one enumerates
 * accounts, the other enumerates live OAuth grants — so they get the same
 * treatment before they ship, not after somebody finds them. The rows fed in
 * are deliberately POLLUTED with credential-looking fields that a careless
 * `...row` spread would carry through.
 *
 * Decode half: `frontend.users.list` failed 100% of the time in its first cut
 * because a raw `sql` fragment returned `timestamptz` as the STRING
 * '2026-08-14 13:07:51.558+00', and the router's `.output()` schema demands a
 * Date. The serializer is the second line of defence against that class of
 * bug, so the fixtures below feed it exactly what an undecoded driver hands
 * back — strings for dates, strings for bigint counts — and the assertions
 * pin that the output still parses under the real contract.
 *
 * Rows are iterated rather than indexed throughout — `noUncheckedIndexedAccess`
 * makes `list[0]` possibly-undefined, and the sibling redaction.test.ts uses
 * the same loop instead of a non-null assertion.
 */

import {
  ActiveOAuthTokenItemSchema,
  UserListItemSchema,
} from "@repo/zod-types";
import { describe, expect, it } from "vitest";

import { OAuthTokensSerializer } from "./oauth-tokens.serializer";
import { UsersSerializer } from "./users.serializer";

const CREATED_AT = new Date("2026-08-13T12:00:00.000Z");
const EXPIRES_AT = new Date("2026-09-13T12:00:00.000Z");

// Credential material that must never reach a response body.
const SECRET_PASSWORD_HASH =
  "$2b$10$do.not.disclose.this.bcrypt.hash.value.ever";
const SECRET_ACCESS_TOKEN = "sk_mt_live_access_token_do_not_disclose";
const SECRET_REFRESH_TOKEN = "sk_mt_live_refresh_token_do_not_disclose";
const SECRET_SESSION_TOKEN = "session_token_do_not_disclose";

const dbUser = {
  id: "user-1",
  email: "attacker@example.invalid",
  name: "Self Registered",
  role: "member",
  emailVerified: false,
  disabled: false,
  disabled_at: null,
  disabled_by: null,
  created_at: CREATED_AT,
  updated_at: CREATED_AT,
  last_session_refresh_at: CREATED_AT,
  // count(*) is bigint, and node-postgres hands bigint back as a STRING.
  // Fed in as strings on purpose: the serializer must coerce, or the router's
  // `.output()` schema rejects the response at runtime.
  active_session_count: "2" as unknown as number,
  active_oauth_token_count: "1" as unknown as number,
  active_api_key_count: "3" as unknown as number,
  // Not columns on `users` today — better-auth keeps the hash on `accounts`.
  // Present here precisely because the serializer must be immune to whatever
  // the query happens to hand it.
  password: SECRET_PASSWORD_HASH,
  passwordHash: SECRET_PASSWORD_HASH,
  sessionToken: SECRET_SESSION_TOKEN,
} as unknown as Parameters<typeof UsersSerializer.serializeUserList>[0][number];

const dbToken = {
  user_id: "user-1",
  user_email: "attacker@example.invalid",
  client_id: "mcp_client_abc",
  client_name: "Claude",
  scope: "mcp",
  created_at: CREATED_AT,
  expires_at: EXPIRES_AT,
  has_refresh_token: true,
  refresh_token_expires_at: EXPIRES_AT,
  // The repository query never selects these. Injected anyway — the
  // serializer is the layer that must hold if the query is ever widened.
  access_token: SECRET_ACCESS_TOKEN,
  refresh_token: SECRET_REFRESH_TOKEN,
} as unknown as Parameters<
  typeof OAuthTokensSerializer.serializeActiveTokenList
>[0][number];

describe("UsersSerializer.serializeUserList", () => {
  it("emits exactly the documented field list — no credential fields", () => {
    const serializedList = UsersSerializer.serializeUserList([dbUser]);
    expect(serializedList).toHaveLength(1);

    for (const serialized of serializedList) {
      expect(Object.keys(serialized).sort()).toEqual(
        [
          "active_api_key_count",
          "active_oauth_token_count",
          "active_session_count",
          "created_at",
          "disabled",
          "disabled_at",
          "disabled_by",
          "email",
          "emailVerified",
          "id",
          "last_session_refresh_at",
          "name",
          "role",
          "updated_at",
        ].sort(),
      );

      expect(serialized).not.toHaveProperty("password");
      expect(serialized).not.toHaveProperty("passwordHash");
      expect(serialized).not.toHaveProperty("sessionToken");
    }
  });

  it("does not carry the password hash or session token anywhere in the payload", () => {
    const payload = JSON.stringify(UsersSerializer.serializeUserList([dbUser]));

    expect(payload).not.toContain(SECRET_PASSWORD_HASH);
    expect(payload).not.toContain(SECRET_SESSION_TOKEN);
    // Broad sweep: nothing that looks like a bcrypt hash or an sk_ scheme
    // token, whatever key it might have been hung under.
    expect(payload).not.toMatch(/\$2[aby]\$/);
    expect(payload).not.toMatch(/sk_[A-Za-z0-9_]+/);
  });

  it("coerces the bigint counts postgres returns as strings into numbers", () => {
    // Without this the `.output()` schema (z.number().int()) rejects every
    // list response at runtime — a failure that no type check would catch,
    // because the repository's TS type already claims `number`.
    for (const serialized of UsersSerializer.serializeUserList([dbUser])) {
      expect(serialized.active_session_count).toBe(2);
      expect(serialized.active_oauth_token_count).toBe(1);
      expect(serialized.active_api_key_count).toBe(3);
    }
  });

  it("parses under the real contract when EVERY date arrives as a driver string", () => {
    // The exact production failure, reproduced without a database: a raw
    // `sql` fragment carries no decoder, so node-postgres returns
    // timestamptz in this wire format. `.output()` then threw
    // "invalid_type: expected date, received string" and the whole listing
    // died for any account that had ever held a session.
    const undecoded = {
      ...dbUser,
      created_at: "2026-08-13 12:00:00+00",
      updated_at: "2026-08-13 12:00:00+00",
      last_session_refresh_at: "2026-08-14 13:07:51.558+00",
      disabled_at: "2026-08-14 09:00:00+00",
      disabled: true,
    } as unknown as Parameters<
      typeof UsersSerializer.serializeUserList
    >[0][number];

    for (const serialized of UsersSerializer.serializeUserList([undecoded])) {
      expect(serialized.last_session_refresh_at).toBeInstanceOf(Date);
      expect(serialized.created_at).toBeInstanceOf(Date);
      expect(serialized.disabled_at).toBeInstanceOf(Date);
      // The contract itself is the assertion that matters — this is what
      // tRPC runs on every response.
      expect(() => UserListItemSchema.parse(serialized)).not.toThrow();
    }
  });

  it("degrades an unparseable date to null rather than an Invalid Date", () => {
    // An Invalid Date IS a Date, so it sails through z.date() and surfaces in
    // the table as the literal text "Invalid Date". Null renders as "Never",
    // which is at least honest.
    const garbage = {
      ...dbUser,
      last_session_refresh_at: "not-a-timestamp",
    } as unknown as Parameters<
      typeof UsersSerializer.serializeUserList
    >[0][number];

    for (const serialized of UsersSerializer.serializeUserList([garbage])) {
      expect(serialized.last_session_refresh_at).toBeNull();
      expect(() => UserListItemSchema.parse(serialized)).not.toThrow();
    }
  });

  it("badges a lost `disabled` value as DISABLED, matching enforcement", () => {
    // The serializer and usersRepository.isDisabled must agree about what an
    // absent value means, and the two answers are not equally safe. The
    // enforcement path reads `?? true`; a `=== true` read here would badge the
    // account ENABLED, so the dashboard would tell an admin that the attacker
    // they just locked out is still active — while the middleware was in fact
    // refusing them. That disagreement is the one lie this screen exists to
    // prevent, so the badge fails in the same direction the gate does.
    for (const missing of [null, undefined]) {
      const lost = {
        ...dbUser,
        disabled: missing,
      } as unknown as Parameters<
        typeof UsersSerializer.serializeUserList
      >[0][number];

      for (const serialized of UsersSerializer.serializeUserList([lost])) {
        expect(serialized.disabled).toBe(true);
        expect(() => UserListItemSchema.parse(serialized)).not.toThrow();
      }
    }
  });

  it("still reports a real `false` as enabled (regression guard)", () => {
    // Fail-closed must not become "always closed": the ordinary case is an
    // enabled account, and badging every account disabled would be its own
    // incident.
    for (const serialized of UsersSerializer.serializeUserList([dbUser])) {
      expect(serialized.disabled).toBe(false);
    }
  });
});

describe("OAuthTokensSerializer.serializeActiveTokenList", () => {
  it("emits exactly the documented field list — no token values", () => {
    const serializedList = OAuthTokensSerializer.serializeActiveTokenList([
      dbToken,
    ]);
    expect(serializedList).toHaveLength(1);

    for (const serialized of serializedList) {
      expect(Object.keys(serialized).sort()).toEqual(
        [
          "client_id",
          "client_name",
          "created_at",
          "expires_at",
          "has_refresh_token",
          "refresh_token_expires_at",
          "scope",
          "user_email",
          "user_id",
        ].sort(),
      );

      expect(serialized).not.toHaveProperty("access_token");
      expect(serialized).not.toHaveProperty("refresh_token");
      expect(() => ActiveOAuthTokenItemSchema.parse(serialized)).not.toThrow();
    }
  });

  it("does not carry either token value anywhere in the payload", () => {
    const payload = JSON.stringify(
      OAuthTokensSerializer.serializeActiveTokenList([dbToken]),
    );

    expect(payload).not.toContain(SECRET_ACCESS_TOKEN);
    expect(payload).not.toContain(SECRET_REFRESH_TOKEN);
    expect(payload).not.toMatch(/sk_[A-Za-z0-9_]+/);
  });

  it("reports refresh-token presence as a boolean, not the value", () => {
    const serialized = OAuthTokensSerializer.serializeActiveTokenList([
      dbToken,
      { ...dbToken, has_refresh_token: false, refresh_token_expires_at: null },
    ]);

    expect(serialized.map((token) => token.has_refresh_token)).toEqual([
      true,
      false,
    ]);
  });

  it("does not treat an undecoded 'false' string as a present refresh token", () => {
    // `Boolean("false")` is TRUE. If a decode regression ever hands this
    // serializer the string form, a truthy coercion would label every row as
    // holding a long-lived refresh credential — failing in the unsafe
    // direction on a security display. `=== true` degrades to false instead.
    const undecoded = {
      ...dbToken,
      has_refresh_token: "false",
    } as unknown as Parameters<
      typeof OAuthTokensSerializer.serializeActiveTokenList
    >[0][number];

    for (const serialized of OAuthTokensSerializer.serializeActiveTokenList([
      undecoded,
    ])) {
      expect(serialized.has_refresh_token).toBe(false);
    }
  });
});
