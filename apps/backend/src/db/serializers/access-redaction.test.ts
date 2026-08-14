/**
 * No-secret-leak contract for the two Access-dashboard listings.
 *
 * The 2026-08-13 pentest recovered three live gateway API keys from a list
 * route that returned `key` raw (see api-keys.serializer.ts). These two
 * listings are new surfaces of the same shape — one enumerates accounts, the
 * other enumerates live OAuth grants — so they get the same treatment before
 * they ship, not after somebody finds them.
 *
 * The rows fed in are deliberately POLLUTED with credential-looking fields
 * that a careless `...row` spread would carry through: a password hash on the
 * user row, and access/refresh token values on the token row. Neither may
 * appear anywhere in the serialized output.
 *
 * Both halves are asserted: the serializer's own field list, AND a
 * whole-response regex sweep for the secret VALUES, so a leak under some
 * other key name is caught too.
 *
 * Rows are iterated rather than indexed throughout — `noUncheckedIndexedAccess`
 * makes `list[0]` possibly-undefined, and the sibling redaction.test.ts uses
 * the same loop instead of a non-null assertion.
 */

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
  created_at: CREATED_AT,
  updated_at: CREATED_AT,
  last_active_at: CREATED_AT,
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
          "email",
          "emailVerified",
          "id",
          "last_active_at",
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
});
