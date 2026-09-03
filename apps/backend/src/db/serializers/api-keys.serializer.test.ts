/**
 * The key_prefix rendering rule, pinned at the serializer.
 *
 * Migration 0034 removed the stored key, so the identifier every key surface
 * shows is built from `last4` — the only readable fragment that still exists.
 * Three surfaces share one private helper precisely so they cannot drift into
 * "one of them still leaks", and these tests are what keeps that true: they
 * assert the same rendering on all three, that nothing longer than four
 * characters of the secret can ever reach it, and that no key-shaped field
 * survives serialization.
 */
import { describe, expect, it } from "vitest";

import { ApiKeysSerializer } from "./api-keys.serializer";

const CREATED = new Date("2026-08-01T00:00:00Z");

describe("ApiKeysSerializer — key_prefix is rendered from the stored last4", () => {
  it("renders scheme tag, elision marker, then the four stored characters", () => {
    const row = {
      uuid: "k1",
      name: "renamed",
      last4: "wxyz",
      created_at: CREATED,
      is_active: true,
    };

    expect(ApiKeysSerializer.serializeApiKey(row).key_prefix).toBe(
      "sk_mt_…wxyz",
    );
  });

  it("renders identically on the member list and the admin list", () => {
    const memberRow = {
      uuid: "k1",
      name: "mine",
      last4: "abcd",
      created_at: CREATED,
      is_active: true,
      user_id: "member-1",
      endpoint_uuid: null,
      acts_as_user_id: null,
    };
    const adminRow = {
      ...memberRow,
      last_used_at: null,
      acts_as_email: null,
      owner_email: "member@example.com",
      admin_plane: false,
    };

    const fromMemberList = ApiKeysSerializer.serializeApiKeyList([memberRow])[0]
      .key_prefix;
    const fromAdminList = ApiKeysSerializer.serializeAdminApiKeyList([
      adminRow,
    ])[0].key_prefix;

    expect(fromMemberList).toBe("sk_mt_…abcd");
    // Same rule on both surfaces — the drift the shared helper exists to stop.
    expect(fromAdminList).toBe(fromMemberList);
  });

  it("exposes at most four characters of the key and no key field at all", () => {
    const key = `sk_mt_${"f".repeat(64)}`;
    const row = {
      uuid: "k1",
      name: "mine",
      last4: key.slice(-4),
      created_at: CREATED,
      is_active: true,
      user_id: null,
      endpoint_uuid: null,
      acts_as_user_id: null,
    };

    const serialized = ApiKeysSerializer.serializeApiKeyList([row])[0];
    const payload = JSON.stringify(serialized);

    expect((serialized as Record<string, unknown>).key).toBeUndefined();
    expect(payload).not.toContain(key);
    // Whole-payload hunt, the same assertion the impl tests use: `sk_mt_`
    // followed by 16+ token characters is far longer than the four a prefix
    // exposes and far shorter than a real key, so it fires on a leak and
    // never on a legitimate identifier.
    expect(payload).not.toMatch(/sk_mt_[A-Za-z0-9_-]{16,}/);
    expect(serialized.key_prefix).toBe("sk_mt_…ffff");
  });

  it("still emits the full key on the mint response — the one-time reveal", () => {
    // The single surface that legitimately carries a usable credential: the
    // value exists only in memory at this point, never in a row.
    const key = `sk_mt_${"g".repeat(64)}`;

    const minted = ApiKeysSerializer.serializeCreateApiKeyResponse({
      uuid: "k1",
      name: "fresh",
      key,
      user_id: "admin-1",
      created_at: CREATED,
    });

    expect(minted.key).toBe(key);
  });
});
