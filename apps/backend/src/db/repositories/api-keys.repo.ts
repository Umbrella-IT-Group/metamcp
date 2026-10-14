import { isIP } from "node:net";

import { ApiKeyCreateInput, ApiKeyUpdateInput } from "@repo/zod-types";
import { and, desc, eq, isNull, or } from "drizzle-orm";
import { alias } from "drizzle-orm/pg-core";
import { customAlphabet } from "nanoid";

import { apiKeyLast4, hashApiKey } from "@/lib/api-key-hash";
import {
  type ApiKeyIpCheck,
  applyApiKeyIpPolicy,
  type GlobalIpPolicy,
  type IpPolicyMode,
} from "@/lib/api-key-ip-policy";
import { configService } from "@/lib/config.service";
import logger from "@/utils/logger";

import { db } from "../index";
import { apiKeysTable, usersTable } from "../schema";
import { shouldTouchLastUsed } from "./api-keys.last-used";

/**
 * The global IP policy, read live (one config query) only when a key with no
 * list of its own is validated under an explicit IP check. A function rather
 * than a direct call so the policy module stays free of database imports.
 */
const readGlobalIpPolicy = async (): Promise<GlobalIpPolicy> =>
  configService.getApiKeyIpPolicy();

/**
 * The address to record in api_keys.last_used_ip: only a value that parses as
 * an IP, so the admin view never shows a malformed header as if it were where
 * the key was used from. Undefined leaves the stored value as it is.
 */
function stampableIp(ipCheck: ApiKeyIpCheck | undefined): string | undefined {
  const ip = ipCheck?.clientIp;
  return ip !== undefined && isIP(ip) !== 0 ? ip : undefined;
}

const nanoid = customAlphabet(
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
  64,
);

export class ApiKeysRepository {
  /**
   * Generate a new API key with the specified format: sk_mt_{64-char-nanoid}
   */
  private generateApiKey(): string {
    const keyPart = nanoid();
    const key = `sk_mt_${keyPart}`;

    return key;
  }

  async create(input: ApiKeyCreateInput): Promise<{
    uuid: string;
    name: string;
    key: string;
    user_id: string | null;
    endpoint_uuid: string | null;
    acts_as_user_id: string | null;
    created_at: Date;
  }> {
    const key = this.generateApiKey();

    const [createdApiKey] = await db
      .insert(apiKeysTable)
      .values({
        name: input.name,
        // Only the hash and the display tail are persisted (migration 0034);
        // the plaintext lives in this local variable and is handed back once,
        // below. There is no second chance to read it — if the caller loses
        // it, the key must be re-minted.
        key_hash: hashApiKey(key),
        last4: apiKeyLast4(key),
        user_id: input.user_id,
        // NULL = unscoped (legacy gateway-wide). The tRPC create path makes
        // NULL an explicit admin choice (all_endpoints: true) — see
        // api-keys.impl.ts; the repository just persists what it's given.
        endpoint_uuid: input.endpoint_uuid ?? null,
        // NULL = no acts-as identity (fail-closed m365 injection). The tRPC
        // create path enforces the admin-only + requires-endpoint-scope
        // policy; the repository just persists what it's given.
        acts_as_user_id: input.acts_as_user_id ?? null,
        // Plane flag (migration 0038). The tRPC create path enforces the
        // admin-only + owner-must-be-admin + plane-exclusivity policy; the
        // repository just persists what it is given (default false = data
        // plane). The CHECK constraints refuse a straddling row regardless.
        admin_plane: input.admin_plane ?? false,
        is_active: input.is_active ?? true,
      })
      .returning({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        user_id: apiKeysTable.user_id,
        endpoint_uuid: apiKeysTable.endpoint_uuid,
        acts_as_user_id: apiKeysTable.acts_as_user_id,
        created_at: apiKeysTable.created_at,
      });

    if (!createdApiKey) {
      throw new Error("Failed to create API key");
    }

    return {
      ...createdApiKey,
      key, // Return the actual key
    };
  }

  // Find all API keys (both public and user-owned). Admin-only surface. LEFT
  // JOIN users so the caller gets each key's owner email (NULL for a public /
  // 'everyone' key) without an N+1 lookup, plus last_used_at for the admin
  // view. `last4` is the display tail the serializer renders as key_prefix;
  // no column here can reconstruct a usable credential (migration 0034).
  async findAll() {
    // Second users join, aliased: acts_as_user_id → the acted-as user's
    // email, so the admin view can label an identity-bound key with WHO it
    // acts as (NULL when unbound or the user row is gone mid-cascade).
    const actsAsUsers = alias(usersTable, "acts_as_users");
    return await db
      .select({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        last4: apiKeysTable.last4,
        created_at: apiKeysTable.created_at,
        last_used_at: apiKeysTable.last_used_at,
        is_active: apiKeysTable.is_active,
        user_id: apiKeysTable.user_id,
        endpoint_uuid: apiKeysTable.endpoint_uuid,
        acts_as_user_id: apiKeysTable.acts_as_user_id,
        acts_as_email: actsAsUsers.email,
        owner_email: usersTable.email,
        // Plane flag (migration 0038): so the admin view can label a
        // control-plane key loudly, the way acts-as is labelled.
        admin_plane: apiKeysTable.admin_plane,
        // IP allowlist (migration 0041): the key's own list (NULL = follows
        // the global policy), its mode, and the last address it was used
        // from. None of it is credential material.
        allowed_cidrs: apiKeysTable.allowed_cidrs,
        ip_policy_mode: apiKeysTable.ip_policy_mode,
        last_used_ip: apiKeysTable.last_used_ip,
      })
      .from(apiKeysTable)
      .leftJoin(usersTable, eq(apiKeysTable.user_id, usersTable.id))
      .leftJoin(actsAsUsers, eq(apiKeysTable.acts_as_user_id, actsAsUsers.id))
      .orderBy(desc(apiKeysTable.created_at));
  }

  // Find API keys accessible to a specific user (public + user's own keys)
  async findAccessibleToUser(userId: string) {
    return await db
      .select({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        last4: apiKeysTable.last4,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
        user_id: apiKeysTable.user_id,
        endpoint_uuid: apiKeysTable.endpoint_uuid,
        acts_as_user_id: apiKeysTable.acts_as_user_id,
      })
      .from(apiKeysTable)
      .where(
        or(
          isNull(apiKeysTable.user_id), // Public API keys
          eq(apiKeysTable.user_id, userId), // User's own API keys
        ),
      )
      .orderBy(desc(apiKeysTable.created_at));
  }

  /**
   * Resolve a presented DATA-plane key.
   *
   * `ipCheck` is the EXPLICIT opt-in to the key's IP policy (migration 0041).
   * The authenticating call sites pass it (both API-key branches of
   * authenticateApiKey, and /oauth/introspect); the tRPC `apiKeys.validate`
   * oracle does not, because it authenticates nothing and has no caller
   * address to judge. Omitted means the policy is not evaluated at all, which
   * is why it is a separate argument rather than a default: a caller that
   * forgets it gets today's behaviour, never a silent refusal.
   */
  async validateApiKey(
    key: string,
    ipCheck?: ApiKeyIpCheck,
  ): Promise<{
    valid: boolean;
    user_id?: string | null;
    key_uuid?: string;
    endpoint_uuid?: string | null;
    acts_as_user_id?: string | null;
    // Set true ONLY on the wrong-plane rejection below, so the data-plane call
    // sites can name the refusal precisely. A valid data-plane key never
    // carries it.
    admin_plane?: boolean;
    // Set true ONLY when the key's IP policy refused the request (enforce
    // mode, address not allowed). The call sites answer it with a 403 BEFORE
    // their invalid-credential branch, so it is never counted by the
    // failed-credential limiter: the credential is real, the address is not
    // permitted. The policy module has already written the throttled audit
    // row, so the call sites emit nothing of their own for it.
    ip_denied?: boolean;
  }> {
    const [apiKey] = await db
      .select({
        uuid: apiKeysTable.uuid,
        user_id: apiKeysTable.user_id,
        endpoint_uuid: apiKeysTable.endpoint_uuid,
        acts_as_user_id: apiKeysTable.acts_as_user_id,
        is_active: apiKeysTable.is_active,
        // Plane flag (migration 0038). Read on the ONE hot data-plane auth
        // read so the refusal below costs no second query.
        admin_plane: apiKeysTable.admin_plane,
        last_used_at: apiKeysTable.last_used_at,
        // IP policy (migration 0041), read on the same row for the same
        // reason: a key with its own list costs no extra query at all.
        allowed_cidrs: apiKeysTable.allowed_cidrs,
        ip_policy_mode: apiKeysTable.ip_policy_mode,
      })
      .from(apiKeysTable)
      // Hash-for-hash comparison (migration 0034): the presented value is
      // hashed here and matched against the stored digest, because the key
      // itself is no longer in the table. The presented string is hashed
      // EXACTLY as it arrived — no trimming, no case folding — so the set of
      // credentials that authenticate is byte-for-byte the set the old
      // `WHERE key = $1` accepted. Callers differ on whitespace handling
      // (the middleware passes the header raw, the OAuth introspection route
      // trims it) and that asymmetry is theirs to own; normalising it here
      // would silently change which padded credentials are accepted.
      .where(eq(apiKeysTable.key_hash, hashApiKey(key)));

    if (!apiKey) {
      return { valid: false };
    }

    // Check if key is active
    if (!apiKey.is_active) {
      return { valid: false };
    }

    // IP POLICY (migration 0041), only under an explicit ipCheck. Placed
    // after existence and is_active (an unknown or revoked key is refused as
    // invalid exactly as before, and an unknown key never reaches the policy,
    // so the audit rows it writes are always about a real key) and BEFORE
    // everything the call sites decide afterwards: the plane refusal below,
    // the disabled-account check and the endpoint-scope check. A holder of a
    // valid key from a wrong address therefore learns nothing about the key's
    // plane, owner or scope; every such request gets the same generic 403.
    // Also before the last_used stamp: a refused request is not a use.
    if (ipCheck) {
      const { denied } = await applyApiKeyIpPolicy(
        {
          uuid: apiKey.uuid,
          allowed_cidrs: apiKey.allowed_cidrs,
          ip_policy_mode: apiKey.ip_policy_mode,
        },
        ipCheck,
        readGlobalIpPolicy,
      );
      if (denied) {
        return { valid: false, ip_denied: true, key_uuid: apiKey.uuid };
      }
    }

    // PLANE SEPARATION (migration 0038), enforced HERE so it holds for every
    // data-plane surface that resolves a key through this ONE validator,
    // present and future, rather than at each call site (the MCP bearer and
    // X-API-Key branches AND the /oauth/introspect credential gate all funnel
    // through validateApiKey; patching them one by one would miss the next one
    // added). A control-plane key is not a data-plane credential: reject it as
    // not-valid so every caller's existing `if (result.valid)` refuses it, and
    // return `admin_plane: true` + the key_uuid so the two MCP branches can
    // emit the distinct `admin_plane_key_on_data_plane` denial. Deliberately
    // BEFORE the last_used stamp: a rejected path must not touch last_used_at.
    if (apiKey.admin_plane) {
      return { valid: false, admin_plane: true, key_uuid: apiKey.uuid };
    }

    // Throttled, fire-and-forget last-used stamp. This is the hot auth path
    // for every public-endpoint request (n8n / Claude / other clients), so the
    // write is (a) throttled to the 15-min window in api-keys.last-used.ts and
    // (b) never awaited and never allowed to reject — a telemetry write must
    // not add latency to, or fail, request authentication.
    if (shouldTouchLastUsed(apiKey.last_used_at, Date.now())) {
      void this.touchLastUsedAt(apiKey.uuid, stampableIp(ipCheck));
    }

    return {
      valid: true,
      user_id: apiKey.user_id,
      key_uuid: apiKey.uuid,
      // Scope binding for checkApiKeyAccess: non-NULL = the ONE endpoint
      // this key may reach; NULL = legacy/unscoped (grandfathered).
      endpoint_uuid: apiKey.endpoint_uuid,
      // Acts-as identity for the streamable-http m365 context gate:
      // non-NULL = the admin-bound better-auth user this key's requests run
      // delegated m365 calls as; NULL = no identity (injection fail-closes).
      acts_as_user_id: apiKey.acts_as_user_id,
    };
  }

  // Fire-and-forget helper for validateApiKey. Self-contained try/catch so it
  // can never reject the caller: a failed last_used_at write is cosmetic (the
  // admin view shows a slightly stale timestamp) whereas propagating it would
  // fail request auth. The swallow is logged, not silent, so it stays
  // observable.
  //
  // last_used_ip (migration 0041) rides the SAME throttled write, so it costs
  // no extra update; between stamps it can be up to the throttle window stale,
  // which is fine for its purpose (showing an operator where a key is used
  // from while they build its allowlist). Absent ip = leave the column as it
  // is, so the validate oracle and a request with no CF-Connecting-IP never
  // blank it.
  private async touchLastUsedAt(uuid: string, ip?: string): Promise<void> {
    try {
      await db
        .update(apiKeysTable)
        .set(
          ip === undefined
            ? { last_used_at: new Date() }
            : { last_used_at: new Date(), last_used_ip: ip },
        )
        .where(eq(apiKeysTable.uuid, uuid));
    } catch (error) {
      logger.debug(
        "Failed to update api_keys.last_used_at (non-fatal):",
        error,
      );
    }
  }

  /**
   * Resolve a CONTROL-plane (admin-plane, migration 0038) key to its owning
   * user, for the tRPC bearer path (lib/admin-plane-auth.ts).
   *
   * Deliberately a SEPARATE resolver from validateApiKey rather than an
   * overload of it: the control plane needs the owner's fresh RBAC role and
   * disabled flag, which the data-plane hot path must never pay a users join
   * for. One atomic api_keys INNER JOIN users read gives a consistent snapshot
   * of is_active, admin_plane, role and disabled, so the plane check, the role
   * and the disabled gate cannot race each other.
   *
   * Returns valid ONLY when the key exists, is active, and is admin_plane; the
   * caller fails closed on `disabled` (the account lock, migration 0027). The
   * INNER JOIN also means a key whose owner row is gone resolves to nothing,
   * fail-closed by construction, and consistent with the requires-owner CHECK.
   * Hashes the presented key through hashApiKey exactly as validateApiKey does
   * (never a second encoding, per the api-key-hash.ts contract).
   */
  async validateAdminPlaneApiKey(
    key: string,
    ipCheck?: ApiKeyIpCheck,
  ): Promise<
    | {
        valid: true;
        key_uuid: string;
        disabled: boolean;
        user: {
          id: string;
          email: string;
          name: string;
          emailVerified: boolean;
          image: string | null;
          role: string;
          createdAt: Date;
          updatedAt: Date;
        };
      }
    | { valid: false; reason: "unknown_key" | "inactive" | "not_admin_plane" }
    // The key's IP policy refused the request (migration 0041). Carries the
    // key uuid for the caller's log; the policy module already wrote the
    // throttled audit row.
    | { valid: false; reason: "ip_not_allowed"; key_uuid: string }
  > {
    const [row] = await db
      .select({
        key_uuid: apiKeysTable.uuid,
        is_active: apiKeysTable.is_active,
        admin_plane: apiKeysTable.admin_plane,
        last_used_at: apiKeysTable.last_used_at,
        allowed_cidrs: apiKeysTable.allowed_cidrs,
        ip_policy_mode: apiKeysTable.ip_policy_mode,
        user_id: usersTable.id,
        email: usersTable.email,
        name: usersTable.name,
        emailVerified: usersTable.emailVerified,
        image: usersTable.image,
        role: usersTable.role,
        disabled: usersTable.disabled,
        createdAt: usersTable.createdAt,
        updatedAt: usersTable.updatedAt,
      })
      .from(apiKeysTable)
      // INNER JOIN: a control-plane key with no owner cannot exist (the
      // requires-owner CHECK), and an owner row torn out mid-cascade must
      // resolve to nothing rather than a partial identity.
      .innerJoin(usersTable, eq(apiKeysTable.user_id, usersTable.id))
      .where(eq(apiKeysTable.key_hash, hashApiKey(key)));

    if (!row) return { valid: false, reason: "unknown_key" };
    if (!row.is_active) return { valid: false, reason: "inactive" };
    // A data-plane key presented on /trpc is not a usable control-plane
    // credential. Not-valid, so createContext leaves the request
    // unauthenticated and protectedProcedure returns its normal UNAUTHORIZED.
    if (!row.admin_plane) return { valid: false, reason: "not_admin_plane" };

    // IP POLICY (migration 0041), only under an explicit ipCheck, and AFTER
    // the plane check on purpose. A data-plane key on /trpc is already refused
    // with the same 401 an unknown key gets, so it reveals nothing, and
    // evaluating a data-plane key's policy on a surface it can never use would
    // write audit rows that misdescribe where the key is used. Before the
    // disabled-owner check and the last_used stamp, so a wrong-address
    // request learns nothing about the owner and is not recorded as a use.
    if (ipCheck) {
      const { denied } = await applyApiKeyIpPolicy(
        {
          uuid: row.key_uuid,
          allowed_cidrs: row.allowed_cidrs,
          ip_policy_mode: row.ip_policy_mode,
        },
        ipCheck,
        readGlobalIpPolicy,
      );
      if (denied) {
        return {
          valid: false,
          reason: "ip_not_allowed",
          key_uuid: row.key_uuid,
        };
      }
    }

    // Throttled fire-and-forget last-used stamp for an ACCEPTED admin-plane
    // request (owner not disabled), same discipline as validateApiKey. A
    // disabled owner's request is rejected downstream, so it does not stamp.
    if (!row.disabled && shouldTouchLastUsed(row.last_used_at, Date.now())) {
      void this.touchLastUsedAt(row.key_uuid, stampableIp(ipCheck));
    }

    return {
      valid: true,
      key_uuid: row.key_uuid,
      disabled: row.disabled,
      user: {
        id: row.user_id,
        email: row.email,
        name: row.name,
        emailVerified: row.emailVerified,
        image: row.image,
        role: row.role,
        createdAt: row.createdAt,
        updatedAt: row.updatedAt,
      },
    };
  }

  // Member-scoped update: uuid AND owned-by-this-user ONLY. Deliberately does
  // NOT match public (user_id IS NULL) keys — a member who lists public keys
  // has their UUIDs, and an `or(eq(user_id, userId), isNull(user_id))` WHERE
  // here would let any member deactivate or rename a key every other
  // consumer depends on. Public keys can only be mutated through
  // updateAsAdmin. A member's attempt against a public (or another user's)
  // uuid matches zero rows and falls into the same not-found path as any
  // other uuid that doesn't belong to them.
  async update(uuid: string, userId: string, input: ApiKeyUpdateInput) {
    const [updatedApiKey] = await db
      .update(apiKeysTable)
      .set({
        ...(input.name && { name: input.name }),
        ...(input.is_active !== undefined && { is_active: input.is_active }),
      })
      .where(and(eq(apiKeysTable.uuid, uuid), eq(apiKeysTable.user_id, userId)))
      .returning({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        // Read back solely so ApiKeysSerializer.serializeApiKey can render the
        // key_prefix from it. Since migration 0034 this is the stored display
        // tail rather than a slice of the secret, so the readback carries no
        // credential material at all. Kept here rather than formatted in SQL
        // so the ONE display rule stays in the serializer, where the list
        // surfaces share it — a second copy in a `.returning()` is exactly the
        // drift that rule exists to prevent.
        last4: apiKeysTable.last4,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
      });

    if (!updatedApiKey) {
      throw new Error("Failed to update API key or API key not found");
    }

    return updatedApiKey;
  }

  // Member-scoped delete: uuid AND owned-by-this-user ONLY. Same reasoning as
  // update() above — a public key is not deletable through this path, only
  // through deleteAsAdmin. Without this, any member could DELETE a key every
  // other consumer (n8n/Claude/other clients) authenticates with, using a uuid they
  // can read off their own `list` query.
  async delete(uuid: string, userId: string) {
    const [deletedApiKey] = await db
      .delete(apiKeysTable)
      .where(and(eq(apiKeysTable.uuid, uuid), eq(apiKeysTable.user_id, userId)))
      .returning({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
      });

    if (!deletedApiKey) {
      throw new Error("Failed to delete API key or API key not found");
    }

    return deletedApiKey;
  }

  // Admin bypass of the ownership WHERE: an admin may rename / activate /
  // deactivate ANY key by uuid, including public keys and other users'
  // private keys. Members go through update(), which is scoped to their OWN
  // keys only — a public key can be mutated exclusively through this method.
  async updateAsAdmin(uuid: string, input: ApiKeyUpdateInput) {
    const [updatedApiKey] = await db
      .update(apiKeysTable)
      .set({
        ...(input.name && { name: input.name }),
        ...(input.is_active !== undefined && { is_active: input.is_active }),
      })
      .where(eq(apiKeysTable.uuid, uuid))
      .returning({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        // Display tail only, same reasoning as update() above — consumed by
        // the serializer and never a credential in the first place.
        last4: apiKeysTable.last4,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
      });

    if (!updatedApiKey) {
      throw new Error("Failed to update API key or API key not found");
    }

    return updatedApiKey;
  }

  // Admin bypass of the ownership WHERE: an admin may delete / revoke ANY key
  // by uuid, including public keys. Members go through delete(), which is
  // scoped to their OWN keys only — a public key can be deleted exclusively
  // through this method.
  async deleteAsAdmin(uuid: string) {
    const [deletedApiKey] = await db
      .delete(apiKeysTable)
      .where(eq(apiKeysTable.uuid, uuid))
      .returning({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
      });

    if (!deletedApiKey) {
      throw new Error("Failed to delete API key or API key not found");
    }

    return deletedApiKey;
  }

  /**
   * Admin write of one key's IP policy (migration 0041). The caller
   * (apiKeys.setIpPolicy) has validated and canonicalised the list and the
   * mode; this persists them and returns the row as it was BEFORE and AFTER,
   * read and written in one transaction under a row lock, so the audit row's
   * old value is the value this write actually replaced, not one a concurrent
   * write had already changed. Returns null when no key has that uuid.
   */
  async setIpPolicy(
    uuid: string,
    policy: { allowed_cidrs: string[] | null; ip_policy_mode: IpPolicyMode },
  ): Promise<{
    before: { allowed_cidrs: string[] | null; ip_policy_mode: string };
    after: {
      uuid: string;
      name: string;
      last4: string;
      is_active: boolean;
      allowed_cidrs: string[] | null;
      ip_policy_mode: string;
      last_used_ip: string | null;
    };
  } | null> {
    return await db.transaction(async (tx) => {
      const [before] = await tx
        .select({
          allowed_cidrs: apiKeysTable.allowed_cidrs,
          ip_policy_mode: apiKeysTable.ip_policy_mode,
        })
        .from(apiKeysTable)
        .where(eq(apiKeysTable.uuid, uuid))
        .for("update");
      if (!before) return null;
      const [after] = await tx
        .update(apiKeysTable)
        .set({
          allowed_cidrs: policy.allowed_cidrs,
          ip_policy_mode: policy.ip_policy_mode,
        })
        .where(eq(apiKeysTable.uuid, uuid))
        .returning({
          uuid: apiKeysTable.uuid,
          name: apiKeysTable.name,
          last4: apiKeysTable.last4,
          is_active: apiKeysTable.is_active,
          allowed_cidrs: apiKeysTable.allowed_cidrs,
          ip_policy_mode: apiKeysTable.ip_policy_mode,
          last_used_ip: apiKeysTable.last_used_ip,
        });
      if (!after) return null;
      return { before, after };
    });
  }
}
