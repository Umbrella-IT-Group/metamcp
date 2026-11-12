/**
 * Resolves an authenticated request's consumer to a human-readable identity
 * (api-key name like "example connector", or the OAuth user's email). Imported
 * ONLY by the router layer (which always runs with a live DB) — never by the
 * audit middleware, so the middleware's module graph stays DB-free for tests.
 *
 * Caching (api-key path): the key's BINDING — its name and acts_as_user_id
 * (migration 0024) — is cached indefinitely per key uuid, because both are
 * creation-time immutable (a re-bind requires a new key, hence a new uuid).
 * The acted-as user's EMAIL is deliberately NOT part of that cache: emails
 * are mutable, and freezing one into an audit label until process restart
 * would let a renamed account keep its old label. The label is composed per
 * call from the cached binding + a short-TTL (60s) email lookup — one
 * PK-indexed SELECT per bound key per minute, cheap and bounded-stale.
 *
 * Failure honesty: when the key row itself cannot be read (DB error), the
 * label says `api-key <short> (identity unresolved)` and the result is NOT
 * cached — a delegated call must never be audited as if no identity was
 * exercised, and the next call should retry the lookup.
 *
 * ACCOUNT EMAIL (`ClientIdentity.account`). Separately from the labels, the
 * resolver reports the effective account behind the request and that
 * account's email: the acts-as target for a bound key, else the key owner,
 * and the OAuth subject for an OAuth caller (the same `actsAsUserId ?? userId`
 * the verified caller headers name). The email is read through one bounded
 * cache with a 60s TTL, and it is either a fresh answer for exactly that user
 * id or null. It is never a stale cached value after a failed lookup, never
 * the key owner's email standing in for an acts-as target, and never a name,
 * a key name or a short-id label: those are display fallbacks for the labels
 * above, and a backend may compare this email to decide who is asking.
 */
import { eq } from "drizzle-orm";

import { db } from "../../db/index";
import { apiKeysTable, usersTable } from "../../db/schema";

export interface ClientIdentity {
  /** Human-readable label: api-key name (e.g. "example connector") or OAuth user email. */
  name: string;
  /** Stable id: api_keys.uuid or the OAuth user_id. */
  id?: string;
  method?: "api_key" | "oauth";
  /**
   * The effective account behind this request and its email: null when the
   * email could not be read now. Absent when the request names no effective
   * user (an owner-less key, or a blank acts-as binding).
   */
  account?: { userId: string; email: string | null };
}

export interface RequestAuthIdentity {
  authMethod?: string;
  apiKeyUuid?: string;
  apiKeyUserId?: string;
  apiKeyActsAsUserId?: string;
  oauthUserId?: string;
}

/** Immutable per-key facts, cacheable forever under the key uuid. */
interface ApiKeyBinding {
  name: string;
  actsAsUserId: string | null;
}

const apiKeyBindingCache = new Map<string, ApiKeyBinding>();
const oauthNameCache = new Map<string, string>();

/**
 * Account emails by user id, each answer kept for ACCOUNT_EMAIL_TTL_MS and
 * the map bounded at ACCOUNT_EMAIL_CACHE_MAX entries (the oldest answer is
 * dropped first). An entry is a fresh answer from the users table, including
 * "this user has no email"; a failed read is never stored.
 */
const accountEmailCache = new Map<
  string,
  { email: string | null; fetchedAt: number }
>();
const ACCOUNT_EMAIL_TTL_MS = 60_000;
const ACCOUNT_EMAIL_CACHE_MAX = 1_000;

/**
 * The last acts-as label shown for a user, kept only so a failed lookup can
 * keep serving it as a LABEL (stale beats a shape change mid-investigation).
 * Never consulted for `account.email`. Bounded like the email cache.
 */
const actsAsLabelCache = new Map<string, string>();

const short = (id: string) => id.slice(0, 8);

function remember<V>(cache: Map<string, V>, key: string, value: V): void {
  cache.delete(key);
  cache.set(key, value);
  while (cache.size > ACCOUNT_EMAIL_CACHE_MAX) {
    const oldest = cache.keys().next().value;
    if (oldest === undefined) break;
    cache.delete(oldest);
  }
}

/**
 * Look up a user's email: `{ ok: true, email }` from a fresh read (or a cached
 * read under ACCOUNT_EMAIL_TTL_MS old), `{ ok: false }` when the read failed.
 * An expired entry is removed before the read, so a failure after expiry
 * cannot fall back to it.
 */
async function lookupAccountEmail(
  userId: string,
): Promise<{ ok: true; email: string | null } | { ok: false }> {
  const now = Date.now();
  const cached = accountEmailCache.get(userId);
  if (cached && now - cached.fetchedAt < ACCOUNT_EMAIL_TTL_MS) {
    return { ok: true, email: cached.email };
  }
  accountEmailCache.delete(userId);
  try {
    const [row] = await db
      .select({ email: usersTable.email })
      .from(usersTable)
      .where(eq(usersTable.id, userId));
    const email =
      typeof row?.email === "string" && row.email !== "" ? row.email : null;
    remember(accountEmailCache, userId, { email, fetchedAt: now });
    return { ok: true, email };
  } catch {
    return { ok: false };
  }
}

/** The effective account for a request, or undefined when it names no user. */
async function resolveAccount(
  userId: string | undefined,
): Promise<ClientIdentity["account"]> {
  if (typeof userId !== "string" || userId === "") return undefined;
  const lookup = await lookupAccountEmail(userId);
  return { userId, email: lookup.ok ? lookup.email : null };
}

/**
 * Resolve the acted-as user's display label (email, or `user <short>` when
 * the row is missing/unreadable). Shares the email cache, so a bound key's
 * hot path pays at most one users SELECT per TTL window while an email change
 * still corrects the audit label within a minute.
 */
async function resolveActsAsLabel(actsAsUserId: string): Promise<string> {
  const lookup = await lookupAccountEmail(actsAsUserId);
  if (lookup.ok) {
    const label = lookup.email ?? `user ${short(actsAsUserId)}`;
    remember(actsAsLabelCache, actsAsUserId, label);
    return label;
  }
  // Keep serving the last-known label if we have one (stale beats a shape
  // change mid-investigation); otherwise the short-id fallback. Never fail
  // identity resolution over a label lookup.
  return actsAsLabelCache.get(actsAsUserId) ?? `user ${short(actsAsUserId)}`;
}

export async function resolveClientIdentity(
  auth: RequestAuthIdentity,
): Promise<ClientIdentity | undefined> {
  if (auth.authMethod === "api_key" && auth.apiKeyUuid) {
    // The effective user exactly as the caller binding names it: the acts-as
    // target the auth middleware stamped, else the key owner. A blank acts-as
    // binding names nobody (no owner fallback), as `verifiedCallerUserId`
    // does. Taken from the request, not from the cached binding below, so the
    // account is the one this request's identity headers will name.
    const account = await resolveAccount(
      auth.apiKeyActsAsUserId ?? auth.apiKeyUserId,
    );
    let binding = apiKeyBindingCache.get(auth.apiKeyUuid);
    if (binding === undefined) {
      try {
        const [row] = await db
          .select({
            name: apiKeysTable.name,
            acts_as_user_id: apiKeysTable.acts_as_user_id,
          })
          .from(apiKeysTable)
          .where(eq(apiKeysTable.uuid, auth.apiKeyUuid));
        binding = {
          name: row?.name || `api-key ${short(auth.apiKeyUuid)}`,
          actsAsUserId: row?.acts_as_user_id ?? null,
        };
        apiKeyBindingCache.set(auth.apiKeyUuid, binding);
      } catch {
        // DB error: we could not read the row, so we DON'T KNOW whether
        // this key carries an acts-as binding. A bare `api-key <short>`
        // here would read exactly like a no-identity key — the one failure
        // mode where the audit trail lies in the dangerous direction. Say
        // so explicitly, and do not cache: the next call retries.
        return {
          name: `api-key ${short(auth.apiKeyUuid)} (identity unresolved)`,
          id: auth.apiKeyUuid,
          method: "api_key",
          account,
        };
      }
    }

    // Acts-as binding (migration 0024): the audit trail must show BOTH the
    // key and the identity its m365 calls run as — labeling by key name
    // alone would hide that a delegated identity was exercised. Same string
    // shape consumers already render (logs UI / tool_call audit read
    // `.name` opaquely), just extended: `key (as email)`. Composed per call
    // so the mutable email component stays fresh (see module doc comment).
    const name = binding.actsAsUserId
      ? `${binding.name} (as ${await resolveActsAsLabel(binding.actsAsUserId)})`
      : binding.name;
    return { name, id: auth.apiKeyUuid, method: "api_key", account };
  }

  if (auth.authMethod === "oauth" && auth.oauthUserId) {
    const account = await resolveAccount(auth.oauthUserId);
    const cacheKey = `oauth:${auth.oauthUserId}`;
    let name = oauthNameCache.get(cacheKey);
    if (name === undefined) {
      try {
        const [row] = await db
          .select({ name: usersTable.name, email: usersTable.email })
          .from(usersTable)
          .where(eq(usersTable.id, auth.oauthUserId));
        name = row?.email || row?.name || `user ${short(auth.oauthUserId)}`;
        oauthNameCache.set(cacheKey, name);
      } catch {
        name = `user ${short(auth.oauthUserId)}`;
      }
    }
    return { name, id: auth.oauthUserId, method: "oauth", account };
  }

  return undefined;
}
