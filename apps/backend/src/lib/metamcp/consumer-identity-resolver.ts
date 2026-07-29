/**
 * Resolves an authenticated request's consumer to a human-readable identity
 * (api-key name like "Tara connector", or the OAuth user's email). Imported
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
 */
import { eq } from "drizzle-orm";

import { db } from "../../db/index";
import { apiKeysTable, usersTable } from "../../db/schema";

export interface ClientIdentity {
  /** Human-readable label: api-key name (e.g. "Tara connector") or OAuth user email. */
  name: string;
  /** Stable id: api_keys.uuid or the OAuth user_id. */
  id?: string;
  method?: "api_key" | "oauth";
}

export interface RequestAuthIdentity {
  authMethod?: string;
  apiKeyUuid?: string;
  apiKeyUserId?: string;
  oauthUserId?: string;
}

/** Immutable per-key facts, cacheable forever under the key uuid. */
interface ApiKeyBinding {
  name: string;
  actsAsUserId: string | null;
}

const apiKeyBindingCache = new Map<string, ApiKeyBinding>();
const oauthNameCache = new Map<string, string>();

/** Acted-as email, cached briefly — mutable, so bounded staleness only. */
const actsAsEmailCache = new Map<
  string,
  { label: string; fetchedAt: number }
>();
const ACTS_AS_EMAIL_TTL_MS = 60_000;

const short = (id: string) => id.slice(0, 8);

/**
 * Resolve the acted-as user's display label (email, or `user <short>` when
 * the row is missing/unreadable). Cached for ACTS_AS_EMAIL_TTL_MS so a
 * bound key's hot path pays at most one users SELECT per TTL window while
 * an email change still corrects the audit label within a minute.
 */
async function resolveActsAsLabel(actsAsUserId: string): Promise<string> {
  const cached = actsAsEmailCache.get(actsAsUserId);
  const now = Date.now();
  if (cached && now - cached.fetchedAt < ACTS_AS_EMAIL_TTL_MS) {
    return cached.label;
  }
  try {
    const [row] = await db
      .select({ email: usersTable.email })
      .from(usersTable)
      .where(eq(usersTable.id, actsAsUserId));
    const label = row?.email || `user ${short(actsAsUserId)}`;
    actsAsEmailCache.set(actsAsUserId, { label, fetchedAt: now });
    return label;
  } catch {
    // Keep serving the last-known label if we have one (stale beats a
    // shape change mid-incident); otherwise the short-id fallback. Never
    // fail identity resolution over a label lookup.
    return cached?.label ?? `user ${short(actsAsUserId)}`;
  }
}

export async function resolveClientIdentity(
  auth: RequestAuthIdentity,
): Promise<ClientIdentity | undefined> {
  if (auth.authMethod === "api_key" && auth.apiKeyUuid) {
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
    return { name, id: auth.apiKeyUuid, method: "api_key" };
  }

  if (auth.authMethod === "oauth" && auth.oauthUserId) {
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
    return { name, id: auth.oauthUserId, method: "oauth" };
  }

  return undefined;
}
