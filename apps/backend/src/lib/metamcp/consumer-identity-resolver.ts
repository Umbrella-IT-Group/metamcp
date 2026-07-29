/**
 * Resolves an authenticated request's consumer to a human-readable identity
 * (api-key name like "Tara connector", or the OAuth user's email). Imported
 * ONLY by the router layer (which always runs with a live DB) — never by the
 * audit middleware, so the middleware's module graph stays DB-free for tests.
 *
 * Results are cached per (method, id): names/emails change rarely and a tool
 * call shouldn't pay a DB round-trip for identity it just looked up.
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

const nameCache = new Map<string, string>();
const short = (id: string) => id.slice(0, 8);

export async function resolveClientIdentity(
  auth: RequestAuthIdentity,
): Promise<ClientIdentity | undefined> {
  if (auth.authMethod === "api_key" && auth.apiKeyUuid) {
    const cacheKey = `api_key:${auth.apiKeyUuid}`;
    let name = nameCache.get(cacheKey);
    if (name === undefined) {
      try {
        const [row] = await db
          .select({
            name: apiKeysTable.name,
            acts_as_user_id: apiKeysTable.acts_as_user_id,
          })
          .from(apiKeysTable)
          .where(eq(apiKeysTable.uuid, auth.apiKeyUuid));
        name = row?.name || `api-key ${short(auth.apiKeyUuid)}`;
        // Acts-as binding (migration 0024): the audit trail must show BOTH
        // the key and the identity its m365 calls run as — labeling by key
        // name alone would hide that a delegated identity was exercised.
        // Same string shape consumers already render (logs UI / tool_call
        // audit read `.name` opaquely), just extended: `key (as email)`.
        // Cacheable under the key uuid because the binding is creation-time
        // immutable — a re-bind requires a new key, hence a new uuid.
        if (row?.acts_as_user_id) {
          let actsAsLabel = `user ${short(row.acts_as_user_id)}`;
          try {
            const [actsAsUser] = await db
              .select({ email: usersTable.email })
              .from(usersTable)
              .where(eq(usersTable.id, row.acts_as_user_id));
            if (actsAsUser?.email) {
              actsAsLabel = actsAsUser.email;
            }
          } catch {
            // Keep the short-id fallback — never fail identity resolution
            // over a label lookup.
          }
          name = `${name} (as ${actsAsLabel})`;
        }
        nameCache.set(cacheKey, name);
      } catch {
        name = `api-key ${short(auth.apiKeyUuid)}`;
      }
    }
    return { name, id: auth.apiKeyUuid, method: "api_key" };
  }

  if (auth.authMethod === "oauth" && auth.oauthUserId) {
    const cacheKey = `oauth:${auth.oauthUserId}`;
    let name = nameCache.get(cacheKey);
    if (name === undefined) {
      try {
        const [row] = await db
          .select({ name: usersTable.name, email: usersTable.email })
          .from(usersTable)
          .where(eq(usersTable.id, auth.oauthUserId));
        name = row?.email || row?.name || `user ${short(auth.oauthUserId)}`;
        nameCache.set(cacheKey, name);
      } catch {
        name = `user ${short(auth.oauthUserId)}`;
      }
    }
    return { name, id: auth.oauthUserId, method: "oauth" };
  }

  return undefined;
}
