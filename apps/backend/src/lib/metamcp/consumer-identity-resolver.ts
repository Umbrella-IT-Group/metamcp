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
import { ClientIdentity } from "./session-client-registry";

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
          .select({ name: apiKeysTable.name })
          .from(apiKeysTable)
          .where(eq(apiKeysTable.uuid, auth.apiKeyUuid));
        name = row?.name || `api-key ${short(auth.apiKeyUuid)}`;
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
