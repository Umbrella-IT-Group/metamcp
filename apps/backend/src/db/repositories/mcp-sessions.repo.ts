/**
 * Persistence layer for Streamable HTTP `Mcp-Session-Id` recovery.
 *
 * When metamcp itself restarts, every consumer's cached `Mcp-Session-Id`
 * becomes "Session not found" because the in-memory transport map is
 * empty after boot. PR #12 + PR #13 handle the BACKEND-restart cascade
 * (recover when the backend MCP container restarts mid-session); this
 * repository powers the GATEWAY-restart cascade (recover when metamcp
 * itself restarts and the consumer's cached session id is gone from
 * memory but still alive in postgres).
 *
 * On `initialize` the streamable-http router persists a row here. On a
 * subsequent request whose `Mcp-Session-Id` doesn't appear in the
 * in-memory transport map, the router queries this table — if the row
 * exists AND the SHA-256(token + auth_method) of the incoming request
 * matches the stored `auth_principal`, the router rebuilds the transport
 * from `init_params` and replays the request. No 404 surfaces to the
 * consumer.
 *
 * TTL pruning runs on boot + every `MCP_SESSION_PRUNER_INTERVAL_MS`
 * (default 24h). Rows whose `last_seen_at` is older than
 * `MCP_SESSION_TTL_DAYS` (default 7) are deleted.
 *
 * See `apps/backend/src/lib/metamcp/session-auth.ts` for the
 * constant-time auth comparison + hashing helpers.
 */

import { eq, lt, sql } from "drizzle-orm";

import { db } from "../index";
import { mcpSessionsTable } from "../schema";

export interface PersistedMcpSession {
  session_id: string;
  namespace_uuid: string;
  endpoint_name: string;
  auth_principal: string;
  auth_method: string;
  init_params: Record<string, unknown>;
  created_at: Date;
  last_seen_at: Date;
  // PR #22: gateway process UUID stamped at session init. Null when the
  // row was persisted by a metamcp version prior to PR #22 — the
  // lazy-recovery path treats null as "no metadata to compare, allow"
  // (pruner reaps these within `MCP_SESSION_TTL_DAYS`).
  gateway_boot_id: string | null;
}

export interface PersistMcpSessionInput {
  session_id: string;
  namespace_uuid: string;
  endpoint_name: string;
  auth_principal: string;
  auth_method: string;
  init_params?: Record<string, unknown>;
  // PR #22: gateway process UUID. Required on every persist call from
  // the router so post-deploy rows are always stamped — only pre-PR-22
  // rows in the table have null stamps.
  gateway_boot_id: string;
}

export class McpSessionsRepository {
  /**
   * Insert a new session row at `initialize` time. Idempotent — if the
   * router happens to fire two persist calls for the same session_id
   * (rare, but the race exists during cold-start), the duplicate is
   * silently absorbed and the stored auth principal stays as-first.
   */
  async persist(input: PersistMcpSessionInput): Promise<void> {
    await db
      .insert(mcpSessionsTable)
      .values({
        session_id: input.session_id,
        namespace_uuid: input.namespace_uuid,
        endpoint_name: input.endpoint_name,
        auth_principal: input.auth_principal,
        auth_method: input.auth_method,
        init_params: input.init_params ?? {},
        gateway_boot_id: input.gateway_boot_id,
      })
      .onConflictDoNothing({ target: mcpSessionsTable.session_id });
  }

  /**
   * Lookup a session by id. Returns the row when present, otherwise
   * `null`. Caller is responsible for the auth-principal compare before
   * acting on the result.
   */
  async findById(sessionId: string): Promise<PersistedMcpSession | null> {
    const rows = await db
      .select()
      .from(mcpSessionsTable)
      .where(eq(mcpSessionsTable.session_id, sessionId))
      .limit(1);
    if (rows.length === 0) {
      return null;
    }
    const row = rows[0];
    return {
      session_id: row.session_id,
      namespace_uuid: row.namespace_uuid,
      endpoint_name: row.endpoint_name,
      auth_principal: row.auth_principal,
      auth_method: row.auth_method,
      init_params: row.init_params as Record<string, unknown>,
      created_at: row.created_at,
      last_seen_at: row.last_seen_at,
      gateway_boot_id: row.gateway_boot_id,
    };
  }

  /**
   * Bump `last_seen_at` to NOW(). Called after every successful request
   * served against the session so TTL pruning only reaps genuinely-idle
   * sessions.
   */
  async touch(sessionId: string): Promise<void> {
    await db
      .update(mcpSessionsTable)
      .set({ last_seen_at: sql`NOW()` })
      .where(eq(mcpSessionsTable.session_id, sessionId));
  }

  /**
   * Hard delete a single row — used by the DELETE /mcp endpoint when
   * the client explicitly tears down its session.
   */
  async delete(sessionId: string): Promise<void> {
    await db
      .delete(mcpSessionsTable)
      .where(eq(mcpSessionsTable.session_id, sessionId));
  }

  /**
   * TTL pruner. Deletes rows whose `last_seen_at` is older than the
   * cutoff. Returns the count of rows deleted (best-effort — postgres
   * doesn't always populate `affectedRows` on DELETE with returning;
   * caller treats the count as advisory).
   */
  async pruneOlderThan(cutoff: Date): Promise<number> {
    const result = await db
      .delete(mcpSessionsTable)
      .where(lt(mcpSessionsTable.last_seen_at, cutoff))
      .returning({ session_id: mcpSessionsTable.session_id });
    return result.length;
  }
}

export const mcpSessionsRepository = new McpSessionsRepository();
