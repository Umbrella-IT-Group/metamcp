import { lt } from "drizzle-orm";

import { db } from "../index";
import { toolCallAuditTable } from "../schema";

export interface ToolCallAuditEntry {
  client_name?: string | null;
  namespace_uuid?: string | null;
  session_id?: string | null;
  server_name: string;
  tool_name: string;
  params_hash?: string | null;
  success: boolean;
  error_code?: string | null;
  latency_ms?: number | null;
}

/**
 * Persistence for the tool-call audit log. Writes come fire-and-forget from
 * the auditing middleware (which imports this module LAZILY to keep its own
 * module graph DB-free for unit tests — same doctrine as
 * `consumer-identity-resolver.ts`). Retention is enforced by `pruneOlderThan`,
 * called from the oauth cleanup interval.
 */
export class ToolCallAuditRepository {
  async record(entry: ToolCallAuditEntry): Promise<void> {
    await db.insert(toolCallAuditTable).values(entry);
  }

  /** Delete rows older than `days`. Returns nothing — best-effort pruning. */
  async pruneOlderThan(days: number): Promise<void> {
    const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
    await db
      .delete(toolCallAuditTable)
      .where(lt(toolCallAuditTable.called_at, cutoff));
  }
}

export const toolCallAuditRepository = new ToolCallAuditRepository();
