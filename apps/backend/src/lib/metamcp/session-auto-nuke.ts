/**
 * One-shot session nuke at metamcp boot, gated on detection of a
 * capability change relative to the persisted `mcp_sessions` rows.
 *
 * Why this exists (Anthropic-client workaround on top of PR #22/#23):
 *
 *   PR #22 added a per-process `gateway_boot_id` stamp; PR #23 layered
 *   a `capability_hash` stamp + the combined `shouldRefuseRecovery`
 *   predicate. Together they correctly refuse lazy-recovery of any
 *   pre-deploy session whose negotiated capability set is stale —
 *   spec-conformant clients respond to the resulting HTTP 404 +
 *   `Mcp-Session-Reinitialize-Required` header by starting a fresh
 *   session (per MCP transport spec).
 *
 *   Anthropic's claude.ai MCP connector currently doesn't honor that
 *   contract — it wraps the 404 + reinit-required response as
 *   `-32600 "Anthropic Proxy: Invalid content from server"` (already
 *   documented for PR #18). Result: a session WEDGES until the row is
 *   manually `DELETE`d from `mcp_sessions`.
 *
 *   This module automates the workaround. On boot, if the persisted
 *   table contains ANY row whose `capability_hash` differs from the
 *   current process's `GATEWAY_CAPABILITY_HASH` (or is NULL — pre-PR-23
 *   row), every non-matching row is deleted in one statement. The
 *   client's NEXT request after the restart then hits the new-session
 *   POST path on the streamable-http router instead of the lazy-
 *   recovery refuse path, so the Anthropic-side 404 mishandling
 *   surfaces at most once (rather than indefinitely).
 *
 *   PR #23's `shouldRefuseRecovery` would have refused these rows
 *   anyway — the nuke is strictly a proactive form of the same
 *   decision. No row that this module deletes was recoverable by the
 *   existing lazy-recovery logic.
 *
 * Idempotency: re-running on a clean table (i.e. all rows already
 * stamped with the current hash, or the table is empty) is a no-op.
 * Two restarts in a row do not loop.
 *
 * Env knob: `MCP_AUTO_NUKE_ON_CAPABILITY_CHANGE` (default "true").
 * Set to "false" for forensic-debugging boots where preserving stale
 * rows is more useful than cleaning them.
 *
 * Failure mode: any DB error is logged and swallowed — auto-nuke is
 * a workaround, not a correctness gate. Callers route this through
 * the existing startup try/catch (see `lib/startup.ts`) so a
 * transient DB error doesn't crash the gateway.
 */

import { isNotNull, sql } from "drizzle-orm";

import { db } from "@/db";
import { mcpSessionsTable } from "@/db/schema";
import logger from "@/utils/logger";

import { GATEWAY_CAPABILITY_HASH } from "./gateway-boot-id";

/**
 * Read env knob with conservative parsing — anything other than a
 * recognised falsy value enables the nuke. Mirrors the parseBool style
 * already used in `lib/startup.ts` but inlined here so this module is
 * self-contained for unit testing.
 */
function isAutoNukeEnabled(): boolean {
  const raw = process.env.MCP_AUTO_NUKE_ON_CAPABILITY_CHANGE;
  if (raw === undefined) return true;
  const normalised = raw.trim().toLowerCase();
  if (["0", "false", "no", "n", "off"].includes(normalised)) return false;
  return true;
}

/**
 * One-shot scan + delete at boot. Public for the integration test +
 * for explicit reinvocation in forensic scripts. Safe to await before
 * mounting routes.
 */
export async function autoNukeStaleSessions(): Promise<void> {
  if (!isAutoNukeEnabled()) {
    logger.info(
      "Auto-nuke disabled via MCP_AUTO_NUKE_ON_CAPABILITY_CHANGE=false; skipping.",
    );
    return;
  }

  try {
    // Step 1: read the DISTINCT non-null hashes already in the table.
    // Empty result set (table empty, or every row has NULL hash) means
    // we can't compare — fall through to the conservative branch that
    // checks for any non-current row by counting.
    const distinctHashRows = await db
      .selectDistinct({ capability_hash: mcpSessionsTable.capability_hash })
      .from(mcpSessionsTable)
      .where(isNotNull(mcpSessionsTable.capability_hash));

    const distinctHashes = distinctHashRows
      .map((r) => r.capability_hash)
      .filter((h): h is string => h !== null);

    // Step 2: also detect rows with NULL capability_hash (pre-PR-23
    // rows, or PR #22-only rows). These can't be safely recovered per
    // PR #23's conservative-refusal branch — they get nuked too.
    const nullHashCountRows = await db
      .select({ count: sql<number>`count(*)::int` })
      .from(mcpSessionsTable)
      .where(sql`${mcpSessionsTable.capability_hash} IS NULL`);
    const nullHashCount = nullHashCountRows[0]?.count ?? 0;

    const otherHashes = distinctHashes.filter(
      (h) => h !== GATEWAY_CAPABILITY_HASH,
    );

    const capabilityChanged = otherHashes.length > 0 || nullHashCount > 0;

    if (!capabilityChanged) {
      logger.info(
        `Auto-nuke: no capability change detected (current=${GATEWAY_CAPABILITY_HASH}); session table is clean.`,
      );
      return;
    }

    // Step 3: forensic snapshot — per-namespace counts of stale rows
    // BEFORE the delete. namespace_uuid is non-sensitive (no token
    // material) so it's safe to log. Capped at a reasonable result
    // size implicitly by the natural namespace count.
    const perNamespaceRows = await db
      .select({
        namespace_uuid: mcpSessionsTable.namespace_uuid,
        count: sql<number>`count(*)::int`,
      })
      .from(mcpSessionsTable)
      .where(
        sql`${mcpSessionsTable.capability_hash} IS NULL OR ${mcpSessionsTable.capability_hash} <> ${GATEWAY_CAPABILITY_HASH}`,
      )
      .groupBy(mcpSessionsTable.namespace_uuid);

    const namespaceSummary = perNamespaceRows
      .map((r) => `${r.namespace_uuid}=${r.count}`)
      .join(", ");

    // Step 4: one-shot DELETE of every row whose hash is null or
    // differs from the current process's hash. The same predicate the
    // PR #23 refusal path uses, materialised as a row-level delete.
    const deleted = await db
      .delete(mcpSessionsTable)
      .where(
        sql`${mcpSessionsTable.capability_hash} IS NULL OR ${mcpSessionsTable.capability_hash} <> ${GATEWAY_CAPABILITY_HASH}`,
      )
      .returning({ session_id: mcpSessionsTable.session_id });

    const priorList = [
      ...otherHashes,
      ...(nullHashCount > 0 ? ["null"] : []),
    ].join(",");

    logger.info(
      `Auto-nuke: capability change detected (current=${GATEWAY_CAPABILITY_HASH} prior=[${priorList}]); deleted ${deleted.length} stale session row(s) across namespaces={${namespaceSummary}}.`,
    );
  } catch (error) {
    // Don't crash the gateway on a transient DB error. The PR #23
    // lazy-recovery refusal path is still in place, so the worst case
    // without the nuke is the pre-existing wedged-session behaviour.
    logger.error("Auto-nuke: postgres error; skipping nuke this boot.", error);
  }
}
