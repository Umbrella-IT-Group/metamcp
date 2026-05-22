/**
 * One-shot session nuke at metamcp boot, gated on detection of a
 * capability change relative to the persisted `mcp_sessions` rows.
 *
 * ============================================================
 * READ FIRST IF YOU'RE STUMBLING ON THIS FILE
 * ============================================================
 *
 * **Persistent sessions are the default + desired behavior.** PR #15
 * (`feat/lazy-session-recovery`) intentionally survives a metamcp
 * restart without forcing the consumer to reconnect: persisted rows
 * in `mcp_sessions` let the router rebuild the transport against the
 * same `Mcp-Session-Id` the client already has cached. 95%+ of
 * metamcp restarts (OAuth tweaks, dep bumps, transport-disconnect
 * detector work, lint sweeps, env-only changes) preserve the
 * advertised MCP server-capability set, and those restarts stay
 * fully transparent to consumers. This module does NOT touch those.
 *
 * The narrow case this module exists for: a deploy that ACTUALLY
 * changes the gateway's advertised MCP capabilities. Example: PR #19
 * added `tools: { listChanged: true }` to the upstream `Server`. MCP
 * `initialize` negotiates capabilities ONCE per session — a recovered
 * session keeps its pre-deploy cached capability set forever. PR #22
 * + PR #23 added stamps (`gateway_boot_id` + `capability_hash`) and
 * a `shouldRefuseRecovery` predicate that correctly returns 404 +
 * `Mcp-Session-Reinitialize-Required` when capabilities changed
 * across the restart. Spec-conformant clients respond by issuing a
 * fresh `initialize`.
 *
 * Anthropic's claude.ai MCP connector doesn't honor that spec
 * contract (already documented for PR #18) — it wraps the 404 +
 * reinit-required response as `-32600 "Anthropic Proxy: Invalid
 * content from server"`. Result: claude.ai sessions WEDGE
 * indefinitely after a capability-changing deploy until the row is
 * manually `DELETE`d from `mcp_sessions`.
 *
 * This module automates that manual workaround for the narrow case
 * only: on boot, if `mcp_sessions` contains any row whose
 * `capability_hash` differs from the current process's
 * `GATEWAY_CAPABILITY_HASH` (or is NULL — pre-PR-23 row), every
 * non-matching row is deleted in a single statement. The client's
 * NEXT request hits the new-session POST path instead of the
 * lazy-recovery refuse path, surfacing the Anthropic-side 404
 * mishandling at most once rather than indefinitely.
 *
 * **PR #23's `shouldRefuseRecovery` would have refused these rows
 * anyway** — the nuke is strictly a proactive form of the same
 * decision, only triggered for the rows that were guaranteed
 * unrecoverable. Rows whose capability_hash matches the current
 * process (i.e., 95%+ of restarts) are never touched.
 *
 * Remove this module when Anthropic's MCP connector ships
 * spec-compliant 404 handling. Counterpart IDEAS entry in the
 * operator's COWORK repo tracks the upstream-fix expectation.
 *
 * ============================================================
 * Operational behaviour
 * ============================================================
 *
 * Idempotency: re-running on a clean table (every row already
 * stamped with the current hash, or table empty) is a no-op. Two
 * restarts in a row do not loop.
 *
 * Env knob: `MCP_AUTO_NUKE_ON_CAPABILITY_CHANGE` (default "true").
 * Set to "false" for forensic-debugging boots where preserving stale
 * rows is more useful than cleaning them.
 *
 * Failure mode: any DB error is logged and swallowed — auto-nuke is
 * a workaround, not a correctness gate. Callers route this through
 * the existing startup try/catch (`apps/backend/src/index.ts`) so a
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
