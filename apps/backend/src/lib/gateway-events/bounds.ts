import {
  GATEWAY_EVENT_PAGE_MAX,
  GATEWAY_EVENT_SEARCH_MAX,
} from "@repo/zod-types";

/**
 * Size and shape bounds for `gateway_events` (migration 0031) — everything
 * that decides how much one event may cost the archive, and how much one
 * filter may cost the database.
 *
 * Kept in its own DB-free module so both halves can import it (the writer in
 * `./sink`, the reader in `db/repositories/gateway-events.repo`) and so the
 * bounds themselves are unit-testable without a database anywhere in the
 * graph — the same reason `lib/audit/audit-emitter` keeps `clampAuditText`
 * beside the emitter rather than inside the repository.
 *
 * WHY BOUNDS AT ALL. A `gateway_events` row is immutable for 30 days, so its
 * SIZE is exactly as permanent as its contents for that whole window: nothing
 * can trim an oversized row, and the retention sweeper cannot reach it early.
 * Events are built from backend stderr, transport error text and connection
 * detail — none of which this gateway authors, and some of which an upstream
 * server can make arbitrarily long. Clamping at the writer is what keeps a
 * chatty backend from becoming a write-amplification primitive against a
 * table that cannot be pruned for a month.
 */

/**
 * 1024 for `message`.
 *
 * The messages this gateway writes are one-liners — "Connected after 3
 * attempts", "Transport closed unexpectedly (backend drop, 4m12s)" — and the
 * longest realistic one is a connect failure carrying an unwrapped undici
 * cause, which lands comfortably under 300 characters. 1024 keeps every real
 * message whole while capping the pathological case: a backend that writes a
 * megabyte of stderr in one line reaches `log-store.addLog` verbatim today.
 */
export const GATEWAY_EVENT_MESSAGE_MAX = 1024;

/**
 * 256 for the identity columns (`server_name`, `client_name`, `session_id`).
 *
 * Server names are operator-chosen and short. Client names are resolved
 * api-key names or OAuth email addresses. Session ids are generated UUIDs. All
 * three are bounded in practice; 256 is the bound made explicit so a malformed
 * or hostile value cannot widen the row.
 */
export const GATEWAY_EVENT_TEXT_MAX = 256;

/**
 * 2048 characters of serialized JSON for `metadata`.
 *
 * `metadata` carries the small structured extras the flat columns have no room
 * for — tool name, duration, normalized error text. It is NOT a place to put a
 * request body or a stack trace, and the bound is what enforces that rather
 * than trusting each future call site to be tasteful. A value that does not
 * serialize, or that serializes past the bound, is dropped entirely rather
 * than truncated: half a JSON document is not a JSON document, and a row with
 * no metadata is strictly better than a row whose metadata cannot be parsed.
 */
export const GATEWAY_EVENT_METADATA_MAX_CHARS = 2048;

// Re-exported, not redefined. Both numbers are part of the wire contract in
// `@repo/zod-types` (the request schema rejects a larger page and clamps a
// longer search), and the repository applies them again server-side. Two
// literals would be two places to change and one place to forget.
export { GATEWAY_EVENT_PAGE_MAX, GATEWAY_EVENT_SEARCH_MAX };

/** Clamp a caller-supplied string, degrading a missing value to null. */
export function clampGatewayText(
  value: string | null | undefined,
  maxLength: number = GATEWAY_EVENT_TEXT_MAX,
): string | null {
  if (value === null || value === undefined) return null;
  const text = String(value);
  if (text === "") return null;
  return text.slice(0, maxLength);
}

/**
 * Clamp a metadata object to something worth storing, or drop it.
 *
 * Returns null for absent, unserializable, or oversized input. Callers store
 * the result directly — there is deliberately no "truncated" marker, because a
 * marker in a jsonb column that a reader must remember to check is worse than
 * an absent column a reader cannot misread.
 */
export function clampGatewayMetadata(
  metadata: Record<string, unknown> | null | undefined,
): Record<string, unknown> | null {
  if (!metadata) return null;
  try {
    const serialized = JSON.stringify(metadata);
    if (serialized === undefined) return null;
    if (serialized.length > GATEWAY_EVENT_METADATA_MAX_CHARS) return null;
    // Round-trip rather than passing the caller's object through: the value is
    // handed to a detached write, so a caller that mutates the object after
    // calling would otherwise change what gets persisted.
    return JSON.parse(serialized) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/**
 * Neutralise LIKE metacharacters in a user-supplied substring filter.
 *
 * Without this, a search for `100%` is a search for "starts with 100" and a
 * search for `_` matches every row — the filter silently means something other
 * than what the operator typed, which on an investigation surface is worse
 * than a filter that errors. `\` is escaped first so escaping the others
 * cannot double-escape it. The caller pairs the result with an explicit
 * `ESCAPE '\'` so the behaviour does not depend on the server's
 * `standard_conforming_strings` setting.
 */
export function escapeLikePattern(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_");
}

/** Clamp a substring filter to the length the read surface will match on. */
export function clampSearchText(value: string): string {
  return value.slice(0, GATEWAY_EVENT_SEARCH_MAX);
}
