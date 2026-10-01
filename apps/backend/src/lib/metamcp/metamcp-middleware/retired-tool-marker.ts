/**
 * Process-local marker for a tool result that the retired-tool redirect
 * produced, carrying the one fact the audit log line needs from it.
 *
 * WHY A WEAKMAP and not a field on the result. The audit middleware has to tell
 * "the gateway itself answered with a retirement notice" apart from "a backend
 * returned text that says it is retired". A field or a text marker on the
 * result could be spoofed by any backend, because a backend controls its own
 * result bodies. An object identity registered in a module-private WeakMap
 * cannot cross a process boundary, so only code in this process can set it.
 *
 * Lives in its own tiny module, imported by both the audit classifier and the
 * redirect middleware, so neither has to import the other (the classifier stays
 * free of the loader and the filesystem; the middleware stays free of the
 * audit). Entries are garbage collected with the result object.
 */

export interface RetiredToolInfo {
  /** The replacement tool name from the retired map, or null when none exists. */
  replacement: string | null;
}

const retiredResults = new WeakMap<object, RetiredToolInfo>();

/** Register a redirect result as gateway-produced. Returns it for chaining. */
export function markRetiredToolResult<T extends object>(
  result: T,
  info: RetiredToolInfo,
): T {
  retiredResults.set(result, info);
  return result;
}

/** True only for an object registered by {@link markRetiredToolResult}. */
export function isRetiredToolResult(value: unknown): boolean {
  return (
    typeof value === "object" && value !== null && retiredResults.has(value)
  );
}

/** What {@link markRetiredToolResult} recorded, or undefined for any other value. */
export function getRetiredToolInfo(
  value: unknown,
): RetiredToolInfo | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  return retiredResults.get(value);
}
