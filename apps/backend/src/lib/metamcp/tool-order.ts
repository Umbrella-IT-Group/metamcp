/**
 * The one order every aggregated tool listing leaves in.
 *
 * WHY THIS EXISTS (issue #278): a namespace listing fans out to every mounted
 * backend at once, and each branch used to append its tools to a shared array
 * when ITS answer arrived. The order was therefore the order the backends
 * finished, which changes from call to call. A client that hashes the list
 * (Open WebUI re-reads openapi.json and treats a changed spec as new tools) or
 * that caches a prompt prefix built from the tool list (every agent of ours)
 * saw a "different" listing each time with no tool added or removed.
 *
 * The order is byte-wise on the tool name: JavaScript `<` on strings compares
 * UTF-16 code units, so it does not depend on the host locale or ICU build the
 * way `localeCompare` does. A name is `<server>__<tool>`, so tools group by
 * server. `Array.prototype.sort` is stable, so equal names (an audit or bridge
 * listing can carry two) keep the order the caller assembled them in, which the
 * handlers make the mount order (never completion order).
 *
 * Pure and dependency-free, like `lean-listing.ts`, so every suite can import
 * it without mocking a database.
 */

export interface NamedTool {
  readonly name: string;
}

/** Byte-wise (UTF-16 code unit) order on the tool name. */
export function compareToolNames(a: NamedTool, b: NamedTool): number {
  return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
}

/**
 * The listing in the one stable order. Returns a copy: the input may be a
 * cached array another reader still holds.
 */
export function sortToolsByName<T extends NamedTool>(tools: readonly T[]): T[] {
  return [...tools].sort(compareToolNames);
}
