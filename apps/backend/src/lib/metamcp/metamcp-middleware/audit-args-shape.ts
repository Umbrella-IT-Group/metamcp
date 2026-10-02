/**
 * The shape of a tool call's arguments, for `tool_call_audit.args_shape`.
 *
 * WHY THIS EXISTS. The audit row stores a sha256 of the arguments and nothing
 * else about them, so a question like "which mode of this tool do people get
 * wrong" or "which parameter name keeps being refused" cannot be answered from
 * SQL for any consumer. This records the SHAPE of the call, not its content:
 * the top-level argument key names, plus the value of a small allowlist of
 * selector keys whose values are short enumerations (a mode, an action, a
 * profile) and never free text.
 *
 * WHAT IS STORED, and the only values that ever are. A key name is chosen by the
 * caller before any tool validates it, so a name is stored only when the tool's
 * OWN published inputSchema declares it (`tool-arg-keys.ts`, filled from
 * tools/list; Sol review 2026-10-02: identifier syntax alone let `Alice_Smith` or
 * `client_secret_x` into an immutable row):
 *   keys            the top-level key names the tool's schema declares, sorted.
 *   sel             the value of each allowlisted selector key the schema
 *                   declares, only when the property declares an enum or const
 *                   and the value is one of its members (and short and
 *                   identifier-shaped); a member-less value stores "?", and a
 *                   selector whose schema has no enum stores "*" (sent, value
 *                   not from a closed set, so not stored).
 *   unknown_keys    count of identifier-shaped keys the schema does not declare.
 *   invalid_keys    count of key names that are not identifier-shaped.
 *   unverified_keys when the tool's schema is not known to this process yet
 *                   (never listed, or a retired name): the count of keys, and
 *                   NO names and NO selector values at all.
 * Argument VALUES outside `sel` are never stored, nested key names are never
 * stored, and no caller-chosen name is ever echoed.
 *
 * PURE and DB-free (the middleware imports this statically; the repository
 * stays a lazy import). It never throws on a well-formed JSON-RPC argument
 * value; the middleware still guards the call because a Proxy with a throwing
 * getter is the one input a JSON parser cannot produce but a test can.
 *
 * Rows are write-once (migration 0032), so a wrong shape cannot be corrected or
 * backfilled. That is why the charset rules below are strict and why there is a
 * kill switch (`TOOL_AUDIT_ARGS_SHAPE=off` stores NULL).
 */

import type { ToolArgSchema } from "../tool-arg-keys";

/**
 * Selector keys whose VALUE is recorded. A code constant, so widening it is a
 * reviewed change. All six are short enumerations on every tool in the fleet
 * (`mode`/`action`/`profile` on the consolidated domain tools, `operation` on
 * the raw-surface vendor tools, `entity` on the registry sync tool, `method`
 * as the HTTP verb on the Graph tools, which separates a read from a write
 * without storing a path).
 */
export const SELECTOR_KEYS = [
  "mode",
  "action",
  "profile",
  "operation",
  "entity",
  "method",
] as const;

/** A selector value is recorded only when it is at most this long. */
export const SELECTOR_VALUE_MAX = 32;
/** A key name longer than this is counted in `invalid_keys`, never echoed. */
export const KEY_MAX_LEN = 40;
/** At most this many key names are stored; the rest set `truncated`. */
export const MAX_KEYS = 32;

/** Marker stored in place of a selector value that failed the value policy. */
export const SELECTOR_MISUSE_MARKER = "?";

/**
 * Marker stored for a selector the schema declares without an enum or const:
 * it was sent, but its value is not from a closed set, so it is not stored.
 */
export const SELECTOR_UNENUMERATED_MARKER = "*";

export interface ArgsShape {
  /** Allowlisted selector values, keyed by selector name. Omitted when none. */
  sel?: Record<string, string>;
  /** Sorted top-level key names (identifier-shaped only), at most MAX_KEYS. */
  keys: string[];
  /** Count of top-level keys that failed the key policy (never echoed). */
  invalid_keys?: number;
  /** Count of identifier-shaped keys the tool's schema does not declare (never echoed). */
  unknown_keys?: number;
  /** Key count when the tool's schema is unknown; then no names or selector values are stored. */
  unverified_keys?: number;
  /** True when more than MAX_KEYS valid keys were sent. */
  truncated?: true;
  /** True when the arguments were not a plain object (array, string, ...). */
  non_object?: true;
}

// A letter or underscore, then up to KEY_MAX_LEN-1 letters, digits, `_`, `.`
// or `-`. Anchored; no `i` flag needed because both cases are listed.
const KEY_PATTERN = new RegExp(
  `^[A-Za-z_][A-Za-z0-9_.-]{0,${KEY_MAX_LEN - 1}}$`,
);

// A letter, then up to SELECTOR_VALUE_MAX-1 letters, digits, `_`, `.`, `:` or
// `-`. No `@`, no whitespace, no slash: an email address, a sentence and a path
// all fail and are stored as the misuse marker.
const SELECTOR_VALUE_PATTERN = new RegExp(
  `^[A-Za-z][A-Za-z0-9_.:-]{0,${SELECTOR_VALUE_MAX - 1}}$`,
);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") return false;
  if (Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Kill switch. `TOOL_AUDIT_ARGS_SHAPE` set to `off`, `false` or `0` (any case,
 * surrounding whitespace ignored) stores NULL instead of a shape. Read on every
 * call: an env lookup is cheap next to the call it audits, and a test or an
 * operator hot-patching a container sees the change without a restart hook.
 */
export function argsShapeEnabled(): boolean {
  const raw = process.env.TOOL_AUDIT_ARGS_SHAPE?.trim().toLowerCase();
  return raw !== "off" && raw !== "false" && raw !== "0";
}

export function buildArgsShape(
  args: unknown,
  schema?: ToolArgSchema,
): ArgsShape {
  if (args === undefined || args === null) {
    return { keys: [] };
  }
  if (!isPlainObject(args)) {
    return { keys: [], non_object: true };
  }

  // Object.keys, not for...in: own enumerable string keys only, so nothing
  // inherited is ever read. A JSON.parse'd `__proto__` is an OWN key and shows
  // up here as an ordinary (valid-shaped) name without touching the prototype.
  const allKeys = Object.keys(args);
  if (!schema) {
    // Unknown tool: no caller-chosen name or value may be stored. The count
    // still shows the call's size.
    return allKeys.length > 0
      ? { keys: [], unverified_keys: allKeys.length }
      : { keys: [] };
  }
  const valid: string[] = [];
  let invalid = 0;
  let unknown = 0;
  for (const key of allKeys) {
    if (!KEY_PATTERN.test(key)) {
      invalid += 1;
    } else if (!schema.keys.has(key)) {
      unknown += 1;
    } else {
      valid.push(key);
    }
  }
  // Default sort: UTF-16 code-unit order, locale independent, so the same call
  // always yields the same array and GROUP BY on `keys` is meaningful.
  valid.sort();

  const shape: ArgsShape = { keys: valid };
  if (valid.length > MAX_KEYS) {
    shape.keys = valid.slice(0, MAX_KEYS);
    shape.truncated = true;
  }
  if (invalid > 0) {
    shape.invalid_keys = invalid;
  }
  if (unknown > 0) {
    shape.unknown_keys = unknown;
  }

  const sel: Record<string, string> = {};
  for (const selector of SELECTOR_KEYS) {
    // hasOwnProperty, not `in`: a selector present only on a prototype is not
    // something the caller sent.
    if (!Object.prototype.hasOwnProperty.call(args, selector)) continue;
    // A selector the schema does not declare is just an unknown key (counted above).
    if (!schema.keys.has(selector)) continue;
    const value = args[selector];
    const declared = schema.enums.get(selector);
    if (!declared) {
      // No enum or const in the schema: any string is possible, so the value
      // could be caller-chosen content (Sol review 2026-10-02, second pass).
      // Record only that the selector was sent.
      sel[selector] = SELECTOR_UNENUMERATED_MARKER;
      continue;
    }
    const ok =
      typeof value === "string" &&
      SELECTOR_VALUE_PATTERN.test(value) &&
      declared.has(value);
    sel[selector] = ok ? (value as string) : SELECTOR_MISUSE_MARKER;
  }
  if (Object.keys(sel).length > 0) {
    shape.sel = sel;
  }

  return shape;
}
