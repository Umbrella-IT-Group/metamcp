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
 * WHAT IS STORED, and the only values that ever are:
 *   keys  every top-level own key name that looks like an identifier, sorted.
 *   sel   the value of each allowlisted selector key that is present, when the
 *         value is a short identifier-shaped string; otherwise the literal
 *         marker "?" so misuse stays visible without echoing the value.
 * Argument VALUES outside `sel` are never stored, nested key names are never
 * stored, and a key name that is not identifier-shaped is counted
 * (`invalid_keys`) and never echoed, because a caller-controlled key name must
 * not become a data channel into an immutable table.
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

export interface ArgsShape {
  /** Allowlisted selector values, keyed by selector name. Omitted when none. */
  sel?: Record<string, string>;
  /** Sorted top-level key names (identifier-shaped only), at most MAX_KEYS. */
  keys: string[];
  /** Count of top-level keys that failed the key policy (never echoed). */
  invalid_keys?: number;
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

export function buildArgsShape(args: unknown): ArgsShape {
  if (args === undefined || args === null) {
    return { keys: [] };
  }
  if (!isPlainObject(args)) {
    return { keys: [], non_object: true };
  }

  // Object.keys, not for...in: own enumerable string keys only, so nothing
  // inherited is ever read. A JSON.parse'd `__proto__` is an OWN key and shows
  // up here as an ordinary (valid-shaped) name without touching the prototype.
  const valid: string[] = [];
  let invalid = 0;
  for (const key of Object.keys(args)) {
    if (KEY_PATTERN.test(key)) {
      valid.push(key);
    } else {
      invalid += 1;
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

  const sel: Record<string, string> = {};
  for (const selector of SELECTOR_KEYS) {
    // hasOwnProperty, not `in`: a selector present only on a prototype is not
    // something the caller sent.
    if (!Object.prototype.hasOwnProperty.call(args, selector)) continue;
    const value = args[selector];
    sel[selector] =
      typeof value === "string" && SELECTOR_VALUE_PATTERN.test(value)
        ? value
        : SELECTOR_MISUSE_MARKER;
  }
  if (Object.keys(sel).length > 0) {
    shape.sel = sel;
  }

  return shape;
}
