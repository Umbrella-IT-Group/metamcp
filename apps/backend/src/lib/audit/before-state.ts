/**
 * The before-state of an update, as an audit row carries it: which fields the
 * write changed, and the previous and new value of each changed field that
 * cannot hold a credential.
 *
 * WHY A SPEC PER UPDATE. An audit row that records only the new value answers
 * "what is it now" and never "what was it before", and the second question is
 * the one asked when a change has to be undone or explained. But a row is
 * permanent, readable by every holder of the audit read, and a server's `env`,
 * `headers`, bearer token, URL and arguments are exactly where credentials
 * live. So every update names its fields in two groups:
 *
 *  - `plain`: recorded with their previous and new value (clamped);
 *  - `credential`: only the fact that they changed is recorded, in
 *    `changed_fields`, never a value, a hash, a length or a diff.
 *
 * A field that is in neither group is not looked at, and a `plain` field whose
 * value is not a scalar or a list of strings is recorded as changed only, so a
 * structure that turns out to carry something else leaks nothing. The caller
 * passes the row as it was under the write's lock and as it is after it.
 *
 * Pure.
 */
import { clampAuditText } from "./audit-emitter";

/** What an audit row may hold of a changed field's value. */
export type AuditFieldValue = string | number | boolean | null | string[];

export interface UpdateFields {
  /** Recorded with previous and new value. Must never hold a credential. */
  readonly plain: readonly string[];
  /** May hold a credential: only the fact of the change is recorded. */
  readonly credential: readonly string[];
}

export interface UpdateBeforeState {
  /** Every changed field of either group, by its snake_case name, sorted. */
  changed_fields: string[];
  /** Previous value of each changed plain field. */
  old_value: Record<string, AuditFieldValue>;
  /** New value of each changed plain field. */
  new_value: Record<string, AuditFieldValue>;
}

const MAX_TEXT = 200;
const MAX_LIST = 100;
const MAX_LIST_TEXT = 100;

/** `bearerToken` is recorded as `bearer_token`. */
function label(key: string): string {
  return key.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`);
}

/** Key-order-independent text of a value, for "did it change". */
function canonical(value: unknown): string {
  if (value === undefined || value === null) return "null";
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([key, inner]) => `${JSON.stringify(key)}:${canonical(inner)}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value);
}

/** The recordable form of a plain value, or undefined when it has none. */
function recordable(value: unknown): AuditFieldValue | undefined {
  if (value === undefined || value === null) return null;
  if (typeof value === "string") return clampAuditText(value, MAX_TEXT);
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : undefined;
  }
  if (typeof value === "boolean") return value;
  if (Array.isArray(value) && value.every((item) => typeof item === "string")) {
    return value
      .slice(0, MAX_LIST)
      .map((item) => clampAuditText(item, MAX_LIST_TEXT));
  }
  return undefined;
}

export function describeUpdate(
  before: Readonly<Record<string, unknown>>,
  after: Readonly<Record<string, unknown>>,
  fields: UpdateFields,
): UpdateBeforeState {
  const changed = new Set<string>();
  const old_value: Record<string, AuditFieldValue> = {};
  const new_value: Record<string, AuditFieldValue> = {};

  for (const key of fields.credential) {
    if (canonical(before[key]) !== canonical(after[key])) {
      changed.add(label(key));
    }
  }
  for (const key of fields.plain) {
    if (canonical(before[key]) === canonical(after[key])) continue;
    changed.add(label(key));
    const previous = recordable(before[key]);
    const current = recordable(after[key]);
    // Both or neither: a half-recorded pair would read as a value that was
    // never there.
    if (previous === undefined || current === undefined) continue;
    old_value[label(key)] = previous;
    new_value[label(key)] = current;
  }
  return { changed_fields: [...changed].sort(), old_value, new_value };
}

/**
 * The fields of each operator-callable update, by row column. A server's
 * connection fields (`command`, `args`, `url`, `env`, `bearerToken`,
 * `headers`) are all `credential`: an argument, a query string or a command
 * line can carry a token as readily as a header can. Only a column that holds
 * a name, a switch, a number, an id or a list of ids is `plain`.
 *
 * The unit test beside this file compares each list with the table's columns,
 * so a column added later has to be put in a group, or named as deliberately
 * not recorded, before the suite passes.
 */
export const ENDPOINT_UPDATE_FIELDS: UpdateFields = {
  plain: [
    "name",
    "description",
    "namespace_uuid",
    "enable_api_key_auth",
    "require_scoped_api_key",
    "enable_oauth",
    "enable_max_rate",
    "enable_client_max_rate",
    "max_rate",
    "max_rate_seconds",
    "client_max_rate",
    "client_max_rate_seconds",
    "client_max_rate_strategy",
    "client_max_rate_strategy_key",
    "use_query_param_auth",
  ],
  credential: [],
};

export const MCP_SERVER_UPDATE_FIELDS: UpdateFields = {
  plain: ["name", "description", "type", "user_id"],
  credential: ["command", "args", "url", "env", "bearerToken", "headers"],
};

export const NAMESPACE_UPDATE_FIELDS: UpdateFields = {
  plain: ["name", "description", "user_id", "server_uuids"],
  credential: [],
};

export const ACCESS_GROUP_UPDATE_FIELDS: UpdateFields = {
  plain: ["name", "description"],
  credential: [],
};

export const TOOL_STATUS_UPDATE_FIELDS: UpdateFields = {
  plain: ["status"],
  credential: [],
};
