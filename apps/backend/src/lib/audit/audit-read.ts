/**
 * What `audit.list` returns of an audit row's `detail`: a whitelist of keys,
 * each value reduced to a primitive, a list of primitives or (for the keys
 * named in NESTED_DETAIL_KEYS) one level of such values.
 *
 * WHY A WHITELIST. `detail` is written by dozens of call sites over the life
 * of the table. Every one of them is meant to carry ids, names, counts and
 * old/new switch values only, but a read surface reachable by a standing
 * credential must not depend on every past writer having been right. Anything
 * not named here is dropped and counted (`detail_omitted`), so a reader can
 * tell a row was reduced without learning what was in it. Strings are clamped
 * so one oversized value cannot fill a page.
 *
 * Pure.
 */

/** Top-level detail keys a row may return. */
export const AUDIT_LIST_DETAIL_KEYS: ReadonlySet<string> = new Set([
  "reason",
  "run_id",
  "budget_class",
  "policy_widened",
  "rule",
  "via",
  "name",
  "previous",
  "restricted",
  "require_scoped_api_key",
  "is_active",
  "disabled",
  "namespace_uuid",
  "endpoint_uuid",
  "endpoint_name",
  "endpoint_restricted",
  "owner_user_id",
  "all_endpoints",
  "acts_as_user_id",
  "key_admin_plane",
  "key_admin_plane_scope",
  "admin_plane_scope",
  "group_name",
  "user_id",
  "enable_api_key_auth",
  "enable_oauth",
  "type",
  "status",
  "tool_policy",
  "tool_uuid",
  "server_uuid",
  "allowed_cidrs",
  "ip_policy_mode",
  "mode",
  "limit",
  "window_seconds",
  "admin_plane",
  "old_value",
  "new_value",
  "changed_fields",
  "ip_policy",
  "members",
  "mappings",
  // The key lifecycle procedures: a rename's old name, a removal's
  // fingerprint and snapshot (identifying metadata only, see
  // lib/api-key-lifecycle-rules `apiKeySnapshot`).
  "previous_name",
  "impact_fingerprint",
  "snapshot",
  // A server error reset: which servers, by uuid and name, and how many.
  "selection",
  "server_uuids",
  "server_names",
  "reset_count",
]);

/** Safe fields of before/after objects, independent of the write-side spec. */
const UPDATE_DETAIL_KEYS: ReadonlySet<string> = new Set([
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
  "type",
  "user_id",
  "server_uuids",
  "status",
  "restricted",
  "tool_policy",
  "allowed_cidrs",
  "ip_policy_mode",
  "mode",
]);

/**
 * Each object has its own field whitelist. Checking only the spelling of an
 * inner key would let a historical credential field such as bearer_token or
 * key_hash through an otherwise allowed old_value or snapshot object.
 */
const NESTED_DETAIL_KEYS: Readonly<Record<string, ReadonlySet<string>>> = {
  admin_plane: new Set(["key_uuid", "owner_user_id", "scope"]),
  old_value: UPDATE_DETAIL_KEYS,
  new_value: UPDATE_DETAIL_KEYS,
  ip_policy: new Set(["mode", "allowed_cidrs"]),
  snapshot: new Set([
    "name",
    "key_prefix",
    "owner_user_id",
    "endpoint_uuid",
    "acts_as_user_id",
    "is_active",
    "admin_plane",
    "allowed_cidrs",
    "ip_policy_mode",
    "created_at",
    "last_used_at",
  ]),
};

const MAX_STRING = 300;
const MAX_LIST = 100;

type Primitive = string | number | boolean | null;

function primitive(value: unknown): Primitive | undefined {
  if (value === null) return null;
  if (typeof value === "string") return value.slice(0, MAX_STRING);
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "boolean") return value;
  return undefined;
}

function flat(value: unknown): Primitive | Primitive[] | undefined {
  if (Array.isArray(value)) {
    const items = value.slice(0, MAX_LIST).map(primitive);
    return items.every((item) => item !== undefined)
      ? (items as Primitive[])
      : undefined;
  }
  return primitive(value);
}

/** The returned detail and how many keys were left out. */
export function projectAuditDetail(raw: unknown): {
  detail: Record<string, unknown>;
  omitted: number;
} {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { detail: {}, omitted: 0 };
  }
  const detail: Record<string, unknown> = {};
  let omitted = 0;
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    if (!AUDIT_LIST_DETAIL_KEYS.has(key)) {
      omitted += 1;
      continue;
    }
    const nestedKeys = NESTED_DETAIL_KEYS[key];
    if (
      nestedKeys &&
      typeof value === "object" &&
      value !== null &&
      !Array.isArray(value)
    ) {
      const nested: Record<string, unknown> = {};
      for (const [innerKey, innerValue] of Object.entries(
        value as Record<string, unknown>,
      )) {
        const reduced = nestedKeys.has(innerKey) ? flat(innerValue) : undefined;
        if (reduced === undefined) {
          omitted += 1;
          continue;
        }
        nested[innerKey] = reduced;
      }
      detail[key] = nested;
      continue;
    }
    const reduced = flat(value);
    if (reduced === undefined) {
      omitted += 1;
      continue;
    }
    detail[key] = reduced;
  }
  return { detail, omitted };
}
