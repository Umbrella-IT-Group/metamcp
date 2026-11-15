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

/** Keys whose value may be one level of object, itself reduced. */
const NESTED_DETAIL_KEYS: ReadonlySet<string> = new Set([
  "admin_plane",
  "old_value",
  "new_value",
  "ip_policy",
  "snapshot",
]);

const NESTED_KEY = /^[a-z][a-z0-9_]{0,39}$/;
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
    if (
      NESTED_DETAIL_KEYS.has(key) &&
      typeof value === "object" &&
      value !== null &&
      !Array.isArray(value)
    ) {
      const nested: Record<string, unknown> = {};
      for (const [innerKey, innerValue] of Object.entries(
        value as Record<string, unknown>,
      )) {
        const reduced = NESTED_KEY.test(innerKey)
          ? flat(innerValue)
          : undefined;
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
