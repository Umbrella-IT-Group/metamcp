import { createHash } from "node:crypto";

import type {
  TopologyRemovalCascade,
  TopologyRemovalDependent,
  TopologyRemovalHidden,
  TopologyRemovalKind,
  TopologyRemovalRule,
  TopologyRemovalSnapshot,
} from "@repo/zod-types";

import { ENDPOINT_GATE_REFUSALS } from "./endpoint-namespace-gate";

/**
 * The rules of the leaf-only topology removals: `endpoints.remove`,
 * `namespaces.remove` and `mcpServers.remove`, with the `removalImpact` reads
 * that prepare them.
 *
 * WHY NOT THE BROAD DELETES. `endpoints.delete`, `namespaces.delete` and
 * `mcpServers.delete` check only ownership, and the database cascades each of
 * them: a namespace takes its endpoints with it, an endpoint takes every API
 * key scoped to it and its access-group mappings, a server takes its mounts
 * and its tools' rows in every namespace. A standing operator-scope key must
 * not hold that. These removals take one row whose dependants are already
 * gone, the same for every caller:
 *
 *  - Never a private row (one with an owner): a person's row stays a person's
 *    act in the UI.
 *  - endpoint: no API key scoped to it, active or inactive (a key is removed
 *    as its own audited change, never as a side effect), and no access-group
 *    mapping. An operator removing the last restricted endpoint must also
 *    qualify for the namespace gate's rollback of its own restriction.
 *  - namespace: no endpoint over it.
 *  - server: no namespace mounts it, and no namespace has a tool row for it,
 *    whether the row names the server directly or names one of its tools (the
 *    two foreign keys of a tool row are independent and can disagree).
 *
 * What a removal still takes with it is the row's own content: an endpoint's
 * presentation row; a namespace's own mounts and tool rows (the servers stay);
 * a server's tool catalog and its upstream OAuth session row. That content is
 * counted in the impact and the audit snapshot and bound by the fingerprint.
 *
 * The caller confirms the row's current name and the fingerprint of its
 * current state, read with `removalImpact`: a mistake guard that refuses a
 * removal prepared against a row that has changed since. The leaf rules hold
 * without it.
 *
 * Every refusal is one fixed sentence that names no row. Pure: no database
 * and no logger.
 */

export type TopologyConfirmRule =
  | "confirm_name_mismatch"
  | "impact_changed"
  | "target_changed";

export type TopologyRefusalRule = TopologyRemovalRule | TopologyConfirmRule;

export const TOPOLOGY_REMOVAL_REFUSALS: Readonly<
  Record<
    TopologyRefusalRule,
    { code: "FORBIDDEN" | "BAD_REQUEST" | "CONFLICT"; message: string }
  >
> = {
  target_private: {
    code: "FORBIDDEN",
    message:
      "A private endpoint, namespace or MCP server cannot be removed through this procedure. Do this in the admin UI.",
  },
  endpoint_has_keys: {
    code: "CONFLICT",
    message:
      "An endpoint can be removed only once no API key is scoped to it, active or inactive. Deactivate and remove each key first, each as its own change.",
  },
  endpoint_has_groups: {
    code: "CONFLICT",
    message:
      "An endpoint can be removed only once no access group is mapped to it. Unmap each group first, each as its own change.",
  },
  admin_plane_unrestrict: ENDPOINT_GATE_REFUSALS.admin_plane_unrestrict,
  namespace_has_endpoints: {
    code: "CONFLICT",
    message:
      "A namespace can be removed only once no endpoint serves it. Remove each endpoint first, each as its own change.",
  },
  server_mounted: {
    code: "CONFLICT",
    message:
      "An MCP server can be removed only once no namespace mounts it. Remove it from each namespace first.",
  },
  server_tools_mapped: {
    code: "CONFLICT",
    message:
      "An MCP server can be removed only once no namespace holds a tool row for it. Remove those rows first.",
  },
  confirm_name_mismatch: {
    code: "BAD_REQUEST",
    message: "confirm_name must equal the row's current name.",
  },
  impact_changed: {
    code: "CONFLICT",
    message:
      "The row or what depends on it changed after its removal impact was read. Read it again and confirm the new fingerprint.",
  },
  target_changed: {
    code: "CONFLICT",
    message: "The row changed while this request was applied. Retry it.",
  },
};

/** The order every rule is reported in (the schema's order). */
const RULE_ORDER: readonly TopologyRemovalRule[] = [
  "target_private",
  "endpoint_has_keys",
  "endpoint_has_groups",
  "admin_plane_unrestrict",
  "namespace_has_endpoints",
  "server_mounted",
  "server_tools_mapped",
];

/** A refusal of one rule, carrying its fixed code and sentence. */
export class TopologyRemovalRefusal extends Error {
  readonly rule: TopologyRefusalRule;
  readonly code: "FORBIDDEN" | "BAD_REQUEST" | "CONFLICT";

  constructor(rule: TopologyRefusalRule) {
    const refusal = TOPOLOGY_REMOVAL_REFUSALS[rule];
    super(refusal.message);
    this.name = "TopologyRemovalRefusal";
    this.rule = rule;
    this.code = refusal.code;
  }
}

/** A value a snapshot or a judged field may hold. */
export type TopologyField = string | number | boolean | null;

/**
 * One row that stops the removal. `key` is its identity in the table that
 * holds it (a uuid, or `group_uuid/endpoint_uuid` for a mapping), used for the
 * fingerprint. `owner_user_id` decides whether the caller may see its name:
 * null for a public row, and for kinds every operator can list (keys, groups).
 */
export interface TopologyBlocker {
  rule: TopologyRemovalRule;
  kind: TopologyRemovalDependent["kind"];
  key: string;
  uuid: string;
  name: string;
  is_active: boolean | null;
  owner_user_id: string | null;
}

/**
 * One row the removal deletes with the target, as its own content. `version`
 * is the row's version (PostgreSQL `xmin`) for content that can be edited in
 * place, and null for content bound by identity only (an upstream OAuth
 * session, whose tokens refresh on the same row).
 */
export interface TopologyCascadeRow {
  kind: TopologyRemovalCascade["kind"];
  key: string;
  version: string | null;
}

/** The state of one removal target as one read or one locked transaction saw it. */
export interface TopologyRemovalState {
  kind: TopologyRemovalKind;
  uuid: string;
  name: string;
  user_id: string | null;
  /** The target row's version (PostgreSQL `xmin`). */
  version: string;
  /** The columns the rules judge and the snapshot records, by name. */
  fields: Readonly<Record<string, TopologyField>>;
  /** Only an endpoint can be the last restricted route over a namespace. */
  unrestrict_refused?: boolean;
  blockers: readonly TopologyBlocker[];
  cascades: readonly TopologyCascadeRow[];
  live_sessions: number | null;
}

/** Every rule that refuses this target now, in the reported order. */
export function removalBlockers(
  state: Pick<
    TopologyRemovalState,
    "user_id" | "blockers" | "unrestrict_refused"
  >,
): TopologyRemovalRule[] {
  const found = new Set<TopologyRemovalRule>(state.blockers.map((b) => b.rule));
  if (state.user_id !== null) found.add("target_private");
  if (state.unrestrict_refused) found.add("admin_plane_unrestrict");
  return RULE_ORDER.filter((rule) => found.has(rule));
}

/** The first rule that refuses this target, or null when it may be removed. */
export function firstRemovalBlocker(
  state: Pick<
    TopologyRemovalState,
    "user_id" | "blockers" | "unrestrict_refused"
  >,
): TopologyRemovalRule | null {
  return removalBlockers(state)[0] ?? null;
}

function sortedFields(
  fields: Readonly<Record<string, TopologyField>>,
): Array<[string, TopologyField]> {
  return Object.keys(fields)
    .sort()
    .map((name) => [name, fields[name] ?? null]);
}

/**
 * The fingerprint of a removal target's current state: sha256 over the
 * operation, the target's identity, owner, row version and judged fields, and
 * every blocker and cascaded row by its key (cascaded content also by its row
 * version), each set sorted so the database's return order cannot change it.
 * Any change between the impact read and the removal (a rename, an in-place
 * edit, a new key, mount or tool row, an edited tool) changes it. Persisted
 * session counts are not an input: they churn every minute and a removal does
 * not touch them. Holds no credential material: a server's connection fields
 * are bound only through its row version.
 */
export function topologyRemovalFingerprint(
  state: TopologyRemovalState,
): string {
  const canonical = JSON.stringify([
    "topology.remove.v1",
    state.kind,
    state.uuid.toLowerCase(),
    state.name,
    state.user_id,
    state.version,
    state.unrestrict_refused ?? false,
    sortedFields(state.fields),
    state.blockers
      .map((b) => [b.rule, b.kind, b.key])
      .sort((a, b) => (a.join("\n") < b.join("\n") ? -1 : 1)),
    state.cascades
      .map((c) => [c.kind, c.key, c.version])
      .sort((a, b) => (`${a[0]}\n${a[1]}` < `${b[0]}\n${b[1]}` ? -1 : 1)),
  ]);
  return `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
}

/** Is this blocker's row one the caller may see by name? */
function visibleTo(blocker: TopologyBlocker, callerUserId: string): boolean {
  return (
    blocker.owner_user_id === null || blocker.owner_user_id === callerUserId
  );
}

/**
 * The blockers the caller may see, by name, sorted by rule then name. A
 * namespace that holds several tool rows of one server is listed once per
 * rule; the fingerprint still binds every row.
 */
export function visibleDependents(
  state: Pick<TopologyRemovalState, "blockers">,
  callerUserId: string,
): TopologyRemovalDependent[] {
  const seen = new Set<string>();
  return state.blockers
    .filter((b) => visibleTo(b, callerUserId))
    .filter((b) => {
      const id = `${b.rule}\n${b.kind}\n${b.uuid}`;
      if (seen.has(id)) return false;
      seen.add(id);
      return true;
    })
    .map((b) => ({
      rule: b.rule,
      kind: b.kind,
      uuid: b.uuid,
      name: b.name,
      is_active: b.is_active,
    }))
    .sort((a, b) =>
      a.rule !== b.rule
        ? RULE_ORDER.indexOf(a.rule) - RULE_ORDER.indexOf(b.rule)
        : a.name !== b.name
          ? a.name < b.name
            ? -1
            : 1
          : a.uuid < b.uuid
            ? -1
            : 1,
    );
}

/** The blockers the caller may not see, counted per rule. */
export function hiddenDependents(
  state: Pick<TopologyRemovalState, "blockers">,
  callerUserId: string,
): TopologyRemovalHidden[] {
  const counts = new Map<TopologyRemovalRule, number>();
  for (const b of state.blockers) {
    if (!visibleTo(b, callerUserId)) {
      counts.set(b.rule, (counts.get(b.rule) ?? 0) + 1);
    }
  }
  return RULE_ORDER.filter((rule) => counts.has(rule)).map((rule) => ({
    rule,
    count: counts.get(rule) as number,
  }));
}

const CASCADE_ORDER: readonly TopologyRemovalCascade["kind"][] = [
  "endpoint_presentation",
  "namespace_server_mapping",
  "namespace_tool_mapping",
  "tool",
  "oauth_session",
];

/** What the removal takes with it, counted per kind (zero counts left out). */
export function cascadeCounts(
  state: Pick<TopologyRemovalState, "cascades">,
): TopologyRemovalCascade[] {
  return CASCADE_ORDER.map((kind) => ({
    kind,
    count: state.cascades.filter((c) => c.kind === kind).length,
  })).filter((c) => c.count > 0);
}

/**
 * What a removal records of the row it deletes: the kind, name and owner, the
 * judged fields the repository picked (an explicit allowlist per kind, never a
 * connection setting, credential or free text), and the cascaded content
 * counted per kind.
 */
export function topologySnapshot(
  state: TopologyRemovalState,
): TopologyRemovalSnapshot {
  const snapshot: TopologyRemovalSnapshot = {
    kind: state.kind,
    name: state.name,
    owner_user_id: state.user_id,
  };
  for (const [name, value] of sortedFields(state.fields)) {
    snapshot[name] = value;
  }
  for (const cascade of cascadeCounts(state)) {
    snapshot[`cascade_${cascade.kind}_count`] = cascade.count;
  }
  return snapshot;
}

/**
 * The confirmation a removal must carry, judged against the state read under
 * the removal's locks: the row's current name, exactly, then the fingerprint
 * of that state.
 */
export function assertTopologyRemovalConfirmed(
  state: TopologyRemovalState,
  confirmName: string,
  fingerprint: string,
): void {
  if (confirmName !== state.name) {
    throw new TopologyRemovalRefusal("confirm_name_mismatch");
  }
  if (fingerprint !== topologyRemovalFingerprint(state)) {
    throw new TopologyRemovalRefusal("impact_changed");
  }
}
