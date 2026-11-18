import type { TopologyRemovalKind } from "@repo/zod-types";
import { type SQL, sql } from "drizzle-orm";

import {
  isOwnRecentRestriction,
  UNRESTRICT_ROLLBACK_WINDOW_HOURS,
} from "../../lib/endpoint-namespace-gate";
import {
  assertTopologyRemovalConfirmed,
  firstRemovalBlocker,
  type TopologyBlocker,
  type TopologyCascadeRow,
  type TopologyField,
  TopologyRemovalRefusal,
  type TopologyRemovalState,
} from "../../lib/topology-removal-rules";
import { lockEndpointNamespaces } from "./admin-plane-locks";
import type { DbTransaction } from "./db-executor";

/**
 * Reads and removals of the leaf-only topology removals (lib/topology-removal-
 * rules has the rules and why). Raw SQL on purpose: each read names the row
 * version (`xmin`) the fingerprint binds, and the locked reads must be exactly
 * the statements below, in this order.
 *
 * Lock order (db/repositories/admin-plane-locks): after the change budget lock
 * (1), an endpoint or namespace removal takes the endpoint gate lock of the
 * namespace concerned (3), then the target row FOR UPDATE (endpoint 5, then
 * its remaining namespace guard, if needed, and presentation row; namespace
 * row after 5, then its own mounts and tool rows in uuid order). A server
 * removal takes the server row FOR UPDATE (9b),
 * then its tool catalog rows FOR UPDATE in uuid order (9c) and its OAuth
 * session FOR KEY SHARE (9d).
 *
 * Why those locks are enough. A child row's foreign-key check takes FOR KEY
 * SHARE on the parent row, which waits for FOR UPDATE. So once the target row
 * is locked, no new API key, group mapping or endpoint can commit against it,
 * and once a server's catalog rows are locked, no new tool row naming one of
 * its tools can either. Every blocker below is read by a statement issued
 * after those locks are held; at READ COMMITTED each statement sees every row
 * committed before it started, including a child whose commit the lock waited
 * for.
 */

type Row = Record<string, unknown>;

interface RemovalCaller {
  userId: string;
  adminPlaneKeyUuid: string | null;
}

async function rows(executor: DbTransaction, query: SQL): Promise<Row[]> {
  const result = await executor.execute(query);
  return (result as unknown as { rows: Row[] }).rows;
}

function text(value: unknown): string {
  return typeof value === "string" ? value : String(value);
}

function nullableText(value: unknown): string | null {
  return value === null || value === undefined ? null : text(value);
}

function iso(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return value instanceof Date ? value.toISOString() : text(value);
}

function bool(value: unknown): boolean {
  return value === true;
}

function count(value: unknown): number {
  return Number(value ?? 0);
}

/** A lock clause for a statement that must lock in a removal, else nothing. */
function forUpdate(lock: boolean): SQL {
  return lock ? sql` FOR UPDATE` : sql``;
}

/** Apply visibility in the target read, including any row recheck after a lock wait. */
function visibleTarget(callerUserId: string): SQL {
  return sql`(user_id IS NULL OR user_id = ${callerUserId})`;
}

async function endpointState(
  executor: DbTransaction,
  uuid: string,
  { userId, adminPlaneKeyUuid }: RemovalCaller,
  lock: boolean,
): Promise<TopologyRemovalState | null> {
  let expectedNamespace: string | undefined;
  if (lock) {
    // The gate lock of the endpoint's namespace first (position 3). The
    // namespace is learned from an unlocked read; the locked row must name
    // the same one, or a concurrent move overtook this request.
    const [first] = await rows(
      executor,
      sql`SELECT namespace_uuid FROM endpoints
          WHERE uuid = ${uuid} AND ${visibleTarget(userId)}`,
    );
    if (!first) return null;
    expectedNamespace = text(first.namespace_uuid);
    await lockEndpointNamespaces(executor, [expectedNamespace]);
  }
  const [row] = await rows(
    executor,
    sql`SELECT uuid, name, user_id, xmin::text AS version, namespace_uuid,
          enable_api_key_auth, enable_oauth, require_scoped_api_key,
          use_query_param_auth, restricted, created_at, updated_at,
          restricted_by_api_key_uuid,
          coalesce(restricted_at > clock_timestamp() - make_interval(hours => ${UNRESTRICT_ROLLBACK_WINDOW_HOURS}), false)
            AS restriction_recent
        FROM endpoints WHERE uuid = ${uuid} AND ${visibleTarget(userId)}${forUpdate(lock)}`,
  );
  // Check visibility before reporting a move. Both can change during the wait.
  if (!row) return null;
  const namespaceUuid = text(row.namespace_uuid);
  if (expectedNamespace !== undefined && namespaceUuid !== expectedNamespace) {
    throw new TopologyRemovalRefusal("target_changed");
  }

  const restricted = bool(row.restricted);
  let unrestrictRefused = false;
  if (
    restricted &&
    adminPlaneKeyUuid !== null &&
    !isOwnRecentRestriction(
      {
        restricted,
        restricted_by_api_key_uuid: nullableText(
          row.restricted_by_api_key_uuid,
        ),
        restriction_recent: bool(row.restriction_recent),
      },
      adminPlaneKeyUuid,
    )
  ) {
    // Removing the last guard opens the namespace just as moving it does.
    // Lock the remaining guard because a broad human delete can remove it
    // without taking our namespace gate lock.
    const [sibling] = await rows(
      executor,
      sql`SELECT 1 FROM endpoints
          WHERE namespace_uuid = ${namespaceUuid} AND restricted AND uuid <> ${uuid}
          ORDER BY uuid LIMIT 1${lock ? sql` FOR SHARE` : sql``}`,
    );
    unrestrictRefused = sibling === undefined;
  }

  const cascades: TopologyCascadeRow[] = (
    await rows(
      executor,
      sql`SELECT endpoint_uuid, xmin::text AS version
          FROM endpoint_presentation WHERE endpoint_uuid = ${uuid}${forUpdate(lock)}`,
    )
  ).map((r) => ({
    kind: "endpoint_presentation",
    key: text(r.endpoint_uuid),
    version: text(r.version),
  }));

  const blockers: TopologyBlocker[] = [
    // Every key, active or not: the database would delete each with the
    // endpoint. Keys are listed to an operator in full (apiKeys.listAll), so
    // each is visible by name.
    ...(
      await rows(
        executor,
        sql`SELECT uuid, name, is_active FROM api_keys
            WHERE endpoint_uuid = ${uuid} ORDER BY uuid`,
      )
    ).map(
      (r): TopologyBlocker => ({
        rule: "endpoint_has_keys",
        kind: "api_key",
        key: text(r.uuid),
        uuid: text(r.uuid),
        name: text(r.name),
        is_active: bool(r.is_active),
        owner_user_id: null,
      }),
    ),
    ...(
      await rows(
        executor,
        sql`SELECT m.group_uuid, g.name FROM access_group_endpoints m
            JOIN access_groups g ON g.uuid = m.group_uuid
            WHERE m.endpoint_uuid = ${uuid} ORDER BY m.group_uuid`,
      )
    ).map(
      (r): TopologyBlocker => ({
        rule: "endpoint_has_groups",
        kind: "access_group",
        key: `${text(r.group_uuid)}/${uuid}`,
        uuid: text(r.group_uuid),
        name: text(r.name),
        is_active: null,
        owner_user_id: null,
      }),
    ),
  ];

  const [sessions] = await rows(
    executor,
    sql`SELECT count(*) AS n FROM mcp_sessions WHERE endpoint_name = ${text(row.name)}`,
  );

  const fields: Record<string, TopologyField> = {
    namespace_uuid: namespaceUuid,
    enable_api_key_auth: bool(row.enable_api_key_auth),
    enable_oauth: bool(row.enable_oauth),
    require_scoped_api_key: bool(row.require_scoped_api_key),
    use_query_param_auth: bool(row.use_query_param_auth),
    restricted,
    created_at: iso(row.created_at),
    updated_at: iso(row.updated_at),
  };
  return {
    kind: "endpoint",
    uuid: text(row.uuid),
    name: text(row.name),
    user_id: nullableText(row.user_id),
    version: text(row.version),
    fields,
    unrestrict_refused: unrestrictRefused,
    blockers,
    cascades,
    live_sessions: count(sessions?.n),
  };
}

async function namespaceState(
  executor: DbTransaction,
  uuid: string,
  { userId }: RemovalCaller,
  lock: boolean,
): Promise<TopologyRemovalState | null> {
  if (lock) {
    // The namespace's own gate lock (position 3) orders this removal against
    // every endpoint create or move onto it; the row lock against everything
    // else that references it.
    await lockEndpointNamespaces(executor, [uuid]);
  }
  const [row] = await rows(
    executor,
    sql`SELECT uuid, name, user_id, xmin::text AS version, tool_policy,
          created_at, updated_at
        FROM namespaces WHERE uuid = ${uuid} AND ${visibleTarget(userId)}${forUpdate(lock)}`,
  );
  if (!row) return null;

  const cascades: TopologyCascadeRow[] = [
    ...(
      await rows(
        executor,
        sql`SELECT uuid, xmin::text AS version FROM namespace_server_mappings
            WHERE namespace_uuid = ${uuid} ORDER BY uuid${forUpdate(lock)}`,
      )
    ).map(
      (r): TopologyCascadeRow => ({
        kind: "namespace_server_mapping",
        key: text(r.uuid),
        version: text(r.version),
      }),
    ),
    ...(
      await rows(
        executor,
        sql`SELECT uuid, xmin::text AS version FROM namespace_tool_mappings
            WHERE namespace_uuid = ${uuid} ORDER BY uuid${forUpdate(lock)}`,
      )
    ).map(
      (r): TopologyCascadeRow => ({
        kind: "namespace_tool_mapping",
        key: text(r.uuid),
        version: text(r.version),
      }),
    ),
  ];

  const blockers: TopologyBlocker[] = (
    await rows(
      executor,
      sql`SELECT uuid, name, user_id FROM endpoints
          WHERE namespace_uuid = ${uuid} ORDER BY uuid`,
    )
  ).map(
    (r): TopologyBlocker => ({
      rule: "namespace_has_endpoints",
      kind: "endpoint",
      key: text(r.uuid),
      uuid: text(r.uuid),
      name: text(r.name),
      is_active: null,
      owner_user_id: nullableText(r.user_id),
    }),
  );

  const [sessions] = await rows(
    executor,
    sql`SELECT count(*) AS n FROM mcp_sessions WHERE namespace_uuid = ${uuid}`,
  );

  return {
    kind: "namespace",
    uuid: text(row.uuid),
    name: text(row.name),
    user_id: nullableText(row.user_id),
    version: text(row.version),
    fields: {
      tool_policy: text(row.tool_policy),
      created_at: iso(row.created_at),
      updated_at: iso(row.updated_at),
    },
    blockers,
    cascades,
    live_sessions: count(sessions?.n),
  };
}

async function serverState(
  executor: DbTransaction,
  uuid: string,
  { userId }: RemovalCaller,
  lock: boolean,
): Promise<TopologyRemovalState | null> {
  // Never the connection columns (command, args, env, url, headers, bearer
  // token): the row version binds them without reading them.
  const [row] = await rows(
    executor,
    sql`SELECT uuid, name, user_id, xmin::text AS version, type, error_status,
          created_at
        FROM mcp_servers WHERE uuid = ${uuid} AND ${visibleTarget(userId)}${forUpdate(lock)}`,
  );
  if (!row) return null;

  // The catalog rows are locked before any tool row is read: a tool row that
  // names one of these tools but another server cannot commit past them.
  const tools: TopologyCascadeRow[] = (
    await rows(
      executor,
      sql`SELECT uuid, xmin::text AS version FROM tools
          WHERE mcp_server_uuid = ${uuid} ORDER BY uuid${forUpdate(lock)}`,
    )
  ).map((r) => ({ kind: "tool", key: text(r.uuid), version: text(r.version) }));

  // The server lock prevents inserts. Lock the session identity as well to
  // see a concurrent delete before judging the fingerprint. FOR KEY SHARE
  // still allows a refresh of the tokens on the same row.
  const oauth: TopologyCascadeRow[] = (
    await rows(
      executor,
      sql`SELECT uuid FROM oauth_sessions WHERE mcp_server_uuid = ${uuid}${lock ? sql` FOR KEY SHARE` : sql``}`,
    )
  ).map((r) => ({ kind: "oauth_session", key: text(r.uuid), version: null }));

  const blockers: TopologyBlocker[] = [
    // Every mount, ACTIVE or INACTIVE, in any namespace, private ones too.
    ...(
      await rows(
        executor,
        sql`SELECT m.uuid, n.uuid AS namespace_uuid, n.name, n.user_id
            FROM namespace_server_mappings m
            JOIN namespaces n ON n.uuid = m.namespace_uuid
            WHERE m.mcp_server_uuid = ${uuid} ORDER BY m.uuid`,
      )
    ).map(
      (r): TopologyBlocker => ({
        rule: "server_mounted",
        kind: "namespace",
        key: text(r.uuid),
        uuid: text(r.namespace_uuid),
        name: text(r.name),
        is_active: null,
        owner_user_id: nullableText(r.user_id),
      }),
    ),
    // Every tool row that the database would delete with the server, by
    // either of its two independent references: the server itself, or one of
    // the server's tools.
    ...(
      await rows(
        executor,
        sql`SELECT m.uuid, n.uuid AS namespace_uuid, n.name, n.user_id
            FROM namespace_tool_mappings m
            JOIN namespaces n ON n.uuid = m.namespace_uuid
            WHERE m.mcp_server_uuid = ${uuid}
               OR m.tool_uuid IN (SELECT t.uuid FROM tools t
                                  WHERE t.mcp_server_uuid = ${uuid})
            ORDER BY m.uuid`,
      )
    ).map(
      (r): TopologyBlocker => ({
        rule: "server_tools_mapped",
        kind: "namespace",
        key: text(r.uuid),
        uuid: text(r.namespace_uuid),
        name: text(r.name),
        is_active: null,
        owner_user_id: nullableText(r.user_id),
      }),
    ),
  ];

  return {
    kind: "mcp_server",
    uuid: text(row.uuid),
    name: text(row.name),
    user_id: nullableText(row.user_id),
    version: text(row.version),
    fields: {
      type: text(row.type),
      error_status: text(row.error_status),
      created_at: iso(row.created_at),
    },
    blockers,
    cascades: [...tools, ...oauth],
    live_sessions: null,
  };
}

const READERS: Record<
  TopologyRemovalKind,
  (
    executor: DbTransaction,
    uuid: string,
    caller: RemovalCaller,
    lock: boolean,
  ) => Promise<TopologyRemovalState | null>
> = {
  endpoint: endpointState,
  namespace: namespaceState,
  mcp_server: serverState,
};

const DELETES: Record<TopologyRemovalKind, (uuid: string) => SQL> = {
  endpoint: (uuid) =>
    sql`DELETE FROM endpoints WHERE uuid = ${uuid} RETURNING uuid`,
  namespace: (uuid) =>
    sql`DELETE FROM namespaces WHERE uuid = ${uuid} RETURNING uuid`,
  mcp_server: (uuid) =>
    sql`DELETE FROM mcp_servers WHERE uuid = ${uuid} RETURNING uuid`,
};

export const topologyRemovalRepository = {
  /**
   * The state a removal is prepared from, read in one REPEATABLE READ
   * read-only transaction so every part of the answer is one snapshot. Null
   * for a missing row and for another person's private row (the caller
   * cannot list it either).
   */
  async readImpact(
    kind: TopologyRemovalKind,
    uuid: string,
    caller: RemovalCaller,
  ): Promise<TopologyRemovalState | null> {
    // Lazy, like lib/audit/admin-write: importing the pool at module load
    // would make every suite that imports an implementation need a
    // DATABASE_URL.
    const { db } = await import("../index");
    return db.transaction(
      (tx) => READERS[kind](tx, uuid.toLowerCase(), caller, false),
      { isolationLevel: "repeatable read", accessMode: "read only" },
    );
  },

  /**
   * Remove one row inside the caller's transaction, leaf-only: the target and
   * its own content locked, every rule judged on what the locks let through,
   * then the caller's name and fingerprint confirmed against that state, then
   * the delete. Throws TopologyRemovalRefusal for each rule.
   */
  async remove(
    tx: DbTransaction,
    kind: TopologyRemovalKind,
    uuid: string,
    caller: RemovalCaller,
    confirmName: string,
    fingerprint: string,
  ): Promise<
    { status: "not_found" } | { status: "removed"; state: TopologyRemovalState }
  > {
    const target = uuid.toLowerCase();
    const state = await READERS[kind](tx, target, caller, true);
    if (!state) {
      return { status: "not_found" };
    }
    const blocker = firstRemovalBlocker(state);
    if (blocker) throw new TopologyRemovalRefusal(blocker);
    assertTopologyRemovalConfirmed(state, confirmName, fingerprint);
    const deleted = await rows(tx, DELETES[kind](target));
    if (deleted.length !== 1) {
      throw new TopologyRemovalRefusal("target_changed");
    }
    return { status: "removed", state };
  },
};
