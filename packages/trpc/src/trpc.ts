import { initTRPC, TRPCError } from "@trpc/server";

/**
 * Per-request attribution the backend threads in from Express, so the two
 * denial emitters below can say WHERE a refused attempt came from.
 *
 * This package cannot reach the express `req` (it is consumed by the frontend
 * too and must stay free of node/DB imports), and the tRPC context it is
 * handed at runtime is the backend's `Context`, which does carry `req` — but
 * only in the backend's own type. Threading the three flat fields is the
 * minimum that makes an audit row useful without dragging express types into
 * this package. Populated in `apps/backend/src/trpc.ts` `createContext`.
 */
export interface AuditRequestContext {
  actor_ip?: string | null;
  actor_user_agent?: string | null;
  request_id?: string | null;
}

/**
 * How a request authenticated, when it did so with an admin-plane
 * (control-plane) API key rather than a browser session.
 *
 * Set ONLY by the backend's `createContext`, from the value its admin-plane
 * bearer resolver returns for a key it has just verified. Nothing a caller
 * sends is copied into it: not a request field, not the synthetic session's
 * id, not the presence of an Authorization header. A cookie session never
 * carries it. `adminPlaneScope` below reads it to confine such a request to
 * the configuration surface, and `auditActor` reads it so admin events name
 * the key that acted.
 */
export interface AdminPlaneAuthOrigin {
  kind: "admin_plane";
  /** The api_keys row that authenticated the request. */
  key_uuid: string;
  /** The key's owning user, whose role the request otherwise runs with. */
  owner_user_id: string;
  /**
   * The key's scope as the backend verified it from the key row (migration
   * 0043). Optional only so a context built without it still type-checks;
   * a missing or unrecognised value is read as `sync`, the narrow scope, by
   * `adminPlaneScopeOf` below. Never copied from the request.
   */
  scope?: AdminPlaneScope;
}

/**
 * What an admin-plane key may do. `sync` is the scope a CI key holds: the
 * configuration-sync procedures and nothing else. `operator` adds the
 * procedures an operator's tooling needs, among them the key lifecycle ones.
 * The scope is fixed when a human administrator creates the key (migration
 * 0043) and is never writable afterwards.
 */
export type AdminPlaneScope = "sync" | "operator";

/**
 * The scope a request runs with, failing closed: anything other than the
 * literal `operator` (missing, unknown, wrongly typed) is `sync`.
 */
export function adminPlaneScopeOf(
  origin: { scope?: unknown } | null | undefined,
): AdminPlaneScope {
  return origin?.scope === "operator" ? "operator" : "sync";
}

/**
 * The caller's own account of one change: why it is made and which run of the
 * caller's tooling made it. Read from the `reason` and `run_id` fields of a
 * mutation's input by the procedure base below (`changeContextOf`), validated
 * there, and carried into the change's audit row by `auditActor`. Never an
 * identity: who acted is decided from the verified credential alone.
 */
export interface ChangeContext {
  reason: string | null;
  run_id: string | null;
}

// Create context interface that can be extended by backend
export interface BaseContext {
  // Auth data that can be added by backend implementations
  // Using generic types so backends can use their own User/Session types
  user?: any;
  session?: any;
  audit?: AuditRequestContext;
  authOrigin?: AdminPlaneAuthOrigin;
  /** Set per mutation call by the procedure base; see ChangeContext. */
  change?: ChangeContext;
}

/** Longest `reason` a change may carry, in characters. */
export const CHANGE_REASON_MAX_LENGTH = 500;
/** Longest `run_id` a change may carry, in characters. */
export const CHANGE_RUN_ID_MAX_LENGTH = 100;

/** The fixed refusals of the change-context checks. */
export const CHANGE_CONTEXT_REFUSALS = {
  reasonRequired:
    "An operator-scope admin-plane API key must send a reason with every change: add a reason field of 1 to 500 printable characters.",
  reasonInvalid:
    "reason must be a string of 1 to 500 printable characters, with no control or direction-override characters.",
  runIdInvalid:
    "run_id must be 1 to 100 characters: letters, numbers, dots, colons, underscores and hyphens.",
} as const;

// C0 and C1 controls, and the Unicode format characters that reorder or hide
// text (bidirectional overrides and isolates, zero-width marks). A reason is
// read by a person reviewing the audit trail, so it must print as it reads.
// The control characters are matched on purpose (they are what is refused),
// so the lint rule against control characters in a pattern does not apply.
const NON_PRINTABLE = new RegExp(
  // eslint-disable-next-line no-control-regex
  "[\\u0000-\\u001f\\u007f-\\u009f\\u200b-\\u200f\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u2069\\ufeff]",
);
const RUN_ID_PATTERN = /^[A-Za-z0-9._:-]+$/;

/**
 * Read and validate `reason` and `run_id` from a mutation's raw input. Absent
 * fields read as null; a present field that is malformed is refused with a
 * fixed sentence (nothing of the value is echoed). Non-object inputs carry
 * neither. Pure, and exported so the backend and the tests share it.
 */
export function changeContextOf(rawInput: unknown): ChangeContext {
  if (
    typeof rawInput !== "object" ||
    rawInput === null ||
    Array.isArray(rawInput)
  ) {
    return { reason: null, run_id: null };
  }
  const { reason, run_id: runId } = rawInput as Record<string, unknown>;
  let parsedReason: string | null = null;
  if (reason !== undefined && reason !== null) {
    if (typeof reason !== "string") {
      throw new TRPCError({
        code: "BAD_REQUEST",
        message: CHANGE_CONTEXT_REFUSALS.reasonInvalid,
      });
    }
    const trimmed = reason.trim();
    if (
      trimmed.length < 1 ||
      trimmed.length > CHANGE_REASON_MAX_LENGTH ||
      NON_PRINTABLE.test(trimmed)
    ) {
      throw new TRPCError({
        code: "BAD_REQUEST",
        message: CHANGE_CONTEXT_REFUSALS.reasonInvalid,
      });
    }
    parsedReason = trimmed;
  }
  let parsedRunId: string | null = null;
  if (runId !== undefined && runId !== null) {
    if (
      typeof runId !== "string" ||
      runId.length < 1 ||
      runId.length > CHANGE_RUN_ID_MAX_LENGTH ||
      !RUN_ID_PATTERN.test(runId)
    ) {
      throw new TRPCError({
        code: "BAD_REQUEST",
        message: CHANGE_CONTEXT_REFUSALS.runIdInvalid,
      });
    }
    parsedRunId = runId;
  }
  return { reason: parsedReason, run_id: parsedRunId };
}

/**
 * The tRPC procedures an admin-plane API key of scope `sync` may call: exactly
 * what the configuration-sync tooling (a CI credential) calls, nothing else.
 * Provenance: the private Umbrella-MCP-Server repo's
 * `metamcp/sync/sync_config.py` and `metamcp/sync/dump_config.py`, every
 * `trpc_query`/`trpc_mutate` name in those two files and no other. Full paths
 * with the `frontend.` router prefix, the form the middleware below compares
 * against.
 *
 * An admin-plane key authenticates as its owning administrator, so without a
 * list it could call everything that administrator can: mint API keys that act
 * as any user, mint further admin-plane keys, edit users, access groups, OAuth
 * clients and auth settings. A key that lives in CI must not be able to do any
 * of that, and must not hold the operator's key and policy powers either. A
 * human administrator's browser session is not affected by these lists.
 *
 * Adding a name here widens what a CI credential can do; it needs the same
 * review as any other change to who can do what, and the consumer repo pins a
 * copy of this list that must change in the same step.
 */
export const ADMIN_PLANE_SYNC_PROCEDURES: ReadonlySet<string> = new Set([
  "frontend.config.getMcpMaxTotalTimeout",
  "frontend.config.getMcpTimeout",
  "frontend.endpoints.list",
  "frontend.mcpServers.create",
  "frontend.mcpServers.list",
  "frontend.mcpServers.update",
  "frontend.namespaces.get",
  "frontend.namespaces.getTools",
  "frontend.namespaces.list",
  "frontend.tools.getByMcpServerUuid",
]);

/**
 * The procedures an admin-plane key of scope `operator` may call: the sync
 * set plus what the operator's tooling (`metamcp/sync/admin_cli.py`) needs.
 * Built from the sync set so the operator can never hold less than it.
 *
 *  - The per-key and global IP-policy procedures, with self-lockout rails in
 *    the implementations (a key cannot lock itself out).
 *  - `apiKeys.listAll` and `apiKeys.deactivate`: inventory and containment.
 *    `deactivate` refuses the calling key and cannot re-activate, rename or
 *    delete; those are the narrow lifecycle procedures below, for data-plane
 *    keys only.
 *  - `apiKeys.create`: reaches the implementation's agent-mint branch, which
 *    only ever creates an endpoint-scoped or gateway-wide DATA-plane key for
 *    one existing enabled user, locked to a narrow IP list at creation. Every
 *    other kind of key (admin-plane of either scope, acts-as, public) is a
 *    human click. The rules are enforced in the implementation, from the
 *    verified origin, not here: this list only decides who gets that far.
 *  - Create and update of namespaces and endpoints, and the tool refresh and
 *    status writes the provisioning verbs call.
 *  - Four reads for answering "who owns what" without a browser: users,
 *    OAuth clients, access groups (list and get). None returns a credential.
 *  - Access groups and who they admit: create, update and delete a group, add
 *    and remove a member, map and unmap an endpoint, and the `restricted`
 *    switch (an accessGroups procedure, not an endpoints one), with
 *    `getEndpointAccess` as the read-back (it answers for an endpoint that has
 *    no mapping, which the list and group-detail reads cannot). And
 *    `namespaces.setToolPolicy`, the allow-all/allowlist switch of a namespace.
 *    Each write is audited in the change's own transaction. A group
 *    restriction cannot cut an operator key off: these procedures are reached
 *    on /trpc and depend on no MCP endpoint.
 *  - Two reads for the operator's own verification: `audit.list` (its audit
 *    trail, safe fields only) and `apiKeys.operatorCapabilities` (what this
 *    scope may call, the reason contract, the confirmations and the change
 *    budget), which the tooling checks before it sends a change.
 *  - The narrow key lifecycle procedures, for DATA-plane keys only:
 *    `apiKeys.reactivate` (the owner, the endpoint and the key's own narrow
 *    enforce policy re-checked against locked rows, by the agent mint's
 *    rules), `apiKeys.rename` (a valid name unused by the key's owner) and
 *    `apiKeys.remove` (leaf-only: an inactive key, confirmed by its name and
 *    by the fingerprint `apiKeys.removalImpact` read). Each refuses an
 *    admin-plane key, the calling key included; the broad `apiKeys.update`
 *    and `.delete` stay human-only.
 *  - `mcpServers.resetErrors`, the twin of the cookie-only REST reset route
 *    and sharing its implementation: the ERROR status change and its audit
 *    row commit together, and connection recovery starts after the commit.
 *  - `logs.history`, the bounded (paged, at most 200 rows) diagnostic
 *    history, with credential-shaped text redacted for an admin-plane key.
 *  - The leaf-only topology removals (contract 4): `endpoints.remove`,
 *    `namespaces.remove` and `mcpServers.remove`, each with its
 *    `removalImpact` read. One public row nothing depends on (an endpoint with
 *    no API key, active or inactive, and no access-group mapping; a namespace
 *    with no endpoint; a server no namespace mounts or holds a tool row for),
 *    confirmed by its name and by the fingerprint the read returned, judged
 *    on rows locked in the removal's transaction and audited with a snapshot.
 *    Removing the last restricted endpoint obeys the namespace gate's rule
 *    for rollback of the acting key's own restriction.
 *    The broad `.delete` of each stays human-only: each cascades through
 *    everything that depends on the row.
 *
 * Every change an operator key makes carries a `reason` (see
 * `changeContextOf`), is counted against the key's change budget and is
 * audited in the change's own transaction (the backend's
 * lib/audit/admin-write). Left out on purpose, and still a human
 * administrator's act in the UI: everything in
 * ADMIN_PLANE_HUMAN_ONLY_PROCEDURES below.
 */
export const ADMIN_PLANE_OPERATOR_PROCEDURES: ReadonlySet<string> = new Set([
  ...ADMIN_PLANE_SYNC_PROCEDURES,
  "frontend.audit.list",
  "frontend.apiKeys.operatorCapabilities",
  "frontend.apiKeys.reactivate",
  "frontend.apiKeys.removalImpact",
  "frontend.apiKeys.remove",
  "frontend.apiKeys.rename",
  "frontend.logs.history",
  "frontend.mcpServers.resetErrors",
  "frontend.accessGroups.addEndpoint",
  "frontend.accessGroups.addMember",
  "frontend.accessGroups.create",
  "frontend.accessGroups.delete",
  "frontend.accessGroups.get",
  "frontend.accessGroups.getEndpointAccess",
  "frontend.accessGroups.list",
  "frontend.accessGroups.removeEndpoint",
  "frontend.accessGroups.removeMember",
  "frontend.accessGroups.setEndpointRestricted",
  "frontend.accessGroups.update",
  "frontend.apiKeys.create",
  "frontend.apiKeys.deactivate",
  "frontend.apiKeys.getGlobalIpPolicy",
  "frontend.apiKeys.listAll",
  "frontend.apiKeys.setGlobalIpPolicy",
  "frontend.apiKeys.setIpPolicy",
  "frontend.endpoints.create",
  "frontend.endpoints.removalImpact",
  "frontend.endpoints.remove",
  "frontend.endpoints.update",
  "frontend.mcpServers.removalImpact",
  "frontend.mcpServers.remove",
  "frontend.namespaces.create",
  "frontend.namespaces.refreshTools",
  "frontend.namespaces.removalImpact",
  "frontend.namespaces.remove",
  "frontend.namespaces.setToolPolicy",
  "frontend.namespaces.update",
  "frontend.namespaces.updateToolStatus",
  "frontend.oauthClients.list",
  "frontend.users.list",
]);

/**
 * The operator procedures that are mutations: every change an operator key
 * can make. Each must carry a reason, is charged to the key's change budget
 * and writes its audit row in the change's transaction. Pinned against the
 * router's own procedure types by the backend's classification test, so a
 * mutation added to the operator set without being listed here fails CI.
 */
export const ADMIN_PLANE_OPERATOR_MUTATIONS: ReadonlySet<string> = new Set([
  "frontend.accessGroups.addEndpoint",
  "frontend.accessGroups.addMember",
  "frontend.accessGroups.create",
  "frontend.accessGroups.delete",
  "frontend.accessGroups.removeEndpoint",
  "frontend.accessGroups.removeMember",
  "frontend.accessGroups.setEndpointRestricted",
  "frontend.accessGroups.update",
  "frontend.apiKeys.create",
  "frontend.apiKeys.deactivate",
  "frontend.apiKeys.reactivate",
  "frontend.apiKeys.remove",
  "frontend.apiKeys.rename",
  "frontend.apiKeys.setGlobalIpPolicy",
  "frontend.apiKeys.setIpPolicy",
  "frontend.endpoints.create",
  "frontend.endpoints.remove",
  "frontend.endpoints.update",
  "frontend.mcpServers.create",
  "frontend.mcpServers.remove",
  "frontend.mcpServers.resetErrors",
  "frontend.mcpServers.update",
  "frontend.namespaces.create",
  "frontend.namespaces.refreshTools",
  "frontend.namespaces.remove",
  "frontend.namespaces.setToolPolicy",
  "frontend.namespaces.update",
  "frontend.namespaces.updateToolStatus",
]);

/**
 * Every procedure no admin-plane key may call, of either scope: a human
 * administrator's act in the admin UI (or, for the reads, a browser session's).
 * Written out so that the three lists (sync, operator-only, this one) classify
 * every procedure in the router exactly once; the backend's classification
 * test fails when a procedure is added to the router without a decision.
 * Moving a name from here to the operator set is a change to what a standing
 * credential can do and needs the same review as the operator set itself.
 */
export const ADMIN_PLANE_HUMAN_ONLY_PROCEDURES: ReadonlySet<string> = new Set([
  "frontend.accessGroups.listEndpoints",
  "frontend.apiKeys.delete",
  "frontend.apiKeys.list",
  "frontend.apiKeys.update",
  "frontend.apiKeys.validate",
  "frontend.config.getAllConfigs",
  "frontend.config.getAuthProviders",
  "frontend.config.getBasicAuthDisabled",
  "frontend.config.getMcpMaxAttempts",
  "frontend.config.getMcpResetTimeoutOnProgress",
  "frontend.config.getSessionLifetime",
  "frontend.config.getSignupDisabled",
  "frontend.config.getSsoSignupDisabled",
  "frontend.config.setBasicAuthDisabled",
  "frontend.config.setConfig",
  "frontend.config.setMcpMaxAttempts",
  "frontend.config.setMcpMaxTotalTimeout",
  "frontend.config.setMcpResetTimeoutOnProgress",
  "frontend.config.setMcpTimeout",
  "frontend.config.setSessionLifetime",
  "frontend.config.setSignupDisabled",
  "frontend.config.setSsoSignupDisabled",
  "frontend.endpointPresentation.get",
  "frontend.endpointPresentation.set",
  "frontend.endpoints.delete",
  "frontend.endpoints.get",
  "frontend.endpoints.listAll",
  "frontend.logs.get",
  "frontend.mcpServers.bulkImport",
  "frontend.mcpServers.delete",
  "frontend.mcpServers.get",
  "frontend.mcpServers.listAll",
  "frontend.mcpServers.reconnect",
  "frontend.namespaces.delete",
  "frontend.namespaces.listAll",
  "frontend.namespaces.updateServerStatus",
  "frontend.namespaces.updateToolOverrides",
  "frontend.oauth.get",
  "frontend.oauth.upsert",
  "frontend.oauthClients.approve",
  "frontend.oauthClients.create",
  "frontend.oauthClients.delete",
  "frontend.oauthClients.reject",
  "frontend.oauthTokens.list",
  "frontend.tools.create",
  "frontend.tools.sync",
  "frontend.users.delete",
  "frontend.users.previewDelete",
  "frontend.users.revokeAccess",
  "frontend.users.setDisabled",
]);

/**
 * Version of the operator contract `apiKeys.operatorCapabilities` reports.
 * Raised whenever the operator set, the reason contract or the meaning of a
 * refusal changes, so the operator's tooling can refuse to send a change to a
 * gateway whose contract it does not know.
 *
 *  - 2: the rails, the reason field, the change budget, `audit.list`.
 *  - 3: the key lifecycle procedures (reactivate, rename, removalImpact,
 *    remove), `mcpServers.resetErrors`, `logs.history`, and the
 *    `confirmations` field (ADMIN_PLANE_OPERATOR_CONFIRMATIONS).
 *  - 4: the leaf-only topology removals (`endpoints`, `namespaces` and
 *    `mcpServers` `.removalImpact` and `.remove`) and their confirmations.
 */
export const ADMIN_PLANE_OPERATOR_CONTRACT_VERSION = 4;

/**
 * The fields beyond `reason` an operator change must carry, by procedure,
 * reported by `apiKeys.operatorCapabilities` so the tooling can build the
 * request. A mistake guard, checked by the implementation against rows it
 * locks; the rule behind it (for a removal, leaf-only) holds without it.
 */
export const ADMIN_PLANE_OPERATOR_CONFIRMATIONS: Readonly<
  Record<string, readonly string[]>
> = {
  "frontend.apiKeys.remove": ["confirm_name", "impact_fingerprint"],
  "frontend.endpoints.remove": ["confirm_name", "impact_fingerprint"],
  "frontend.mcpServers.remove": ["confirm_name", "impact_fingerprint"],
  "frontend.namespaces.remove": ["confirm_name", "impact_fingerprint"],
};

/**
 * Behaviours of this gateway that `apiKeys.operatorCapabilities` reports by
 * name, beyond the contract version, so a consumer that depends on one can
 * refuse to send its request to a gateway that lacks it. Sorted. Added only
 * for behaviour a consumer has to detect; the contract version stays what it
 * was.
 *
 *  - `server-reads-redacted-v1`: every server object an admin-plane key reads
 *    or receives back (`mcpServers.list`, `listAll`, `get`, `create` and
 *    `update` replies, and the servers embedded in `namespaces.get`) keeps its
 *    `env` and `headers` names with empty values, and carries no command,
 *    arguments or URL (see ServerDetailLevel).
 *  - `server-update-metadata-only-v1`: `mcpServers.update` accepts the strict
 *    `metadata_only` request (a rename and/or a description) and an
 *    operator-scope key may send nothing else.
 */
export const ADMIN_PLANE_OPERATOR_MARKERS: readonly string[] = [
  "server-reads-redacted-v1",
  "server-update-metadata-only-v1",
];

/**
 * How much of a stored server's connection a reply may carry, decided by the
 * router from the verified caller and handed to the implementation and the
 * serializers explicitly (there is no default, and an unrecognised value reads
 * as the least):
 *
 *  - `full`: a person signed in as an administrator, who edits the connection
 *    in the admin UI: command, arguments, environment, URL and headers as
 *    stored. The stored bearer token is never returned at any level.
 *  - `names_only`: an admin-plane API key of either scope. `env` and `headers`
 *    keep their names and every value is the empty string; the command, the
 *    arguments and the URL (a path, query or fragment can carry a credential
 *    too) are withheld as the schema's own null and empty values. What the
 *    tooling needs is the name and the uuid.
 *  - `redacted`: everyone else (a member): nothing of the connection.
 */
export type ServerDetailLevel = "full" | "names_only" | "redacted";

/**
 * The detail level a caller's server replies carry, from the verified request
 * context alone: an admin-plane origin (set only by the backend's context
 * builder from a key row it has verified, never from anything the request
 * sends) is `names_only` whatever its owner's role; otherwise the session
 * role decides. Never throws: a context it cannot read gets `redacted`.
 */
export function serverDetailLevelOf(
  ctx: BaseContext | undefined | null,
): ServerDetailLevel {
  try {
    if (adminPlaneOrigin(ctx)) return "names_only";
    return ctx?.user?.role === "admin" ? "full" : "redacted";
  } catch {
    return "redacted";
  }
}

/** One constant refusal for every procedure outside the list. */
export const ADMIN_PLANE_FORBIDDEN_MESSAGE =
  "This procedure is not available to an admin-plane API key.";

/** The admin-plane origin on a context, or null for every other request. */
export function adminPlaneOrigin(
  ctx: BaseContext | undefined | null,
): AdminPlaneAuthOrigin | null {
  const origin = ctx?.authOrigin;
  return origin?.kind === "admin_plane" ? origin : null;
}

/**
 * A denied authentication or authorization attempt at the tRPC boundary.
 *
 * `path` is the procedure the caller reached for — the difference between
 * "a member's browser polled a page it cannot see" and "someone walked the
 * admin mutation surface" is entirely in that field.
 */
export interface TrpcDenialEvent {
  action: "rbac.denied" | "authn.denied";
  actor_type: "user" | "anonymous" | "api_key";
  actor_id: string | null;
  actor_label: string | null;
  path: string;
  /** tRPC operation type — `query` / `mutation` / `subscription`. */
  type: string;
  http_status: number;
  audit?: AuditRequestContext;
  /** Set when an admin-plane API key was refused; see AdminPlaneAuthOrigin. */
  admin_plane?: {
    key_uuid: string;
    owner_user_id: string;
    scope?: AdminPlaneScope;
  };
}

/**
 * `void | Promise<void>` is deliberate, not permissive.
 *
 * A plain `=> void` return type would NOT keep an async sink out — TypeScript
 * happily assigns `() => Promise<void>` to `() => void` (return-type
 * bivariance for void). So the type could never have been the guard, and
 * pretending it was is how an async sink gets registered by a future lane
 * without anyone noticing. Declaring the async case makes it visible AND
 * makes `emitDenial`'s rejection handling obviously load-bearing rather than
 * defensive noise.
 */
export type TrpcAuditSink = (event: TrpcDenialEvent) => void | Promise<void>;

let auditSink: TrpcAuditSink | null = null;

/**
 * Register the durable audit writer. Called once by the backend
 * (`apps/backend/src/routers/trpc.ts`); left null everywhere else, so this
 * package keeps booting in the frontend and in unit tests with no database
 * anywhere in the graph.
 */
export function setTrpcAuditSink(sink: TrpcAuditSink | null): void {
  auditSink = sink;
}

/**
 * Emit a denial, and NEVER let that emission affect the request.
 *
 * The two call sites are the RBAC choke point for every admin-gated mutation
 * in the product and the authentication gate in front of it. A failure
 * escaping here would not lose an audit row — it would replace a clean
 * FORBIDDEN or UNAUTHORIZED with a 500 on every denied call, and (worse) a
 * sink that failed on the SUCCESS path would break the product outright.
 *
 * THREE failure modes are swallowed, and all three are reachable:
 *
 *  1. `build()` throwing. The event is constructed from `ctx.user` and
 *     `ctx.audit`, which are typed `any`/optional — a property access on a
 *     hostile or exotic object can throw. Building INSIDE the guard is why
 *     this takes a thunk instead of a finished event: with the construction
 *     outside, a throwing getter on `ctx.user` would turn the rethrown
 *     FORBIDDEN into an INTERNAL_SERVER_ERROR.
 *  2. The sink throwing synchronously.
 *  3. The sink REJECTING. `TrpcAuditSink` allows `Promise<void>` (and even a
 *     `=> void` signature could not have excluded it — see the type). An
 *     unhandled rejection is process death under Node's default
 *     `--unhandled-rejections=throw`, i.e. the entire gateway, not one
 *     request. `Promise.resolve(...)` normalises the sync and async cases so
 *     one `.catch` covers both.
 *
 * `apps/backend/src/trpc/rbac-denial-audit.test.ts` registers a throwing sink
 * and a rejecting sink and asserts the caller still gets its normal denial.
 */
function emitDenial(build: () => TrpcDenialEvent): void {
  try {
    const event = build();
    void Promise.resolve(auditSink?.(event)).catch(() => {
      // Swallowed by design — see above.
    });
  } catch {
    // Swallowed by design — see above.
  }
}

/** Read an id/email off the loosely-typed context user without throwing. */
function actorFields(user: unknown): {
  id: string | null;
  label: string | null;
} {
  const candidate = user as
    | { id?: unknown; email?: unknown }
    | null
    | undefined;
  return {
    id: typeof candidate?.id === "string" ? candidate.id : null,
    label: typeof candidate?.email === "string" ? candidate.email : null,
  };
}

/**
 * The five envelope fields an audit row needs to say WHO did something and
 * from WHERE, flattened out of the tRPC context.
 *
 * Exists because the SUCCESS-path emitters live in the backend's `*.impl.ts`
 * files, which are handed `input` (and sometimes `ctx.user.id`) and nothing
 * else — the routers in this package are the only layer that holds both the
 * session user and the request attribution Express stamped on. Threading one
 * flat object is the same idiom the routers already use for `ctx.user.id`,
 * and it keeps `audit_log`'s actor columns identical whether the row came
 * from a denial hook here or from a mutation over there.
 */
export interface AuditActor {
  actor_id: string | null;
  actor_label: string | null;
  actor_ip: string | null;
  actor_user_agent: string | null;
  request_id: string | null;
  /**
   * Present only when the request authenticated with an admin-plane API key.
   * The backend's admin-event writer then records the KEY as the actor and
   * keeps the owning user beside it, so a change made from CI is never
   * recorded as if the owner had made it in the browser.
   *
   * `scope` is the verified scope of that key, normalised by `auditActor`
   * (anything but `operator` reads `sync`). It is what an implementation
   * checks when a branch is reserved for operator keys: a direct call that
   * omits it is not an operator, so such a branch fails closed.
   */
  admin_plane?: {
    key_uuid: string;
    owner_user_id: string;
    scope?: AdminPlaneScope;
  };
  /**
   * The caller's reason and run id for this change, as the procedure base
   * validated them from the request (see `changeContextOf`). Absent on a query
   * and on a change that sent neither. Recorded in the audit row; never used
   * to decide who acted.
   */
  reason?: string | null;
  run_id?: string | null;
}

/**
 * Build the actor bundle a mutation's audit row will carry.
 *
 * NEVER THROWS, and that is the entire reason it is a function rather than an
 * object literal at each call site. It is evaluated as an ARGUMENT to the
 * implementation call, i.e. strictly before the mutation runs, so a throwing
 * property read on `ctx.user` (typed `any`, reached from JSON) would abort the
 * write itself — the audit path deciding whether an admin's toggle takes
 * effect. Degrading to an all-null actor loses attribution on one row; the
 * alternative loses the operation.
 */
export function auditActor(ctx: BaseContext): AuditActor {
  try {
    const actor = actorFields(ctx?.user);
    const adminPlane = adminPlaneOrigin(ctx);
    return {
      actor_id: actor.id,
      actor_label: actor.label,
      actor_ip: ctx?.audit?.actor_ip ?? null,
      actor_user_agent: ctx?.audit?.actor_user_agent ?? null,
      request_id: ctx?.audit?.request_id ?? null,
      // Added only for an admin-plane request, so a browser session's actor
      // keeps exactly the shape it had.
      ...(adminPlane
        ? {
            admin_plane: {
              key_uuid: adminPlane.key_uuid,
              owner_user_id: adminPlane.owner_user_id,
              scope: adminPlaneScopeOf(adminPlane),
            },
          }
        : {}),
      // Added only when the request carried one, so an actor without them
      // keeps exactly the shape it had.
      ...changeFields(ctx),
    };
  } catch {
    // Attribution degrades to nulls, but the admin-plane PROVENANCE must not:
    // a branch that is reserved for (or closed to) admin-plane keys reads it,
    // and an actor that silently lost it would be mistaken for a human
    // session. The origin is a plain object createContext built, read on its
    // own so a throwing getter elsewhere on the context cannot take it down.
    let admin_plane: AuditActor["admin_plane"];
    try {
      const origin = adminPlaneOrigin(ctx);
      if (origin) {
        admin_plane = {
          key_uuid: origin.key_uuid,
          owner_user_id: origin.owner_user_id,
          scope: adminPlaneScopeOf(origin),
        };
      }
    } catch {
      // Left undefined; the router-level guard on `apiKeys.create` refuses.
    }
    let change: Partial<Pick<AuditActor, "reason" | "run_id">> = {};
    try {
      change = changeFields(ctx);
    } catch {
      // Left out; the reason requirement was already judged by the procedure
      // base before the implementation ran.
    }
    return {
      actor_id: null,
      actor_label: null,
      actor_ip: null,
      actor_user_agent: null,
      request_id: null,
      ...(admin_plane ? { admin_plane } : {}),
      ...change,
    };
  }
}

/** The reason and run id the procedure base stamped, when there are any. */
function changeFields(
  ctx: BaseContext,
): Partial<Pick<AuditActor, "reason" | "run_id">> {
  const change = ctx?.change;
  if (!change) return {};
  return {
    ...(change.reason !== null ? { reason: change.reason } : {}),
    ...(change.run_id !== null ? { run_id: change.run_id } : {}),
  };
}

// Initialize tRPC with base context.
//
// errorFormatter strips `stack` from every error payload. @trpc/server only
// attaches the stack when its `isDev` flag is on, and `isDev` defaults to
// `process.env.NODE_ENV !== "production"`, so whether a stack ships is a
// property of the deployment rather than of this code. The image and the
// compose files set no NODE_ENV themselves, but both compose files pass the
// whole `.env` in through `env_file:` and `example.env` ships
// `NODE_ENV=production` on its first line, so the flag is set on a quickstart
// deployment derived from that file and unset on one that dropped the line.
// On the second, every 4xx/5xx from a procedure built by this factory shipped
// an internal stack trace (absolute `/app/...` paths, bundled dependency
// names and versions) to the caller. Stripping it here is unconditional for
// that reason: the payload does not depend on how the process was started.
//
// This mirrors the same formatter on the backend's own `initTRPC` instance
// (apps/backend/src/trpc.ts). BOTH are needed: routers in this package are
// built from `t` here, while the backend builds others from its own
// instance, and an errorFormatter only covers the instance it is passed to.
const t = initTRPC.context<BaseContext>().create({
  errorFormatter({ shape }) {
    const { stack: _stack, ...data } = shape.data as typeof shape.data & {
      stack?: string;
    };
    // Mask the message for unexpected server errors too. @trpc/server sets
    // shape.message = error.message unconditionally, and getTRPCErrorFromUnknown
    // preserves cause.message when wrapping an unexpected throw as
    // INTERNAL_SERVER_ERROR — so a raw driver/DB message (internal hostnames,
    // SQL, table names) can reach an unauthenticated caller through any
    // publicProcedure that lacks its own try/catch (e.g. the config router).
    // Safe: every deliberate INTERNAL_SERVER_ERROR in this tree already throws a
    // fixed string, and all user-facing messages are FORBIDDEN/NOT_FOUND/
    // UNAUTHORIZED, so no UI copy degrades. `code`/`httpStatus`/`path` stay.
    const message =
      data.code === "INTERNAL_SERVER_ERROR"
        ? "Internal server error"
        : shape.message;
    return { ...shape, message, data };
  },
});

/**
 * Refuse an admin-plane request for any procedure outside its scope's set
 * (ADMIN_PLANE_SYNC_PROCEDURES, or ADMIN_PLANE_OPERATOR_PROCEDURES for an
 * `operator` key; a missing or unknown scope is `sync`). Throws FORBIDDEN with
 * one constant message and records the refusal; does nothing for any other
 * request.
 *
 * Exported so the backend's own tRPC instance (apps/backend/src/trpc.ts) can
 * apply the identical rule to its builders.
 *
 * Checked per procedure, on the procedure's full path, because that is the
 * only place the path is known: a tRPC batch shares one context across all of
 * its calls, so createContext cannot decide which of them are allowed.
 */
export function assertAdminPlaneProcedureAllowed(
  ctx: BaseContext,
  path: string,
  type: string,
): void {
  const origin = adminPlaneOrigin(ctx);
  if (!origin) return;
  const scope = adminPlaneScopeOf(origin);
  const allowed =
    scope === "operator"
      ? ADMIN_PLANE_OPERATOR_PROCEDURES
      : ADMIN_PLANE_SYNC_PROCEDURES;
  if (allowed.has(path)) {
    return;
  }
  emitDenial(() => {
    const actor = actorFields(ctx.user);
    return {
      action: "rbac.denied",
      actor_type: "api_key",
      actor_id: origin.key_uuid,
      actor_label: actor.label,
      path,
      type,
      http_status: 403,
      audit: ctx.audit,
      admin_plane: {
        key_uuid: origin.key_uuid,
        owner_user_id: origin.owner_user_id,
        scope,
      },
    };
  });
  throw new TRPCError({
    code: "FORBIDDEN",
    message: ADMIN_PLANE_FORBIDDEN_MESSAGE,
  });
}

/**
 * The change context of one call, after the scope check: for a mutation, the
 * validated `reason` and `run_id` of its input (see `changeContextOf`), with
 * the reason REQUIRED when the caller is an operator-scope admin-plane key.
 * Returns null for a query. Throws BAD_REQUEST with a fixed sentence before
 * the procedure runs.
 *
 * Why the operator scope only: a person in the admin UI and the CI sync key
 * (whose tooling predates the field) may keep sending changes without one; an
 * operator key is the credential an agent holds, and its changes are the ones
 * an after-action review has to be able to explain from the trail alone.
 * Judged per call, so one call of a batch without a reason is refused while
 * the others are judged on their own.
 */
export async function changeContextForCall(
  ctx: BaseContext,
  type: string,
  getRawInput: () => Promise<unknown>,
): Promise<ChangeContext | null> {
  if (type !== "mutation") return null;
  const rawInput = await getRawInput();
  const change = changeContextOf(rawInput);
  const origin = adminPlaneOrigin(ctx);
  // Required of an input that is an object, the only shape any operator
  // mutation's schema accepts (pinned by the backend's classification test).
  // Anything else is refused by that schema with its own sentence before the
  // procedure runs, so it can make no change without a reason either.
  const isObjectInput =
    typeof rawInput === "object" &&
    rawInput !== null &&
    !Array.isArray(rawInput);
  if (
    origin &&
    adminPlaneScopeOf(origin) === "operator" &&
    isObjectInput &&
    change.reason === null
  ) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: CHANGE_CONTEXT_REFUSALS.reasonRequired,
    });
  }
  return change;
}

/**
 * The base every exported builder starts from, so no procedure in this
 * package can be built without the admin-plane scope check. It runs before
 * authentication and RBAC, and an ordinary request (anonymous or a browser
 * session) passes straight through it. For a mutation it then reads the
 * change context (above) and hands it to the procedure on its own context
 * copy, so calls of one batch never share it.
 */
const scopedProcedure = t.procedure.use(
  async ({ ctx, next, path, type, getRawInput }) => {
    assertAdminPlaneProcedureAllowed(ctx, path, type);
    const change = await changeContextForCall(ctx, type, getRawInput);
    return change ? next({ ctx: { ...ctx, change } }) : next();
  },
);

// Export router and procedure helpers
export const router = t.router;
export const publicProcedure = scopedProcedure;
export const createTRPCRouter = t.router;
export const baseProcedure = scopedProcedure;

// Create a protected procedure that requires authentication
export const protectedProcedure = scopedProcedure.use(
  ({ ctx, next, path, type }) => {
    if (!ctx.user || !ctx.session) {
      // Every unauthenticated tRPC attempt in the product funnels through this
      // one branch, so one emit here covers the whole surface. Emitted BEFORE
      // the throw, and by a helper that cannot throw, so the caller still gets
      // its normal UNAUTHORIZED whatever the audit sink does. The event is
      // built inside the thunk so even reading `ctx.audit` happens under the
      // guard.
      emitDenial(() => ({
        action: "authn.denied",
        actor_type: "anonymous",
        actor_id: null,
        actor_label: null,
        path,
        type,
        http_status: 401,
        audit: ctx.audit,
      }));
      throw new TRPCError({
        code: "UNAUTHORIZED",
        message: "You must be logged in to access this resource",
      });
    }

    return next({
      ctx: {
        ...ctx,
        // Override types to indicate user and session are guaranteed to exist
        user: ctx.user,
        session: ctx.session,
      },
    });
  },
);

// The pure RBAC authorization check that `adminProcedure` runs. Extracted as
// a standalone function so the gate can be unit-tested directly, without
// standing up a tRPC caller. A hard FORBIDDEN throw (not a silently-filtered
// result) is deliberate: administrative mutations — MCP-server / namespace /
// endpoint create-update-delete, all API-key administration, and minting
// 'everyone' (public) keys — must be unreachable to members, and FORBIDDEN is
// the honest signal. `role` comes from the session user, which the backend
// populates from the database per request via better-auth `additionalFields`
// (apps/backend/src/auth.ts) with `input: false`, so the client cannot spoof
// it.
export function requireAdmin(user: { role?: string } | undefined | null): void {
  if (!user || user.role !== "admin") {
    throw new TRPCError({
      code: "FORBIDDEN",
      message: "This action requires an administrator role.",
    });
  }
}

// Admin-only procedure: layers the role gate on top of authentication.
// protectedProcedure runs first (an unauthenticated caller gets UNAUTHORIZED
// before the role is ever inspected), then requireAdmin rejects any
// authenticated non-admin with FORBIDDEN.
export const adminProcedure = protectedProcedure.use(
  ({ ctx, next, path, type }) => {
    try {
      requireAdmin(ctx.user);
    } catch (error) {
      // An authenticated non-admin reaching for an admin mutation is an
      // attempted privilege escalation, and until this existed it was thrown
      // and forgotten — no row, no counter, nothing to alert on. Caught rather
      // than emitted inside `requireAdmin` so that function stays a pure,
      // directly unit-testable predicate (admin-procedure.test.ts calls it with
      // no context at all), and rethrown untouched so the FORBIDDEN the caller
      // sees is byte-identical to before.
      //
      // `actorFields(ctx.user)` is evaluated INSIDE the thunk. `ctx.user` is
      // typed `any` and reaches here from JSON, but a property read on an
      // exotic object can throw, and outside the thunk that throw would
      // replace this rethrown FORBIDDEN with an INTERNAL_SERVER_ERROR — the
      // audit path silently changing the security answer, which is the one
      // thing it must never do.
      emitDenial(() => {
        const actor = actorFields(ctx.user);
        // An allowlisted call can still fail RBAC after its owner is demoted.
        // Attribute that refusal to the credential, as the scope gate does.
        const origin = adminPlaneOrigin(ctx);
        return {
          action: "rbac.denied",
          actor_type: origin ? "api_key" : "user",
          actor_id: origin?.key_uuid ?? actor.id,
          actor_label: actor.label,
          path,
          type,
          http_status: 403,
          audit: ctx.audit,
          ...(origin
            ? {
                admin_plane: {
                  key_uuid: origin.key_uuid,
                  owner_user_id: origin.owner_user_id,
                  scope: adminPlaneScopeOf(origin),
                },
              }
            : {}),
        };
      });
      throw error;
    }
    return next({ ctx });
  },
);
