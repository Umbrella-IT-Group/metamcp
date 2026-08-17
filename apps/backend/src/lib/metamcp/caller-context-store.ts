import { AsyncLocalStorage } from "node:async_hooks";

/**
 * Request-scoped caller identity for the tool-call audit trail.
 *
 * WHY THIS IS AsyncLocalStorage AND NOT THE HANDLER CONTEXT. A MetaMCP server
 * instance is POOLED and its `MetaMCPHandlerContext` is per-INSTANCE, so
 * anything stamped there describes whichever request stamped it last, not the
 * request whose tool call is being audited. Two facts make that unusable as
 * the source of truth:
 *
 *   1. Parallel `tools/call` on one session is the NORMAL case for a busy
 *      consumer, not an edge. The second request overwrites the binding
 *      before the first's call is audited, and the `request_id` that is
 *      supposed to join a tool call to the `audit_log` rows of the SAME
 *      request silently points at a sibling.
 *   2. The in-memory session lookup on the Streamable-HTTP POST leg resolves a
 *      session by namespace + endpoint. It does not re-derive the caller from
 *      the credential presented on THIS request, so a pooled instance's
 *      stamped identity is not guaranteed to belong to the request being
 *      served. An audit row that names the wrong principal is worse than one
 *      that names none.
 *
 * AsyncLocalStorage has neither problem: the store is entered per request and
 * Node propagates it across awaits, timers and synchronous EventEmitter
 * dispatch, which covers the MCP SDK's request path. The precedent is
 * `lib/m365/request-context.ts`, which carries the delegated user identity
 * down the same path into the injected fetch for exactly this reason.
 *
 * WHY THIS IS ITS OWN MODULE, split from `caller-context.ts`: the auditing
 * middleware reads this store, and its module graph is deliberately kept free
 * of the database and of express so unit tests exercise it without postgres
 * (see `metamcp-middleware/auditing.functional.ts`). `caller-context.ts`
 * imports the express-side header helpers to BUILD a binding; this file holds
 * only the type and the store, so importing it costs the middleware nothing
 * but `node:async_hooks`.
 */

/**
 * The caller half of a `tool_call_audit` row.
 *
 * Treated as ONE ATOMIC UNIT by every reader. Fields are never mixed between
 * two sources — a row built half from this request and half from a stale
 * pooled stamp would look complete and be false.
 */
export interface CallerContext {
  /** Human-readable label (api-key name / OAuth user email), for `client_name`. */
  clientName?: string;
  apiKeyUuid?: string;
  authMethod?: string;
  /** The credential OWNER — api-key owner, OAuth subject, or session user. */
  userId?: string;
  /** An admin key's acts-as target (`api_keys.acts_as_user_id`), when bound. */
  actsAsUserId?: string;
  callerIp?: string;
  requestId?: string;
}

const storage = new AsyncLocalStorage<CallerContext>();

/**
 * Run `fn` with `caller` as the request-scoped binding.
 *
 * An undefined caller runs OUTSIDE any store rather than entering an empty
 * one. That difference matters to `getCallerContext`'s reader: "no store" and
 * "a store that happens to be blank" must stay distinguishable, because the
 * first is a path that was never wired and the second is a request that
 * genuinely resolved no identity.
 */
export function runWithCallerContext<T>(
  caller: CallerContext | undefined,
  fn: () => T,
): T {
  if (!caller) return fn();
  return storage.run(caller, fn);
}

export function getCallerContext(): CallerContext | undefined {
  return storage.getStore();
}
