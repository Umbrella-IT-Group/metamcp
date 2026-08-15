import { createHash } from "node:crypto";

import type express from "express";

import logger from "@/utils/logger";

/**
 * Fire-and-forget writer for the control-plane security audit log
 * (`audit_log`, migration 0028).
 *
 * THE SAFETY PROPERTY, and it outranks everything else in this file: an audit
 * write must NEVER block, delay, or fail the request it describes. The two
 * emitters wired in Phase 1A sit on the RBAC choke point (every admin-gated
 * tRPC mutation) and the MCP bearer path (every proxied MCP call). A throw
 * escaping `emit()` would not lose a log line — it would take the gateway
 * down. So `emit()` returns `void`, never a promise the caller can await into
 * the request path, and swallows every failure at every layer:
 *
 *   1. building the row is inside the try — a malformed `detail` must not
 *      throw at the call site;
 *   2. resolving the repository is lazy and failure-tolerant (no DATABASE_URL
 *      in unit tests / tooling disables the sink for the process lifetime
 *      rather than re-attempting the import per event);
 *   3. the write itself is a detached promise with a `.catch`.
 *
 * Failures log at debug only. An audit sink that shouts on every write error
 * turns a database blip into a log flood on the exact paths that are hottest.
 *
 * Same discipline (and the same lazy-import trick) as
 * `lib/metamcp/metamcp-middleware/auditing.functional.ts`, which has carried
 * the data-plane tool-call writes since PR #57.
 *
 * SECRETS: never pass a raw credential, token, password or request body into
 * an event. Use `credentialFingerprint()` — sha256 plus last-4, which is
 * enough to correlate repeated use of one stolen key across rows and enough
 * for an operator to match a row against a key list, and useless to anyone
 * who steals the audit table.
 */

export type AuditActorType =
  | "user"
  | "api_key"
  | "oauth_client"
  | "anonymous"
  | "system";

export type AuditOutcome = "success" | "failure" | "denied";

export interface AuditEvent {
  actor_type: AuditActorType;
  actor_id?: string | null;
  actor_label?: string | null;
  actor_ip?: string | null;
  actor_user_agent?: string | null;
  /** Verb from the controlled list (e.g. `rbac.denied`, `mcp.auth.denied`). */
  action: string;
  target_type?: string | null;
  target_id?: string | null;
  outcome: AuditOutcome;
  request_id?: string | null;
  http_status?: number | null;
  detail?: Record<string, unknown>;
}

type AuditSink = (event: AuditEvent) => Promise<void>;

let auditSink: AuditSink | null | undefined;

async function resolveSink(): Promise<AuditSink | null> {
  if (auditSink !== undefined) return auditSink;
  try {
    const { auditLogRepository } = await import(
      "../../db/repositories/audit-log.repo"
    );
    auditSink = (event) =>
      auditLogRepository.record({
        actor_type: event.actor_type,
        actor_id: event.actor_id ?? null,
        actor_label: event.actor_label ?? null,
        actor_ip: event.actor_ip ?? null,
        actor_user_agent: event.actor_user_agent ?? null,
        action: event.action,
        target_type: event.target_type ?? null,
        target_id: event.target_id ?? null,
        outcome: event.outcome,
        request_id: event.request_id ?? null,
        http_status: event.http_status ?? null,
        detail: event.detail ?? {},
      });
  } catch {
    // No database in this process (unit tests, tooling) — disable for the
    // process lifetime rather than re-attempting the import per event.
    auditSink = null;
  }
  return auditSink;
}

/** Test seam: override or disable the persistence sink (undefined = re-resolve). */
export function setAuditSinkForTesting(
  sink: AuditSink | null | undefined,
): void {
  auditSink = sink;
}

/**
 * Record a security event. Returns immediately; the write happens detached.
 *
 * Every failure mode ends here — callers do not need (and must not add) a
 * try/catch of their own, and must not `await` this.
 */
export function emit(event: AuditEvent): void {
  try {
    void resolveSink()
      .then((sink) => sink?.(event))
      .catch((error) => {
        logger.debug("[audit] write failed (ignored):", error);
      });
  } catch (error) {
    // Defence in depth: `resolveSink()` is async and should never throw
    // synchronously, but a future refactor that makes it sync must not be
    // able to turn a logging failure into a 500 on the auth path.
    logger.debug("[audit] emit failed (ignored):", error);
  }
}

/**
 * Per-request attribution fields, stamped on `req` by the audit-context
 * middleware. Named rather than declaration-merged onto express's `Request`
 * so the property cannot collide with an upstream or dependency field —
 * matching the `ApiKeyAuthenticatedRequest` idiom in
 * `middleware/api-key-oauth.middleware.ts`.
 */
export interface AuditRequestFields {
  auditRequestId?: string;
  auditClientIp?: string;
}

export type AuditAttributedRequest = express.Request & AuditRequestFields;

export interface AuditRequestContext {
  actor_ip: string | null;
  actor_user_agent: string | null;
  request_id: string | null;
}

/**
 * Build the request half of the envelope.
 *
 * `actor_ip` comes from the middleware's CF-Connecting-IP read, NOT from
 * `req.ip`: the backend is reached through the frontend's in-container
 * rewrite, so `req.ip` is the same loopback address for every caller on
 * earth. Nullable rather than "unknown" — a column that says `127.0.0.1`
 * for everyone is worse than one that admits it does not know.
 */
export function auditRequestContext(
  req: express.Request | undefined | null,
): AuditRequestContext {
  const attributed = req as AuditAttributedRequest | undefined | null;
  const ua = attributed?.headers?.["user-agent"];
  return {
    actor_ip: attributed?.auditClientIp ?? null,
    actor_user_agent: typeof ua === "string" ? ua : null,
    request_id: attributed?.auditRequestId ?? null,
  };
}

/**
 * Header names the `/api/auth` relay in `index.ts` writes onto the internal
 * `Request` it hands to `auth.handler()`, purely so better-auth's
 * `databaseHooks` can see the same attribution as the Express layer.
 *
 * WHY A HEADER AND NOT A PARAMETER. The signup / session-lifecycle events are
 * emitted from `databaseHooks` in `auth.ts`, which better-auth calls with a
 * `GenericEndpointContext` — the web `Request` it was given, and nothing from
 * Express. Without this, every hook-emitted row would carry a null
 * `request_id` and a null `actor_ip`, and could not be joined to the
 * `auth.login.*` row the same HTTP request produced. The relay is the one
 * place that holds both objects.
 *
 * NOT CLIENT-CONTROLLED. The relay copies the caller's headers into that
 * Request first, so a caller CAN put its own value under these names — which
 * is why the relay then unconditionally `set`s them when it has a value and
 * `delete`s them when it does not. Overwriting alone would not be enough: the
 * case with no `CF-Connecting-IP` is exactly the case where a forged
 * `x-audit-client-ip` would otherwise survive. These names are internal to
 * that one hop and are never emitted on any outbound request.
 */
export const AUDIT_REQUEST_ID_HEADER = "x-audit-request-id";
export const AUDIT_CLIENT_IP_HEADER = "x-audit-client-ip";

/**
 * Write this request's attribution onto the internal `Request` the `/api/auth`
 * relay hands to better-auth, replacing anything the caller sent under the
 * same names.
 *
 * EVERY branch writes, and the `delete` half is the security part rather than
 * tidiness: the relay copies the caller's headers into that bag first, so a
 * client that sends `x-audit-client-ip` has already put its own value there.
 * Setting only when we have a value would leave the forged one standing in
 * exactly the case that matters — a request with no `CF-Connecting-IP`, i.e.
 * one that did not come through the Cloudflare tunnel and whose IP claims are
 * therefore worthless. Deleting on absence makes "unknown" mean unknown.
 *
 * Lives here rather than inline in `index.ts` so the property is testable:
 * importing `index.ts` boots the entire server.
 */
export function stampAuditHeaders(
  headers: Headers,
  context: AuditRequestContext,
): void {
  if (context.request_id) {
    headers.set(AUDIT_REQUEST_ID_HEADER, context.request_id);
  } else {
    headers.delete(AUDIT_REQUEST_ID_HEADER);
  }
  if (context.actor_ip) {
    headers.set(AUDIT_CLIENT_IP_HEADER, context.actor_ip);
  } else {
    headers.delete(AUDIT_CLIENT_IP_HEADER);
  }
}

/** Anything header-shaped enough to read a value out of. */
interface HeaderReader {
  get(name: string): string | null;
}

/**
 * Read one header from the first of several candidate bags that can answer.
 *
 * Plural because better-auth types the hook context's `headers` as the loose
 * `HeadersInit`, which is satisfied by a plain object or an array of pairs as
 * well as by a real `Headers`. Reading only `context.headers` and giving up
 * when it has no `.get` would silently produce an unattributed row even
 * though `context.request.headers` — a genuine `Headers` — was sitting right
 * there. Falling through per lookup rather than picking one bag up front is
 * what makes that impossible.
 */
function readHeader(sources: unknown[], name: string): string | null {
  for (const source of sources) {
    const candidate = source as HeaderReader | null | undefined;
    if (typeof candidate?.get !== "function") continue;
    const value = candidate.get(name);
    if (typeof value === "string" && value !== "") return value;
  }
  return null;
}

/**
 * Rebuild the request half of the envelope inside a better-auth database
 * hook, from the two relay headers above plus the caller's User-Agent.
 *
 * Takes `unknown` deliberately: better-auth types the hook's context as
 * `GenericEndpointContext | null`, whose `headers` is the loose `HeadersInit`
 * and whose `request` may be absent, and this runs on the sign-up and
 * sign-in paths where a type assumption that turns out wrong at runtime would
 * throw inside an awaited hook — i.e. break authentication to record it.
 * Every read is guarded and every miss degrades to null.
 */
export function auditContextFromHook(context: unknown): AuditRequestContext {
  try {
    const candidate = context as
      | { headers?: unknown; request?: { headers?: unknown } }
      | null
      | undefined;
    const bags = [candidate?.headers, candidate?.request?.headers];
    return {
      actor_ip: readHeader(bags, AUDIT_CLIENT_IP_HEADER),
      actor_user_agent: readHeader(bags, "user-agent"),
      request_id: readHeader(bags, AUDIT_REQUEST_ID_HEADER),
    };
  } catch {
    return { actor_ip: null, actor_user_agent: null, request_id: null };
  }
}

/**
 * Bound a caller-supplied string before it goes into `detail`.
 *
 * `audit_log` has UPDATE/DELETE/TRUNCATE triggers and deliberately no prune
 * path, so a row's SIZE is as permanent as its contents. Anything that
 * reaches an emitter from a request body is therefore a write-amplification
 * primitive unless it is clamped at the emitter: the JSON body limit is 50mb
 * and `/oauth/register` is unauthenticated, so one anonymous request could
 * otherwise push megabytes into a jsonb column nobody can delete from. The
 * point of the table is to survive an attack, not to be the vector for the
 * next one.
 *
 * Clamping is lossy on purpose. A redirect URI truncated at 512 characters
 * still identifies where a grant was aimed; the untruncated value is not
 * worth an unbounded column.
 */
export function clampAuditText(value: unknown, maxLength: number): string {
  return String(value ?? "").slice(0, maxLength);
}

/**
 * Bound a caller-supplied ARRAY of strings the same way — both how many
 * entries are kept and how long each one may be.
 *
 * Array length matters as much as element length: `redirect_uris` arrives
 * verbatim from anonymous dynamic client registration, and nothing upstream
 * of the emitter caps how many entries a caller may send. Callers that keep
 * a count alongside the clamped list can still see when truncation happened.
 */
export function clampAuditTextList(
  values: unknown,
  maxItems: number,
  maxLength: number,
): string[] {
  if (!Array.isArray(values)) return [];
  return values.slice(0, maxItems).map((v) => clampAuditText(v, maxLength));
}

export interface CredentialFingerprint {
  /** sha256 of the presented credential — correlates reuse without storing it. */
  sha256: string | null;
  /** Last 4 characters, so an operator can match a row against a key list. */
  last4: string | null;
}

/**
 * Fingerprint a presented credential for storage in `detail`.
 *
 * NEVER store the credential itself. sha256 is one-way, and 4 trailing
 * characters of a high-entropy token identify a key to a human who already
 * holds the key list without being usable by anyone who does not.
 */
export function credentialFingerprint(
  credential: string | undefined | null,
): CredentialFingerprint {
  if (!credential) return { sha256: null, last4: null };
  try {
    return {
      sha256: createHash("sha256").update(credential).digest("hex"),
      last4: credential.slice(-4),
    };
  } catch {
    // Unhashable input is not a reason to lose the event — the row still
    // records that a credential was presented and refused.
    return { sha256: null, last4: null };
  }
}
