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
