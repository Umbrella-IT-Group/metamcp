import type express from "express";

import type { AuditRequestFields } from "@/lib/audit/audit-emitter";
// From `lib/client-ip`, not through the `audit-context.middleware` re-export:
// this is a `lib/` module, and that file records why `lib/` importing
// `middleware/` is the shape that becomes an import cycle.
import { resolveClientIp } from "@/lib/client-ip";

import type { CallerContext } from "./caller-context-store";
import { MetaMCPHandlerContext } from "./metamcp-middleware/functional-middleware";

/**
 * Caller binding for the tool-call audit trail.
 *
 * `tool_call_audit` could already name a consumer (`client_name`), but a
 * display label is not an identity: it is composed from a mutable email, it
 * says nothing about WHICH credential was presented, and it is empty on every
 * path that never resolved one. So a row could describe a call and still not
 * attribute it — the question "which key, which auth method, which account,
 * from which address, as part of which request" had no answer in the table.
 *
 * All of it is resolved per request by middleware that runs BEFORE any tool
 * handler: `authenticateApiKey` stamps the identity, and
 * `auditContextMiddleware` stamps the request id and the caller IP. They were
 * simply never carried down to the auditing middleware. This module builds
 * the binding; `caller-context-store` carries it (see that file for why the
 * carrier is AsyncLocalStorage and not the pooled handler context).
 *
 * WHERE EACH VALUE COMES FROM:
 *
 *   apiKeyUuid   <- `authenticateApiKey`: the `api_keys` row that
 *                   authenticated this request. Recorded as a bare uuid with
 *                   NO foreign key, because the audit row has to outlive the
 *                   key it names.
 *   authMethod   <- `authenticateApiKey`: "api_key" | "oauth". The admin
 *                   Inspector surface adds "session".
 *   userId       <- the key OWNER (`apiKeyUserId`), the OAuth subject
 *                   (`oauthUserId`), or the session user.
 *   actsAsUserId <- `api_keys.acts_as_user_id` (migration 0024) when an admin
 *                   key carries a delegated binding. A SEPARATE column from
 *                   `userId` on purpose: one answers "whose credential", the
 *                   other "whose identity was exercised", and collapsing them
 *                   makes a delegated call indistinguishable from a direct
 *                   one. It also rides `client_name` as `key (as email)`, but
 *                   that string is composed from a mutable email through a
 *                   cache that degrades to a short-id on a read failure —
 *                   fine as a label, not a thing to query on.
 *   callerIp     <- CF-Connecting-IP, never `req.ip`.
 *   requestId    <- `auditContextMiddleware`'s per-request id, so a tool call
 *                   joins to whatever `audit_log` rows the same request
 *                   produced — an auth denial and the call it preceded become
 *                   one queryable sequence instead of two timestamps.
 */

/**
 * Structural view of the request fields the auth and audit-context
 * middlewares stamp.
 *
 * EXTENDS `AuditRequestFields` rather than redeclaring `auditRequestId` /
 * `auditClientIp` locally, and that is the point: those two are stamped in
 * `middleware/audit-context.middleware` and read here, in a different module,
 * off a plain express request. Redeclared as loose optional properties, a
 * rename on the stamping side would leave this module compiling green and
 * silently writing NULL into both columns. Inheriting the declaration makes
 * the rename a compile error at the read sites below.
 *
 * The identity half stays structural — declaring it against
 * `ApiKeyAuthenticatedRequest` would put three DB repositories in this
 * module's import graph. Express requests satisfy it by shape.
 */
export interface CallerContextSource extends AuditRequestFields {
  headers?: express.Request["headers"];
  apiKeyUuid?: string;
  apiKeyUserId?: string;
  apiKeyActsAsUserId?: string;
  oauthUserId?: string;
  authMethod?: string;
}

export type { CallerContext };

export function resolveCallerContext(req: CallerContextSource): CallerContext {
  return {
    apiKeyUuid: req.apiKeyUuid,
    authMethod: req.authMethod,
    // An OAuth request never carries `apiKeyUserId` and an API-key request
    // never carries `oauthUserId`, so this coalesce picks the one the auth
    // middleware actually resolved rather than preferring either method.
    userId: req.apiKeyUserId ?? req.oauthUserId,
    actsAsUserId: req.apiKeyActsAsUserId,
    // Prefer the value `auditContextMiddleware` already stamped — it is what
    // `audit_log.actor_ip` records for this same request, and reading it here
    // means the two tables cannot silently disagree about where a request came
    // from. The header re-read is the fallback for a route that runs before or
    // outside that middleware.
    //
    // TRUST ASSUMPTION, restated at the read site because it is what makes
    // this column evidence rather than an assertion: `CF-Connecting-IP` is
    // written by the Cloudflare edge and OVERWRITTEN on every request, so a
    // client cannot forge it THROUGH Cloudflare — and that is true only while
    // the Cloudflare Tunnel is the sole ingress to this gateway. Publish the
    // origin any other way and every `caller_ip` in the archive becomes
    // caller-controlled. Either path bounds the value at 64 chars
    // (AUDIT_IP_MAX); see `middleware/audit-context.middleware` for the full
    // rationale and for why `trust proxy` stays off.
    callerIp:
      req.auditClientIp ??
      (req.headers ? resolveClientIp(req.headers) : undefined),
    // No fallback id is minted when the middleware did not run. A synthetic
    // request id would be a join key that matches nothing while looking
    // exactly like a real one; NULL is the honest "not known" — the same call
    // `resolveClientIp` makes about a missing IP.
    requestId: req.auditRequestId,
  };
}

/**
 * Copy the caller binding onto a pooled handler context.
 *
 * This is the FALLBACK carrier, not the authoritative one — the audit row is
 * built from the request-scoped store in `caller-context-store` whenever a
 * request entered it. It is still stamped so a code path that reaches the
 * auditing middleware outside any request scope has something better than
 * nothing, and so the two carriers cannot drift in shape.
 *
 * ASSIGNS EVERY FIELD, including the undefined ones, and that is the point:
 * instances are pooled and reused across consumers, so a partial stamp would
 * leave the previous caller's uuid or IP in place and a later call could be
 * described with someone else's credential. Clearing is the safe direction —
 * a NULL column reads as "not known", a stale one reads as evidence.
 */
export function stampCallerContext(
  context: MetaMCPHandlerContext,
  req: CallerContextSource,
  clientName?: string,
): void {
  const caller = resolveCallerContext(req);
  context.clientName = clientName;
  context.apiKeyUuid = caller.apiKeyUuid;
  context.authMethod = caller.authMethod;
  context.userId = caller.userId;
  context.actsAsUserId = caller.actsAsUserId;
  context.callerIp = caller.callerIp;
  context.requestId = caller.requestId;
}
