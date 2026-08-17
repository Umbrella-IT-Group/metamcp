import type express from "express";

import { resolveClientIp } from "@/middleware/audit-context.middleware";

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
 * All five facts are resolved per request by middleware that runs BEFORE any
 * tool handler: `authenticateApiKey` stamps the identity, and
 * `auditContextMiddleware` stamps the request id and the caller IP. They were
 * simply never threaded into the proxy's handler context, which is the only
 * thing the auditing middleware can see. This module is that thread.
 *
 * DB-FREE BY CONSTRUCTION, and it must stay that way. The auditing middleware
 * reads these fields off the handler context and its module graph is
 * deliberately import-clean of the database so unit tests exercise it without
 * postgres (see `metamcp-middleware/auditing.functional.ts`). Everything this
 * module imports — `resolveClientIp`, and the handler-context type — is on the
 * same DB-free side of that line.
 *
 * WHERE EACH VALUE COMES FROM:
 *
 *   apiKeyUuid  <- `authenticateApiKey`: the `api_keys` row that authenticated
 *                  this request. Recorded as a bare uuid with NO foreign key,
 *                  because the audit row has to outlive the key it names.
 *   authMethod  <- `authenticateApiKey`: "api_key" | "oauth".
 *   userId      <- the key OWNER (`apiKeyUserId`) or the OAuth subject
 *                  (`oauthUserId`). An admin key's ACTS-AS target is
 *                  deliberately not recorded here: it already rides
 *                  `client_name` as `key (as email)`, and this field answers
 *                  "whose credential was used", not "whose identity was
 *                  exercised". Collapsing the two would make a delegated call
 *                  indistinguishable from a direct one.
 *   callerIp    <- CF-Connecting-IP via `resolveClientIp`, never `req.ip`.
 *   requestId   <- `auditContextMiddleware`'s per-request id, so a tool call
 *                  joins to whatever `audit_log` rows the same request
 *                  produced — an auth denial and the call it preceded become
 *                  one queryable sequence instead of two timestamps.
 */

/**
 * Structural view of the request fields the auth + audit-context middlewares
 * stamp.
 *
 * Declared structurally rather than importing `ApiKeyAuthenticatedRequest` and
 * `AuditAttributedRequest` so this module keeps no edge — not even a
 * type-only one that a later refactor could turn into a value import — to
 * `api-key-oauth.middleware`, which pulls three DB repositories. Express
 * requests satisfy it by shape.
 */
export interface CallerContextSource {
  headers?: express.Request["headers"];
  apiKeyUuid?: string;
  apiKeyUserId?: string;
  oauthUserId?: string;
  authMethod?: string;
  auditRequestId?: string;
}

/** The caller-binding half of a `tool_call_audit` row. */
export interface CallerContext {
  apiKeyUuid?: string;
  authMethod?: string;
  userId?: string;
  callerIp?: string;
  requestId?: string;
}

export function resolveCallerContext(req: CallerContextSource): CallerContext {
  return {
    apiKeyUuid: req.apiKeyUuid,
    authMethod: req.authMethod,
    // An OAuth request never carries `apiKeyUserId` and an API-key request
    // never carries `oauthUserId`, so this coalesce picks the one the auth
    // middleware actually resolved rather than preferring either method.
    userId: req.apiKeyUserId ?? req.oauthUserId,
    // TRUST ASSUMPTION, restated at the read site because it is what makes
    // this column evidence rather than an assertion: `CF-Connecting-IP` is
    // written by the Cloudflare edge and OVERWRITTEN on every request, so a
    // client cannot forge it THROUGH Cloudflare — and that is true only while
    // the Cloudflare Tunnel is the sole ingress to this gateway. Publish the
    // origin any other way and every `caller_ip` in the archive becomes
    // caller-controlled. `resolveClientIp` also bounds the value (64 chars,
    // AUDIT_IP_MAX); see `middleware/audit-context.middleware` for the full
    // rationale and for why `trust proxy` stays off.
    callerIp: req.headers ? resolveClientIp(req.headers) : undefined,
    // No fallback id is minted when the middleware did not run. A synthetic
    // request id would be a join key that matches nothing while looking
    // exactly like a real one; NULL is the honest "not known" — the same call
    // `resolveClientIp` makes about a missing IP.
    requestId: req.auditRequestId,
  };
}

/**
 * Copy the caller binding onto a handler context.
 *
 * ASSIGNS EVERY FIELD, including the undefined ones, and that is the point:
 * MetaMCP server instances are POOLED and reused across consumers, so a
 * partial stamp would leave the previous caller's uuid or IP in place and the
 * next call would be audited under someone else's credential. Clearing is the
 * safe direction — a NULL column reads as "not known", a stale one reads as
 * evidence.
 */
export function stampCallerContext(
  context: MetaMCPHandlerContext,
  req: CallerContextSource,
): void {
  const caller = resolveCallerContext(req);
  context.apiKeyUuid = caller.apiKeyUuid;
  context.authMethod = caller.authMethod;
  context.userId = caller.userId;
  context.callerIp = caller.callerIp;
  context.requestId = caller.requestId;
}
