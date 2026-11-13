import type express from "express";

import logger from "@/utils/logger";

import { auditRequestContext, emit } from "../lib/audit/audit-emitter";
import { metamcpLogStore } from "../lib/metamcp/log-store";
import {
  clampMethod,
  classifyRoute,
  currentOriginPolicyMode,
  decideAuditRow,
  decideOriginReport,
  describeSecFetchSite,
  endpointNameFromPath,
  evaluateOrigin,
  formatOriginEventMessage,
  isLivenessRequest,
  ORIGIN_REFUSAL_BODY,
  type OriginEventClass,
  originReportKey,
  type RouteFamily,
  type SecFetchSiteDescription,
  statusClass,
} from "../lib/origin-policy";

/**
 * The Origin guard for `/metamcp/*`. Policy, modes and what it does not close
 * are in ../lib/origin-policy; this is the request-time half.
 *
 * Mounted FIRST on the public router, ahead of the CORS middleware, the
 * endpoint lookup, credential checks and rate limiting. Position relative to
 * the CORS middleware is style only (the guard allows every origin that
 * middleware would grant, and an untrusted preflight falls through it to
 * Express either way); what matters is that a refused request takes no session
 * slot, no failed-auth budget and no database round trip, and in `enforce`
 * reveals nothing about which endpoints exist (403 for every path).
 *
 * It sees only what is mounted under `/metamcp`. `/oauth/*`, `/.well-known/*`,
 * `/api/auth`, `/trpc`, `/mcp-proxy` and `/m365` are other mounts, so they are
 * exempt by construction; a test pins that.
 *
 * The order of the early returns is the cost model. With the guard `off`, or
 * with no `Origin` header (every server-side caller), it reads one property
 * and moves on.
 */
export function originPolicyMiddleware(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
): void {
  const mode = currentOriginPolicyMode();
  if (mode === "off") return next();

  const header = req.headers.origin;
  if (header === undefined) return next();

  if (isLivenessRequest(req.method, req.path)) return next();

  const evaluation = evaluateOrigin(header);
  if (evaluation.kind !== "refused") return next();

  const snapshot = snapshotRefusedRequest(req, evaluation.described);

  if (mode === "enforce") {
    // The cors package adds `Vary: Origin` only when it grants one, so without
    // this a shared cache could replay the grant-less answer to a trusted
    // origin.
    res.vary("Origin");
    recordRefusal(req, snapshot, "enforce", "refused", 403);
    res.status(403).json(ORIGIN_REFUSAL_BODY);
    return;
  }

  // `audit`: serve the request exactly as before and record it once its status
  // is known. Recording at request time would say only that an untrusted
  // origin showed up; the operator deciding whether to enforce needs to know
  // whether such a request was SERVED, because a 2xx under an untrusted Origin
  // is a legitimate caller this guard would refuse.
  onceAtResponseHead(res, (status) => {
    recordRefusal(req, snapshot, "audit", statusClass(status), status);
  });
  next();
}

/**
 * What is worth knowing about a refused request, read once at request time:
 * the routers below may rewrite `req.url` while they run, and the record is
 * written later (at response head) in `audit`.
 */
interface RefusedRequestSnapshot {
  described: string;
  route: RouteFamily;
  method: string;
  endpointName: string | null;
  credentialPresent: boolean;
  secFetchSite: SecFetchSiteDescription;
  userAgent: unknown;
}

function snapshotRefusedRequest(
  req: express.Request,
  described: string,
): RefusedRequestSnapshot {
  return {
    described,
    route: classifyRoute(req.path),
    method: clampMethod(req.method),
    endpointName: endpointNameFromPath(req.path),
    credentialPresent: credentialPresented(req),
    secFetchSite: describeSecFetchSite(req.headers["sec-fetch-site"]),
    userAgent: req.headers["user-agent"],
  };
}

/**
 * Whether the request carried a credential, as a boolean. The value is never
 * read into the record: a refused origin is a caller this gateway has not
 * authenticated, and what it sent in `X-API-Key` is not for a log to hold. The
 * three places the data plane looks for one (`X-API-Key`, `Authorization`, and
 * the `api_key` / `apikey` query parameters) are checked for presence only.
 */
function credentialPresented(req: express.Request): boolean {
  if (nonEmpty(req.headers["x-api-key"])) return true;
  if (nonEmpty(req.headers.authorization)) return true;
  try {
    const query = req.query;
    return nonEmpty(query?.api_key) || nonEmpty(query?.apikey);
  } catch {
    return false;
  }
}

function nonEmpty(value: unknown): boolean {
  if (typeof value === "string") return value.length > 0;
  return Array.isArray(value) && value.length > 0;
}

/**
 * Write one refused request down: always to the activity history (log buffer,
 * stdout and `gateway_events`, one call), and in `enforce` also to `audit_log`.
 *
 * Never throws and never changes the answer, the contract `emitMcpAuthDenial`
 * and `emitSessionBindingDenial` keep: a refusal must be answered whether or
 * not it can be recorded.
 *
 * `audit` mode writes no `audit_log` row on purpose. The signal belongs in the
 * prunable table, and the permanent one must not take noise from callers that
 * are not yet classified. `enforce` reuses the existing `mcp.auth.denied`
 * verb, as the session-binding refusals do, so queries that already read it see
 * these too; `detail.reason` separates them.
 */
function recordRefusal(
  req: express.Request,
  snapshot: RefusedRequestSnapshot,
  mode: "audit" | "enforce",
  eventClass: OriginEventClass,
  status: number,
): void {
  const key = originReportKey({
    mode,
    described: snapshot.described,
    route: snapshot.route,
    method: snapshot.method,
    eventClass,
    credentialPresent: snapshot.credentialPresent,
  });

  try {
    // OPTIONS is answered without authentication, including when the caller
    // adds a fake credential header. Its 200 must not spend the reserve that
    // protects evidence of clients actually served by a data-plane handler.
    // Nor may "other" routes: Express also serves non-exempt spellings of
    // liveness paths (such as /HEALTH and /health/sessions/) without auth.
    const event = decideOriginReport(
      key,
      eventClass === "served" &&
        snapshot.method !== "OPTIONS" &&
        snapshot.route !== "other"
        ? "served"
        : "other",
    );
    if (event.report) {
      metamcpLogStore.record({
        category: "system",
        serverName: "origin-policy",
        level: "warn",
        message: formatOriginEventMessage({
          mode,
          origin: snapshot.described,
          route: snapshot.route,
          method: snapshot.method,
          eventClass,
          status,
          credentialPresent: snapshot.credentialPresent,
          secFetchSite: snapshot.secFetchSite,
          userAgent: snapshot.userAgent,
          suppressed: event.suppressed,
          droppedByCeiling: event.droppedByCeiling,
        }),
      });
    }
  } catch {
    reportRecordingFailure("event");
  }

  if (mode !== "enforce") return;

  // The two sinks are independent: losing an activity event must not skip
  // the security audit row as well. Their existing limits bound diagnostics
  // too, and neither a failure nor its exception text may change the response
  // or expose caller-controlled data in a log.
  try {
    const audit = decideAuditRow(key);
    if (!audit.report) return;

    const requestContext = auditRequestContext(req);
    emit({
      actor_type: "anonymous",
      actor_id: null,
      actor_label: null,
      actor_ip: requestContext.actor_ip,
      actor_user_agent: requestContext.actor_user_agent,
      action: "mcp.auth.denied",
      target_type: "endpoint",
      target_id: null,
      outcome: "denied",
      request_id: requestContext.request_id,
      http_status: 403,
      detail: {
        reason: "origin_not_allowed",
        origin: snapshot.described,
        route: snapshot.route,
        method: snapshot.method,
        endpoint_name: snapshot.endpointName,
        credential_present: snapshot.credentialPresent,
        sec_fetch_site: snapshot.secFetchSite,
        // Refusals swallowed by the per-key collapse, and rows dropped by the
        // hourly ceiling, since the last row: the aggregate stays complete
        // even though an individual refusal is not written.
        suppressed_since_last: audit.suppressed,
        dropped_by_ceiling: audit.droppedByCeiling,
      },
    });
  } catch {
    reportRecordingFailure("audit");
  }
}

function reportRecordingFailure(
  stage: "event" | "audit" | "response-head",
): void {
  const message = `[origin-policy] ${stage} recording failed (request unaffected).`;
  try {
    logger.warn(message);
  } catch {
    // A broken logger can itself be why the event failed. Keep the diagnostic
    // visible through the console without retrying that same broken sink.
    console.warn(message);
  }
}

/**
 * Run `fn` once, with the status code, when the response head is written.
 *
 * Wraps `res.writeHead` on this one response, the technique the `on-headers`
 * package uses (hand-rolled because it is not a direct dependency). It covers
 * both ways a head is written: Express `res.json` / `res.end` reach Node's
 * implicit header path, which calls `this.writeHead(this.statusCode)`, and the
 * SDK transports and the SSE router call `writeHead` directly. A streaming
 * response is therefore recorded at its status line, not at close. If the
 * client aborts before any head is written, nothing is recorded: nothing was
 * served.
 *
 * The status is the first argument when it is a number, because
 * `res.statusCode` is not reliable on the direct path (the SDK's node adapter
 * writes the head with an explicit status and leaves `statusCode` at its
 * default).
 *
 * Transparent: the original is called with the unchanged arguments and `this`,
 * and a throw from `fn` is reported without changing the response.
 */
export function onceAtResponseHead(
  res: express.Response,
  fn: (status: number) => void,
): void {
  const original = res.writeHead as (
    this: express.Response,
    ...args: unknown[]
  ) => express.Response;
  let fired = false;

  res.writeHead = function patchedWriteHead(
    this: express.Response,
    ...args: unknown[]
  ) {
    if (!fired) {
      fired = true;
      try {
        fn(statusFromWriteHeadArgs(args[0], this.statusCode));
      } catch {
        reportRecordingFailure("response-head");
      }
    }
    return original.apply(this, args);
  } as typeof res.writeHead;
}

function statusFromWriteHeadArgs(first: unknown, fallback: number): number {
  const candidate =
    typeof first === "number" || typeof first === "string"
      ? Number(first)
      : Number.NaN;
  return Number.isInteger(candidate) && candidate >= 100 && candidate <= 999
    ? candidate
    : fallback;
}
