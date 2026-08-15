import express from "express";

import type { AuditAttributedRequest } from "@/lib/audit/audit-emitter";
import { sendAuthenticationRequiredChallenge } from "@/lib/auth-challenge";
import { AuthRateLimiter } from "@/lib/auth-rate-limiter";
import logger from "@/utils/logger";

import { endpointsRepository } from "../db/repositories/endpoints.repo";
import type { ApiKeyAuthenticatedRequest } from "./api-key-oauth.middleware";

/**
 * ENDPOINT-NAME PROBES, the traffic this limiter exists for.
 *
 * A legitimate caller reaches `/metamcp/<name>/*` with a name it was given, so
 * it never produces a not-found. The only source of a sustained stream of them
 * is someone walking a wordlist, which is why counting ONLY not-founds is both
 * safe for real clients and the exact signal worth bounding. It is the same
 * failure-only discipline `getPublicOAuthRateLimitIdentifier` documents in
 * `lib/auth-rate-limiter`.
 *
 * Its own `AuthRateLimiter` INSTANCE, with its own Map, so a scanner cannot
 * spend the endpoint data plane's failed-auth budget or the public OAuth
 * routes' budget, and vice versa.
 *
 * BUDGET: 20 not-found probes per 5 minutes per client IP. Set against real
 * use rather than against the attacker, because the attacker is unbounded
 * either way once they know a name: 20 is far more mistyped URLs than an
 * operator produces in a sitting, and far fewer names than an enumeration run
 * needs to be worth doing.
 */
const ENDPOINT_PROBE_WINDOW_MS = 5 * 60 * 1000;
const ENDPOINT_PROBE_MAX = 20;
const endpointProbeRateLimiter = new AuthRateLimiter(
  ENDPOINT_PROBE_MAX,
  ENDPOINT_PROBE_WINDOW_MS,
);

/**
 * Throttled operator notice, same shape as the one in
 * `trpc-rate-limit.middleware`.
 *
 * A probe run is by definition high-volume and attacker-paced, so one log line
 * per probe would let the scanner size our log file for us. One line per
 * minute carrying the running total keeps the event visible without handing
 * over that lever.
 */
const PROBE_REPORT_INTERVAL_MS = 60 * 1000;
let probesTotal = 0;
let lastProbeReportAt = 0;

function reportProbe(endpointName: string, clientIp: string | undefined): void {
  probesTotal += 1;
  const now = Date.now();
  // The `!== 0` half matters under a mocked clock: a suite that pins Date to
  // the epoch would otherwise have its very first report silently swallowed.
  if (
    lastProbeReportAt !== 0 &&
    now - lastProbeReportAt < PROBE_REPORT_INTERVAL_MS
  ) {
    return;
  }
  lastProbeReportAt = now;
  // The real reason lives HERE and only here. The response deliberately does
  // not say "no such endpoint", so this log line is the only place the name
  // and the caller are recorded. Both values are attacker-controlled strings,
  // so both are JSON-stringified rather than interpolated raw: an embedded
  // newline would otherwise let a probe forge additional log lines.
  logger.warn(
    `[endpoint-lookup] unknown endpoint name ${JSON.stringify(endpointName)} ` +
      `from ${JSON.stringify(clientIp ?? "unattributed")}, ` +
      `${probesTotal} probe(s) since startup`,
  );
}

/** Test seam for the module-level report throttle. */
export function __resetEndpointProbeReporting(): void {
  probesTotal = 0;
  lastProbeReportAt = 0;
}

/**
 * Look up the endpoint named in the URL and stamp it on the request.
 *
 * THE 404 THIS NO LONGER SENDS was an endpoint-enumeration oracle. This
 * middleware runs BEFORE authentication on the whole `/metamcp` data plane
 * (it has to, because `authenticateApiKey` reads `req.endpoint` to decide
 * which auth mode applies), so an anonymous caller used to get a 404 saying
 * `No endpoint found with name: <name>` for a name that does not exist, and a
 * 401 for one that does. That difference answers "is this a real endpoint?"
 * for free, with no credential, at whatever rate the caller likes: a wordlist
 * plus that oracle is the whole integration estate's endpoint list. The 401
 * body then named the endpoint's auth mode on top of it, which is fixed in
 * `api-key-oauth.middleware`.
 *
 * So a name that does not exist now answers with the SAME challenge a real
 * endpoint answers an unauthenticated request with: same status, same body,
 * same header, no echo of the name asked for. There is nothing left in the
 * response to compare.
 *
 * ACCEPTED COST, because it is real and it is the price of the property: a
 * genuinely mistyped endpoint URL used to say "no endpoint found with that
 * name" and now says "authenticate". Diagnosing a typo moves to the server log
 * (see `reportProbe`) and to the admin UI, which lists endpoints to an
 * authenticated administrator and is where that answer belongs. A CORRECT
 * connector URL is unaffected in every respect, authenticated or not.
 *
 * The probe limiter is checked BEFORE the database is touched, so a scanner
 * that has already burned its budget cannot keep spending a query per guess.
 * It refuses NAME-INDEPENDENTLY once tripped, real endpoints included, which
 * is deliberate: a limiter that only refused not-founds would rebuild the very
 * oracle above out of 429-versus-401.
 *
 * `afterAuthentication` is for the ONE mount where this runs behind a
 * completed authentication gate rather than in front of one: the two operator
 * routes in `routers/public-metamcp/admin.ts`. Neither the challenge nor the
 * probe limiter is right there. A caller who has already proved they are an
 * enabled administrator has learned nothing by being told a name is wrong
 * (the admin UI lists every endpoint to them), so they get the honest 404
 * back; and throttling an operator's typos on a control-panel route would be
 * a self-inflicted outage with no attacker to stop, since an anonymous
 * enumerator never gets past the session check to reach this code at all.
 *
 * Factory so a test can supply a limiter with a small budget instead of
 * driving 20 real probes through the middleware.
 */
export function createLookupEndpoint({
  limiter = endpointProbeRateLimiter,
  afterAuthentication = false,
}: {
  limiter?: AuthRateLimiter;
  afterAuthentication?: boolean;
} = {}) {
  return async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction,
  ) => {
    const endpointName = req.params.endpoint_name;
    // `auditClientIp` is `CF-Connecting-IP`, per-caller and not forgeable
    // through the tunnel; `req.ip` is one shared in-container address for
    // every caller and would make this a scheduled outage rather than a
    // limiter. The no-header class is EXEMPT from the limiter rather than
    // bucketed together, for the reason spelled out at length in
    // `trpc-rate-limit.middleware`: one shared "unknown" bucket is the
    // failure mode this keying exists to avoid.
    const clientIp = (req as AuditAttributedRequest).auditClientIp;
    const probeKey =
      clientIp && !afterAuthentication
        ? `endpoint-probe:${clientIp}`
        : undefined;

    if (probeKey && limiter.isCurrentlyLimited(probeKey)) {
      // Read-only check on purpose: `isRateLimited` counts the call it is
      // asked about, so using it here would let ordinary MCP traffic, which
      // passes this gate, fill the bucket and eventually refuse itself.
      res.set(
        "Retry-After",
        String(Math.ceil(ENDPOINT_PROBE_WINDOW_MS / 1000)),
      );
      // Byte-identical to the data plane's own 429 (see
      // `api-key-oauth.middleware`), so which limiter refused a caller is not
      // itself something the caller can read off the response.
      return res.status(429).json({
        error: "too_many_requests",
        error_description:
          "Too many failed authentication attempts. Please try again later.",
        timestamp: new Date().toISOString(),
      });
    }

    try {
      const endpoint = await endpointsRepository.findByName(endpointName);
      if (!endpoint) {
        if (afterAuthentication) {
          return res.status(404).json({
            error: "Endpoint not found",
            message: `No endpoint found with name: ${endpointName}`,
            timestamp: new Date().toISOString(),
          });
        }
        if (probeKey) limiter.recordFailedAttempt(probeKey);
        reportProbe(endpointName, clientIp);
        return sendAuthenticationRequiredChallenge(req, res);
      }

      // Add the endpoint info to the request for use in handlers
      const authReq = req as ApiKeyAuthenticatedRequest;
      authReq.namespaceUuid = endpoint.namespace_uuid;
      authReq.endpointName = endpointName;
      authReq.endpoint = endpoint;

      next();
    } catch (error) {
      logger.error("Error looking up endpoint:", error);
      return res.status(500).json({
        error: "Internal server error",
        message: "Failed to lookup endpoint",
        timestamp: new Date().toISOString(),
      });
    }
  };
}

// Middleware to lookup endpoint by name and add namespace info to request.
// Mounted IN FRONT of authentication on the whole `/metamcp` data plane, so an
// unknown name answers with the ordinary challenge.
export const lookupEndpoint = createLookupEndpoint();

// The behind-the-gate variant, for callers who are already authenticated by
// the time it runs. See `afterAuthentication` above.
export const lookupEndpointAfterAuth = createLookupEndpoint({
  afterAuthentication: true,
});
