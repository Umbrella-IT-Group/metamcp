import express from "express";

import {
  auditRequestContext,
  stampAuditHeaders,
} from "@/lib/audit/audit-emitter";
import { emitAuthRelayEvent } from "@/lib/audit/auth-relay-audit";
import { isCorsResponseHeader } from "@/lib/cors-policy";
import { INTERNAL_ERROR_BODY } from "@/middleware/error-handler.middleware";
import logger from "@/utils/logger";

import { auth } from "../auth";

/**
 * The `/api/auth` relay: an Express request in, a better-auth `Response` out.
 *
 * Lives in its own module rather than inline in ../index because ../index
 * cannot be imported — it calls `app.listen()` and initialises the pool at
 * module scope. The two rules this relay has to hold (no CORS grant copied out
 * of better-auth, no error detail copied out to the caller) are security
 * behaviour, and behaviour that cannot be imported cannot be tested; see
 * `auth-relay.test.ts`.
 *
 * Mounted directly after `authApiCorsMiddleware` in ../index, which owns the
 * CORS policy for these paths.
 */
export const authApiRelay = async (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) => {
  if (!req.path.startsWith("/api/auth")) return next();

  try {
    // Create a web Request object from Express request
    const url = new URL(req.url, `http://${req.headers.host}`);
    const headers = new Headers();

    // Copy headers from Express request
    Object.entries(req.headers).forEach(([key, value]) => {
      if (value) {
        headers.set(key, Array.isArray(value) ? value[0] : value);
      }
    });

    // Hand the Express request's audit attribution across the relay seam.
    // better-auth's `databaseHooks` (auth.ts) see only this Request, so
    // without these two the signup and session rows they emit would carry a
    // null request_id and could not be joined to the auth.login.* row from
    // the same HTTP call. Must run AFTER the copy loop above, which brings
    // the CALLER's headers in verbatim — including any it invented under
    // these names. See lib/audit/audit-emitter for why the absent case
    // deletes rather than skips.
    const auditContext = auditRequestContext(req);
    stampAuditHeaders(headers, auditContext);

    // Create Request object
    const request = new Request(url.toString(), {
      method: req.method,
      headers,
      body:
        req.method !== "GET" && req.method !== "HEAD"
          ? JSON.stringify(req.body)
          : undefined,
    });

    // Call better-auth directly
    const response = await auth.handler(request);

    // Convert Response back to Express response
    res.status(response.status);

    // Copy headers, minus any CORS grant. better-auth emits none today, so
    // this changes nothing now; it is here so a future release that starts
    // emitting one cannot silently replace the deliberate policy applied by
    // `authApiCorsMiddleware` with an upstream default — on the one route in
    // this app whose responses carry the session.
    response.headers.forEach((value, key) => {
      if (isCorsResponseHeader(key)) return;
      res.setHeader(key, value);
    });

    // Send body
    const body = await response.text();

    // Record the outcome AFTER better-auth has answered and BEFORE the
    // response goes out, so the row describes a verdict that has actually
    // been reached. Fire-and-forget and never throws — see
    // lib/audit/auth-relay-audit; a logging failure here must not turn a
    // successful sign-in into a 500 (the catch below would answer one).
    emitAuthRelayEvent({
      path: req.path,
      status: response.status,
      requestBody: req.body,
      responseBody: body,
      audit: auditContext,
    });

    res.send(body);
  } catch (error) {
    // The detail goes to the server log and nowhere else, the same rule the
    // terminal handler follows (@/middleware/error-handler.middleware, whose
    // body constant this is). This relay reaches better-auth, the drizzle
    // adapter and postgres, so `error.message` here is routinely a driver
    // error naming internal hosts, table and column names — and `/api/auth/*`
    // is unauthenticated by definition, so whoever provokes the failure needs
    // no credentials to read whatever came back.
    logger.error("Auth route error:", error);
    res.status(500).json(INTERNAL_ERROR_BODY);
  }
};

export default authApiRelay;
