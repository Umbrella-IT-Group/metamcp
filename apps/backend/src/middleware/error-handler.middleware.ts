import express from "express";

import logger from "@/utils/logger";

/**
 * The gateway's terminal error handler.
 *
 * Redteam re-verification 2026-08-14, live-confirmed against production: a
 * POST of malformed JSON to any non-proxy route —
 * `curl -X POST .../trpc/x -H 'Content-Type: application/json' --data-binary '{bad'`
 * — came back with a full stack trace. `express.json()` rejects the body
 * BEFORE tRPC is ever reached, so neither tRPC errorFormatter (the one in
 * `packages/trpc/src/trpc.ts` or the backend's own) was on that path, and
 * nothing else was: the response was written by Express's built-in final
 * handler, which serialises `err.stack` whenever NODE_ENV is not
 * "production". Nothing in this image or its compose files ever sets
 * NODE_ENV, so that branch was always live. What an unauthenticated caller
 * got was absolute `/app/...` container paths, the pnpm store layout with
 * exact dependency names AND versions (`body-parser`, `raw-body`, …) and
 * node internals — a free dependency inventory to match against advisories,
 * from one request with no credentials.
 *
 * Two failure classes, two constant bodies, no error text ever echoed:
 *
 *  - 4xx (the caller's fault): the STATUS is passed through so a client can
 *    still tell "your JSON is broken" (400) from "your body is too big"
 *    (413), but the BODY is the same two keys either way. A status code
 *    carries no internals; a message can, and body-parser's messages quote
 *    the offending input back.
 *  - anything else: a fixed 500. The full error goes to the server log,
 *    where the operator who needs the stack can read it, and nowhere else.
 *
 * Registered LAST in `index.ts`, after every route mount, because Express
 * dispatches error middleware in registration order — one registered before
 * a router never sees that router's errors.
 */

/** Constant 4xx body. Never includes the error's own message: see above. */
export const BAD_REQUEST_BODY = { error: "bad_request" } as const;

/** Constant 5xx body. The detail lives in the server log, not the response. */
export const INTERNAL_ERROR_BODY = { error: "internal_server_error" } as const;

/**
 * `err.type` values body-parser stamps on a rejected body.
 *
 * Matched in addition to `err.status`, not instead of it: the status is what
 * these errors normally carry, and this set is the belt to that suspenders —
 * a body-parser release that ever ships one of these without an http-errors
 * status would otherwise fall through to the 500 branch, which answers the
 * caller safely but mislabels a malformed request as our fault and buries a
 * routine 400 in the error log.
 */
const MALFORMED_INPUT_TYPES = new Set([
  "entity.parse.failed",
  "entity.verify.failed",
  "entity.too.large",
  "request.aborted",
  "request.size.did.not.match",
  "parameters.too.many",
  "charset.unsupported",
  "encoding.unsupported",
]);

/**
 * The HTTP status an error should be answered with.
 *
 * Exported so the classification can be tested directly, without a socket.
 * Anything not positively recognised as a client error resolves to 500 —
 * the failure direction that reveals nothing.
 */
export function resolveErrorStatus(err: unknown): number {
  const candidate = err as
    | { status?: unknown; statusCode?: unknown; type?: unknown }
    | null
    | undefined;

  const declared =
    typeof candidate?.statusCode === "number"
      ? candidate.statusCode
      : typeof candidate?.status === "number"
        ? candidate.status
        : undefined;

  if (
    declared !== undefined &&
    Number.isInteger(declared) &&
    declared >= 400 &&
    declared <= 599
  ) {
    return declared;
  }

  if (
    typeof candidate?.type === "string" &&
    MALFORMED_INPUT_TYPES.has(candidate.type)
  ) {
    return 400;
  }

  // A bare SyntaxError is what a JSON body fails as. Checked last so a real
  // status always wins over the guess.
  if (err instanceof SyntaxError) return 400;

  return 500;
}

/**
 * MUST keep exactly four declared parameters.
 *
 * Express 5 routes to error middleware purely by arity — `router@2.2.0`
 * `lib/layer.js` runs `handleError` only when `fn.length === 4`, and
 * `handleRequest` SKIPS any layer with `fn.length > 3`. Drop or default the
 * unused parameter and this stops being an error handler at all: it silently
 * becomes a no-op the normal pipeline walks straight past, Express's built-in
 * final handler takes the request back, and the stack-trace leak returns with
 * nothing failing. `error-handler.middleware.test.ts` pins the arity for that
 * reason.
 */
export const errorHandler = (
  err: unknown,
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) => {
  // A stream that already began (the `/mcp-proxy` and `/metamcp` SSE legs
  // write headers immediately) cannot be given a status or a JSON body any
  // more. Hand it back to Express, whose final handler destroys the socket —
  // the only correct answer at that point, and one that writes no body.
  if (res.headersSent) {
    return next(err);
  }

  const status = resolveErrorStatus(err);

  if (status < 500) {
    // Logged at debug: a caller sending broken input is not an incident, and
    // an unauthenticated route that anyone can POST garbage to would let a
    // higher level be used to flood the log.
    logger.debug(
      `Rejected ${req.method} ${req.path} with ${status}:`,
      err instanceof Error ? err.message : String(err),
    );
    return res.status(status).json(BAD_REQUEST_BODY);
  }

  logger.error(`Unhandled error on ${req.method} ${req.path}:`, err);
  return res.status(500).json(INTERNAL_ERROR_BODY);
};
