import express from "express";

import { isOAuthServedPath } from "../routers/oauth/utils";

/**
 * The app-wide request-body policy, as a mountable middleware.
 *
 * WHY THIS IS A MODULE AND NOT SIX LINES IN index.ts, which is where it lived.
 * The behaviour here is pure routing-order, and routing-order is the class of
 * bug that reads correctly in a diff and is wrong on the wire. index.ts calls
 * `app.listen()` at module scope, so no test can import it — which meant the
 * only way to cover this was for a test to hand-copy the branches into a model
 * app, and a hand-copied model passes just as happily after someone deletes
 * the real branch. Extracting it makes the thing under test the thing that
 * runs. Same reason the better-auth relay body lives in routers/auth-relay.
 *
 * THREE LANES, and the two exceptions are exceptions for opposite reasons.
 *
 * 1. Raw-stream paths (`/mcp-proxy/`, `/metamcp/`) get NO parser at all: they
 *    are the MCP data plane and hand the socket to a transport that reads it
 *    itself. Parsing here would consume the stream out from under it.
 *
 * 2. OAuth-served paths get no parser HERE so that the OAuth router's own
 *    parser binds instead, at OAUTH_BODY_LIMIT (256kb) rather than 50mb.
 *    body-parser marks a request as read (`req._body`) and every later parser
 *    no-ops against it, so whichever one runs FIRST sets the ceiling. Before
 *    this branch existed, `/oauth/*` inherited the 50mb below and the router's
 *    own limit was dead code — on `POST /oauth/register`, which takes no
 *    credential and stores what it is given.
 *
 * 3. Everything else gets `express.json` at the generous global limit, which
 *    is what the tRPC and auth surfaces have always run with.
 */

/**
 * Paths whose body must reach a transport unparsed.
 *
 * Trailing slashes are deliberate: these are prefix tests for a mounted
 * sub-app, not the whole-segment test `isOAuthServedPath` performs, and the
 * bare `/metamcp` and `/mcp-proxy` roots serve nothing.
 */
export const RAW_STREAM_PREFIXES = ["/mcp-proxy/", "/metamcp/"] as const;

/**
 * The limit for everything that is not OAuth-served or a raw stream.
 *
 * Unchanged at 50mb from before the OAuth scoping: the point of that change
 * was to stop the anonymous endpoints riding this number, not to squeeze the
 * authenticated surfaces that legitimately need it.
 */
export const GLOBAL_JSON_BODY_LIMIT = "50mb";

const globalJson = express.json({ limit: GLOBAL_JSON_BODY_LIMIT });

export function globalBodyParser(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
): void {
  if (RAW_STREAM_PREFIXES.some((prefix) => req.path.startsWith(prefix))) {
    next();
    return;
  }

  if (isOAuthServedPath(req.path)) {
    // Deliberately unparsed here so the OAuth router's own parser binds at
    // OAUTH_BODY_LIMIT instead. See lane 2 above.
    next();
    return;
  }

  globalJson(req, res, next);
}
