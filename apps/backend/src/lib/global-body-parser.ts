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
 * FIVE LANES. This middleware runs FIRST in index.ts, so the limit it picks is
 * the one that binds: body-parser marks a request as read (`req._body`) and
 * every later parser no-ops against it, so whichever one runs FIRST sets the
 * ceiling. That is why a per-surface limit has to be chosen here rather than
 * mounted on each router.
 *
 * 1. Raw-stream paths (`/mcp-proxy/`, `/metamcp/`) get NO parser at all: they
 *    are the MCP data plane and hand the socket to a transport that reads it
 *    itself. Parsing here would consume the stream out from under it.
 *
 * 2. OAuth-served paths get no parser HERE so that the OAuth router's own
 *    parser binds instead, at OAUTH_BODY_LIMIT (256kb) rather than 50mb. Before
 *    this branch existed, `/oauth/*` inherited the 50mb below and the router's
 *    own limit was dead code — on `POST /oauth/register`, which takes no
 *    credential and stores what it is given.
 *
 * 3. `/api/auth` gets AUTH_RELAY_BODY_LIMIT (64kb). The relay
 *    (routers/auth-relay) parses this body at whatever ceiling binds first,
 *    BEFORE the sign-in limiter or better-auth runs, so at 50mb an
 *    Access-authenticated caller could force a 50mb JSON parse per request up
 *    to the limiter budget. A sign-in, sign-up or client-registration body is
 *    a few hundred bytes; 64kb is orders of magnitude of headroom over the
 *    real ones and two orders below the old ceiling.
 *
 * 4. `/trpc` gets TRPC_BODY_LIMIT (1mb). The frontend procedures carry modest
 *    JSON, so the same 50mb amplification applied here too; 1mb keeps the
 *    generous headroom the authenticated app needs without the 50mb per-request
 *    parse cost.
 *
 * 5. Everything else gets `express.json` at the generous global limit, which is
 *    what the remaining authenticated surfaces have always run with.
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

/**
 * Body ceiling for the `/api/auth` relay (lane 3). See the header for why 64kb
 * is far above any real sign-in, sign-up or client-registration body.
 */
export const AUTH_RELAY_BODY_LIMIT = "64kb";

/** Body ceiling for `/trpc` (lane 4). See the header. */
export const TRPC_BODY_LIMIT = "1mb";

const globalJson = express.json({ limit: GLOBAL_JSON_BODY_LIMIT });
const authRelayJson = express.json({ limit: AUTH_RELAY_BODY_LIMIT });
const trpcJson = express.json({ limit: TRPC_BODY_LIMIT });

/** Whole-segment prefix test so `/api/authx` does not ride the auth lane. */
function isAuthRelayPath(path: string): boolean {
  return path === "/api/auth" || path.startsWith("/api/auth/");
}

/** Whole-segment prefix test so `/trpcx` does not ride the tRPC lane. */
function isTrpcPath(path: string): boolean {
  return path === "/trpc" || path.startsWith("/trpc/");
}

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

  if (isAuthRelayPath(req.path)) {
    authRelayJson(req, res, next);
    return;
  }

  if (isTrpcPath(req.path)) {
    trpcJson(req, res, next);
    return;
  }

  globalJson(req, res, next);
}
