import express from "express";

import logger from "@/utils/logger";

import { BAD_REQUEST_BODY } from "../middleware/error-handler.middleware";
import { isOAuthServedPath } from "../routers/oauth/utils";
import { MCP_REQUEST_BODY_LIMIT_BYTES } from "./metamcp/mcp-request-body-limit";

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
 * TWO MIDDLEWARES, both mounted in index.ts ahead of every router.
 *
 * `declaredLengthGuard` runs first, on every path and method. A request whose
 * declared Content-Length is over MCP_REQUEST_BODY_LIMIT_BYTES (10 MiB) is
 * answered 413 from its headers, without reading the body. That number is the
 * largest body the frontend forwards: every request reaches this process
 * through a Next.js rewrite, which passes on at most that many bytes of a body
 * and keeps the original Content-Length (lib/metamcp/mcp-request-body-limit).
 * A request declaring more cannot be served in full on any lane, so refusing
 * it at the headers changes no request that can succeed, and it covers every
 * named parser below and every router's own parser at once.
 *
 * `globalBodyParser` then picks the lane. It is the FIRST body parser, so the
 * limit it picks is the one that binds: body-parser marks a request as read
 * (`req._body`) and every later parser no-ops against it, so whichever one
 * runs FIRST sets the ceiling. That is why a per-surface limit has to be
 * chosen here rather than mounted on each router. Five lanes:
 *
 * 1. Raw-stream paths (`/mcp-proxy/`, `/metamcp/`) get NO parser at all: they
 *    are the MCP data plane and hand the socket to a transport that reads it
 *    itself. Parsing here would consume the stream out from under it.
 *
 * 2. OAuth-served paths get no parser HERE so that the OAuth router's own
 *    parser binds instead, at OAUTH_BODY_LIMIT (256kb). Before this branch
 *    existed, `/oauth/*` inherited the default lane, then 50mb, and the
 *    router's own limit was dead code — on `POST /oauth/register`, which takes
 *    no credential and stores what it is given.
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
 * 5. Everything else, the default lane, gets `express.json` at
 *    DEFAULT_JSON_BODY_LIMIT_BYTES (64 KiB). What is mounted there is
 *    `/health`, `/health/*`, the `/m365/*` enrollment routes and unrouted
 *    paths: GET handlers, plus `POST /m365/disconnect`, which reads the
 *    session and no body field. No route on this lane takes a large body, so
 *    it carries the auth relay's ceiling rather than a generous one.
 *
 * WHY A DECLARED-LENGTH CHECK AND NOT ONLY A LIMIT. body-parser 2.x (through
 * raw-body) notices an oversized Content-Length before buffering anything, but
 * it then reads the rest of the request and only passes the 413 on once the
 * request has ended (`read.js`, the `dump` on error). So a parser limit alone
 * answers only after the whole declared body has arrived. The guard above
 * and the default lane's own check answer from the headers instead, and close
 * the connection after the response (see `refuseDeclaredBody`). Requests with
 * no Content-Length (chunked) have no declared length to check and still go
 * through the bounded parser.
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
 * Body ceiling for the default lane (lane 5), in bytes. Applied twice: to the
 * declared Content-Length before parsing (wire bytes, so before any
 * decompression) and as the parser's own limit (decoded bytes). See the header
 * for what the lane serves.
 */
export const DEFAULT_JSON_BODY_LIMIT_BYTES = 64 * 1024;

/**
 * The media type the default lane parses. Shared by the parser and its
 * declared-length check, so the check refuses only what the parser would read.
 */
const DEFAULT_JSON_TYPE = "application/json";

/**
 * Body ceiling for the `/api/auth` relay (lane 3). See the header for why 64kb
 * is far above any real sign-in, sign-up or client-registration body.
 */
export const AUTH_RELAY_BODY_LIMIT = "64kb";

/** Body ceiling for `/trpc` (lane 4). See the header. */
export const TRPC_BODY_LIMIT = "1mb";

const defaultJson = express.json({
  limit: DEFAULT_JSON_BODY_LIMIT_BYTES,
  type: DEFAULT_JSON_TYPE,
});
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

/** The declared body length, or NaN when there is no Content-Length. */
function declaredLength(req: express.Request): number {
  return Number(req.headers["content-length"]);
}

/**
 * Answer 413 without reading the body, and close the connection after it.
 *
 * The body is the terminal error handler's constant 4xx body, so this refusal
 * reads the same as a parser's 413. `Connection: close` makes Node end the
 * socket once the response has been written, and never before it flushes; the
 * unread remainder of the declared body is then never taken for the start of a
 * next request, and the connection is not reused.
 */
function refuseDeclaredBody(
  req: express.Request,
  res: express.Response,
  limit: number,
): void {
  // Debug, as the terminal handler logs its 4xx answers: a caller sending an
  // oversized request is routine and must not be able to flood the log.
  logger.debug(
    `Refused ${req.method} ${req.path} declaring ${declaredLength(req)} body bytes, over the ${limit}-byte limit.`,
  );
  res.status(413).set("Connection", "close").json(BAD_REQUEST_BODY);
}

/**
 * Answer any request whose declared body is larger than the frontend forwards
 * with 413, on every path and method. Mounted in index.ts before
 * `globalBodyParser` and every router; see the header.
 *
 * The same comparison as the MCP routes' `refuseDeclaredOversize`
 * (`Number(Content-Length) > MCP_REQUEST_BODY_LIMIT_BYTES`), so an absent or
 * non-numeric header passes through. Because this runs first, it is the one
 * that answers a declared oversize on those routes too.
 */
export function declaredLengthGuard(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
): void {
  if (declaredLength(req) > MCP_REQUEST_BODY_LIMIT_BYTES) {
    refuseDeclaredBody(req, res, MCP_REQUEST_BODY_LIMIT_BYTES);
    return;
  }
  next();
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

  // The default lane. `req.is` is the same media-type match the parser makes
  // (type-is against DEFAULT_JSON_TYPE, false or null when there is no body),
  // so a request the parser would skip is left alone here as well.
  if (
    req.is(DEFAULT_JSON_TYPE) &&
    declaredLength(req) > DEFAULT_JSON_BODY_LIMIT_BYTES
  ) {
    refuseDeclaredBody(req, res, DEFAULT_JSON_BODY_LIMIT_BYTES);
    return;
  }

  defaultJson(req, res, next);
}
