/**
 * Who opened each admin Inspector session, and which server row it came from.
 *
 * The Inspector routers (routers/mcp-proxy/server.ts and metamcp.ts) keep
 * their sessions in memory, keyed by a session id. A session answers the
 * signed-in user who opened it: it records the better-auth user id
 * (`req.user.id`, which `betterAuthMcpMiddleware` sets) of the request that
 * opened it, and its routes answer only that user. A fresh login of the same
 * account keeps its sessions, because the id is the account's, not the
 * login's or the cookie's.
 *
 * A session opened from a registered row also records the row's uuid. Its
 * transport was built from the row as it was when the session opened (the
 * destination, the stored headers, the bearer or OAuth token, the stdio
 * command), so `mcpServers.update` and `.delete` close the row's sessions
 * when the row changes in a way that matters (trpc/mcp-servers.impl.ts). The
 * close is the gateway's own: it does not ask the upstream server to end its
 * session, since the row may be gone or its address unreachable.
 *
 * A row can change while a connection to it is still opening, after the row
 * was read and before the session exists. Each direct open therefore holds an
 * open token from before its first row lookup until it registers its session
 * or gives up. Closing a row's sessions marks the row on every pending token,
 * and registering refuses a token marked for its own row, or one already
 * released (the request ended first). The check and the registration are one
 * synchronous step, so nothing can land between them.
 *
 * This module imports only the logger and the log-safe error summary, so both
 * routers and the tRPC implementation can use it without an import cycle.
 */
import type express from "express";

import { describeDbError } from "@/lib/db-error-summary";
import logger from "@/utils/logger";

interface InspectorSessionEntry {
  userId: string;
  serverUuid?: string;
  close: () => unknown;
}

const sessions = new Map<string, InspectorSessionEntry>();

/** An open in progress, from before its first row lookup until it ends. */
export interface InspectorOpenToken {
  /** Set when the open ended: it registered, gave up, or its request ended. */
  released: boolean;
  /** Rows whose sessions were closed while this open was pending. */
  readonly changedRows: Set<string>;
}

const pendingOpens = new Set<InspectorOpenToken>();

/** Start an open. Pair every call with finishInspectorOpen. */
export function beginInspectorOpen(): InspectorOpenToken {
  const openToken: InspectorOpenToken = {
    released: false,
    changedRows: new Set(),
  };
  pendingOpens.add(openToken);
  return openToken;
}

/**
 * End an open: after it registered, when it gave up, or when its request
 * ended. A released token can no longer register a session. Safe to call
 * more than once.
 */
export function finishInspectorOpen(openToken: InspectorOpenToken): void {
  openToken.released = true;
  pendingOpens.delete(openToken);
}

/**
 * Whether an open may still register a session for `serverUuid` (its
 * resolved row, if it has one): it is not released, and that row was not
 * changed while it was pending.
 */
export function isInspectorOpenUsable(
  openToken: InspectorOpenToken,
  serverUuid?: string,
): boolean {
  if (openToken.released) return false;
  return serverUuid === undefined || !openToken.changedRows.has(serverUuid);
}

/** How many opens are pending. For tests and diagnostics. */
export function inspectorOpensPending(): number {
  return pendingOpens.size;
}

/** The signed-in user's id, only when it is a non-empty string. */
export function callerUserId(req: express.Request): string | undefined {
  const id = (req as express.Request & { user?: { id?: unknown } }).user?.id;
  return typeof id === "string" && id !== "" ? id : undefined;
}

/**
 * Record that the signed-in user on `req` opened `sessionId`, and the row it
 * was opened from. Returns whether it was registered: never without a user id
 * (the gates ahead of the routers already require one, so that means the
 * chain changed), and never for an open token that was released or whose row
 * changed meanwhile. A caller that gets false must close what it opened and
 * must not hand out the session id.
 */
export function bindInspectorSession(
  sessionId: string,
  req: express.Request,
  close: () => unknown,
  serverUuid?: string,
  openToken?: InspectorOpenToken,
): boolean {
  if (openToken && !isInspectorOpenUsable(openToken, serverUuid)) {
    return false;
  }
  const userId = callerUserId(req);
  if (!userId || typeof sessionId !== "string" || sessionId === "") {
    logger.warn("Inspector session not registered: no signed-in user");
    return false;
  }
  sessions.set(sessionId, { userId, serverUuid, close });
  return true;
}

/**
 * Whether `sessionId` is a registered session opened by the signed-in user on
 * `req`. False for anything else, so a route answers it as an unknown id.
 */
export function inspectorSessionBelongsToCaller(
  sessionId: unknown,
  req: express.Request,
): boolean {
  if (typeof sessionId !== "string") return false;
  const entry = sessions.get(sessionId);
  const userId = callerUserId(req);
  return entry !== undefined && userId !== undefined && entry.userId === userId;
}

/** Forget a session. Each router's cleanup calls it first. */
export function forgetInspectorSession(sessionId: string): void {
  sessions.delete(sessionId);
}

/**
 * How long `closeInspectorSessionsForServer` waits for one session's close.
 *
 * Why a bound: the row mutations await these closes after their write commits
 * and before they reply and invalidate the row's pooled connections. A close
 * that never settles (a stdio child that does not exit, an upstream that
 * does not answer) would otherwise hold both for as long as it hangs. A
 * transport close normally settles well within five seconds. A close still
 * running at the limit is no longer awaited and counts as a failed close; its
 * session was detached before it started, so no request can reach it.
 */
export const INSPECTOR_SESSION_CLOSE_TIMEOUT_MS = 5_000;

/** The rejection of a close that was still running at the limit. */
class InspectorCloseTimedOut extends Error {}

/**
 * Run one close and settle with it, or reject once the limit passes. The
 * `async () => close()` wrapper turns a synchronous throw into a rejection,
 * so a throwing close is isolated like a rejecting one.
 */
function closeWithinLimit(close: () => unknown): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new InspectorCloseTimedOut()),
      INSPECTOR_SESSION_CLOSE_TIMEOUT_MS,
    );
    (async () => close())().then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

/**
 * Close every Inspector session opened from `serverUuid`, and refuse any open
 * of that row still pending. Returns how many sessions it detached, closes
 * that failed or timed out included. Never throws: it runs after a committed
 * write, and a close problem must not turn that write into an error. Each
 * close is awaited for at most INSPECTOR_SESSION_CLOSE_TIMEOUT_MS.
 *
 * The matching entries are detached before any close runs, so a close that
 * re-enters the registry, or an overlapping call, does not run one twice.
 */
export async function closeInspectorSessionsForServer(
  serverUuid: string,
): Promise<number> {
  for (const openToken of pendingOpens) {
    openToken.changedRows.add(serverUuid);
  }

  const closing: Array<() => unknown> = [];
  for (const [sessionId, entry] of sessions) {
    if (entry.serverUuid === serverUuid) {
      sessions.delete(sessionId);
      closing.push(entry.close);
    }
  }

  try {
    // Every close is attempted and allSettled sees each outcome.
    const outcomes = await Promise.allSettled(closing.map(closeWithinLimit));
    for (const outcome of outcomes) {
      if (outcome.status === "rejected") {
        logger.error(
          "Closing an Inspector session failed:",
          outcome.reason instanceof InspectorCloseTimedOut
            ? `no answer within ${INSPECTOR_SESSION_CLOSE_TIMEOUT_MS} ms`
            : describeDbError(outcome.reason),
        );
      }
    }
  } catch {
    // Only the logger can throw here, and there is nowhere left to report it.
  }
  return closing.length;
}
