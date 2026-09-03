import type { BaseContext } from "@repo/trpc";
import { initTRPC, TRPCError } from "@trpc/server";
import type { Request, Response } from "express";

import { auth, type Session, type User } from "./auth";
import { auditRequestContext } from "./lib/audit/audit-emitter";
import logger from "./utils/logger";

/**
 * The disabled-account check, reached through a LAZY import.
 *
 * `users.repo` pulls in `db/index`, which throws at module load without
 * DATABASE_URL and constructs a pg Pool. Importing it at the top of this file
 * would make the tRPC instance itself undloadable without a database — and
 * error-formatter.test.ts deliberately imports this module with `../auth`
 * mocked precisely because the instance under test is independent of all
 * that. Deferring the import keeps that true: the database is touched when a
 * REQUEST arrives, not when the router is defined.
 *
 * ESM caches the module after the first await, so this costs one resolution
 * on the first authenticated request and nothing thereafter.
 */
async function isSessionUserDisabled(userId: string): Promise<boolean> {
  const { usersRepository } = await import("./db/repositories/users.repo");
  return usersRepository.isDisabled(userId);
}

/**
 * The admin-plane (control-plane) bearer resolver (migration 0038), reached
 * through the SAME lazy import as `isSessionUserDisabled` and for the same
 * reason: it touches the repositories and thus `db/index`, so importing it at
 * the top of this file would make the tRPC instance un-loadable without a
 * database. error-formatter.test.ts imports this module with `../auth` mocked
 * precisely because the instance is independent of all that; deferring keeps it
 * so. Costs one resolution on the first bearer request and nothing after.
 */
async function resolveAdminPlaneBearer(token: string, req: Request) {
  const { resolveAdminPlaneSession } = await import("./lib/admin-plane-auth");
  return resolveAdminPlaneSession(token, req);
}

// Extend the base context with Express request/response and auth data
export interface Context extends BaseContext {
  req: Request;
  res: Response;
  user?: User;
  session?: Session;
}

// Create context from Express request/response with auth
export const createContext = async ({
  req,
  res,
}: {
  req: Request;
  res: Response;
}): Promise<Context> => {
  let user: User | undefined;
  let session: Session | undefined;

  try {
    // Check if we have cookies in the request
    if (req.headers.cookie) {
      // Create a proper Request object for better-auth
      const sessionUrl = new URL(
        "/api/auth/get-session",
        `http://${req.headers.host}`,
      );

      const headers = new Headers();
      headers.set("cookie", req.headers.cookie);

      const sessionRequest = new Request(sessionUrl.toString(), {
        method: "GET",
        headers,
      });

      const sessionResponse = await auth.handler(sessionRequest);

      if (sessionResponse.ok) {
        const sessionData = (await sessionResponse.json()) as {
          user?: User;
          session?: Session;
        };

        if (sessionData?.user && sessionData?.session) {
          // HALF TWO of `users.disabled` enforcement (migration 0027). The
          // sign-in hook in auth.ts stops a locked account getting a NEW
          // session; this stops the sessions it ALREADY holds.
          //
          // Both halves are required. Sessions in this fork live 30 days
          // (BETTER_AUTH_SESSION_EXPIRES_IN_SECONDS), so an attacker who is
          // disabled while signed in would otherwise keep full access for a
          // month — the disable button would look like it worked and would
          // not have. Re-reading the column per request is what makes the
          // lock take effect on the very next call.
          //
          // Dropping the user/session (rather than throwing) makes the
          // request look UNAUTHENTICATED, so protectedProcedure returns its
          // normal UNAUTHORIZED and the frontend's existing sign-in redirect
          // handles it. Fail-closed: if the lookup itself throws, the outer
          // catch leaves user/session undefined, which is also unauthenticated.
          const disabled = await isSessionUserDisabled(sessionData.user.id);

          if (disabled) {
            logger.warn(
              `Rejected request from disabled account ${sessionData.user.id}`,
            );
          } else {
            user = sessionData.user;
            session = sessionData.session;
          }
        }
      }
    }

    // Admin-plane (control-plane) bearer path (migration 0038), reached ONLY
    // when the cookie block above resolved nothing. COOKIE PRECEDENCE is the
    // point: if a cookie authenticated, this never runs, so the cookie path
    // stays byte-identical (the "cookie path unchanged" test) and a browser
    // carrying a stray Authorization header never changes behaviour. A
    // control-plane API key presented here authenticates AS its owning user;
    // resolveAdminPlaneSession fails closed (returns null) for an unknown key,
    // an inactive key, a data-plane key, a disabled owner, a malformed header,
    // or the kill switch, and the request then stays unauthenticated exactly as
    // the disabled-account branch above leaves it. The resolver is DB-backed, so
    // it is a lazy import (see resolveAdminPlaneBearer) to keep this module
    // loadable without a database.
    if (!user && !session) {
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith("Bearer ")) {
        const token = authHeader.substring(7);
        const resolved = await resolveAdminPlaneBearer(token, req);
        if (resolved) {
          user = resolved.user;
          session = resolved.session;
        }
      }
    }
  } catch (error) {
    // Log error but don't throw - we want to allow unauthenticated requests
    logger.error("Error getting session in tRPC context:", error);
  }

  return {
    req,
    res,
    user,
    session,
    // Flattened request attribution for the RBAC/authn denial emitters in
    // @repo/trpc. That package holds the choke points but cannot type or
    // import the express `req` on this context, so the three fields it needs
    // are threaded explicitly. Built from the fields
    // `middleware/audit-context.middleware` stamped on the request.
    audit: auditRequestContext(req),
  };
};

// Initialize tRPC with extended context.
//
// errorFormatter strips `stack` from every error payload. @trpc/server only
// attaches the stack when its `isDev` flag is on, and `isDev` defaults to
// `process.env.NODE_ENV !== "production"`, which makes stack disclosure a
// property of how the deployment was assembled rather than of this code. The
// image and the compose files set no NODE_ENV themselves, but both compose
// files pass the whole `.env` in through `env_file:` and `example.env` ships
// `NODE_ENV=production` on its first line: a quickstart deployment derived
// from that file has the flag set, one that dropped or edited the line does
// not. On the second, every 4xx/5xx from a tRPC procedure shipped an internal
// stack trace (absolute `/app/...` paths, bundled dependency names and
// versions) to the caller. Stripping it here UNCONDITIONALLY is the design
// point: the payload is the same however the process was started, and it does
// not silently change any other NODE_ENV-conditional behaviour in this
// codebase (redirect-URI validation in routers/oauth/utils.ts reads the same
// variable).
//
// `code`, `httpStatus`, and `path` stay — clients and the frontend error
// handling need them, and none of them disclose internals.
const t = initTRPC.context<Context>().create({
  errorFormatter({ shape }) {
    const { stack: _stack, ...data } = shape.data as typeof shape.data & {
      stack?: string;
    };
    // Mask the message for unexpected server errors too — @trpc/server sets
    // shape.message = error.message unconditionally, and an unexpected throw
    // wrapped as INTERNAL_SERVER_ERROR keeps cause.message, which can carry a
    // raw driver/DB message (internal hostnames, SQL) to an unauthenticated
    // caller through any publicProcedure lacking its own try/catch. Deliberate
    // INTERNAL_SERVER_ERROR throws in this tree already use fixed strings and
    // every user-facing message is FORBIDDEN/NOT_FOUND/UNAUTHORIZED, so no UI
    // copy degrades. Mirrors the same mask in packages/trpc/src/trpc.ts.
    const message =
      data.code === "INTERNAL_SERVER_ERROR"
        ? "Internal server error"
        : shape.message;
    return { ...shape, message, data };
  },
});

// Export router and procedure helpers
export const router = t.router;
export const publicProcedure = t.procedure;

// Create a protected procedure that requires authentication
export const protectedProcedure = t.procedure.use(({ ctx, next }) => {
  if (!ctx.user || !ctx.session) {
    throw new TRPCError({
      code: "UNAUTHORIZED",
      message: "You must be logged in to access this resource",
    });
  }

  return next({
    ctx: {
      ...ctx,
      // Override types to indicate user and session are guaranteed to exist
      user: ctx.user,
      session: ctx.session,
    } as Context & { user: User; session: Session },
  });
});
