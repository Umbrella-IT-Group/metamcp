import type { BaseContext } from "@repo/trpc";
import { initTRPC, TRPCError } from "@trpc/server";
import type { Request, Response } from "express";

import { auth, type Session, type User } from "./auth";
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
  } catch (error) {
    // Log error but don't throw - we want to allow unauthenticated requests
    logger.error("Error getting session in tRPC context:", error);
  }

  return {
    req,
    res,
    user,
    session,
  };
};

// Initialize tRPC with extended context.
//
// errorFormatter strips `stack` from every error payload. @trpc/server only
// attaches the stack when its `isDev` flag is on, and `isDev` defaults to
// `process.env.NODE_ENV !== "production"` — which is always true here,
// because nothing in the container image or compose files ever sets
// NODE_ENV. The result was that every 4xx/5xx from a tRPC procedure shipped
// an internal stack trace (absolute `/app/...` paths, bundled dependency
// names and versions) to the caller. Stripping it here rather than setting
// NODE_ENV is deliberate: it holds regardless of how the process is started,
// and it does not silently change any other NODE_ENV-conditional behaviour
// in this codebase (redirect-URI validation in routers/oauth/utils.ts reads
// the same variable).
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
