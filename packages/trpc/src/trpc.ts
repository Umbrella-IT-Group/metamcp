import { initTRPC, TRPCError } from "@trpc/server";

// Create context interface that can be extended by backend
export interface BaseContext {
  // Auth data that can be added by backend implementations
  // Using generic types so backends can use their own User/Session types
  user?: any;
  session?: any;
}

// Initialize tRPC with base context.
//
// errorFormatter strips `stack` from every error payload. @trpc/server only
// attaches the stack when its `isDev` flag is on, and `isDev` defaults to
// `process.env.NODE_ENV !== "production"` — which is always true in the
// deployed gateway, because nothing in the container image or compose files
// ever sets NODE_ENV. Every 4xx/5xx from a procedure built by this factory
// therefore shipped an internal stack trace (absolute `/app/...` paths,
// bundled dependency names and versions) to the caller.
//
// This mirrors the same formatter on the backend's own `initTRPC` instance
// (apps/backend/src/trpc.ts). BOTH are needed: routers in this package are
// built from `t` here, while the backend builds others from its own
// instance, and an errorFormatter only covers the instance it is passed to.
const t = initTRPC.context<BaseContext>().create({
  errorFormatter({ shape }) {
    const { stack: _stack, ...data } = shape.data as typeof shape.data & {
      stack?: string;
    };
    return { ...shape, data };
  },
});

// Export router and procedure helpers
export const router = t.router;
export const publicProcedure = t.procedure;
export const createTRPCRouter = t.router;
export const baseProcedure = t.procedure;

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
    },
  });
});

// The pure RBAC authorization check that `adminProcedure` runs. Extracted as
// a standalone function so the gate can be unit-tested directly, without
// standing up a tRPC caller. A hard FORBIDDEN throw (not a silently-filtered
// result) is deliberate: administrative mutations — MCP-server / namespace /
// endpoint create-update-delete, all API-key administration, and minting
// 'everyone' (public) keys — must be unreachable to members, and FORBIDDEN is
// the honest signal. `role` comes from the session user, which the backend
// populates from the database per request via better-auth `additionalFields`
// (apps/backend/src/auth.ts) with `input: false`, so the client cannot spoof
// it.
export function requireAdmin(user: { role?: string } | undefined | null): void {
  if (!user || user.role !== "admin") {
    throw new TRPCError({
      code: "FORBIDDEN",
      message: "This action requires an administrator role.",
    });
  }
}

// Admin-only procedure: layers the role gate on top of authentication.
// protectedProcedure runs first (an unauthenticated caller gets UNAUTHORIZED
// before the role is ever inspected), then requireAdmin rejects any
// authenticated non-admin with FORBIDDEN.
export const adminProcedure = protectedProcedure.use(({ ctx, next }) => {
  requireAdmin(ctx.user);
  return next({ ctx });
});
