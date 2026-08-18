import { initTRPC, TRPCError } from "@trpc/server";

/**
 * Per-request attribution the backend threads in from Express, so the two
 * denial emitters below can say WHERE a refused attempt came from.
 *
 * This package cannot reach the express `req` (it is consumed by the frontend
 * too and must stay free of node/DB imports), and the tRPC context it is
 * handed at runtime is the backend's `Context`, which does carry `req` — but
 * only in the backend's own type. Threading the three flat fields is the
 * minimum that makes an audit row useful without dragging express types into
 * this package. Populated in `apps/backend/src/trpc.ts` `createContext`.
 */
export interface AuditRequestContext {
  actor_ip?: string | null;
  actor_user_agent?: string | null;
  request_id?: string | null;
}

// Create context interface that can be extended by backend
export interface BaseContext {
  // Auth data that can be added by backend implementations
  // Using generic types so backends can use their own User/Session types
  user?: any;
  session?: any;
  audit?: AuditRequestContext;
}

/**
 * A denied authentication or authorization attempt at the tRPC boundary.
 *
 * `path` is the procedure the caller reached for — the difference between
 * "a member's browser polled a page it cannot see" and "someone walked the
 * admin mutation surface" is entirely in that field.
 */
export interface TrpcDenialEvent {
  action: "rbac.denied" | "authn.denied";
  actor_type: "user" | "anonymous";
  actor_id: string | null;
  actor_label: string | null;
  path: string;
  /** tRPC operation type — `query` / `mutation` / `subscription`. */
  type: string;
  http_status: number;
  audit?: AuditRequestContext;
}

/**
 * `void | Promise<void>` is deliberate, not permissive.
 *
 * A plain `=> void` return type would NOT keep an async sink out — TypeScript
 * happily assigns `() => Promise<void>` to `() => void` (return-type
 * bivariance for void). So the type could never have been the guard, and
 * pretending it was is how an async sink gets registered by a future lane
 * without anyone noticing. Declaring the async case makes it visible AND
 * makes `emitDenial`'s rejection handling obviously load-bearing rather than
 * defensive noise.
 */
export type TrpcAuditSink = (event: TrpcDenialEvent) => void | Promise<void>;

let auditSink: TrpcAuditSink | null = null;

/**
 * Register the durable audit writer. Called once by the backend
 * (`apps/backend/src/routers/trpc.ts`); left null everywhere else, so this
 * package keeps booting in the frontend and in unit tests with no database
 * anywhere in the graph.
 */
export function setTrpcAuditSink(sink: TrpcAuditSink | null): void {
  auditSink = sink;
}

/**
 * Emit a denial, and NEVER let that emission affect the request.
 *
 * The two call sites are the RBAC choke point for every admin-gated mutation
 * in the product and the authentication gate in front of it. A failure
 * escaping here would not lose an audit row — it would replace a clean
 * FORBIDDEN or UNAUTHORIZED with a 500 on every denied call, and (worse) a
 * sink that failed on the SUCCESS path would break the product outright.
 *
 * THREE failure modes are swallowed, and all three are reachable:
 *
 *  1. `build()` throwing. The event is constructed from `ctx.user` and
 *     `ctx.audit`, which are typed `any`/optional — a property access on a
 *     hostile or exotic object can throw. Building INSIDE the guard is why
 *     this takes a thunk instead of a finished event: with the construction
 *     outside, a throwing getter on `ctx.user` would turn the rethrown
 *     FORBIDDEN into an INTERNAL_SERVER_ERROR.
 *  2. The sink throwing synchronously.
 *  3. The sink REJECTING. `TrpcAuditSink` allows `Promise<void>` (and even a
 *     `=> void` signature could not have excluded it — see the type). An
 *     unhandled rejection is process death under Node's default
 *     `--unhandled-rejections=throw`, i.e. the entire gateway, not one
 *     request. `Promise.resolve(...)` normalises the sync and async cases so
 *     one `.catch` covers both.
 *
 * `apps/backend/src/trpc/rbac-denial-audit.test.ts` registers a throwing sink
 * and a rejecting sink and asserts the caller still gets its normal denial.
 */
function emitDenial(build: () => TrpcDenialEvent): void {
  try {
    const event = build();
    void Promise.resolve(auditSink?.(event)).catch(() => {
      // Swallowed by design — see above.
    });
  } catch {
    // Swallowed by design — see above.
  }
}

/** Read an id/email off the loosely-typed context user without throwing. */
function actorFields(user: unknown): {
  id: string | null;
  label: string | null;
} {
  const candidate = user as
    | { id?: unknown; email?: unknown }
    | null
    | undefined;
  return {
    id: typeof candidate?.id === "string" ? candidate.id : null,
    label: typeof candidate?.email === "string" ? candidate.email : null,
  };
}

/**
 * The five envelope fields an audit row needs to say WHO did something and
 * from WHERE, flattened out of the tRPC context.
 *
 * Exists because the SUCCESS-path emitters live in the backend's `*.impl.ts`
 * files, which are handed `input` (and sometimes `ctx.user.id`) and nothing
 * else — the routers in this package are the only layer that holds both the
 * session user and the request attribution Express stamped on. Threading one
 * flat object is the same idiom the routers already use for `ctx.user.id`,
 * and it keeps `audit_log`'s actor columns identical whether the row came
 * from a denial hook here or from a mutation over there.
 */
export interface AuditActor {
  actor_id: string | null;
  actor_label: string | null;
  actor_ip: string | null;
  actor_user_agent: string | null;
  request_id: string | null;
}

/**
 * Build the actor bundle a mutation's audit row will carry.
 *
 * NEVER THROWS, and that is the entire reason it is a function rather than an
 * object literal at each call site. It is evaluated as an ARGUMENT to the
 * implementation call, i.e. strictly before the mutation runs, so a throwing
 * property read on `ctx.user` (typed `any`, reached from JSON) would abort the
 * write itself — the audit path deciding whether an admin's toggle takes
 * effect. Degrading to an all-null actor loses attribution on one row; the
 * alternative loses the operation.
 */
export function auditActor(ctx: BaseContext): AuditActor {
  try {
    const actor = actorFields(ctx?.user);
    return {
      actor_id: actor.id,
      actor_label: actor.label,
      actor_ip: ctx?.audit?.actor_ip ?? null,
      actor_user_agent: ctx?.audit?.actor_user_agent ?? null,
      request_id: ctx?.audit?.request_id ?? null,
    };
  } catch {
    return {
      actor_id: null,
      actor_label: null,
      actor_ip: null,
      actor_user_agent: null,
      request_id: null,
    };
  }
}

// Initialize tRPC with base context.
//
// errorFormatter strips `stack` from every error payload. @trpc/server only
// attaches the stack when its `isDev` flag is on, and `isDev` defaults to
// `process.env.NODE_ENV !== "production"`, so whether a stack ships is a
// property of the deployment rather than of this code. The image and the
// compose files set no NODE_ENV themselves, but both compose files pass the
// whole `.env` in through `env_file:` and `example.env` ships
// `NODE_ENV=production` on its first line, so the flag is set on a quickstart
// deployment derived from that file and unset on one that dropped the line.
// On the second, every 4xx/5xx from a procedure built by this factory shipped
// an internal stack trace (absolute `/app/...` paths, bundled dependency
// names and versions) to the caller. Stripping it here is unconditional for
// that reason: the payload does not depend on how the process was started.
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
    // Mask the message for unexpected server errors too. @trpc/server sets
    // shape.message = error.message unconditionally, and getTRPCErrorFromUnknown
    // preserves cause.message when wrapping an unexpected throw as
    // INTERNAL_SERVER_ERROR — so a raw driver/DB message (internal hostnames,
    // SQL, table names) can reach an unauthenticated caller through any
    // publicProcedure that lacks its own try/catch (e.g. the config router).
    // Safe: every deliberate INTERNAL_SERVER_ERROR in this tree already throws a
    // fixed string, and all user-facing messages are FORBIDDEN/NOT_FOUND/
    // UNAUTHORIZED, so no UI copy degrades. `code`/`httpStatus`/`path` stay.
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
export const createTRPCRouter = t.router;
export const baseProcedure = t.procedure;

// Create a protected procedure that requires authentication
export const protectedProcedure = t.procedure.use(
  ({ ctx, next, path, type }) => {
    if (!ctx.user || !ctx.session) {
      // Every unauthenticated tRPC attempt in the product funnels through this
      // one branch, so one emit here covers the whole surface. Emitted BEFORE
      // the throw, and by a helper that cannot throw, so the caller still gets
      // its normal UNAUTHORIZED whatever the audit sink does. The event is
      // built inside the thunk so even reading `ctx.audit` happens under the
      // guard.
      emitDenial(() => ({
        action: "authn.denied",
        actor_type: "anonymous",
        actor_id: null,
        actor_label: null,
        path,
        type,
        http_status: 401,
        audit: ctx.audit,
      }));
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
  },
);

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
export const adminProcedure = protectedProcedure.use(
  ({ ctx, next, path, type }) => {
    try {
      requireAdmin(ctx.user);
    } catch (error) {
      // An authenticated non-admin reaching for an admin mutation is an
      // attempted privilege escalation, and until this existed it was thrown
      // and forgotten — no row, no counter, nothing to alert on. Caught rather
      // than emitted inside `requireAdmin` so that function stays a pure,
      // directly unit-testable predicate (admin-procedure.test.ts calls it with
      // no context at all), and rethrown untouched so the FORBIDDEN the caller
      // sees is byte-identical to before.
      //
      // `actorFields(ctx.user)` is evaluated INSIDE the thunk. `ctx.user` is
      // typed `any` and reaches here from JSON, but a property read on an
      // exotic object can throw, and outside the thunk that throw would
      // replace this rethrown FORBIDDEN with an INTERNAL_SERVER_ERROR — the
      // audit path silently changing the security answer, which is the one
      // thing it must never do.
      emitDenial(() => {
        const actor = actorFields(ctx.user);
        return {
          action: "rbac.denied",
          actor_type: "user",
          actor_id: actor.id,
          actor_label: actor.label,
          path,
          type,
          http_status: 403,
          audit: ctx.audit,
        };
      });
      throw error;
    }
    return next({ ctx });
  },
);
