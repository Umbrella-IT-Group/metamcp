import { SetConfigRequest, SetConfigRequestSchema } from "@repo/zod-types";
import { z } from "zod";

import {
  adminProcedure,
  type AuditActor,
  auditActor,
  protectedProcedure,
  publicProcedure,
  router,
} from "../../trpc";

export const createConfigRouter = (implementations: {
  getSignupDisabled: () => Promise<boolean>;
  setSignupDisabled: (
    input: {
      disabled: boolean;
    },
    actor: AuditActor,
  ) => Promise<{ success: boolean }>;
  getSsoSignupDisabled: () => Promise<boolean>;
  setSsoSignupDisabled: (
    input: {
      disabled: boolean;
    },
    actor: AuditActor,
  ) => Promise<{ success: boolean }>;
  getBasicAuthDisabled: () => Promise<boolean>;
  setBasicAuthDisabled: (
    input: {
      disabled: boolean;
    },
    actor: AuditActor,
  ) => Promise<{ success: boolean }>;
  getMcpResetTimeoutOnProgress: () => Promise<boolean>;
  setMcpResetTimeoutOnProgress: (input: {
    enabled: boolean;
  }) => Promise<{ success: boolean }>;
  getMcpTimeout: () => Promise<number>;
  setMcpTimeout: (input: { timeout: number }) => Promise<{ success: boolean }>;
  getMcpMaxTotalTimeout: () => Promise<number>;
  setMcpMaxTotalTimeout: (input: {
    timeout: number;
  }) => Promise<{ success: boolean }>;
  getMcpMaxAttempts: () => Promise<number>;
  setMcpMaxAttempts: (input: {
    maxAttempts: number;
  }) => Promise<{ success: boolean }>;
  getSessionLifetime: () => Promise<number | null>;
  setSessionLifetime: (
    input: {
      lifetime?: number | null;
    },
    actor: AuditActor,
  ) => Promise<{ success: boolean }>;
  getAllConfigs: () => Promise<
    Array<{ id: string; value: string; description?: string | null }>
  >;
  setConfig: (
    input: SetConfigRequest,
    actor: AuditActor,
  ) => Promise<{ success: boolean }>;
  getAuthProviders: () => Promise<
    Array<{ id: string; name: string; enabled: boolean }>
  >;
}) =>
  router({
    // Deliberately public, and the only reads in this router that stay so.
    //
    // security review re-verification 2026-08-14 flagged the whole `publicProcedure`
    // read cluster here: an anonymous caller could enumerate the gateway's
    // operational configuration from `/trpc`. The MCP timeout/attempt/session
    // getters had no reason to be reachable that way and are now
    // `protectedProcedure` (see the block above `getMcpResetTimeoutOnProgress`).
    // These THREE stay public because the SIGN-IN PAGES read them before a
    // session can exist, so gating them would leave a login screen that cannot
    // render itself:
    //   getSignupDisabled     — login/page.tsx:37, register/page.tsx:46,99,121
    //   getBasicAuthDisabled  — login/page.tsx:52
    //   getAuthProviders      — login/page.tsx:67
    // Membership here is decided by an actual pre-auth CALL SITE, not by
    // topic: `getSsoSignupDisabled` reads like a fourth sibling — same auth
    // posture, adjacent toggle in the same settings card — and was public for
    // exactly that reason, but no sign-in page has ever called it. It is now
    // `protectedProcedure` too. Adding a getter to this cluster means finding
    // it in a page that renders without a session, not that it sounds like it
    // belongs.
    // None of the three describes a user, a server, an endpoint or a timing
    // window; each is one boolean or the enabled-provider list the login form
    // has to draw buttons for. Every paired WRITE is `adminProcedure`.
    getSignupDisabled: publicProcedure.query(async () => {
      return await implementations.getSignupDisabled();
    }),

    // Admin only: global gateway config write. Members have no business
    // flipping auth-posture toggles (signup/SSO/basic-auth) or gateway
    // behavior (session lifetime, MCP timeouts/attempts) — the entire config
    // write surface is admin-gated, reads stay open per their existing
    // access level.
    setSignupDisabled: adminProcedure
      .input(z.object({ disabled: z.boolean() }))
      .mutation(async ({ input, ctx }) => {
        return await implementations.setSignupDisabled(input, auditActor(ctx));
      }),

    // Authenticated read. Grouped with the pre-auth cluster above until
    // 2026-08-14, when a call-site sweep of `apps/frontend` found its only
    // reader is the settings page (`settings/page.tsx:62`), inside the app
    // shell `middleware.ts` admits only with a session — the sign-in pages
    // read `getSignupDisabled` and never this. Public by association is not
    // a reason, so it moved to `protectedProcedure` with the operational
    // getters below. The paired WRITE stays `adminProcedure`.
    //
    // If a future register page needs to hide the SSO button pre-session,
    // this is the getter to move back — deliberately, with that call site as
    // the evidence.
    getSsoSignupDisabled: protectedProcedure.query(async () => {
      return await implementations.getSsoSignupDisabled();
    }),

    setSsoSignupDisabled: adminProcedure
      .input(z.object({ disabled: z.boolean() }))
      .mutation(async ({ input, ctx }) => {
        return await implementations.setSsoSignupDisabled(
          input,
          auditActor(ctx),
        );
      }),

    // Deliberately public: the login page reads this BEFORE any session
    // exists, to decide whether to render the email/password form at all
    // (apps/frontend/app/[locale]/login/page.tsx). Gating it would leave
    // users on a login screen that cannot tell them basic auth is off. The
    // value is a single boolean about the gateway's own auth posture and
    // discloses nothing about users, servers or endpoints. The paired
    // WRITE (setBasicAuthDisabled, below) is admin-only.
    getBasicAuthDisabled: publicProcedure.query(async () => {
      return await implementations.getBasicAuthDisabled();
    }),

    setBasicAuthDisabled: adminProcedure
      .input(z.object({ disabled: z.boolean() }))
      .mutation(async ({ input, ctx }) => {
        return await implementations.setBasicAuthDisabled(
          input,
          auditActor(ctx),
        );
      }),

    // Authenticated read (security review re-verification 2026-08-14). This and the
    // four getters below were `publicProcedure`, so an anonymous caller could
    // read the gateway's MCP retry/timeout budget and session lifetime from
    // `/trpc` with no credentials. Individually each is a number; together
    // they are the timing model of the service — how long a stalled upstream
    // is held, how many reconnects are attempted before the breaker trips,
    // and how long a stolen session cookie stays good — which is exactly the
    // information that tunes a resource-exhaustion attempt against the
    // backend pool (the failure mode of the 2026-07-14 pool-cap outage)
    // rather than merely attempting one.
    //
    // Safe to gate because nothing pre-auth reads them. Every frontend call
    // site is inside the authenticated app shell, which `middleware.ts`
    // admits only with a session (its `publicRoutes` are /login, /register,
    // /cors-error and /, and / is a client-side redirect to /mcp-servers):
    //   getMcpResetTimeoutOnProgress — settings/page.tsx:74, useConnection.ts:113
    //   getMcpTimeout                — settings/page.tsx:80, useConnection.ts:104
    //   getMcpMaxTotalTimeout        — settings/page.tsx:86, useConnection.ts:109
    //   getMcpMaxAttempts            — settings/page.tsx:92
    //   getSessionLifetime           — settings/page.tsx:98
    // `useConnection` is imported only by mcp-inspector, mcp-servers/[uuid]
    // and namespaces/[uuid], all under the same gate, and reads each value
    // through a `?? default` fallback.
    //
    // The MCP RUNTIME is unaffected: the backend never goes through tRPC for
    // these. `metamcp-proxy.ts`, `mcp-server-pool.ts`, `metamcp-server-pool.ts`,
    // `server-error-tracker.ts`, `session-lifetime-manager.ts` and the OpenAPI
    // handlers all call `configService.*` directly.
    getMcpResetTimeoutOnProgress: protectedProcedure.query(async () => {
      return await implementations.getMcpResetTimeoutOnProgress();
    }),

    setMcpResetTimeoutOnProgress: adminProcedure
      .input(z.object({ enabled: z.boolean() }))
      .mutation(async ({ input }) => {
        return await implementations.setMcpResetTimeoutOnProgress(input);
      }),

    // Authenticated read — see the block above getMcpResetTimeoutOnProgress.
    getMcpTimeout: protectedProcedure.query(async () => {
      return await implementations.getMcpTimeout();
    }),

    setMcpTimeout: adminProcedure
      .input(z.object({ timeout: z.number().min(1000).max(86400000) }))
      .mutation(async ({ input }) => {
        return await implementations.setMcpTimeout(input);
      }),

    // Authenticated read — see the block above getMcpResetTimeoutOnProgress.
    getMcpMaxTotalTimeout: protectedProcedure.query(async () => {
      return await implementations.getMcpMaxTotalTimeout();
    }),

    setMcpMaxTotalTimeout: adminProcedure
      .input(z.object({ timeout: z.number().min(1000).max(86400000) }))
      .mutation(async ({ input }) => {
        return await implementations.setMcpMaxTotalTimeout(input);
      }),

    // Authenticated read — see the block above getMcpResetTimeoutOnProgress.
    getMcpMaxAttempts: protectedProcedure.query(async () => {
      return await implementations.getMcpMaxAttempts();
    }),

    setMcpMaxAttempts: adminProcedure
      .input(z.object({ maxAttempts: z.number().min(1).max(10) }))
      .mutation(async ({ input }) => {
        return await implementations.setMcpMaxAttempts(input);
      }),

    // Authenticated read — see the block above getMcpResetTimeoutOnProgress.
    // The most sensitive of the five: it is how long a stolen session cookie
    // remains valid, and this fork runs 30-day sessions.
    getSessionLifetime: protectedProcedure.query(async () => {
      return await implementations.getSessionLifetime();
    }),

    setSessionLifetime: adminProcedure
      .input(
        z.object({
          lifetime: z.number().min(300000).max(86400000).nullable().optional(),
        }),
      )
      .mutation(async ({ input, ctx }) => {
        return await implementations.setSessionLifetime(input, auditActor(ctx));
      }),

    // Admin only. Unlike the individually-gated getters above, this returns
    // the ENTIRE config table in one unfiltered read, and every paired write
    // in this router is `adminProcedure`. A call-site sweep of `apps/frontend`
    // found no consumer at all — the settings page reads each value through
    // its named getter, never this — so gating it removes a member-level
    // whole-table read with no UI impact. Left on `protectedProcedure`, a
    // future sensitive config key would leak to every member automatically
    // the moment it was added.
    getAllConfigs: adminProcedure.query(async () => {
      return await implementations.getAllConfigs();
    }),

    setConfig: adminProcedure
      .input(SetConfigRequestSchema)
      .mutation(async ({ input, ctx }) => {
        return await implementations.setConfig(input, auditActor(ctx));
      }),

    getAuthProviders: publicProcedure.query(async () => {
      return await implementations.getAuthProviders();
    }),
  });
