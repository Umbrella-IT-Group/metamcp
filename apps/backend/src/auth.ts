import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { APIError } from "better-auth/api";
import { genericOAuth, GenericOAuthConfig } from "better-auth/plugins";

import { db } from "./db/index";
// Imported from the module directly, not the repositories barrel: the barrel
// pulls in every repository (and their transitive imports) into the auth
// module graph, which is loaded before almost everything else.
import { usersRepository } from "./db/repositories/users.repo";
import * as schema from "./db/schema";
import {
  emitSessionCreated,
  emitSessionRevoked,
  emitSignupCreated,
  emitSignupDenied,
} from "./lib/audit/auth-hook-audit";
import { isBootstrapSignupAllowed } from "./lib/bootstrap-signup-override";
import { configService } from "./lib/config.service";
import logger from "./utils/logger";

// Provide default values for development
if (!process.env.BETTER_AUTH_SECRET) {
  throw new Error("BETTER_AUTH_SECRET environment variable is required");
}
if (!process.env.APP_URL) {
  throw new Error("APP_URL environment variable is required");
}

const BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET;
const BETTER_AUTH_URL = process.env.APP_URL;

// Helper function to create basic auth middleware
const createBasicAuthCheckMiddleware = () => {
  return async (request: unknown) => {
    const isBasicAuthDisabled = await configService.isBasicAuthDisabled();
    if (isBasicAuthDisabled) {
      throw new Error(
        "Basic email/password authentication is currently disabled. Please use SSO/OIDC authentication instead.",
      );
    }
    return { request };
  };
};

// OIDC Provider configuration - optional, only if environment variables are provided
const oidcProviders: GenericOAuthConfig[] = [];

// Add OIDC provider if configured
if (process.env.OIDC_CLIENT_ID && process.env.OIDC_CLIENT_SECRET) {
  const oidcConfig: GenericOAuthConfig = {
    providerId: process.env.OIDC_PROVIDER_ID || "oidc",
    clientId: process.env.OIDC_CLIENT_ID,
    clientSecret: process.env.OIDC_CLIENT_SECRET,
    scopes: (process.env.OIDC_SCOPES || "openid email profile").split(" "),
    pkce: process.env.OIDC_PKCE !== "false", // Enable PKCE by default for security
    discoveryUrl: process.env.OIDC_DISCOVERY_URL,
    authorizationUrl: process.env.OIDC_AUTHORIZATION_URL, //this is required due to a bug in better-auth: https://github.com/better-auth/better-auth/issues/3278
  };

  oidcProviders.push(oidcConfig);
  logger.info(`✓ OIDC Provider configured: ${oidcConfig.providerId}`);
}

// Default trusted origins for development
const DEFAULT_TRUSTED_ORIGINS = [
  "http://localhost",
  "http://localhost:3000",
  "http://localhost:12008",
  "http://127.0.0.1",
  "http://127.0.0.1:12008",
  "http://127.0.0.1:3000",
  "http://0.0.0.0",
  "http://0.0.0.0:3000",
  "http://0.0.0.0:12008",
];

// Parse extra trusted origins from environment variable (comma-separated)
const extraTrustedOrigins = process.env.EXTRA_TRUSTED_ORIGINS
  ? process.env.EXTRA_TRUSTED_ORIGINS.split(",")
      .map((origin: string) => origin.trim())
      .filter(Boolean)
  : [];

const trustedOrigins = [...DEFAULT_TRUSTED_ORIGINS, ...extraTrustedOrigins];

export const auth = betterAuth({
  secret: BETTER_AUTH_SECRET,
  baseURL: BETTER_AUTH_URL,
  database: drizzleAdapter(db, {
    provider: "pg",
    schema: {
      user: schema.usersTable,
      session: schema.sessionsTable,
      account: schema.accountsTable,
      verification: schema.verificationsTable,
    },
  }),
  trustedOrigins,
  // OFF EXPLICITLY, because it is currently off only by accident, and because
  // turning it on in its default shape would be worse than leaving it off.
  //
  // better-auth defaults this to `enabled ?? isProduction`, so today the
  // limiter is disabled purely because NODE_ENV is unset in the container. A
  // deployment that picks up `NODE_ENV=production`, which `example.env` ships
  // on its first line, would enable it as a side effect of an unrelated
  // environment edit.
  //
  // WHY THAT WOULD BE A SELF-DoS. The key is `${ip}|${path}`, and better-auth
  // resolves that ip from `x-forwarded-for` ONLY (its default
  // `ipAddressHeaders`), never from `CF-Connecting-IP`. With no
  // `trustedProxies` configured it accepts the header only when it carries
  // exactly one entry, and behind this deployment's
  // `client -> Cloudflare -> cloudflared -> Next.js rewrite -> express` chain
  // it carries more, so the address resolves to null and the limiter falls
  // back to the literal key `no-trusted-ip`: ONE shared bucket per path for
  // every caller. It logs a warning once when that happens, so this is loud
  // rather than silent, but the bucket is the problem either way. And the
  // default rules are tighter than the headline 100-per-10s: better-auth
  // applies a special rule of window 10s / max 3 to `/sign-in*`, `/sign-up*`,
  // `/change-password*` and `/change-email*`. Three sign-in attempts per ten
  // seconds, shared globally, means any single caller can lock everyone else
  // out of signing in. An availability control an attacker can aim at other
  // users is inverted, which is the same defect this fork's own failed-auth
  // limiter had when it keyed on `req.ip`.
  //
  // WHAT THIS PIN DOES NOT DO. It prevents that inversion; it does not by
  // itself put a limiter on `/api/auth`. That surface is served by
  // `routers/auth-relay.ts` calling `auth.handler` directly, so a limiter has
  // to be mounted ahead of the relay — which is what
  // `middleware/auth-signin-rate-limit.middleware` now is, keyed per caller on
  // `CF-Connecting-IP` via `lib/client-ip` the way the fork's other limiters
  // already are (`lib/auth-rate-limiter` on the lookup-endpoint, token and
  // api-key-oauth paths, `routers/oauth/utils` on `/oauth/*`,
  // `middleware/trpc-rate-limit.middleware` on `/trpc`). It covers the
  // credential sign-in POST and deliberately nothing else on this surface.
  //
  // That is the remedy rather than enabling this one, and the order matters:
  // enabling better-auth's would first need
  // `advanced.ipAddress.ipAddressHeaders` / `trustedProxies` set so the address
  // resolves per caller, and until that is done, on is strictly worse than off.
  // Two limiters on the same path with different keying would also make a
  // refusal impossible to attribute.
  rateLimit: { enabled: false },
  plugins: [
    // Add generic OAuth plugin for OIDC support
    ...(oidcProviders.length > 0
      ? [genericOAuth({ config: oidcProviders })]
      : []),
  ],
  emailAndPassword: {
    enabled: true, // This will be dynamically controlled by middleware
    requireEmailVerification: false, // Set to true if you want email verification
  },
  account: {
    accountLinking: {
      enabled: true,
      // Allow linking accounts with the same email address
      allowDifferentEmails: false,
      // Trusted providers for automatic linking (add your OIDC provider here)
      trustedProviders: oidcProviders.map((p) => p.providerId),
      // Allow automatic linking for same email addresses
      allowSameEmail: true,
      // Require email verification for account linking
      requireEmailVerification: false,
    },
  },
  // Umbrella fork: session lifetime is env-var configurable so we can pull
  // Entra-SSO re-auth out of the daily path. Defaults bumped from 7d/1d to
  // 30d/7d (max-connectivity policy). The OAuth refresh-token TTL is the
  // outer ceiling; this is the inner one (the cookie that gates
  // /oauth/authorize). See UMBRELLA_FORK.md.
  session: {
    expiresIn: (() => {
      const raw = process.env.BETTER_AUTH_SESSION_EXPIRES_IN_SECONDS;
      const parsed = raw ? Number.parseInt(raw, 10) : NaN;
      return Number.isFinite(parsed) && parsed > 0 ? parsed : 60 * 60 * 24 * 30; // 30 days
    })(),
    updateAge: (() => {
      const raw = process.env.BETTER_AUTH_SESSION_UPDATE_AGE_SECONDS;
      const parsed = raw ? Number.parseInt(raw, 10) : NaN;
      return Number.isFinite(parsed) && parsed > 0 ? parsed : 60 * 60 * 24 * 7; // 7 days (sliding refresh)
    })(),
  },
  user: {
    additionalFields: {
      emailVerified: {
        type: "boolean",
        defaultValue: false,
      },
      // RBAC role surfaced into the session user so both the backend
      // (adminProcedure reads ctx.user.role) and the frontend (nav/mint
      // gating reads session.user.role) get it without a second query.
      // `input: false` is the security boundary: better-auth will NOT accept
      // a client-supplied role on sign-up or user-update, so a member can
      // never self-promote to admin — role is set only by the DB default
      // ('member') and the seed migration / a direct DB update. Sessions are
      // read fresh from the DB per request here (no cookie-cache configured),
      // so a demotion takes effect immediately.
      role: {
        type: "string",
        defaultValue: "member",
        input: false,
      },
    },
  },
  advanced: {
    crossSubDomainCookies: {
      enabled: true,
    },
  },
  logger: {
    level: "debug", // Enable debug logging
  },
  databaseHooks: {
    user: {
      create: {
        before: async (user, context) => {
          // Check if signup is disabled based on the registration method
          const isSignupDisabled = await configService.isSignupDisabled();
          const isSsoSignupDisabled = await configService.isSsoSignupDisabled();

          // The bootstrap exemption. Bootstrap onboards its configured
          // administrators through THIS route, and this fork stores
          // DISABLE_SIGNUP=true from the first boot onward, so without the
          // exemption a restart with BOOTSTRAP_RECREATE_USER=true deletes the
          // administrator (and its API keys) and is then refused permission to
          // recreate it. The flag is false for every request that arrives over
          // HTTP: it is only ever true inside the pre-listen bootstrap pass,
          // and lib/bootstrap-signup-override.ts carries the full argument for
          // why that leaves no reachable open-signup window.
          //
          // Applied to BOTH branches rather than only the basic-auth one:
          // `isSsoRegistration` below is a path heuristic, not a fact about the
          // caller, so scoping the exemption by branch would make bootstrap's
          // success depend on how better-auth happens to label the request.
          // The flag itself is what scopes this, and it is scoped to bootstrap.
          const isBootstrapSignup = isBootstrapSignupAllowed();

          // Determine if this is an SSO/OAuth registration by checking the request path
          // OAuth/SSO registrations typically come through callback endpoints
          const isSsoRegistration =
            context?.path?.includes("/callback/") ||
            context?.path?.includes("/oauth/") ||
            context?.path?.includes("/oidc/");

          if (isSsoRegistration) {
            if (isSsoSignupDisabled && !isBootstrapSignup) {
              // The abuse's front door, from the inside. When
              // self-registration was open the accounts that
              // walked through it left no trace beyond the `users` rows
              // themselves; when it is CLOSED, the attempts that bounce off
              // it leave nothing at all — and a burst of them is the clearest
              // possible signal that someone is still trying. Emitted before
              // the throw, by a helper that cannot throw, so the caller's
              // rejection is unchanged.
              emitSignupDenied(user, context, "sso");
              throw new Error(
                "New user registration via SSO/OAuth is currently disabled.",
              );
            }
          } else {
            if (isSignupDisabled && !isBootstrapSignup) {
              emitSignupDenied(user, context, "basic");
              throw new Error("New user registration is currently disabled.");
            }
          }

          return { data: user };
        },

        // Only reachable on success — `before` above is what refuses a
        // registration, so anything arriving here is an account that now
        // exists. This is the row that answers "when did this account appear
        // and from where", which the 2026-08-13 review had to reconstruct
        // from `users.created_at` and inference.
        after: async (user, context) => {
          emitSignupCreated(user, context);
        },
      },
    },
    session: {
      create: {
        // HALF ONE of two-part enforcement for `users.disabled` (migration
        // 0027): refuse to mint a session for a locked account. This is the
        // hook every sign-in path funnels through — email/password, OIDC
        // callback, account linking — so one guard here covers all of them
        // without having to enumerate endpoints.
        //
        // HALF TWO lives in `createContext` (src/trpc.ts) and the OAuth
        // authorize handler, and it is not optional: sessions in this fork
        // live 30 days, so blocking new logins alone would leave a disabled
        // attacker working from the session they already hold for a month.
        // Together the two halves mean "disabled" takes effect on the very
        // next request, which is the only definition of disabled worth
        // shipping during a live investigation.
        //
        // Throwing (rather than returning `false`) is deliberate: better-auth
        // treats a `false` return as "abort and return null", which surfaces
        // to the user as an opaque broken sign-in. An APIError produces an
        // honest 403 with a message the login page can show.
        before: async (session) => {
          const userId = (session as { userId?: string }).userId;
          if (!userId) return { data: session };

          // Read straight from the database rather than from anything on the
          // session being built — the flag must be current as of THIS login,
          // not as of whenever some cached value was populated.
          if (await usersRepository.isDisabled(userId)) {
            logger.warn(
              `Blocked session creation for disabled account ${userId}`,
            );
            throw new APIError("FORBIDDEN", {
              message: "This account has been disabled.",
            });
          }

          return { data: session };
        },

        // The universal record of "a credential that grants access to this
        // gateway came into existence". Every sign-in path funnels through
        // it — email/password, the OIDC callback, account linking — which is
        // why it is wired IN ADDITION to the `/api/auth` relay wrap in
        // index.ts: that wrap can only read a status code, and a 200 from
        // `sign-in/social` means "here is a redirect URL", not "someone
        // authenticated". SSO logins are recorded here or nowhere.
        //
        // This is also the direct replacement for the forensic record lost at
        // containment on 2026-08-13, when the attacker's sessions were
        // DELETEd and took their `ip_address` and `user_agent` with them.
        after: async (session, context) => {
          emitSessionCreated(session, context);
        },
      },

      delete: {
        // Fires once per deleted row for single deletes (sign-out) and for
        // bulk deletes alike — verified against better-auth 1.6.23's
        // `deleteWithHooks` / `deleteManyWithHooks`, which loop the `after`
        // hook over every entity they removed.
        //
        // NOTE ON COVERAGE: this covers session deletions that go THROUGH
        // better-auth. The admin `users.revokeAccess` and `users.delete`
        // paths tear down session rows with drizzle directly and never reach
        // this hook; they emit `user.access.revoked` / `user.delete` from
        // `users.impl.ts` instead. Between the two, every path that destroys
        // a session today is recorded somewhere — a new teardown that uses
        // neither would be silent.
        after: async (session, context) => {
          emitSessionRevoked(session, context);
        },
      },
    },
  },
  // Add middleware to check basic auth setting
  middleware: [
    {
      path: "/sign-in/email",
      middleware: createBasicAuthCheckMiddleware(),
    },
    {
      path: "/sign-up/email",
      middleware: createBasicAuthCheckMiddleware(),
    },
    {
      path: "/forgot-password",
      middleware: createBasicAuthCheckMiddleware(),
    },
    {
      path: "/reset-password",
      middleware: createBasicAuthCheckMiddleware(),
    },
  ],
});

console.log("✓ Better Auth instance created successfully");
console.log(`✓ OIDC Providers configured: ${oidcProviders.length}`);

export type Session = typeof auth.$Infer.Session;
// Note: User type needs to be inferred from Session.user
export type User = typeof auth.$Infer.Session.user;
