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

          // Determine if this is an SSO/OAuth registration by checking the request path
          // OAuth/SSO registrations typically come through callback endpoints
          const isSsoRegistration =
            context?.path?.includes("/callback/") ||
            context?.path?.includes("/oauth/") ||
            context?.path?.includes("/oidc/");

          if (isSsoRegistration) {
            if (isSsoSignupDisabled) {
              throw new Error(
                "New user registration via SSO/OAuth is currently disabled.",
              );
            }
          } else {
            if (isSignupDisabled) {
              throw new Error("New user registration is currently disabled.");
            }
          }

          return { data: user };
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
        // shipping during an incident.
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
