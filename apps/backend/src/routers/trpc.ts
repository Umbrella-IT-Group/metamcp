import { createAppRouter, setTrpcAuditSink } from "@repo/trpc";
import * as trpcExpress from "@trpc/server/adapters/express";
import cors from "cors";
import express from "express";
import helmet from "helmet";

import { trpcDenialSink } from "../lib/audit/trpc-denial-sink";
import { credentialedCorsOrigin } from "../lib/cors-policy";
import { trpcAdminKeyRateLimitMiddleware } from "../middleware/trpc-admin-key-rate-limit.middleware";
import { trpcRateLimitMiddleware } from "../middleware/trpc-rate-limit.middleware";
import { createContext } from "../trpc";
import { accessGroupsImplementations } from "../trpc/access-groups.impl";
import { apiKeysImplementations } from "../trpc/api-keys.impl";
import { configImplementations } from "../trpc/config.impl";
import { endpointsImplementations } from "../trpc/endpoints.impl";
import { logsImplementations } from "../trpc/logs.impl";
import { mcpServersImplementations } from "../trpc/mcp-servers.impl";
import { namespacesImplementations } from "../trpc/namespaces.impl";
import { oauthImplementations } from "../trpc/oauth.impl";
import { oauthClientsImplementations } from "../trpc/oauth-clients.impl";
import { oauthTokensImplementations } from "../trpc/oauth-tokens.impl";
import { toolsImplementations } from "../trpc/tools.impl";
import { usersImplementations } from "../trpc/users.impl";

// Give @repo/trpc's RBAC/authn denial hooks somewhere durable to write.
//
// Registered here rather than inside the package because @repo/trpc is also
// consumed by the frontend and must stay free of any database import; the
// backend is the only consumer that has an `audit_log` to write to. Done at
// module load, i.e. before the tRPC handler below can serve a request. The
// sink is fire-and-forget and never throws — see lib/audit/audit-emitter.
setTrpcAuditSink(trpcDenialSink);

// Create the app router with implementations
const appRouter = createAppRouter({
  frontend: {
    mcpServers: mcpServersImplementations,
    namespaces: namespacesImplementations,
    endpoints: endpointsImplementations,
    oauth: oauthImplementations,
    oauthClients: oauthClientsImplementations,
    oauthTokens: oauthTokensImplementations,
    users: usersImplementations,
    tools: toolsImplementations,
    apiKeys: apiKeysImplementations,
    config: configImplementations,
    logs: logsImplementations,
    accessGroups: accessGroupsImplementations,
  },
});

// Export the router type for client usage
export type AppRouter = typeof appRouter;

// Create Express router
const trpcRouter = express.Router();

// Apply security middleware for frontend communication
trpcRouter.use(helmet());
// Every procedure on this router is session-authenticated, so the origin is
// resolved against the shared allowlist rather than handed the raw `APP_URL`.
// A bare `origin: process.env.APP_URL` has two failure modes the allowlist does
// not: an unset or empty APP_URL is falsy, and the cors package answers a
// falsy origin with the literal `*` — beside `credentials: true` — while a
// trailing slash or a case difference makes the string comparison miss and
// silently drops CORS for the app's own frontend. See ../lib/cors-policy.
trpcRouter.use(
  cors({
    origin: credentialedCorsOrigin,
    credentials: true,
  }),
);

// Per-caller request cap, AFTER cors on purpose. The cors middleware answers
// and ends the OPTIONS preflight itself, so mounting here keeps preflights out
// of the budget entirely, and it means a 429 carries the CORS headers the
// browser needs to surface it as a 429 rather than as an opaque network
// failure. See ../middleware/trpc-rate-limit.middleware for the keying
// decision, which is the part that matters.
trpcRouter.use(trpcRateLimitMiddleware);

// Failure-only 429 gate for the admin-plane (control-plane) bearer path
// (migration 0038). AFTER the request cap above so total volume is already
// bounded and this refusal carries the CORS headers, and it CHECKS only,
// lib/admin-plane-auth records a failed verification. It skips cookie-carrying
// requests so a stale bearer on a cookie user is never refused (cookie
// precedence). See ../middleware/trpc-admin-key-rate-limit.middleware.
trpcRouter.use(trpcAdminKeyRateLimitMiddleware);

// Better-auth integration now handled in tRPC context

// Mount tRPC handler
trpcRouter.use(
  "/frontend",
  trpcExpress.createExpressMiddleware({
    router: appRouter,
    createContext,
  }),
);

export default trpcRouter;
