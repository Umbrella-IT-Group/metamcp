import { createAppRouter, setTrpcAuditSink } from "@repo/trpc";
import * as trpcExpress from "@trpc/server/adapters/express";
import cors from "cors";
import express from "express";
import helmet from "helmet";

import { trpcDenialSink } from "../lib/audit/trpc-denial-sink";
import { createContext } from "../trpc";
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
  },
});

// Export the router type for client usage
export type AppRouter = typeof appRouter;

// Create Express router
const trpcRouter = express.Router();

// Apply security middleware for frontend communication
trpcRouter.use(helmet());
trpcRouter.use(
  cors({
    origin: process.env.APP_URL,
    credentials: true,
  }),
);

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
