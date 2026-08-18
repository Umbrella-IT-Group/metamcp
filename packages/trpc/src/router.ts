import { createFrontendRouter } from "./routers/frontend";
import { router } from "./trpc";

export const createAppRouter = (implementations: {
  frontend: Parameters<typeof createFrontendRouter>[0];
}) => {
  const frontendRouters = createFrontendRouter(implementations.frontend);

  return router({
    frontend: router({
      mcpServers: frontendRouters.mcpServers,
      namespaces: frontendRouters.namespaces,
      endpoints: frontendRouters.endpoints,
      oauth: frontendRouters.oauth,
      oauthClients: frontendRouters.oauthClients,
      // Access dashboard. Sub-routers are enumerated
      // explicitly here, so a router that is not listed is unreachable no
      // matter how it is wired elsewhere.
      oauthTokens: frontendRouters.oauthTokens,
      users: frontendRouters.users,
      tools: frontendRouters.tools,
      apiKeys: frontendRouters.apiKeys,
      config: frontendRouters.config,
      logs: frontendRouters.logs,
      // Access groups (migration 0033): which OAuth users may reach which
      // endpoints. Listed here for the reason stated above — wiring the
      // implementations into `createFrontendRouter` is NOT enough to mount it.
      accessGroups: frontendRouters.accessGroups,
    }),
  });
};

export type AppRouter = ReturnType<typeof createAppRouter>;

// Export types for the router
export type { BaseContext } from "./trpc";
export { createFrontendRouter } from "./routers/frontend";
