import { RequestOptions } from "@modelcontextprotocol/sdk/shared/protocol.js";
import {
  CallToolResult,
  CompatibilityCallToolResultSchema,
  ListToolsResultSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

import logger from "@/utils/logger";

import { configService } from "../../../lib/config.service";
import { ConnectedClient } from "../../../lib/metamcp";
import { getMcpServers } from "../../../lib/metamcp/fetch-metamcp";
import { mcpServerPool } from "../../../lib/metamcp/mcp-server-pool";
import {
  createFilterCallToolMiddleware,
  createFilterListToolsMiddleware,
} from "../../../lib/metamcp/metamcp-middleware/filter-tools.functional";
import {
  CallToolHandler,
  compose,
  ListToolsHandler,
  MetaMCPHandlerContext,
} from "../../../lib/metamcp/metamcp-middleware/functional-middleware";
import {
  createToolOverridesCallToolMiddleware,
  createToolOverridesListToolsMiddleware,
} from "../../../lib/metamcp/metamcp-middleware/tool-overrides.functional";
import { isRecoverableBackendError } from "../../../lib/metamcp/session-error";
import { sanitizeName } from "../../../lib/metamcp/utils";

// Original List Tools Handler (adapted from metamcp-proxy.ts)
export const createOriginalListToolsHandler = (
  includeInactiveServers: boolean = false,
): ListToolsHandler => {
  return async (request, context) => {
    const serverParams = await getMcpServers(
      context.namespaceUuid,
      includeInactiveServers,
    );
    const allTools: Tool[] = [];
    // Mirrors metamcp-proxy.ts's PR #28 tripwire: every backend that
    // contributes zero tools because of a failure (not because it has
    // no tools capability) is recorded here so the namespace-level
    // DEGRADED line below fires. Without this, OpenAPI-path
    // degradation was invisible to the Grafana rule that greps
    // "DEGRADED for namespace".
    const failedServers: string[] = [];
    const allServerEntries = Object.entries(serverParams);

    await Promise.allSettled(
      allServerEntries.map(async ([mcpServerUuid, params]) => {
        const session = await mcpServerPool.getSession(
          context.sessionId,
          mcpServerUuid,
          params,
          context.namespaceUuid,
        );
        if (!session) {
          logger.error(
            `OpenAPI bridge: No session for server ${params.name || mcpServerUuid} (${mcpServerUuid}) during tools/list — pool returned null (ERROR-gated, at cap, or connect failed); server excluded from namespace response`,
          );
          failedServers.push(params.name || mcpServerUuid);
          return;
        }

        const capabilities = session.client.getServerCapabilities();
        if (!capabilities?.tools) return;

        // Use name assigned by user, fallback to name from server
        const serverName =
          params.name || session.client.getServerVersion()?.name || "";

        // Get configurable timeout values to bypass MCP SDK default enforcement
        const resetTimeoutOnProgress =
          await configService.getMcpResetTimeoutOnProgress();
        const timeout = await configService.getMcpTimeout();
        const maxTotalTimeout = await configService.getMcpMaxTotalTimeout();

        const mcpRequestOptions: RequestOptions = {
          resetTimeoutOnProgress,
          timeout,
          maxTotalTimeout,
        };

        const listOnce = (active: ConnectedClient) =>
          active.client.request(
            {
              method: "tools/list",
              params: { _meta: request.params?._meta },
            },
            ListToolsResultSchema,
            mcpRequestOptions,
          );

        try {
          let activeSession = session;
          let result: z.infer<typeof ListToolsResultSchema>;
          try {
            result = await listOnce(activeSession);
          } catch (error) {
            if (!isRecoverableBackendError(error)) {
              throw error;
            }
            // 2026-05-14 regression mirror — the OpenAPI tools/list
            // path also needs PR #13/#15/#16's recovery cascade. Without
            // it, a single backend restart leaves the namespace's tool
            // catalog empty until metamcp itself bounces. Invalidate
            // the stale pool entry, re-acquire a fresh session, retry
            // once.
            logger.warn(
              `OpenAPI bridge: backend connection lost for server ${mcpServerUuid} on tools/list; invalidating pool and retrying once. (envelope: ${
                error instanceof Error ? error.message : String(error)
              })`,
            );
            await mcpServerPool.invalidateServerConnection(
              context.sessionId,
              mcpServerUuid,
            );
            const fresh = await mcpServerPool.getSession(
              context.sessionId,
              mcpServerUuid,
              params,
              context.namespaceUuid,
            );
            if (!fresh) {
              throw new Error(
                `OpenAPI bridge: failed to re-initialize session for server ${mcpServerUuid} after backend session loss during tools/list`,
              );
            }
            activeSession = fresh;
            result = await listOnce(activeSession);
          }

          const toolsWithSource =
            result.tools?.map((tool) => {
              const toolName = `${sanitizeName(serverName)}__${tool.name}`;
              return {
                ...tool,
                name: toolName,
                description: tool.description,
              };
            }) || [];

          allTools.push(...toolsWithSource);
        } catch (error) {
          logger.error(`Error fetching tools from: ${serverName}`, error);
          failedServers.push(serverName || mcpServerUuid);
        }
      }),
    );

    if (failedServers.length > 0) {
      // Same log shape as metamcp-proxy.ts so the Grafana alert rule
      // (`|= "DEGRADED for namespace"`) catches both consumer paths;
      // the "OpenAPI bridge" suffix splits them when investigating.
      logger.error(
        `tools/list DEGRADED for namespace ${context.namespaceUuid} (OpenAPI bridge): ${failedServers.length}/${allServerEntries.length} backend server(s) failed (${failedServers.join(", ")}); returning ${allTools.length} tools`,
      );
    }

    return { tools: allTools };
  };
};

// Original Call Tool Handler (adapted from metamcp-proxy.ts)
export const createOriginalCallToolHandler = (): CallToolHandler => {
  const toolToClient: Record<string, ConnectedClient> = {};
  const toolToServerUuid: Record<string, string> = {};

  return async (request, context) => {
    const { name, arguments: args } = request.params;

    // Extract the original tool name by removing the server prefix
    const firstDoubleUnderscoreIndex = name.indexOf("__");
    if (firstDoubleUnderscoreIndex === -1) {
      throw new Error(`Invalid tool name format: ${name}`);
    }

    const serverPrefix = name.substring(0, firstDoubleUnderscoreIndex);
    const originalToolName = name.substring(firstDoubleUnderscoreIndex + 2);

    // Get server parameters and find the right session for this tool
    const serverParams = await getMcpServers(context.namespaceUuid);
    let targetSession = null;

    for (const [mcpServerUuid, params] of Object.entries(serverParams)) {
      const session = await mcpServerPool.getSession(
        context.sessionId,
        mcpServerUuid,
        params,
        context.namespaceUuid,
      );
      if (!session) continue;

      const capabilities = session.client.getServerCapabilities();
      if (!capabilities?.tools) continue;

      // Use name assigned by user, fallback to name from server
      const serverName =
        params.name || session.client.getServerVersion()?.name || "";

      if (sanitizeName(serverName) === serverPrefix) {
        targetSession = session;
        toolToClient[name] = session;
        toolToServerUuid[name] = mcpServerUuid;
        break;
      }
    }

    if (!targetSession) {
      throw new Error(`Unknown tool: ${name}`);
    }

    const targetServerUuid = toolToServerUuid[name];

    // Get configurable timeout values to bypass MCP SDK default enforcement
    const resetTimeoutOnProgress =
      await configService.getMcpResetTimeoutOnProgress();
    const timeout = await configService.getMcpTimeout();
    const maxTotalTimeout = await configService.getMcpMaxTotalTimeout();

    const mcpRequestOptions: RequestOptions = {
      resetTimeoutOnProgress,
      timeout,
      maxTotalTimeout,
    };

    const callOnce = (session: ConnectedClient) =>
      session.client.request(
        {
          method: "tools/call",
          params: {
            name: originalToolName,
            arguments: args || {},
            _meta: {
              progressToken: request.params._meta?.progressToken,
            },
          },
        },
        CompatibilityCallToolResultSchema,
        mcpRequestOptions,
      );

    try {
      return (await callOnce(targetSession)) as CallToolResult;
    } catch (error) {
      // 2026-05-14 regression — the OpenAPI bridge had its own fork of
      // the tools/call handler that pre-dated PR #13/#15/#16's recovery
      // wiring in `metamcp-proxy.ts`. Tara + any OpenAPI consumer
      // (registry-sync worker, external integration) hit this handler
      // and got bare `Error POSTing ... HTTP 404 ... Session not found`
      // pass-through with zero invalidation. Mirror the
      // Streamable-HTTP path's recovery cascade here: detect the
      // session-lost / transport-lost envelope, invalidate the pooled
      // ConnectedClient (PR #16 makes this cascade across every
      // session's slot for the same serverUuid), re-acquire a fresh
      // session via the pool, retry once. Logs are tagged "OpenAPI
      // bridge" so operators can split this recovery from the
      // Streamable-HTTP one when investigating.
      if (!isRecoverableBackendError(error)) {
        logger.error(
          `Error calling tool "${name}" through ${
            targetSession.client.getServerVersion()?.name || "unknown"
          }:`,
          error,
        );
        throw error;
      }

      logger.warn(
        `OpenAPI bridge: backend connection lost for server ${targetServerUuid} on tool "${name}"; invalidating pool and retrying once. (envelope: ${
          error instanceof Error ? error.message : String(error)
        })`,
      );

      await mcpServerPool.invalidateServerConnection(
        context.sessionId,
        targetServerUuid,
      );
      delete toolToClient[name];
      delete toolToServerUuid[name];

      const serverParamsAfter = await getMcpServers(context.namespaceUuid);
      const paramsForServer = serverParamsAfter[targetServerUuid];
      if (!paramsForServer) {
        throw new Error(
          `Cannot re-initialize OpenAPI session: server ${targetServerUuid} no longer present in namespace ${context.namespaceUuid}`,
        );
      }

      const freshSession = await mcpServerPool.getSession(
        context.sessionId,
        targetServerUuid,
        paramsForServer,
        context.namespaceUuid,
      );
      if (!freshSession) {
        throw new Error(
          `OpenAPI bridge: failed to re-initialize session for server ${targetServerUuid} after backend session loss`,
        );
      }

      toolToClient[name] = freshSession;
      toolToServerUuid[name] = targetServerUuid;

      try {
        return (await callOnce(freshSession)) as CallToolResult;
      } catch (retryError) {
        logger.error(
          `OpenAPI bridge: error calling tool "${name}" through ${
            freshSession.client.getServerVersion()?.name || "unknown"
          } after session re-initialize:`,
          retryError,
        );
        throw retryError;
      }
    }
  };
};

// Helper function to create middleware-enabled handlers
export const createMiddlewareEnabledHandlers = (
  sessionId: string,
  namespaceUuid: string,
) => {
  // Create the handler context
  const handlerContext: MetaMCPHandlerContext = {
    namespaceUuid,
    sessionId,
  };

  // Create original handlers
  const originalListToolsHandler = createOriginalListToolsHandler();
  const originalCallToolHandler = createOriginalCallToolHandler();

  // Compose middleware with handlers
  const listToolsWithMiddleware = compose(
    createToolOverridesListToolsMiddleware({ cacheEnabled: true }),
    createFilterListToolsMiddleware({ cacheEnabled: true }),
    // Add more middleware here as needed
    // createLoggingMiddleware(),
    // createRateLimitingMiddleware(),
  )(originalListToolsHandler);

  const callToolWithMiddleware = compose(
    createFilterCallToolMiddleware({
      cacheEnabled: true,
      customErrorMessage: (toolName, reason) =>
        `Access denied to tool "${toolName}": ${reason}`,
    }),
    createToolOverridesCallToolMiddleware({ cacheEnabled: true }),
    // Add more middleware here as needed
    // createAuditingMiddleware(),
    // createAuthorizationMiddleware(),
  )(originalCallToolHandler);

  return {
    handlerContext,
    listToolsWithMiddleware,
    callToolWithMiddleware,
  };
};
