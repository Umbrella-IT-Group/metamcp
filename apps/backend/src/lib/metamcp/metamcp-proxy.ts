import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { RequestOptions } from "@modelcontextprotocol/sdk/shared/protocol.js";
import {
  CallToolRequestSchema,
  CallToolResult,
  CompatibilityCallToolResultSchema,
  GetPromptRequestSchema,
  GetPromptResultSchema,
  ListPromptsRequestSchema,
  ListPromptsResultSchema,
  ListResourcesRequestSchema,
  ListResourcesResultSchema,
  ListResourceTemplatesRequestSchema,
  ListResourceTemplatesResultSchema,
  ListToolsRequestSchema,
  ListToolsResultSchema,
  ReadResourceRequestSchema,
  ReadResourceResultSchema,
  ResourceTemplate,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

import logger from "@/utils/logger";

import { toolsImplementations } from "../../trpc/tools.impl";
import { configService } from "../config.service";
import { ConnectedClient } from "./client";
import { getMcpServers } from "./fetch-metamcp";
import { GATEWAY_CAPABILITIES } from "./gateway-capabilities";
import { requestWithSessionRecovery } from "./list-handler-recovery";
import { mcpServerPool } from "./mcp-server-pool";
import { createAuditingMiddleware } from "./metamcp-middleware/auditing.functional";
import {
  createFilterCallToolMiddleware,
  createFilterListToolsMiddleware,
} from "./metamcp-middleware/filter-tools.functional";
import {
  CallToolHandler,
  compose,
  ListToolsHandler,
  MetaMCPHandlerContext,
} from "./metamcp-middleware/functional-middleware";
import {
  createToolOverridesCallToolMiddleware,
  createToolOverridesListToolsMiddleware,
  mapOverrideNameToOriginal,
} from "./metamcp-middleware/tool-overrides.functional";
import { isRecoverableBackendError } from "./session-error";
import { parseToolName } from "./tool-name-parser";
import { toolsSyncCache } from "./tools-sync-cache";
import { sanitizeName } from "./utils";

/**
 * Filter out tools that are overrides of existing tools to prevent duplicates in database
 * Uses the existing tool overrides cache for optimal performance
 */
async function filterOutOverrideTools(
  tools: Tool[],
  namespaceUuid: string,
  serverName: string,
): Promise<Tool[]> {
  if (!tools || tools.length === 0) {
    return tools;
  }

  const filteredTools: Tool[] = [];

  await Promise.allSettled(
    tools.map(async (tool) => {
      try {
        // Check if this tool name is actually an override name for an existing tool
        // by using the existing mapOverrideNameToOriginal function
        const fullToolName = `${sanitizeName(serverName)}__${tool.name}`;
        const originalName = await mapOverrideNameToOriginal(
          fullToolName,
          namespaceUuid,
          true, // use cache
        );

        // If the original name is different from the current name,
        // this tool is an override and should be filtered out
        if (originalName !== fullToolName) {
          // This is an override, skip it (don't save to database)
          return;
        }

        // This is not an override, include it
        filteredTools.push(tool);
      } catch (error) {
        logger.error(
          `Error checking if tool ${tool.name} is an override:`,
          error,
        );
        // On error, include the tool (fail-safe behavior)
        filteredTools.push(tool);
      }
    }),
  );

  return filteredTools;
}

export const createServer = async (
  namespaceUuid: string,
  sessionId: string,
  includeInactiveServers: boolean = false,
) => {
  const toolToClient: Record<string, ConnectedClient> = {};
  const toolToServerUuid: Record<string, string> = {};
  const promptToClient: Record<string, ConnectedClient> = {};
  const resourceToClient: Record<string, ConnectedClient> = {};

  // Helper function to detect if a server is the same instance
  const isSameServerInstance = (
    params: { name?: string; url?: string | null },
    _serverUuid: string,
  ): boolean => {
    // Check if server name is exactly the same as our current server instance
    // This prevents exact recursive calls to the same server
    if (params.name === `metamcp-unified-${namespaceUuid}`) {
      return true;
    }

    return false;
  };

  const server = new Server(
    {
      name: `metamcp-unified-${namespaceUuid}`,
      version: "1.0.0",
    },
    {
      // Capabilities live in `gateway-capabilities.ts` as a single
      // source of truth — the same object is hashed into
      // `GATEWAY_CAPABILITY_HASH` (PR #23) and stamped onto every
      // persisted session row, so lazy-recovery can refuse only when
      // the advertised set actually changed across a restart. Mutate
      // the constant, not this declaration.
      capabilities: GATEWAY_CAPABILITIES,
    },
  );

  // Subscribers we've registered on backend `ConnectedClient`s for this
  // upstream `Server`. We track them so the `server.onclose` hook below
  // can detach them — the `ConnectedClient` outlives this `Server` (it's
  // pooled), so leaving subscribers attached would leak fan-out targets
  // pointing at a closed proxy server.
  const registeredSubscriptions = new Set<{
    client: ConnectedClient;
    subscriber: () => Promise<void>;
  }>();

  /**
   * Attach a subscriber to the backend client that:
   *   1. Invalidates the tools-sync cache for this server so the next
   *      `tools/list` re-syncs to DB.
   *   2. Emits `notifications/tools/list_changed` upstream.
   *
   * Idempotent: the `ConnectedClient.listChangedSubscribers` field is a
   * `Set`, but each `createServer` call gets its own subscriber closure
   * (different `server` instance), so we de-dupe per upstream-server by
   * tracking subscribers we've already attached for this proxy server.
   */
  const registerListChangedSubscriber = (
    session: ConnectedClient,
    mcpServerUuid: string,
  ): void => {
    // De-dupe: don't attach a second subscriber to the same client from
    // this same upstream `Server` instance. (Different upstream Servers
    // legitimately each get their own subscriber.)
    for (const entry of registeredSubscriptions) {
      if (entry.client === session) {
        return;
      }
    }

    const subscriber = async (): Promise<void> => {
      toolsSyncCache.clear(mcpServerUuid);
      try {
        await server.notification({
          method: "notifications/tools/list_changed",
          params: {},
        });
      } catch (notifyError) {
        logger.warn(
          `Failed to forward tools/list_changed upstream for server ${mcpServerUuid}:`,
          notifyError,
        );
      }
    };

    session.listChangedSubscribers.add(subscriber);
    registeredSubscriptions.add({ client: session, subscriber });
  };

  // Detach all subscribers when this upstream Server closes — otherwise
  // they outlive the proxy server (the backend ConnectedClient is pooled
  // and keeps the subscriber set alive). The `Server` exposes `onclose`
  // from the underlying `Protocol`; we install our hook here.
  server.onclose = () => {
    for (const { client, subscriber } of registeredSubscriptions) {
      client.listChangedSubscribers.delete(subscriber);
    }
    registeredSubscriptions.clear();
  };

  // Create the handler context
  const handlerContext: MetaMCPHandlerContext = {
    namespaceUuid,
    sessionId,
  };

  // Original List Tools Handler
  const originalListToolsHandler: ListToolsHandler = async (
    request,
    context,
  ) => {
    logger.debug(
      "[DEBUG-TOOLS] 🔍 tools/list called for namespace:",
      namespaceUuid,
    );
    const startTime = performance.now();
    const serverParams = await getMcpServers(
      context.namespaceUuid,
      includeInactiveServers,
    );
    const allTools: Tool[] = [];

    // Servers that should have contributed but didn't — used for the
    // degraded-response tripwire after the fan-out completes. A failure
    // here must be LOUD: a swallowed failure returns a "successful"
    // 0-tool namespace and nobody notices until a human runs
    // `docker restart metamcp` (incident 2026-06-11).
    const failedServers: string[] = [];

    // Track visited servers to detect circular references - reset on each call
    const visitedServers = new Set<string>();

    // We'll filter servers during processing after getting sessions to check actual MCP server names
    const allServerEntries = Object.entries(serverParams);

    logger.debug(
      `[DEBUG-TOOLS] 📋 Processing ${allServerEntries.length} servers`,
    );

    // Cold-start warmup: if pool has 0 idle + 0 active sessions but servers
    // exist in DB, trigger a blocking warmup before tools/list responds.
    // This prevents 0-tool responses after idle timeout expires all connections.
    const poolStatus = mcpServerPool.getPoolStatus();
    if (
      poolStatus.idle === 0 &&
      poolStatus.active === 0 &&
      allServerEntries.length > 0
    ) {
      logger.debug(
        `[DEBUG-TOOLS] ⚠️ Cold start: 0 idle, 0 active sessions but ${allServerEntries.length} servers registered. Warming up...`,
      );
      for (const [uuid] of allServerEntries) {
        await mcpServerPool.resetServerErrorState(uuid);
      }
      await mcpServerPool.ensureIdleSessions(serverParams, namespaceUuid);
      const afterStatus = mcpServerPool.getPoolStatus();
      logger.debug(
        `[DEBUG-TOOLS] ✅ Pool warmup complete: ${afterStatus.idle} idle, ${afterStatus.active} active`,
      );
    }

    await Promise.allSettled(
      allServerEntries.map(async ([mcpServerUuid, params]) => {
        logger.debug(
          `[DEBUG-TOOLS] 🔧 Server: ${params.name || mcpServerUuid}`,
        );

        // Skip if we've already visited this server to prevent circular references
        if (visitedServers.has(mcpServerUuid)) {
          logger.debug(
            `[DEBUG-TOOLS] ⏭️  Skipping already visited: ${params.name}`,
          );
          return;
        }
        const session = await mcpServerPool.getSession(
          context.sessionId,
          mcpServerUuid,
          params,
          namespaceUuid,
        );
        if (!session) {
          // No pooled session and the pool couldn't create one — server is
          // ERROR-gated, connection-capped, or unreachable. Error level, not
          // debug: this server is silently missing from the namespace's
          // tool surface until the pool recovers.
          logger.error(
            `tools/list: no session available for server ${params.name || mcpServerUuid} — excluded from namespace response (error state, connection cap, or backend unreachable)`,
          );
          failedServers.push(params.name || mcpServerUuid);
          return;
        }

        // Attach our `list_changed` fan-out subscriber on every
        // `getSession`. Idempotent via the per-upstream-Server dedupe
        // check inside the helper. Catches:
        //   - First contact with this backend (no subscriber yet).
        //   - Backend restart cycle: pool invalidation hands us a fresh
        //     ConnectedClient whose subscriber set is empty.
        registerListChangedSubscriber(session, mcpServerUuid);

        // Now check for self-referencing using the actual MCP server name
        const serverVersion = session.client.getServerVersion();
        const actualServerName = serverVersion?.name || params.name || "";
        const ourServerName = `metamcp-unified-${namespaceUuid}`;

        if (actualServerName === ourServerName) {
          logger.info(
            `Skipping self-referencing MetaMCP server: "${actualServerName}"`,
          );
          return;
        }

        // Check basic self-reference patterns
        if (isSameServerInstance(params, mcpServerUuid)) {
          return;
        }

        // Mark this server as visited
        visitedServers.add(mcpServerUuid);

        const capabilities = session.client.getServerCapabilities();
        if (!capabilities?.tools) return;

        // Use name assigned by user, fallback to name from server
        const serverName =
          params.name || session.client.getServerVersion()?.name || "";

        try {
          const toolFetchStart = performance.now();

          // Paginated tool discovery - load all pages automatically
          const fetchAllToolPages = async (
            active: ConnectedClient,
          ): Promise<Tool[]> => {
            const pages: Tool[] = [];
            let cursor: string | undefined = undefined;
            let hasMore = true;

            while (hasMore) {
              const result: z.infer<typeof ListToolsResultSchema> =
                await active.client.request(
                  {
                    method: "tools/list",
                    params: {
                      cursor: cursor,
                      _meta: request.params?._meta,
                    },
                  },
                  ListToolsResultSchema,
                );

              if (result.tools && result.tools.length > 0) {
                pages.push(...result.tools);
              }

              cursor = result.nextCursor;
              hasMore = !!result.nextCursor;
            }

            return pages;
          };

          // Invalidate-and-retry-once on session-lost / transport-lost —
          // the same cascade tools/call has had since PR #13/#16. Without
          // it a dead pooled session is never evicted from here and the
          // namespace serves 0 tools as "success" until a manual restart.
          let activeSession = session;
          const allServerTools = await requestWithSessionRecovery({
            pool: mcpServerPool,
            sessionId: context.sessionId,
            serverUuid: mcpServerUuid,
            params,
            namespaceUuid,
            operation: "tools/list",
            serverName,
            session,
            attempt: fetchAllToolPages,
            onFreshSession: (fresh) => {
              registerListChangedSubscriber(fresh, mcpServerUuid);
              activeSession = fresh;
            },
          });

          logger.debug(
            `[DEBUG-TOOLS] ⏱️  Fetched ${allServerTools.length} tools from ${serverName} in ${(performance.now() - toolFetchStart).toFixed(2)}ms`,
          );

          // Save original tools to database (before middleware processing)
          // This ensures we only save the actual tool names, not override names
          // Filter out tools that are overrides of existing tools to prevent duplicates
          try {
            // PERFORMANCE OPTIMIZATION: Check hash FIRST to avoid expensive operations
            const toolNames = allServerTools.map((tool) => tool.name);
            const hasChanged = toolsSyncCache.hasChanged(
              mcpServerUuid,
              toolNames,
            );

            logger.debug(
              `[DEBUG-TOOLS] 🔍 Hash check for ${serverName}: ${hasChanged ? "CHANGED" : "UNCHANGED"}`,
            );

            if (hasChanged) {
              const toolsToSave = await filterOutOverrideTools(
                allServerTools,
                namespaceUuid,
                serverName,
              );

              if (toolsToSave.length > 0) {
                // Update cache
                toolsSyncCache.update(mcpServerUuid, toolNames);

                // Sync with cleanup
                await toolsImplementations.sync({
                  tools: toolsToSave,
                  mcpServerUuid: mcpServerUuid,
                });
              }
            }
          } catch (dbError) {
            logger.error(
              `Error syncing tools to database for server ${serverName}:`,
              dbError,
            );
          }

          // Use original tools for client response (middleware will be applied later)
          const toolsWithSource = allServerTools.map((tool) => {
            const toolName = `${sanitizeName(serverName)}__${tool.name}`;
            toolToClient[toolName] = activeSession;
            toolToServerUuid[toolName] = mcpServerUuid;

            return {
              ...tool,
              name: toolName,
              description: tool.description,
            };
          });

          allTools.push(...toolsWithSource);
        } catch (error) {
          logger.error(`Error fetching tools from: ${serverName}`, error);
          failedServers.push(serverName || mcpServerUuid);
        }
      }),
    );

    const totalTime = performance.now() - startTime;
    logger.debug(
      `[DEBUG-TOOLS] ✅ tools/list completed in ${totalTime.toFixed(2)}ms, returning ${allTools.length} tools`,
    );

    // Degraded-response tripwire: a server that should have contributed
    // tools failed even after the recovery retry. The response is still
    // returned (partial truth beats a hard error for the surviving
    // servers) but the failure must be loud enough for log-based
    // monitoring to catch — this exact silent-degradation mode ran for
    // weeks before incident 2026-06-11.
    if (failedServers.length > 0) {
      logger.error(
        `tools/list DEGRADED for namespace ${namespaceUuid}: ${failedServers.length}/${allServerEntries.length} backend server(s) failed (${failedServers.join(", ")}); returning ${allTools.length} tools`,
      );
    }

    return { tools: allTools };
  };

  // Original Call Tool Handler
  const originalCallToolHandler: CallToolHandler = async (
    request,
    _context,
  ) => {
    const { name, arguments: args } = request.params;

    // Parse the tool name using shared utility
    const parsed = parseToolName(name);
    if (!parsed) {
      throw new Error(`Invalid tool name format: ${name}`);
    }

    const { serverName: serverPrefix, originalToolName } = parsed;

    // Try to find the tool in pre-populated mappings first
    let clientForTool = toolToClient[name];
    let serverUuid = toolToServerUuid[name];

    // If not found in mappings, dynamically find the server and route the call
    if (!clientForTool || !serverUuid) {
      try {
        // Get all MCP servers for this namespace
        const serverParams = await getMcpServers(
          namespaceUuid,
          includeInactiveServers,
        );

        // Find the server with the matching name prefix
        for (const [mcpServerUuid, params] of Object.entries(serverParams)) {
          const session = await mcpServerPool.getSession(
            sessionId,
            mcpServerUuid,
            params,
            namespaceUuid,
          );

          if (session) {
            // Idempotent — see registerListChangedSubscriber dedupe note.
            // Required here too: tools discovered only via dynamic-find
            // never hit the `originalListToolsHandler` `getSession`, so
            // without this they'd never get a subscriber attached.
            registerListChangedSubscriber(session, mcpServerUuid);

            const capabilities = session.client.getServerCapabilities();
            if (!capabilities?.tools) continue;

            // Use name assigned by user, fallback to name from server
            const serverName =
              params.name || session.client.getServerVersion()?.name || "";

            if (sanitizeName(serverName) === serverPrefix) {
              // Found the server, now check if it has this tool with pagination.
              // If the cached session is stale (backend restarted between when
              // we last connected and now), `tools/list` returns the same
              // -32600 / "Session not found" envelope as `tools/call`. Engage
              // the same recovery path: invalidate the pool entry, re-acquire
              // a fresh session, retry once. Without this the dynamic-find
              // path silently swallows the failure (logs error, continues to
              // next server) and the agent gets `Unknown tool` instead of
              // either a successful tool call or a real not-found error.
              const listToolsOnce = async (
                activeSession: ConnectedClient,
              ): Promise<z.infer<typeof ListToolsResultSchema>[]> => {
                const pages: z.infer<typeof ListToolsResultSchema>[] = [];
                let cursor: string | undefined = undefined;
                let hasMore = true;
                while (hasMore) {
                  const page: z.infer<typeof ListToolsResultSchema> =
                    await activeSession.client.request(
                      {
                        method: "tools/list",
                        params: { cursor },
                      },
                      ListToolsResultSchema,
                    );
                  pages.push(page);
                  cursor = page.nextCursor;
                  hasMore = !!page.nextCursor;
                }
                return pages;
              };

              const matchOnPages = (
                pages: z.infer<typeof ListToolsResultSchema>[],
              ): boolean =>
                pages.some((page) =>
                  page.tools?.some(
                    (tool: Tool) => tool.name === originalToolName,
                  ),
                );

              try {
                let activeSession = session;
                let pages: z.infer<typeof ListToolsResultSchema>[];
                try {
                  pages = await listToolsOnce(activeSession);
                } catch (error) {
                  if (!isRecoverableBackendError(error)) {
                    throw error;
                  }
                  logger.warn(
                    `Backend connection lost for server ${mcpServerUuid} on dynamic tools/list while routing tool "${name}"; invalidating pool and retrying once. (envelope: ${
                      error instanceof Error ? error.message : String(error)
                    })`,
                  );
                  await mcpServerPool.invalidateServerConnection(
                    sessionId,
                    mcpServerUuid,
                  );
                  const fresh = await mcpServerPool.getSession(
                    sessionId,
                    mcpServerUuid,
                    params,
                    namespaceUuid,
                  );
                  if (!fresh) {
                    throw new Error(
                      `Failed to re-initialize session for server ${mcpServerUuid} after backend session loss during dynamic tool routing`,
                    );
                  }
                  registerListChangedSubscriber(fresh, mcpServerUuid);
                  activeSession = fresh;
                  pages = await listToolsOnce(activeSession);
                }

                if (matchOnPages(pages)) {
                  // Tool exists, populate mappings for future use and use it
                  clientForTool = activeSession;
                  serverUuid = mcpServerUuid;
                  toolToClient[name] = activeSession;
                  toolToServerUuid[name] = mcpServerUuid;
                  break;
                }
              } catch (error) {
                logger.error(
                  `Error checking tools for server ${serverName}:`,
                  error,
                );
                continue;
              }
            }
          }
        }
      } catch (error) {
        logger.error(`Error dynamically finding tool ${name}:`, error);
      }
    }

    if (!clientForTool) {
      throw new Error(`Unknown tool: ${name}`);
    }

    if (!serverUuid) {
      throw new Error(`Server UUID not found for tool: ${name}`);
    }

    const abortController = new AbortController();

    // Get configurable timeout values
    const resetTimeoutOnProgress =
      await configService.getMcpResetTimeoutOnProgress();
    const timeout = await configService.getMcpTimeout();
    const maxTotalTimeout = await configService.getMcpMaxTotalTimeout();

    const mcpRequestOptions: RequestOptions = {
      signal: abortController.signal,
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
            _meta: request.params._meta,
          },
        },
        CompatibilityCallToolResultSchema,
        mcpRequestOptions,
      );

    try {
      return (await callOnce(clientForTool)) as CallToolResult;
    } catch (error) {
      if (!isRecoverableBackendError(error)) {
        logger.error(
          `Error calling tool "${name}" through ${
            clientForTool.client.getServerVersion()?.name || "unknown"
          }:`,
          error,
        );
        throw error;
      }

      logger.warn(
        `Backend connection lost for server ${serverUuid} on tool "${name}"; invalidating pool and retrying once. (envelope: ${
          error instanceof Error ? error.message : String(error)
        })`,
      );

      await mcpServerPool.invalidateServerConnection(sessionId, serverUuid);
      delete toolToClient[name];

      const serverParamsMap = await getMcpServers(
        namespaceUuid,
        includeInactiveServers,
      );
      const params = serverParamsMap[serverUuid];
      if (!params) {
        throw new Error(
          `Cannot re-initialize session: server ${serverUuid} no longer present in namespace ${namespaceUuid}`,
        );
      }

      const freshSession = await mcpServerPool.getSession(
        sessionId,
        serverUuid,
        params,
        namespaceUuid,
      );
      if (!freshSession) {
        throw new Error(
          `Failed to re-initialize session for server ${serverUuid} after backend session loss`,
        );
      }

      registerListChangedSubscriber(freshSession, serverUuid);
      toolToClient[name] = freshSession;

      try {
        return (await callOnce(freshSession)) as CallToolResult;
      } catch (retryError) {
        logger.error(
          `Error calling tool "${name}" through ${
            freshSession.client.getServerVersion()?.name || "unknown"
          } after session re-initialize:`,
          retryError,
        );
        throw retryError;
      }
    }
  };

  // Compose middleware with handlers - this is the Express-like functional approach
  const listToolsWithMiddleware = compose(
    createToolOverridesListToolsMiddleware({
      cacheEnabled: true,
      persistentCacheOnListTools: true,
    }),
    createFilterListToolsMiddleware({ cacheEnabled: true }),
    // Add more middleware here as needed
    // createLoggingMiddleware(),
    // createRateLimitingMiddleware(),
  )(originalListToolsHandler);

  const callToolWithMiddleware = compose(
    // Outermost: records every call (incl. denied) to the Live Logs store.
    createAuditingMiddleware(),
    createFilterCallToolMiddleware({
      cacheEnabled: true,
      customErrorMessage: (toolName, reason) =>
        `Access denied to tool "${toolName}": ${reason}`,
    }),
    createToolOverridesCallToolMiddleware({ cacheEnabled: true }),
    // Add more middleware here as needed
    // createAuthorizationMiddleware(),
  )(originalCallToolHandler);

  // Set up the handlers with middleware
  server.setRequestHandler(ListToolsRequestSchema, async (request) => {
    return await listToolsWithMiddleware(request, handlerContext);
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    return await callToolWithMiddleware(request, handlerContext);
  });

  // Get Prompt Handler
  server.setRequestHandler(GetPromptRequestSchema, async (request) => {
    const { name } = request.params;
    const clientForPrompt = promptToClient[name];

    if (!clientForPrompt) {
      throw new Error(`Unknown prompt: ${name}`);
    }

    try {
      // Parse the prompt name using shared utility
      const parsed = parseToolName(name);
      if (!parsed) {
        throw new Error(`Invalid prompt name format: ${name}`);
      }

      const promptName = parsed.originalToolName;
      const response = await clientForPrompt.client.request(
        {
          method: "prompts/get",
          params: {
            name: promptName,
            arguments: request.params.arguments || {},
            _meta: request.params._meta,
          },
        },
        GetPromptResultSchema,
      );

      return response;
    } catch (error) {
      logger.error(
        `Error getting prompt through ${
          clientForPrompt.client.getServerVersion()?.name
        }:`,
        error,
      );
      throw error;
    }
  });

  // List Prompts Handler
  server.setRequestHandler(ListPromptsRequestSchema, async (request) => {
    const serverParams = await getMcpServers(
      namespaceUuid,
      includeInactiveServers,
    );
    const allPrompts: z.infer<typeof ListPromptsResultSchema>["prompts"] = [];
    const failedServers: string[] = [];

    // Track visited servers to detect circular references - reset on each call
    const visitedServers = new Set<string>();

    // Filter out self-referencing servers before processing
    const validPromptServers = Object.entries(serverParams).filter(
      ([uuid, params]) => {
        // Skip if we've already visited this server to prevent circular references
        if (visitedServers.has(uuid)) {
          logger.info(
            `Skipping already visited server in prompts: ${params.name || uuid}`,
          );
          return false;
        }

        // Check if this server is the same instance to prevent self-referencing
        if (isSameServerInstance(params, uuid)) {
          logger.info(
            `Skipping self-referencing server in prompts: ${params.name || uuid}`,
          );
          return false;
        }

        // Mark this server as visited
        visitedServers.add(uuid);
        return true;
      },
    );

    await Promise.allSettled(
      validPromptServers.map(async ([uuid, params]) => {
        const session = await mcpServerPool.getSession(
          sessionId,
          uuid,
          params,
          namespaceUuid,
        );
        if (!session) {
          logger.error(
            `prompts/list: no session available for server ${params.name || uuid} — excluded from namespace response (error state, connection cap, or backend unreachable)`,
          );
          failedServers.push(params.name || uuid);
          return;
        }

        // Now check for self-referencing using the actual MCP server name
        const serverVersion = session.client.getServerVersion();
        const actualServerName = serverVersion?.name || params.name || "";
        const ourServerName = `metamcp-unified-${namespaceUuid}`;

        if (actualServerName === ourServerName) {
          logger.info(
            `Skipping self-referencing MetaMCP server in prompts: "${actualServerName}"`,
          );
          return;
        }

        const capabilities = session.client.getServerCapabilities();
        if (!capabilities?.prompts) return;

        // Use name assigned by user, fallback to name from server
        const serverName =
          params.name || session.client.getServerVersion()?.name || "";
        try {
          let activeSession = session;
          const result = await requestWithSessionRecovery({
            pool: mcpServerPool,
            sessionId,
            serverUuid: uuid,
            params,
            namespaceUuid,
            operation: "prompts/list",
            serverName,
            session,
            attempt: (active) =>
              active.client.request(
                {
                  method: "prompts/list",
                  params: {
                    cursor: request.params?.cursor,
                    _meta: request.params?._meta,
                  },
                },
                ListPromptsResultSchema,
              ),
            onFreshSession: (fresh) => {
              registerListChangedSubscriber(fresh, uuid);
              activeSession = fresh;
            },
          });

          if (result.prompts) {
            const promptsWithSource = result.prompts.map((prompt) => {
              const promptName = `${sanitizeName(serverName)}__${prompt.name}`;
              promptToClient[promptName] = activeSession;
              return {
                ...prompt,
                name: promptName,
                description: prompt.description || "",
              };
            });
            allPrompts.push(...promptsWithSource);
          }
        } catch (error) {
          logger.error(`Error fetching prompts from: ${serverName}`, error);
          failedServers.push(serverName || uuid);
        }
      }),
    );

    if (failedServers.length > 0) {
      logger.error(
        `prompts/list DEGRADED for namespace ${namespaceUuid}: ${failedServers.length} backend server(s) failed (${failedServers.join(", ")}); returning ${allPrompts.length} prompts`,
      );
    }

    return {
      prompts: allPrompts,
      nextCursor: request.params?.cursor,
    };
  });

  // List Resources Handler
  server.setRequestHandler(ListResourcesRequestSchema, async (request) => {
    const serverParams = await getMcpServers(
      namespaceUuid,
      includeInactiveServers,
    );
    const allResources: z.infer<typeof ListResourcesResultSchema>["resources"] =
      [];
    const failedServers: string[] = [];

    // Track visited servers to detect circular references - reset on each call
    const visitedServers = new Set<string>();

    // Filter out self-referencing servers before processing
    const validResourceServers = Object.entries(serverParams).filter(
      ([uuid, params]) => {
        // Skip if we've already visited this server to prevent circular references
        if (visitedServers.has(uuid)) {
          logger.info(
            `Skipping already visited server in resources: ${params.name || uuid}`,
          );
          return false;
        }

        // Check if this server is the same instance to prevent self-referencing
        if (isSameServerInstance(params, uuid)) {
          logger.info(
            `Skipping self-referencing server in resources: ${params.name || uuid}`,
          );
          return false;
        }

        // Mark this server as visited
        visitedServers.add(uuid);
        return true;
      },
    );

    await Promise.allSettled(
      validResourceServers.map(async ([uuid, params]) => {
        const session = await mcpServerPool.getSession(
          sessionId,
          uuid,
          params,
          namespaceUuid,
        );
        if (!session) {
          logger.error(
            `resources/list: no session available for server ${params.name || uuid} — excluded from namespace response (error state, connection cap, or backend unreachable)`,
          );
          failedServers.push(params.name || uuid);
          return;
        }

        // Now check for self-referencing using the actual MCP server name
        const serverVersion = session.client.getServerVersion();
        const actualServerName = serverVersion?.name || params.name || "";
        const ourServerName = `metamcp-unified-${namespaceUuid}`;

        if (actualServerName === ourServerName) {
          logger.info(
            `Skipping self-referencing MetaMCP server in resources: "${actualServerName}"`,
          );
          return;
        }

        const capabilities = session.client.getServerCapabilities();
        if (!capabilities?.resources) return;

        // Use name assigned by user, fallback to name from server
        const serverName =
          params.name || session.client.getServerVersion()?.name || "";
        try {
          let activeSession = session;
          const result = await requestWithSessionRecovery({
            pool: mcpServerPool,
            sessionId,
            serverUuid: uuid,
            params,
            namespaceUuid,
            operation: "resources/list",
            serverName,
            session,
            attempt: (active) =>
              active.client.request(
                {
                  method: "resources/list",
                  params: {
                    cursor: request.params?.cursor,
                    _meta: request.params?._meta,
                  },
                },
                ListResourcesResultSchema,
              ),
            onFreshSession: (fresh) => {
              registerListChangedSubscriber(fresh, uuid);
              activeSession = fresh;
            },
          });

          if (result.resources) {
            const resourcesWithSource = result.resources.map((resource) => {
              resourceToClient[resource.uri] = activeSession;
              return {
                ...resource,
                name: resource.name || "",
              };
            });
            allResources.push(...resourcesWithSource);
          }
        } catch (error) {
          logger.error(`Error fetching resources from: ${serverName}`, error);
          failedServers.push(serverName || uuid);
        }
      }),
    );

    if (failedServers.length > 0) {
      logger.error(
        `resources/list DEGRADED for namespace ${namespaceUuid}: ${failedServers.length} backend server(s) failed (${failedServers.join(", ")}); returning ${allResources.length} resources`,
      );
    }

    return {
      resources: allResources,
      nextCursor: request.params?.cursor,
    };
  });

  // Read Resource Handler
  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const { uri } = request.params;
    const clientForResource = resourceToClient[uri];

    if (!clientForResource) {
      throw new Error(`Unknown resource: ${uri}`);
    }

    try {
      return await clientForResource.client.request(
        {
          method: "resources/read",
          params: {
            uri,
            _meta: request.params._meta,
          },
        },
        ReadResourceResultSchema,
      );
    } catch (error) {
      logger.error(
        `Error reading resource through ${
          clientForResource.client.getServerVersion()?.name
        }:`,
        error,
      );
      throw error;
    }
  });

  // List Resource Templates Handler
  server.setRequestHandler(
    ListResourceTemplatesRequestSchema,
    async (request) => {
      const serverParams = await getMcpServers(
        namespaceUuid,
        includeInactiveServers,
      );
      const allTemplates: ResourceTemplate[] = [];
      const failedServers: string[] = [];

      // Track visited servers to detect circular references - reset on each call
      const visitedServers = new Set<string>();

      // Filter out self-referencing servers before processing
      const validTemplateServers = Object.entries(serverParams).filter(
        ([uuid, params]) => {
          // Skip if we've already visited this server to prevent circular references
          if (visitedServers.has(uuid)) {
            logger.info(
              `Skipping already visited server in resource templates: ${params.name || uuid}`,
            );
            return false;
          }

          // Check if this server is the same instance to prevent self-referencing
          if (isSameServerInstance(params, uuid)) {
            logger.info(
              `Skipping self-referencing server in resource templates: ${params.name || uuid}`,
            );
            return false;
          }

          // Mark this server as visited
          visitedServers.add(uuid);
          return true;
        },
      );

      await Promise.allSettled(
        validTemplateServers.map(async ([uuid, params]) => {
          const session = await mcpServerPool.getSession(
            sessionId,
            uuid,
            params,
            namespaceUuid,
          );
          if (!session) {
            logger.error(
              `resources/templates/list: no session available for server ${params.name || uuid} — excluded from namespace response (error state, connection cap, or backend unreachable)`,
            );
            failedServers.push(params.name || uuid);
            return;
          }

          // Now check for self-referencing using the actual MCP server name
          const serverVersion = session.client.getServerVersion();
          const actualServerName = serverVersion?.name || params.name || "";
          const ourServerName = `metamcp-unified-${namespaceUuid}`;

          if (actualServerName === ourServerName) {
            logger.info(
              `Skipping self-referencing MetaMCP server in resource templates: "${actualServerName}"`,
            );
            return;
          }

          const capabilities = session.client.getServerCapabilities();
          if (!capabilities?.resources) return;

          const serverName =
            params.name || session.client.getServerVersion()?.name || "";

          try {
            const result = await requestWithSessionRecovery({
              pool: mcpServerPool,
              sessionId,
              serverUuid: uuid,
              params,
              namespaceUuid,
              operation: "resources/templates/list",
              serverName,
              session,
              attempt: (active) =>
                active.client.request(
                  {
                    method: "resources/templates/list",
                    params: {
                      cursor: request.params?.cursor,
                      _meta: request.params?._meta,
                    },
                  },
                  ListResourceTemplatesResultSchema,
                ),
              onFreshSession: (fresh) => {
                registerListChangedSubscriber(fresh, uuid);
              },
            });

            if (result.resourceTemplates) {
              const templatesWithSource = result.resourceTemplates.map(
                (template) => ({
                  ...template,
                  name: template.name || "",
                }),
              );
              allTemplates.push(...templatesWithSource);
            }
          } catch (error) {
            logger.error(
              `Error fetching resource templates from: ${serverName}`,
              error,
            );
            failedServers.push(serverName || uuid);
            return;
          }
        }),
      );

      if (failedServers.length > 0) {
        logger.error(
          `resources/templates/list DEGRADED for namespace ${namespaceUuid}: ${failedServers.length} backend server(s) failed (${failedServers.join(", ")}); returning ${allTemplates.length} templates`,
        );
      }

      return {
        resourceTemplates: allTemplates,
        nextCursor: request.params?.cursor,
      };
    },
  );

  const cleanup = async () => {
    // Cleanup is now handled by the pool
    await mcpServerPool.cleanupSession(sessionId);
  };

  // Expose handlerContext so the caller can stamp the consumer identity onto
  // it AFTER acquiring the (possibly idle-warmed) instance. The handler
  // closures read context.clientName by reference at call time, so a late set
  // is seen by the audit middleware — this is how the Streamable-HTTP path
  // attaches "who" without the pool knowing the consumer at warm time.
  return { server, cleanup, handlerContext };
};
