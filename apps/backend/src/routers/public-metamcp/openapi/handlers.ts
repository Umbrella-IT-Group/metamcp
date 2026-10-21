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
import { CallerContext } from "../../../lib/metamcp/caller-context";
import { getMcpServers } from "../../../lib/metamcp/fetch-metamcp";
import { mcpServerPool } from "../../../lib/metamcp/mcp-server-pool";
import { createAuditingMiddleware } from "../../../lib/metamcp/metamcp-middleware/auditing.functional";
import {
  createFilterCallToolMiddleware,
  createFilterListToolsMiddleware,
  type ToolFilterCallContext,
} from "../../../lib/metamcp/metamcp-middleware/filter-tools.functional";
import {
  CallToolHandler,
  compose,
  ListToolsHandler,
  MetaMCPHandlerContext,
} from "../../../lib/metamcp/metamcp-middleware/functional-middleware";
import { createRetiredToolMiddleware } from "../../../lib/metamcp/metamcp-middleware/retired-tool.functional";
import { createTimeoutHintMiddleware } from "../../../lib/metamcp/metamcp-middleware/timeout-hint.functional";
import {
  createToolOverridesCallToolMiddleware,
  createToolOverridesListToolsMiddleware,
} from "../../../lib/metamcp/metamcp-middleware/tool-overrides.functional";
import {
  isRecoverableBackendError,
  isToolCallReplaySafeError,
} from "../../../lib/metamcp/session-error";
import {
  recoverFailedSession,
  SessionRecoveries,
} from "../../../lib/metamcp/session-recovery";
import { routeUnmappedToolCall } from "../../../lib/metamcp/tool-call-routing";
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

        // This prefix must round-trip through the first-'__' call parser,
        // otherwise curation would judge a different server and backend name.
        if (sanitizeName(serverName).includes("__")) {
          logger.error(
            `Cannot list tools for server ${mcpServerUuid}: name ${JSON.stringify(serverName)} contains the tool-name separator`,
          );
          failedServers.push(serverName || mcpServerUuid);
          return;
        }

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
            // Regression mirror — the OpenAPI tools/list
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

// Session recoveries for the bridge, per OpenAPI session id. A handler is
// built per request, so the map that lets concurrent calls share one recovery
// has to outlive it. The bridge's session id is `openapi_<namespace uuid>`
// (tool-execution.ts), so this holds one small WeakMap per namespace.
const openApiRecoveries = new Map<string, SessionRecoveries>();
const recoveriesFor = (sessionId: string): SessionRecoveries => {
  let recoveries = openApiRecoveries.get(sessionId);
  if (!recoveries) {
    recoveries = new WeakMap();
    openApiRecoveries.set(sessionId, recoveries);
  }
  return recoveries;
};

// Original Call Tool Handler (adapted from metamcp-proxy.ts)
export const createOriginalCallToolHandler = (): CallToolHandler => {
  return async (request, context) => {
    // `name` is the caller-controlled tool name (a URL-decoded path segment on
    // the OpenAPI path). Every log line and thrown message below runs it
    // through JSON.stringify so an embedded CR/LF cannot forge log lines, the
    // same discipline as the mcp-proxy connection log.
    const { name, arguments: args } = request.params;

    // Extract the original tool name by removing the server prefix
    const firstDoubleUnderscoreIndex = name.indexOf("__");
    if (firstDoubleUnderscoreIndex === -1) {
      throw new Error(`Invalid tool name format: ${JSON.stringify(name)}`);
    }

    const serverPrefix = name.substring(0, firstDoubleUnderscoreIndex);
    const originalToolName = name.substring(firstDoubleUnderscoreIndex + 2);
    const { allowedToolServerUuids } = context as ToolFilterCallContext;
    const isAllowedServer = (uuid: string): boolean =>
      !allowedToolServerUuids || allowedToolServerUuids.includes(uuid);

    // Resolve the server from the tool's prefix, touching only the servers
    // whose name matches it. The bridge keeps no routing map across calls (a
    // handler is built per request) and routes by prefix without listing, as
    // it always has; what it shares with metamcp-proxy.ts is the candidate
    // choice, the fallbacks and the honest "backend unavailable" answer for a
    // mounted server it could not reach. See tool-call-routing.ts.
    const serverParams = await getMcpServers(context.namespaceUuid);
    const route = await routeUnmappedToolCall({
      namespaceUuid: context.namespaceUuid,
      sessionId: context.sessionId,
      toolName: name,
      serverPrefix,
      originalToolName,
      serverParams,
      isAllowedServer,
      toolPolicy: (context as ToolFilterCallContext).toolPolicy,
      includeInactiveServers: false,
      unknownToolMessage: `Unknown tool: ${JSON.stringify(name)}`,
      pool: mcpServerPool,
      logPrefix: "OpenAPI bridge: ",
      probe: async (session, candidate) => {
        if (!session.client.getServerCapabilities()?.tools) {
          return { kind: "absent" };
        }
        // The configured name already matched the prefix; this is the final
        // gate for a server stored with no name.
        const serverName =
          candidate.params.name ||
          session.client.getServerVersion()?.name ||
          "";
        return sanitizeName(serverName) === serverPrefix
          ? { kind: "found", session }
          : { kind: "absent" };
      },
    });

    const targetSession: ConnectedClient = route.session;
    const targetServerUuid = route.serverUuid;

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
      // Regression — the OpenAPI bridge had its own fork of
      // the tools/call handler that pre-dated PR #13/#15/#16's recovery
      // wiring in `metamcp-proxy.ts`. Any OpenAPI consumer
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
      //
      // The retry is gated on isToolCallReplaySafeError, NOT the
      // isRecoverableBackendError the tools/list path above uses: a
      // tools/call is replayed only when the failure proves the backend
      // never ran it (HTTP 404 "Session not found", or a transport closed
      // before the send). A timeout, a mid-call drop or a 5xx surfaces
      // with no replay, because the backend may already have executed a
      // non-idempotent tool and a second send runs it twice. Found while
      // investigating the 2026-09-30 client-side duplicate; same rule as
      // metamcp-proxy.ts.
      if (!isToolCallReplaySafeError(error)) {
        logger.error(
          `Error calling tool ${JSON.stringify(name)} through ${
            targetSession.client.getServerVersion()?.name || "unknown"
          }:`,
          error,
        );
        throw error;
      }

      logger.warn(
        `OpenAPI bridge: backend connection lost for server ${targetServerUuid} on tool ${JSON.stringify(name)}; recovering the session and retrying once. (envelope: ${
          error instanceof Error ? error.message : String(error)
        })`,
      );

      // One recovery per failed client across every concurrent bridge call
      // on this session id, and no invalidation when the client was already
      // retired by another recovery (session-recovery.ts), as in
      // metamcp-proxy.ts.
      const failedClient = targetSession;
      const freshSession = await recoverFailedSession({
        pool: mcpServerPool,
        recoveries: recoveriesFor(context.sessionId),
        sessionId: context.sessionId,
        serverUuid: targetServerUuid,
        failedClient,
        reacquire: async () => {
          const serverParamsAfter = await getMcpServers(context.namespaceUuid);
          const paramsForServer = serverParamsAfter[targetServerUuid];
          if (!paramsForServer) {
            throw new Error(
              `Cannot re-initialize OpenAPI session: server ${targetServerUuid} no longer present in namespace ${context.namespaceUuid}`,
            );
          }
          return await mcpServerPool.getSession(
            context.sessionId,
            targetServerUuid,
            paramsForServer,
            context.namespaceUuid,
          );
        },
      });
      if (!freshSession) {
        throw new Error(
          `OpenAPI bridge: failed to re-initialize session for server ${targetServerUuid} after backend session loss`,
        );
      }
      try {
        return (await callOnce(freshSession)) as CallToolResult;
      } catch (retryError) {
        logger.error(
          `OpenAPI bridge: error calling tool ${JSON.stringify(name)} through ${
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
  clientName?: string,
  caller?: CallerContext,
) => {
  // Create the handler context. OpenAPI is stateless (one deterministic
  // sessionId per namespace shared across consumers), so the calling
  // consumer's identity rides the per-call context here rather than the
  // session registry — no cross-consumer race.
  //
  // That property is why the caller binding is a plain parameter here and not
  // stamped onto a pooled instance the way the Streamable-HTTP path has to do
  // it: this context object is built fresh for one call and discarded, so
  // `requestId` and `callerIp` cannot be overwritten by a concurrent request
  // on the same shared `openapi_<namespace>` session id.
  const handlerContext: MetaMCPHandlerContext = {
    namespaceUuid,
    sessionId,
    ...caller,
    // Last, so the explicitly-passed label always wins over anything a future
    // `CallerContext` field of the same name could carry.
    clientName,
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
    // Outermost, matching the Streamable-HTTP chain in metamcp-proxy: records
    // every call — including the ones the filter middleware below denies — to
    // the Live Logs store and to tool_call_audit.
    //
    // This chain ran WITHOUT it until now, so every tool call made through the
    // OpenAPI bridge executed with no audit row at all. The gap was invisible
    // from the table: the rows the other path writes look the same, so the
    // absence read as "these consumers were quiet" rather than "these
    // consumers are not recorded". Both entry points reach the same backend
    // servers with the same credentials, so both have to be recorded the same
    // way for retention on this table to mean anything.
    createAuditingMiddleware(),
    // Second, outside the filter, as in the Streamable-HTTP chain: a call that
    // already failed as an unknown tool gets the retired-tool map's answer.
    // The bridge routes by server prefix only, so a retired name on a live
    // server reaches the backend and comes back as an isError "Unknown tool";
    // this turns that into a redirect (surfaced as the bridge's usual 403 body).
    createRetiredToolMiddleware(),
    // Override names resolve BEFORE the filter, so the filter judges the tool
    // that will actually run: the same order as the Streamable-HTTP chain in
    // metamcp-proxy (fork #208). This chain still had the filter outside, so
    // a call by an alias reached the filter as the alias, which has no
    // mapping row of its own. Under `allow_all` that read as "no row,
    // allowed" and an INACTIVE tool stayed callable by its alias; under the
    // `allowlist` tool policy (migration 0040) it would read as "no row,
    // refused" and every alias of an allowlisted tool would be refused. A
    // name that is not an override passes the override middleware unchanged.
    createToolOverridesCallToolMiddleware({ cacheEnabled: true }),
    createFilterCallToolMiddleware({
      cacheEnabled: true,
      customErrorMessage: (toolName, reason) =>
        `Access denied to tool "${toolName}": ${reason}`,
    }),
    // Innermost: added text on the gateway's own -32001 timeout (the outcome is
    // unknown, read the target's state before retrying), same code and data. The bridge
    // maps a thrown error to a 500 whose message carries it.
    createTimeoutHintMiddleware(),
    // Add more middleware here as needed
    // createAuthorizationMiddleware(),
  )(originalCallToolHandler);

  return {
    handlerContext,
    listToolsWithMiddleware,
    callToolWithMiddleware,
  };
};
