import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { RequestOptions } from "@modelcontextprotocol/sdk/shared/protocol.js";
import {
  CallToolRequestSchema,
  CallToolResult,
  CompatibilityCallToolResultSchema,
  ErrorCode,
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
  McpError,
  ReadResourceRequestSchema,
  ReadResourceResultSchema,
  ResourceTemplate,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { McpServerErrorStatusEnum, ServerParameters } from "@repo/zod-types";
import { z } from "zod";

import logger from "@/utils/logger";

import { mcpServersRepository } from "../../db/repositories/mcp-servers.repo";
import { toolsImplementations } from "../../trpc/tools.impl";
import { configService } from "../config.service";
import { buildM365BrokerErrorResult } from "../m365/broker-error-result";
import { isM365BrokerError } from "../m365/errors";
import { ConnectedClient } from "./client";
import { resolveColdConnectBrokerFallback } from "./cold-connect-broker-fallback";
import {
  getMcpServers,
  getNamespaceListingServers,
  type NamespaceListingServers,
} from "./fetch-metamcp";
import { GATEWAY_CAPABILITIES } from "./gateway-capabilities";
import { requestWithSessionRecovery } from "./list-handler-recovery";
import { mcpServerPool } from "./mcp-server-pool";
import { createAuditingMiddleware } from "./metamcp-middleware/auditing.functional";
import {
  createFilterCallToolMiddleware,
  createFilterListToolsMiddleware,
  type ToolFilterCallContext,
} from "./metamcp-middleware/filter-tools.functional";
import {
  CallToolHandler,
  compose,
  ListToolsHandler,
  MetaMCPHandlerContext,
} from "./metamcp-middleware/functional-middleware";
import { createRetiredToolMiddleware } from "./metamcp-middleware/retired-tool.functional";
import { createTimeoutHintMiddleware } from "./metamcp-middleware/timeout-hint.functional";
import {
  createToolOverridesCallToolMiddleware,
  createToolOverridesListToolsMiddleware,
} from "./metamcp-middleware/tool-overrides.functional";
import {
  isRecoverableBackendError,
  isToolCallReplaySafeError,
} from "./session-error";
import { recoverFailedSession, SessionRecoveries } from "./session-recovery";
import { ToolArgSchemaRegistry } from "./tool-arg-keys";
import {
  PrefixCandidate,
  ProbeOutcome,
  routeUnmappedToolCall,
} from "./tool-call-routing";
import {
  parseToolName,
  registerToolRoute,
  ToolRouteOwner,
} from "./tool-name-parser";
import {
  renotifyMaxRounds,
  toolsListRenotifyEnabled,
  toolsListRenotifyWatch,
} from "./tools-list-renotify";
import { toolsSyncCache } from "./tools-sync-cache";
import { sanitizeName } from "./utils";

export const createServer = async (
  namespaceUuid: string,
  sessionId: string,
  includeInactiveServers: boolean = false,
) => {
  const toolToClient: Record<string, ConnectedClient> = {};
  const toolToServerUuid: Record<string, string> = {};
  // Which server first claimed each fully-qualified tool name, so a second
  // server that sanitizes to the same prefix and exposes the same tool name is
  // detected as a collision rather than silently overwriting the route. See
  // the collision guard at namespace assembly below.
  const toolNameOwner = new Map<string, ToolRouteOwner>();
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

    const subscriber = (): Promise<void> => emitToolListChanged(mcpServerUuid);

    session.listChangedSubscribers.add(subscriber);
    registeredSubscriptions.add({ client: session, subscriber });
  };

  /**
   * Tell this session's client that `mcpServerUuid`'s tools changed: drop the
   * server's tools-sync hash and the audit snapshot, then send
   * `notifications/tools/list_changed` upstream. Used by the backend
   * subscriber above and by the tools/list re-notify below. Never throws.
   */
  const emitToolListChanged = async (mcpServerUuid: string): Promise<void> => {
    toolsSyncCache.clear(mcpServerUuid);
    // A changed backend surface invalidates the audit snapshot immediately;
    // stale names must not remain verified until the consumer lists again.
    toolSchemaGeneration += 1;
    toolArgSchemas.replace([]);
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

  // Servers this session's last tools/list left out because they could not
  // be reached, each with the cancel function of its re-notify watch. The
  // session is owed one list_changed per server once it answers again, so a
  // client that re-listed into a backend restart (and replaced its tool set
  // with the reduced listing) gets those tools back without reconnecting.
  // See tools-list-renotify.ts for the defect and the probe.
  const owedServers = new Map<string, () => void>();
  // How many times each server was re-notified and then failed this
  // session's re-list again. Starts that server's next watch further along
  // the backoff, so a flapping backend cannot drive a re-list every two
  // seconds, and, at `renotifyMaxRounds()`, stops the session arming another
  // (the backoff alone bounds the probe cadence, not the number of rounds).
  // Cleared by a listing that reaches the server, or when the server leaves
  // the namespace.
  const renotifyRounds = new Map<string, number>();
  // Servers whose cap was reached and already logged for this session, so
  // the WARN is once per (session, server) until the count is reset.
  const renotifyCapLogged = new Set<string>();
  let proxyClosed = false;

  // Does an owed server answer for a listing again? Not while its error gate
  // is set: the listing would leave it out again, so telling the session to
  // re-list would only earn it another error. The gate is checked first, so
  // a gated server is not sent a request at all (and the pool's connect path
  // refuses a gated server anyway). It is reset by the pool's half-open
  // probe or by an operator; the probe after that decides.
  const probeOwedServer = async (
    params: ServerParameters,
  ): Promise<boolean> => {
    // The pool's isServerInErrorState returns false on a failed read. That
    // cannot establish that the gate is clear: an existing pooled client
    // could answer and discharge this watch while the backend stays gated.
    // Let a read failure reach the watch's retry path, and require a current
    // row with NONE before any backend request (a deleted server is not up).
    const current = await mcpServersRepository.findByUuid(params.uuid);
    return (
      current?.error_status === McpServerErrorStatusEnum.enum.NONE &&
      (await mcpServerPool.probeServerTools(params, namespaceUuid))
    );
  };

  const onOwedServerAnswers = (mcpServerUuid: string, serverName: string) => {
    if (proxyClosed || !owedServers.delete(mcpServerUuid)) return;
    renotifyRounds.set(
      mcpServerUuid,
      (renotifyRounds.get(mcpServerUuid) ?? 0) + 1,
    );
    logger.info(
      `tools/list re-notify: server ${serverName} (${mcpServerUuid}) answers tools/list again; sending notifications/tools/list_changed to session ${sessionId}`,
    );
    void emitToolListChanged(mcpServerUuid);
  };

  /**
   * After a listing: settle what this session is owed. A server the listing
   * reached, or that left the namespace, is owed nothing; a server it could
   * not reach gets a watch (one per server, kept until it answers or the
   * session closes). `mountedServerUuids` includes the error-gated servers:
   * a gated server is still mounted, so its watch must not be cancelled as
   * if it had left.
   */
  const settleOwedServers = (
    mountedServerUuids: ReadonlySet<string>,
    settledServerUuids: ReadonlySet<string>,
    unreachableServers: ReadonlyMap<string, ServerParameters>,
  ): void => {
    for (const [mcpServerUuid, cancel] of owedServers) {
      if (
        settledServerUuids.has(mcpServerUuid) ||
        !mountedServerUuids.has(mcpServerUuid)
      ) {
        cancel();
        owedServers.delete(mcpServerUuid);
      }
    }
    for (const mcpServerUuid of settledServerUuids) {
      renotifyRounds.delete(mcpServerUuid);
      renotifyCapLogged.delete(mcpServerUuid);
    }
    // A server that left the namespace is a new server if it returns.
    for (const mcpServerUuid of Array.from(renotifyRounds.keys())) {
      if (!mountedServerUuids.has(mcpServerUuid)) {
        renotifyRounds.delete(mcpServerUuid);
        renotifyCapLogged.delete(mcpServerUuid);
      }
    }
    if (proxyClosed || !toolsListRenotifyEnabled()) return;
    for (const [mcpServerUuid, params] of unreachableServers) {
      if (owedServers.has(mcpServerUuid)) continue;
      const serverName = params.name || mcpServerUuid;
      const rounds = renotifyRounds.get(mcpServerUuid) ?? 0;
      const maxRounds = renotifyMaxRounds();
      if (rounds >= maxRounds) {
        // This session was told `rounds` times and each time re-listed into
        // a failure: more notifications would only repeat that. It keeps the
        // reduced listing it has. Said once per (session, server).
        if (!renotifyCapLogged.has(mcpServerUuid)) {
          renotifyCapLogged.add(mcpServerUuid);
          logger.warn(
            `tools/list re-notify: session ${sessionId} stopped re-notifying server ${serverName} (${mcpServerUuid}) after ${rounds} rounds that each re-listed into a failure; it keeps the reduced listing until it reconnects or a listing reaches the server`,
          );
        }
        continue;
      }
      const cancel = toolsListRenotifyWatch.watch(
        mcpServerUuid,
        () => probeOwedServer(params),
        () => onOwedServerAnswers(mcpServerUuid, serverName),
        rounds,
      );
      owedServers.set(mcpServerUuid, cancel);
      logger.info(
        `tools/list re-notify: session ${sessionId} is owed notifications/tools/list_changed for server ${serverName} (${mcpServerUuid}), which this listing left out`,
      );
    }
  };

  const stopOwedServerWatches = (): void => {
    proxyClosed = true;
    for (const cancel of owedServers.values()) cancel();
    owedServers.clear();
    renotifyRounds.clear();
    renotifyCapLogged.clear();
  };

  // Detach all subscribers when this upstream Server closes — otherwise
  // they outlive the proxy server (the backend ConnectedClient is pooled
  // and keeps the subscriber set alive). The `Server` exposes `onclose`
  // from the underlying `Protocol`; we install our hook here. The owed
  // re-notify watches stop with it: there is no client left to tell.
  server.onclose = () => {
    for (const { client, subscriber } of registeredSubscriptions) {
      client.listChangedSubscribers.delete(subscriber);
    }
    registeredSubscriptions.clear();
    stopOwedServerWatches();
  };

  // Create the handler context
  const handlerContext: MetaMCPHandlerContext = {
    namespaceUuid,
    sessionId,
  };
  const toolArgSchemas = new ToolArgSchemaRegistry();
  let toolSchemaGeneration = 0;

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
    // Not getMcpServers: it hides an error-gated server and answers {} when
    // the read fails, and this listing read either as "the namespace mounts
    // nothing", a successful empty answer that also cancelled the session's
    // owed re-notifies. A failed read is a retryable error here, thrown
    // before anything below prunes routes or settles what is owed.
    let listing: NamespaceListingServers;
    try {
      listing = await getNamespaceListingServers(
        context.namespaceUuid,
        includeInactiveServers,
      );
    } catch (error) {
      logger.error(
        `tools/list could not read the servers of namespace ${namespaceUuid}; answering a retryable error, not an empty list:`,
        error,
      );
      throw new McpError(
        ErrorCode.InternalError,
        "tools/list could not read this namespace's servers: no tools were listed, which is not the same as an empty tool list. Retry shortly.",
        {
          code: "backend_unavailable",
          reason: "namespace_lookup_failed",
          servers: [],
          retryable: true,
        },
      );
    }
    // The routable servers, the same set getMcpServers answers: the only ones
    // this listing connects to, warms or keeps routes for.
    const serverParams = listing.routable;
    // A live proxy outlasts namespace edits. Drop removed owners before the
    // collision guard so a same-named replacement can list its own tools.
    for (const [toolName, owner] of toolNameOwner) {
      if (!serverParams[owner.uuid]) {
        toolNameOwner.delete(toolName);
        delete toolToClient[toolName];
        delete toolToServerUuid[toolName];
      }
    }
    const allTools: Tool[] = [];

    // Servers that should have contributed but didn't — used for the
    // degraded-response tripwire after the fan-out completes. A failure
    // here must be LOUD: a swallowed failure returns a "successful"
    // 0-tool namespace and nobody notices until a human runs
    // `docker restart metamcp` (the zero-tool outage).
    const failedServers: string[] = [];
    // Per-server outcome by uuid, for the owed re-notify (settleOwedServers).
    // Settled: this listing reached the server (it listed, has no tools, is
    // a self-reference, or has a misconfigured name no reconnect would fix),
    // so nothing about it is owed. Unreachable: no session, or its listing
    // failed after recovery; owed a list_changed once it answers.
    const settledServerUuids = new Set<string>();
    const unreachableServers = new Map<string, ServerParameters>();
    // The unreachable servers that are error-gated, named as such in the error.
    const errorGatedUuids = new Set<string>();

    // Error-gated servers are mounted but never connected to (the pool's
    // connect path refuses them too). They are unreachable for this listing:
    // owed a re-notify, and part of the error when nothing else lists tools.
    // A misconfigured name stays excluded exactly as below, since resetting
    // the gate would not make it listable.
    for (const [mcpServerUuid, params] of Object.entries(listing.errorGated)) {
      if (isSameServerInstance(params, mcpServerUuid)) {
        settledServerUuids.add(mcpServerUuid);
        continue;
      }
      if (params.name && sanitizeName(params.name).includes("__")) {
        logger.error(
          `Cannot list tools for server ${mcpServerUuid}: name ${JSON.stringify(params.name)} contains the tool-name separator`,
        );
        failedServers.push(params.name);
        settledServerUuids.add(mcpServerUuid);
        continue;
      }
      logger.error(
        `tools/list: server ${params.name || mcpServerUuid} is error-gated; excluded from namespace response until its error state is reset`,
      );
      failedServers.push(params.name || mcpServerUuid);
      unreachableServers.set(mcpServerUuid, params);
      errorGatedUuids.add(mcpServerUuid);
    }

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

    const listingOutcomes = await Promise.allSettled(
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
        // A stored separator is a configuration exclusion even while the
        // backend is down. Check it before connecting so retryable recovery
        // is reserved for servers a reconnect can actually make listable.
        if (params.name && sanitizeName(params.name).includes("__")) {
          logger.error(
            `Cannot list tools for server ${mcpServerUuid}: name ${JSON.stringify(params.name)} contains the tool-name separator`,
          );
          failedServers.push(params.name);
          settledServerUuids.add(mcpServerUuid);
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
          unreachableServers.set(mcpServerUuid, params);
          return;
        }

        // Attach our `list_changed` fan-out subscriber on every
        // `getSession`. Idempotent via the per-upstream-Server dedupe
        // check inside the helper. Catches:
        //   - First contact with this backend (no subscriber yet).
        //   - Backend restart cycle: pool invalidation hands us a fresh
        //     ConnectedClient whose subscriber set is empty.
        registerListChangedSubscriber(session, mcpServerUuid);
        settledServerUuids.add(mcpServerUuid);

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

        // The first '__' separates the server from the backend tool. A stored
        // server name containing it cannot round-trip and could borrow an
        // ACTIVE row on the parent prefix while listing an unreviewed tool.
        if (sanitizeName(serverName).includes("__")) {
          logger.error(
            `Cannot list tools for server ${mcpServerUuid}: name ${JSON.stringify(serverName)} contains the tool-name separator`,
          );
          failedServers.push(serverName || mcpServerUuid);
          return;
        }

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
          // These are raw backend names. A namespace alias can match a real
          // backend tool, so reverse-mapping here would omit that native tool
          // from the catalog shared by every namespace. Presentation overrides
          // belong only in the response middleware, never in this write.
          try {
            // PERFORMANCE OPTIMIZATION: Check hash FIRST to avoid expensive operations
            // Hash the FULL definitions (name + description + inputSchema); a
            // schema/description-only change keeps every name identical, so a
            // name-only hash would skip the resync (see tools-sync-cache.ts).
            const hasChanged = toolsSyncCache.hasChanged(
              mcpServerUuid,
              allServerTools,
            );

            logger.debug(
              `[DEBUG-TOOLS] 🔍 Hash check for ${serverName}: ${hasChanged ? "CHANGED" : "UNCHANGED"}`,
            );

            if (hasChanged && allServerTools.length > 0) {
              // Claim the full definitions we just observed, so concurrent
              // listings of the same set skip, then write. The write must
              // not re-check this cache: `tools.impl` sync used to, found
              // the hash claimed here and skipped, so this path never wrote
              // the catalog (see syncFromListing). The claim is released if
              // the write fails, so the next tools/list retries it instead
              // of skipping a write that never happened.
              toolsSyncCache.update(mcpServerUuid, allServerTools);
              try {
                await toolsImplementations.syncFromListing({
                  tools: allServerTools,
                  mcpServerUuid: mcpServerUuid,
                });
                // A different listing can claim a newer hash while this
                // write is in flight, then commit first. Record the set
                // THIS completed write persisted, so a later current
                // listing retries instead of treating a stale catalog as current.
                toolsSyncCache.update(mcpServerUuid, allServerTools);
              } catch (writeError) {
                toolsSyncCache.clear(mcpServerUuid);
                throw writeError;
              }
            }
          } catch (dbError) {
            logger.error(
              `Error syncing tools to database for server ${serverName}:`,
              dbError,
            );
          }

          // Use original tools for client response (middleware will be applied later)
          //
          // Cross-server tool-name collision guard: the routing maps are keyed on
          // `sanitizeName(serverName)__toolName`. sanitizeName strips every
          // character outside [a-zA-Z0-9_-], so two servers in one namespace
          // whose names sanitize to the same prefix (or share a name, or fall
          // back to an unvalidated backend-reported version name) and expose
          // the same tool name would produce the SAME key. Left unchecked,
          // last writer wins and a call silently routes to the wrong backend.
          // We keep the FIRST registration, drop the duplicate, and WARN naming
          // both servers so the operator can rename one. Disambiguating by a
          // uuid suffix instead was rejected: the assembly runs concurrently
          // (Promise.allSettled below), so which server won the base name would
          // be non-deterministic, and it would rename a tool the caller invokes
          // by name. This synchronous loop is atomic per server relative to the
          // others, so the check-then-set sees every already-registered server.
          const toolsWithSource: Tool[] = [];
          for (const tool of allServerTools) {
            const toolName = `${sanitizeName(serverName)}__${tool.name}`;
            const outcome = registerToolRoute(
              toolName,
              { uuid: mcpServerUuid, name: serverName },
              toolNameOwner,
            );
            if (!outcome.registered) {
              const other = outcome.collidedWith;
              logger.warn(
                `Tool name collision in namespace ${namespaceUuid}: "${toolName}" is exposed by both server "${other?.name}" (${other?.uuid}) and server "${serverName}" (${mcpServerUuid}); keeping the first and dropping the duplicate. Rename one server so their sanitized name prefixes differ.`,
              );
              continue;
            }
            toolToClient[toolName] = activeSession;
            toolToServerUuid[toolName] = mcpServerUuid;
            toolsWithSource.push({
              ...tool,
              name: toolName,
              description: tool.description,
            });
          }

          allTools.push(...toolsWithSource);
        } catch (error) {
          // NO special case for a typed M365 broker error, on purpose. The
          // injected fetch mints no token for a listing (m365/injected-fetch.ts,
          // invariant 5), so a per-user broker error can no longer occur here.
          // One that does reach this catch means that gate regressed, and it
          // must stay exactly what it is today: an ERROR line, a failed server
          // and the DEGRADED line. Classing it as info or keeping it out of
          // `failedServers` would hide the one signal that catches that
          // regression.
          logger.error(`Error fetching tools from: ${serverName}`, error);
          failedServers.push(serverName || mcpServerUuid);
          settledServerUuids.delete(mcpServerUuid);
          unreachableServers.set(mcpServerUuid, params);
        }
      }),
    );

    // Session acquisition and capability reads can reject before the
    // per-listing catch. Promise.allSettled isolates those failures, but
    // ignoring its rejected outcomes would still turn them into a successful
    // empty list and leave the session without a recovery notification.
    for (const [index, [mcpServerUuid, params]] of allServerEntries.entries()) {
      const outcome = listingOutcomes[index];
      if (outcome?.status !== "rejected") continue;
      logger.error(
        `Error preparing tools listing for: ${params.name || mcpServerUuid}`,
        outcome.reason,
      );
      failedServers.push(params.name || mcpServerUuid);
      settledServerUuids.delete(mcpServerUuid);
      unreachableServers.set(mcpServerUuid, params);
    }

    // Mounted means routable or error-gated: a gated server's watch stays.
    const mountedServerUuids = new Set([
      ...Object.keys(serverParams),
      ...Object.keys(listing.errorGated),
    ]);
    settleOwedServers(
      mountedServerUuids,
      settledServerUuids,
      unreachableServers,
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
    // weeks before the zero-tool outage.
    if (failedServers.length > 0) {
      logger.error(
        `tools/list DEGRADED for namespace ${namespaceUuid}: ${failedServers.length}/${mountedServerUuids.size} backend server(s) failed (${failedServers.join(", ")}); returning ${allTools.length} tools`,
      );
    }

    // No tools at all while a server could not be reached: answer an error,
    // never an empty list. An empty result says "this namespace has no
    // tools", and a client that re-lists on list_changed replaces its whole
    // tool set with it. That is how a backend restart emptied a one-server
    // namespace for a long-lived session until it reconnected. With an error
    // the client keeps the tools it had (a call meanwhile gets the retryable
    // backend unavailable answer) and, through the owed re-notify above, is
    // told to list again once the server answers. A partial listing (some
    // server listed tools) is still returned: partial truth beats a hard
    // error for the servers that work, and the unreachable ones are owed a
    // re-notify. An error-gated server counts as unreachable: its gate is
    // reset by the pool's half-open probe or by an operator, so the error is
    // retryable and the session is owed the same re-notify. A server excluded
    // for a misconfigured name is not part of this: no retry fixes it, and
    // an error would only make every listing of the namespace fail until it
    // is renamed (it stays in the DEGRADED line).
    if (allTools.length === 0 && unreachableServers.size > 0) {
      const unreachableNames = Array.from(
        unreachableServers,
        ([mcpServerUuid, params]) => params.name || mcpServerUuid,
      );
      const described = Array.from(
        unreachableServers,
        ([mcpServerUuid, params]) =>
          `${JSON.stringify(params.name || mcpServerUuid)}${
            errorGatedUuids.has(mcpServerUuid) ? " (error-gated)" : ""
          }`,
      );
      const renotify = toolsListRenotifyEnabled()
        ? " This session gets notifications/tools/list_changed when the server answers again."
        : "";
      throw new McpError(
        ErrorCode.InternalError,
        `tools/list could not reach ${described.join(", ")}: no tools were listed, which is not the same as an empty tool list. Retry shortly.${renotify}`,
        {
          code: "backend_unavailable",
          servers: unreachableNames,
          retryable: true,
        },
      );
    }

    return { tools: allTools };
  };

  // Session recoveries started by this proxy's tool calls, one per failed
  // client however many calls fail on it (session-recovery.ts). Per proxy,
  // because a proxy serves exactly one session id.
  const recoveries: SessionRecoveries = new WeakMap();

  const listToolPages = async (
    session: ConnectedClient,
  ): Promise<z.infer<typeof ListToolsResultSchema>[]> => {
    const pages: z.infer<typeof ListToolsResultSchema>[] = [];
    let cursor: string | undefined = undefined;
    let hasMore = true;
    while (hasMore) {
      const page: z.infer<typeof ListToolsResultSchema> =
        await session.client.request(
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

  /**
   * Does this prefix-matched server serve the tool? Lists its tools (all
   * pages) and looks for the backend name. A stale pooled session answers
   * tools/list with the same session-lost envelope as tools/call, so a
   * recoverable failure gets one recovery (shared with any parallel call
   * failing on the same client) and one more listing; a timeout or any other
   * failure is reported as a failed lookup, never as "no such tool".
   */
  const probeServerForTool = async (
    session: ConnectedClient,
    candidate: PrefixCandidate,
    name: string,
    serverPrefix: string,
    originalToolName: string,
  ): Promise<ProbeOutcome> => {
    // Idempotent. Tools discovered only through this lookup never pass the
    // list handler's getSession, so without this they would never get a
    // list_changed subscriber.
    registerListChangedSubscriber(session, candidate.uuid);

    if (!session.client.getServerCapabilities()?.tools) {
      return { kind: "absent" };
    }
    // The configured name already matched the prefix; this is the final gate
    // for a server stored with no name, identified by its backend name.
    const serverName =
      candidate.params.name || session.client.getServerVersion()?.name || "";
    if (sanitizeName(serverName) !== serverPrefix) {
      return { kind: "absent" };
    }

    let activeSession = session;
    let pages: z.infer<typeof ListToolsResultSchema>[];
    try {
      pages = await listToolPages(activeSession);
    } catch (error) {
      if (!isRecoverableBackendError(error)) {
        logger.warn(
          `Tool lookup on server ${candidate.uuid} failed while routing tool ${JSON.stringify(name)}; the server is mounted, so this is reported as unavailable, not as an unknown tool. (${
            error instanceof Error ? error.message : String(error)
          })`,
        );
        return { kind: "lookup_failed" };
      }
      logger.warn(
        `Backend connection lost for server ${candidate.uuid} on dynamic tools/list while routing tool ${JSON.stringify(name)}; recovering the session and retrying once. (envelope: ${
          error instanceof Error ? error.message : String(error)
        })`,
      );
      let fresh: ConnectedClient | undefined;
      try {
        fresh = await recoverFailedSession({
          pool: mcpServerPool,
          recoveries,
          sessionId,
          serverUuid: candidate.uuid,
          failedClient: activeSession,
          reacquire: () =>
            mcpServerPool.getSession(
              sessionId,
              candidate.uuid,
              candidate.params,
              namespaceUuid,
            ),
        });
      } catch (recoveryError) {
        logger.error(
          `Failed to re-initialize session for server ${candidate.uuid} after backend session loss during dynamic tool routing:`,
          recoveryError,
        );
        return { kind: "no_session" };
      }
      if (!fresh) {
        logger.error(
          `Failed to re-initialize session for server ${candidate.uuid} after backend session loss during dynamic tool routing`,
        );
        return { kind: "no_session" };
      }
      registerListChangedSubscriber(fresh, candidate.uuid);
      activeSession = fresh;
      try {
        pages = await listToolPages(activeSession);
      } catch (retryError) {
        logger.warn(
          `Tool lookup on server ${candidate.uuid} failed again after session recovery while routing tool ${JSON.stringify(name)}. (${
            retryError instanceof Error
              ? retryError.message
              : String(retryError)
          })`,
        );
        return { kind: "lookup_failed" };
      }
    }

    const listed = pages.some((page) =>
      page.tools?.some((tool: Tool) => tool.name === originalToolName),
    );
    return listed
      ? { kind: "found", session: activeSession }
      : { kind: "absent" };
  };

  /** Drop every route that still points at a client whose recovery failed. */
  const forgetRoutesTo = (failedClient: ConnectedClient): void => {
    for (const [routedName, routedClient] of Object.entries(toolToClient)) {
      if (routedClient === failedClient) {
        delete toolToClient[routedName];
      }
    }
  };

  // Original Call Tool Handler
  const originalCallToolHandler: CallToolHandler = async (request, context) => {
    const { name, arguments: args } = request.params;

    // Parse the tool name using shared utility
    const parsed = parseToolName(name);
    if (!parsed) {
      throw new Error(`Invalid tool name format: ${name}`);
    }

    const { serverName: serverPrefix, originalToolName } = parsed;
    const { allowedToolServerUuids } = context as ToolFilterCallContext;
    const isAllowedServer = (uuid: string): boolean =>
      !allowedToolServerUuids || allowedToolServerUuids.includes(uuid);

    // Try to find the tool in pre-populated mappings first
    let clientForTool: ConnectedClient | undefined = toolToClient[name];
    let serverUuid: string | undefined = toolToServerUuid[name];
    if (serverUuid && !isAllowedServer(serverUuid)) {
      // The filter checked today's mounts, but this live proxy may retain the
      // removed server's route. Resolve again instead of executing that client.
      delete toolToClient[name];
      delete toolToServerUuid[name];
      toolNameOwner.delete(name);
      clientForTool = undefined;
      serverUuid = undefined;
    }

    // Not in the routing map: resolve the server from the tool's prefix.
    // Only the namespace's servers whose name matches the prefix are touched;
    // a miss on a mounted server answers "backend unavailable" (the tool was
    // not run, retry) instead of "Unknown tool". See tool-call-routing.ts.
    if (!clientForTool || !serverUuid) {
      const serverParams = await getMcpServers(
        namespaceUuid,
        includeInactiveServers,
      );
      const route = await routeUnmappedToolCall({
        namespaceUuid,
        sessionId,
        toolName: name,
        serverPrefix,
        originalToolName,
        serverParams,
        isAllowedServer,
        toolPolicy: (context as ToolFilterCallContext).toolPolicy,
        includeInactiveServers,
        unknownToolMessage: `Unknown tool: ${name}`,
        pool: mcpServerPool,
        probe: (session, candidate) =>
          probeServerForTool(
            session,
            candidate,
            name,
            serverPrefix,
            originalToolName,
          ),
      });
      // Idempotent; a session reached only through the fallback warm-up has
      // not had its subscriber attached yet.
      registerListChangedSubscriber(route.session, route.serverUuid);
      clientForTool = route.session;
      serverUuid = route.serverUuid;
      toolToClient[name] = route.session;
      toolToServerUuid[name] = route.serverUuid;
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
      // Replay a tools/call ONLY when the failure proves the backend never
      // ran it: an HTTP 404 "Session not found" answer to the POST, or a
      // transport already closed before the send. A tool call is not
      // idempotent (a delete, a reboot, a password reset), so a timeout, a
      // connection dropped mid-call or a 5xx surfaces to the client instead:
      // the backend may have executed it, and a second send runs it twice.
      // The 2026-09-30 client-side duplicate prompted finding this separate
      // gateway retry: a 60 s timeout's -32001 read as session-lost. Do not
      // swap this back to isRecoverableBackendError; see isToolCallReplaySafeError.
      // A typed M365 broker refusal (no grant, expired, revoked, MFA, broker
      // not configured, mint failed) is the answer to this user's call, not a
      // tool failure: the outer catch below turns it into the enrollment
      // result and logs the one `m365_broker_refusal` line. No ERROR line for
      // a per-user state.
      if (isM365BrokerError(error)) {
        throw error;
      }
      if (!isToolCallReplaySafeError(error)) {
        logger.error(
          `Error calling tool "${name}" through ${
            clientForTool.client.getServerVersion()?.name || "unknown"
          }:`,
          error,
        );
        throw error;
      }

      logger.warn(
        `Backend connection lost for server ${serverUuid} on tool "${name}" before the call was executed; recovering the session and retrying once. (envelope: ${
          error instanceof Error ? error.message : String(error)
        })`,
      );

      // One recovery per failed client, shared by every call that fails on
      // it, and no invalidation when that client was already retired by
      // another recovery (session-recovery.ts). Parallel calls on a stale
      // client used to each invalidate the server, retiring the replacement a
      // sibling had just built and cutting calls already running on it.
      const failedClient = clientForTool;
      const routedServerUuid = serverUuid;
      let freshSession: ConnectedClient | undefined;
      try {
        freshSession = await recoverFailedSession({
          pool: mcpServerPool,
          recoveries,
          sessionId,
          serverUuid: routedServerUuid,
          failedClient,
          reacquire: async () => {
            const serverParamsMap = await getMcpServers(
              namespaceUuid,
              includeInactiveServers,
            );
            const params = serverParamsMap[routedServerUuid];
            if (!params) {
              throw new Error(
                `Cannot re-initialize session: server ${routedServerUuid} no longer present in namespace ${namespaceUuid}`,
              );
            }
            return await mcpServerPool.getSession(
              sessionId,
              routedServerUuid,
              params,
              namespaceUuid,
            );
          },
        });
      } catch (recoveryError) {
        forgetRoutesTo(failedClient);
        throw recoveryError;
      }
      if (!freshSession) {
        forgetRoutesTo(failedClient);
        throw new Error(
          `Failed to re-initialize session for server ${routedServerUuid} after backend session loss`,
        );
      }

      registerListChangedSubscriber(freshSession, routedServerUuid);
      // Replace, never delete-then-set: a call arriving while the recovery
      // ran found the old route, failed on the dead client and joined this
      // same recovery, instead of finding no route and taking the dynamic
      // lookup. Every route that pointed at the dead client moves over.
      for (const [routedName, routedClient] of Object.entries(toolToClient)) {
        if (routedClient === failedClient) {
          toolToClient[routedName] = freshSession;
        }
      }
      toolToClient[name] = freshSession;

      try {
        return (await callOnce(freshSession)) as CallToolResult;
      } catch (retryError) {
        // Same as above: a broker refusal on the retry is the user's own
        // state, answered by the outer catch, not an ERROR here.
        if (!isM365BrokerError(retryError)) {
          logger.error(
            `Error calling tool "${name}" through ${
              freshSession.client.getServerVersion()?.name || "unknown"
            } after session re-initialize:`,
            retryError,
          );
        }
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
    createAuditingMiddleware((name) => toolArgSchemas.get(name)),
    // Second, OUTSIDE the filter so it also sees the filter's fail-closed
    // denial for a deleted server: answers a call that already failed as an
    // unknown tool with the replacement from the retired-tool map. Consulted
    // only AFTER a failure, so it cannot shadow a live tool.
    createRetiredToolMiddleware(),
    // Override names resolve BEFORE the filter, so the INACTIVE check judges
    // the tool that will actually run. With the filter outside this, a call
    // by an override name (`<server>__<alias>`) reached the filter as the
    // alias, found no mapping row for it, read that as "allowed", and was then
    // routed to the original tool, so a tool curated INACTIVE stayed callable
    // by its alias while its real name was refused. This mirrors the list
    // chain above, where the filter also runs on the real names, inside the
    // rename. A name that is not an override passes this middleware unchanged,
    // so the filter sees exactly the name it saw before; an alias call is
    // refused with the same text its real name gets (it names the real tool).
    createToolOverridesCallToolMiddleware({ cacheEnabled: true }),
    createFilterCallToolMiddleware({
      cacheEnabled: true,
      customErrorMessage: (toolName, reason) =>
        `Access denied to tool "${toolName}": ${reason}`,
    }),
    // Innermost, directly around the routing handler: adds text to the
    // SDK-shaped -32001 timeout saying the outcome is unknown and a write's
    // target should be read before a retry. Same code, same data; text only.
    createTimeoutHintMiddleware(),
    // Add more middleware here as needed
    // createAuthorizationMiddleware(),
  )(originalCallToolHandler);

  // Set up the handlers with middleware
  server.setRequestHandler(ListToolsRequestSchema, async (request) => {
    const generation = ++toolSchemaGeneration;
    toolArgSchemas.replace([]);
    const result = await listToolsWithMiddleware(request, handlerContext);
    // Use final names after filters and overrides, and discard removed names.
    // Another proxy's listing cannot teach this routing instance a schema.
    // A notification or overlapping listing makes an older response unsafe to
    // retain. Counts-only is honest until a fresh uncontested listing arrives.
    toolArgSchemas.replace(
      generation === toolSchemaGeneration ? result.tools : [],
    );
    return result;
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    try {
      return await callToolWithMiddleware(request, handlerContext);
    } catch (error) {
      // WARM path: a mint failure inside the injected fetch on the
      // tools/call request itself (no enrollment, expired grant, CA
      // challenge, ...) propagates here as a typed error. This is where it
      // surfaces for m365 now: the handshake and the listings mint nothing
      // (m365/injected-fetch.ts, invariant 5). Answer with a
      // structured isError tool result carrying the enrollment URL (+
      // best-effort SEP-1036 URL elicitation) instead of an opaque
      // -32603 so the consumer can actually resolve it. Design doc §4.3.
      if (isM365BrokerError(error)) {
        return buildM365BrokerErrorResult(error, server);
      }

      // COLD path (Track A5): see cold-connect-broker-fallback.ts for the
      // full rationale — drains any broker failure client.ts latched
      // during this request's cold connect and, if it belongs to the
      // server that owns the requested tool, answers with the same
      // enrollment result the WARM path above returns. A BACKSTOP for m365
      // (its handshake mints nothing, so its connect cannot latch one);
      // kept for any other injected server.
      const coldFallback = resolveColdConnectBrokerFallback(
        request.params.name,
        server,
      );
      if (coldFallback) {
        return coldFallback;
      }
      throw error;
    }
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
    stopOwedServerWatches();
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
