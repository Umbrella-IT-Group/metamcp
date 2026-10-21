import { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { NamespaceToolPolicy } from "@repo/zod-types";
import { and, eq } from "drizzle-orm";

import logger from "@/utils/logger";

import { db } from "../../../db/index";
import {
  namespacesTable,
  namespaceToolMappingsTable,
  toolsTable,
} from "../../../db/schema";
import { parseToolName } from "../tool-name-parser";
import {
  CallToolMiddleware,
  ListToolsMiddleware,
  MetaMCPHandlerContext,
} from "./functional-middleware";
import { findNamespaceServerUuidsByName } from "./namespace-server-lookup";

/**
 * Configuration for the filter middleware
 */
export interface FilterToolsConfig {
  cacheEnabled?: boolean;
  cacheTTL?: number; // milliseconds
  customErrorMessage?: (toolName: string, reason: string) => string;
}

/** The routing handler may use only the servers this call's filter judged. */
export interface ToolFilterCallContext extends MetaMCPHandlerContext {
  allowedToolServerUuids?: readonly string[];
  /**
   * The namespace tool policy this call was judged under. The routing handler
   * routes a tool with no mapping row through its prefix-matched server only
   * under `allow_all` (tool-call-routing.ts), so it reads the same policy the
   * verdict used rather than reading it again. Absent when no filter ran, and
   * the handler then never widens.
   */
  toolPolicy?: NamespaceToolPolicy;
}

/**
 * Tool status cache for performance
 */
class ToolStatusCache {
  private cache = new Map<string, "ACTIVE" | "INACTIVE">();
  private expiry = new Map<string, number>();
  private ttl: number;

  constructor(ttl: number = 1000) {
    this.ttl = ttl;
  }

  private getCacheKey(
    namespaceUuid: string,
    toolName: string,
    serverUuid: string,
  ): string {
    return `${namespaceUuid}:${serverUuid}:${toolName}`;
  }

  get(
    namespaceUuid: string,
    toolName: string,
    serverUuid: string,
  ): "ACTIVE" | "INACTIVE" | null {
    const key = this.getCacheKey(namespaceUuid, toolName, serverUuid);
    const expiry = this.expiry.get(key);

    if (!expiry || Date.now() > expiry) {
      this.cache.delete(key);
      this.expiry.delete(key);
      return null;
    }

    return this.cache.get(key) || null;
  }

  set(
    namespaceUuid: string,
    toolName: string,
    serverUuid: string,
    status: "ACTIVE" | "INACTIVE",
  ): void {
    const key = this.getCacheKey(namespaceUuid, toolName, serverUuid);
    this.cache.set(key, status);
    this.expiry.set(key, Date.now() + this.ttl);
  }

  clear(namespaceUuid?: string): void {
    if (namespaceUuid) {
      for (const key of this.cache.keys()) {
        if (key.startsWith(`${namespaceUuid}:`)) {
          this.cache.delete(key);
          this.expiry.delete(key);
        }
      }
    } else {
      this.cache.clear();
      this.expiry.clear();
    }
  }
}

// Global cache instance
const toolStatusCache = new ToolStatusCache();

/**
 * Namespace tool-policy cache, same 1 s lifetime as the status cache above so
 * a flip made through `namespaces.setToolPolicy` takes effect within a second
 * even on a path that did not clear it (the setter clears it outright).
 */
class ToolPolicyCache {
  private cache = new Map<
    string,
    { policy: NamespaceToolPolicy; expiresAt: number }
  >();
  private ttl: number;
  private generation = 0;

  constructor(ttl: number = 1000) {
    this.ttl = ttl;
  }

  get(namespaceUuid: string): NamespaceToolPolicy | null {
    const entry = this.cache.get(namespaceUuid);
    if (!entry || Date.now() > entry.expiresAt) {
      this.cache.delete(namespaceUuid);
      return null;
    }
    return entry.policy;
  }

  getGeneration(): number {
    return this.generation;
  }

  set(
    namespaceUuid: string,
    policy: NamespaceToolPolicy,
    generation: number,
  ): void {
    // A read started before a policy flip can finish after the setter cleared
    // the cache. It must not re-cache allow_all and reopen later calls.
    if (generation !== this.generation) return;
    this.cache.set(namespaceUuid, {
      policy,
      expiresAt: Date.now() + this.ttl,
    });
  }

  clear(namespaceUuid?: string): void {
    this.generation++;
    if (namespaceUuid) {
      this.cache.delete(namespaceUuid);
    } else {
      this.cache.clear();
    }
  }
}

const toolPolicyCache = new ToolPolicyCache();

/**
 * The namespace's tool policy (migration 0040), with caching.
 *
 * `allow_all` is the original behaviour: a tool with no mapping row is served.
 * `allowlist`: no row means INACTIVE, so only an ACTIVE row serves a tool.
 *
 * FAIL CLOSED, the same direction as the rest of this file (operator decision
 * 2026-09-02): a database error propagates to the caller, which excludes or
 * denies, and a namespace that does not exist throws rather than defaulting to
 * `allow_all`. Any stored value other than `allow_all` reads as `allowlist`;
 * the CHECK constraint makes that unreachable, and if it were ever bypassed the
 * stricter reading is the safe one.
 */
async function getNamespaceToolPolicy(
  namespaceUuid: string,
  useCache: boolean = true,
): Promise<NamespaceToolPolicy> {
  if (useCache) {
    const cached = toolPolicyCache.get(namespaceUuid);
    if (cached !== null) {
      return cached;
    }
  }

  const generation = toolPolicyCache.getGeneration();
  const [namespace] = await db
    .select({ toolPolicy: namespacesTable.tool_policy })
    .from(namespacesTable)
    .where(eq(namespacesTable.uuid, namespaceUuid));

  if (!namespace) {
    throw new Error(`namespace ${namespaceUuid} not found`);
  }

  const policy: NamespaceToolPolicy =
    namespace.toolPolicy === "allow_all" ? "allow_all" : "allowlist";

  if (useCache) {
    toolPolicyCache.set(namespaceUuid, policy, generation);
  }

  return policy;
}

/** Why a tool is refused, as the call side reports it. */
const INACTIVE_REASON = "Tool has been marked as inactive in this namespace";
const NOT_ALLOWLISTED_REASON = "Tool is not on this namespace's allowlist";

/**
 * One tool's verdict on one server, given that server's mapping status (null
 * when there is no row) and the namespace's policy. `allow_all`: served
 * unless the row is INACTIVE. `allowlist`: served only when the row is ACTIVE.
 * The single place the two policies differ, so the list path and the call
 * path cannot disagree about them.
 */
function judgeToolStatus(
  status: "ACTIVE" | "INACTIVE" | null,
  policy: NamespaceToolPolicy,
): { served: true } | { served: false; reason: string } {
  if (status === "ACTIVE") {
    return { served: true };
  }
  if (status === "INACTIVE") {
    return { served: false, reason: INACTIVE_REASON };
  }
  // No mapping row.
  return policy === "allow_all"
    ? { served: true }
    : { served: false, reason: NOT_ALLOWLISTED_REASON };
}

/**
 * Judge a parsed `<server>__<tool>` against every server mounted in the
 * namespace under that prefix. Served only when it is served on EVERY
 * candidate: with one candidate (the normal case) that is just its verdict;
 * with two same-named mounted servers (possible, see
 * namespace-server-lookup.ts) the routing maps keep whichever registered
 * first, which this middleware cannot see, so the tool is refused unless both
 * would serve it. No candidate at all is "server could not be resolved".
 * Errors propagate; callers fail closed.
 */
async function judgeParsedTool(
  namespaceUuid: string,
  serverUuids: string[],
  originalToolName: string,
  policy: NamespaceToolPolicy,
  useCache: boolean,
): Promise<{ served: true } | { served: false; reason: string }> {
  if (serverUuids.length === 0) {
    return { served: false, reason: "server could not be resolved" };
  }
  for (const serverUuid of serverUuids) {
    const status = await getToolStatus(
      namespaceUuid,
      originalToolName,
      serverUuid,
      useCache,
    );
    const verdict = judgeToolStatus(status, policy);
    if (!verdict.served) {
      return verdict;
    }
  }
  return { served: true };
}

/**
 * Get tool status from database with caching.
 *
 * A `null` return means NO mapping row exists, which the callers read through
 * the namespace's tool policy: served under `allow_all`, refused under
 * `allowlist` (see judgeToolStatus). A DB error is deliberately NOT caught here: it must stay
 * distinguishable from that legitimate `null`, so it propagates and each caller
 * fails CLOSED (operator decision 2026-09-02). Swallowing it to `null` would
 * silently re-enable a disabled tool the moment the database blips, the
 * opposite of how the access-group gate behaves.
 */
async function getToolStatus(
  namespaceUuid: string,
  toolName: string,
  serverUuid: string,
  useCache: boolean = true,
): Promise<"ACTIVE" | "INACTIVE" | null> {
  // Check cache first
  if (useCache) {
    const cached = toolStatusCache.get(namespaceUuid, toolName, serverUuid);
    if (cached !== null) {
      return cached;
    }
  }

  // Query database for tool status
  const [toolMapping] = await db
    .select({
      status: namespaceToolMappingsTable.status,
    })
    .from(namespaceToolMappingsTable)
    .innerJoin(
      toolsTable,
      eq(toolsTable.uuid, namespaceToolMappingsTable.tool_uuid),
    )
    .where(
      and(
        eq(namespaceToolMappingsTable.namespace_uuid, namespaceUuid),
        eq(toolsTable.name, toolName),
        eq(namespaceToolMappingsTable.mcp_server_uuid, serverUuid),
      ),
    );

  const status = toolMapping?.status || null;

  // Cache the result if found and caching is enabled
  if (status && useCache) {
    toolStatusCache.set(namespaceUuid, toolName, serverUuid, status);
  }

  return status;
}

/**
 * Filter tools based on their status in the namespace and the namespace's
 * tool policy.
 */
async function filterActiveTools(
  tools: Tool[],
  namespaceUuid: string,
  useCache: boolean = true,
): Promise<Tool[]> {
  if (!tools || tools.length === 0) {
    return tools;
  }

  let policy: NamespaceToolPolicy;
  try {
    policy = await getNamespaceToolPolicy(namespaceUuid, useCache);
  } catch (error) {
    // FAIL CLOSED (operator decision 2026-09-02): without the policy no tool
    // can be judged, so none is served.
    logger.error(
      `Error reading the tool policy of namespace ${namespaceUuid}; serving no tools:`,
      error,
    );
    return [];
  }

  // One server lookup per prefix per listing, not per tool. A rejected lookup
  // stays rejected for every tool that shares the prefix, so each of them is
  // excluded by its own catch below.
  const serverLookups = new Map<string, Promise<string[]>>();
  const serversFor = (serverName: string): Promise<string[]> => {
    let lookup = serverLookups.get(serverName);
    if (!lookup) {
      lookup = findNamespaceServerUuidsByName(namespaceUuid, serverName);
      serverLookups.set(serverName, lookup);
    }
    return lookup;
  };

  const activeTools: Tool[] = [];

  await Promise.allSettled(
    tools.map(async (tool) => {
      try {
        const parsed = parseToolName(tool.name);
        if (!parsed) {
          // Not one of our prefixed tools, so no mapping row can exist for
          // it. `allow_all` includes it unchanged, as before; `allowlist`
          // reads "no row" as INACTIVE, so it is excluded.
          if (policy === "allow_all") {
            activeTools.push(tool);
          }
          return;
        }

        // FAIL CLOSED (operator decision 2026-09-02): a prefix that matches
        // no server mounted in this namespace means we cannot confirm the
        // tool is enabled, so judgeParsedTool excludes it rather than serve a
        // possibly-disabled tool. This matches the access-group gate's
        // fail-closed direction; the two layers used to disagree.
        const verdict = await judgeParsedTool(
          namespaceUuid,
          await serversFor(parsed.serverName),
          parsed.originalToolName,
          policy,
          useCache,
        );

        if (verdict.served) {
          activeTools.push(tool);
        }
      } catch (error) {
        logger.error(`Error checking tool status for ${tool.name}:`, error);
        // FAIL CLOSED (operator decision 2026-09-02): a DB error must not
        // silently re-enable a disabled tool, so exclude it rather than
        // include. Was fail-open (include on error).
      }
    }),
  );

  return activeTools;
}

/**
 * Check if a tool is allowed to be called
 */
async function isToolAllowed(
  toolName: string,
  namespaceUuid: string,
  useCache: boolean = true,
): Promise<{
  allowed: boolean;
  reason?: string;
  serverUuids?: string[];
  policy?: NamespaceToolPolicy;
}> {
  try {
    const policy = await getNamespaceToolPolicy(namespaceUuid, useCache);

    const parsed = parseToolName(toolName);
    if (!parsed) {
      // Not one of our prefixed names, so no mapping row can exist for it:
      // `allow_all` lets it through to the handler as before (which rejects
      // the format); `allowlist` refuses it here.
      return policy === "allow_all"
        ? { allowed: true, policy }
        : { allowed: false, reason: NOT_ALLOWLISTED_REASON };
    }

    // FAIL CLOSED (operator decision 2026-09-02): a server-name miss (no
    // server mounted in this namespace under that prefix) used to skip this
    // check entirely and let the call through. judgeParsedTool denies
    // instead, so the call side agrees with the list side and the
    // access-group gate on failure direction.
    const serverUuids = await findNamespaceServerUuidsByName(
      namespaceUuid,
      parsed.serverName,
    );
    const verdict = await judgeParsedTool(
      namespaceUuid,
      serverUuids,
      parsed.originalToolName,
      policy,
      useCache,
    );

    return verdict.served
      ? { allowed: true, serverUuids, policy }
      : { allowed: false, reason: verdict.reason };
  } catch (error) {
    logger.error(
      `Error checking if tool ${toolName} is allowed in namespace ${namespaceUuid}:`,
      error,
    );
    // FAIL CLOSED (operator decision 2026-09-02): deny on error rather than
    // allow, so a DB blip cannot let a call through to a tool that may be
    // disabled. Matches the access-group gate; was fail-open (allow on error).
    return {
      allowed: false,
      reason: "tool status could not be verified",
    };
  }
}

/**
 * Creates a List Tools middleware that filters out inactive tools
 */
export function createFilterListToolsMiddleware(
  config: FilterToolsConfig = {},
): ListToolsMiddleware {
  const useCache = config.cacheEnabled ?? true;

  return (handler) => {
    return async (request, context) => {
      // Call the original handler to get the tools
      const response = await handler(request, context);

      // Filter the tools based on namespace tool mappings
      if (response.tools) {
        const filteredTools = await filterActiveTools(
          response.tools,
          context.namespaceUuid,
          useCache,
        );

        return {
          ...response,
          tools: filteredTools,
        };
      }

      return response;
    };
  };
}

/**
 * Creates a Call Tool middleware that blocks calls to inactive tools.
 *
 * It judges the name it is handed, and an override name has no mapping row of
 * its own (it reads as "no mapping": allowed under `allow_all`, refused under
 * `allowlist`, wrong either way), so it must be composed INSIDE
 * `createToolOverridesCallToolMiddleware`, which resolves an override name to
 * the original tool first. See the call chains in `metamcp-proxy.ts` and
 * `routers/public-metamcp/openapi/handlers.ts`.
 */
export function createFilterCallToolMiddleware(
  config: FilterToolsConfig = {},
): CallToolMiddleware {
  const useCache = config.cacheEnabled ?? true;
  const customErrorMessage =
    config.customErrorMessage ??
    ((toolName: string, reason: string) =>
      `Tool "${toolName}" is currently inactive and disallowed in this namespace: ${reason}`);

  return (handler) => {
    return async (request, context) => {
      const toolName = request.params.name;

      // The server is resolved from the tool name's prefix among the servers
      // mounted in THIS namespace (namespace-server-lookup.ts), never by name
      // across the whole estate.
      const { allowed, reason, serverUuids, policy } = await isToolAllowed(
        toolName,
        context.namespaceUuid,
        useCache,
      );

      if (!allowed) {
        // Return error response instead of calling the handler
        return {
          content: [
            {
              type: "text",
              text: customErrorMessage(toolName, reason || "Unknown reason"),
            },
          ],
          isError: true,
        };
      }

      // Bind the verdict to the server identities it checked. A pooled proxy
      // can still hold a route for a server replaced by a same-named mount.
      // Clone the instance context so concurrent calls cannot share verdicts.
      const callContext: ToolFilterCallContext = {
        ...context,
        allowedToolServerUuids: serverUuids,
        toolPolicy: policy,
      };
      return handler(request, callContext);
    };
  };
}

/**
 * Utility function to clear cache: the tool statuses and the tool policy, for
 * one namespace or all of them.
 */
export function clearFilterCache(namespaceUuid?: string): void {
  toolStatusCache.clear(namespaceUuid);
  toolPolicyCache.clear(namespaceUuid);
}
