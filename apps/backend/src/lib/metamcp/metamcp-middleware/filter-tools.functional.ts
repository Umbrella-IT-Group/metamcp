import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { and, eq } from "drizzle-orm";

import logger from "@/utils/logger";

import { db } from "../../../db/index";
import {
  mcpServersTable,
  namespaceToolMappingsTable,
  toolsTable,
} from "../../../db/schema";
import { parseToolName } from "../tool-name-parser";
import {
  CallToolMiddleware,
  ListToolsMiddleware,
} from "./functional-middleware";

/**
 * Configuration for the filter middleware
 */
export interface FilterToolsConfig {
  cacheEnabled?: boolean;
  cacheTTL?: number; // milliseconds
  customErrorMessage?: (toolName: string, reason: string) => string;
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
 * Get tool status from database with caching.
 *
 * A `null` return means NO mapping row exists, which the callers read as "tool
 * active by default". A DB error is deliberately NOT caught here: it must stay
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

// parseToolName is now imported from shared utility

/**
 * Get server UUID by name
 */
async function getServerUuidByName(serverName: string): Promise<string | null> {
  try {
    const [server] = await db
      .select({ uuid: mcpServersTable.uuid })
      .from(mcpServersTable)
      .where(eq(mcpServersTable.name, serverName));

    return server?.uuid || null;
  } catch (error) {
    logger.error(`Error fetching server UUID for ${serverName}:`, error);
    return null;
  }
}

/**
 * Filter tools based on their status in the namespace
 */
async function filterActiveTools(
  tools: Tool[],
  namespaceUuid: string,
  useCache: boolean = true,
): Promise<Tool[]> {
  if (!tools || tools.length === 0) {
    return tools;
  }

  const activeTools: Tool[] = [];

  await Promise.allSettled(
    tools.map(async (tool) => {
      try {
        const parsed = parseToolName(tool.name);
        if (!parsed) {
          // Not one of our prefixed tools, so tool-status curation does not
          // apply: include it unchanged.
          activeTools.push(tool);
          return;
        }

        const serverUuid = await getServerUuidByName(parsed.serverName);
        if (!serverUuid) {
          // FAIL CLOSED (operator decision 2026-09-02): an unresolved server
          // means we cannot confirm the tool is enabled, so exclude it rather
          // than serve a possibly-disabled tool. This matches the access-group
          // gate's fail-closed direction; the two layers used to disagree.
          return;
        }

        const status = await getToolStatus(
          namespaceUuid,
          parsed.originalToolName,
          serverUuid,
          useCache,
        );

        // If no mapping exists or tool is active, include it
        if (status === null || status === "ACTIVE") {
          activeTools.push(tool);
        }
        // If status is "INACTIVE", tool is filtered out
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
  serverUuid: string,
  useCache: boolean = true,
): Promise<{ allowed: boolean; reason?: string }> {
  try {
    const parsed = parseToolName(toolName);
    if (!parsed) {
      // If tool name doesn't follow expected format, allow it
      return { allowed: true };
    }

    const status = await getToolStatus(
      namespaceUuid,
      parsed.originalToolName,
      serverUuid,
      useCache,
    );

    // If no mapping exists or tool is active, allow it
    if (status === null || status === "ACTIVE") {
      return { allowed: true };
    }

    // Tool is inactive
    return {
      allowed: false,
      reason: "Tool has been marked as inactive in this namespace",
    };
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
 * Creates a Call Tool middleware that blocks calls to inactive tools
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
      // Extract tool name and server info from the request
      const toolName = request.params.name;

      // We need to get serverUuid somehow - this would need to be passed through context
      // For now, let's extract it from the tool name format
      const parsed = parseToolName(toolName);
      if (parsed) {
        const serverUuid = await getServerUuidByName(parsed.serverName);
        // FAIL CLOSED (operator decision 2026-09-02): a server-name miss (row
        // absent, or a DB error surfacing as a null from getServerUuidByName)
        // used to skip this check entirely and let the call through. Deny
        // instead, so the call side agrees with the list side and the
        // access-group gate on failure direction.
        const { allowed, reason } = serverUuid
          ? await isToolAllowed(
              toolName,
              context.namespaceUuid,
              serverUuid,
              useCache,
            )
          : { allowed: false, reason: "server could not be resolved" };

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
      }

      // Tool is allowed, call the original handler
      return handler(request, context);
    };
  };
}

/**
 * Utility function to clear cache
 */
export function clearFilterCache(namespaceUuid?: string): void {
  toolStatusCache.clear(namespaceUuid);
}
