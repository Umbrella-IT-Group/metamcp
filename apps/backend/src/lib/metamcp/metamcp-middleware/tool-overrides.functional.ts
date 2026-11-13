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
  MetaMCPHandlerContext,
} from "./functional-middleware";
import { findNamespaceServerUuidsByName } from "./namespace-server-lookup";

/**
 * Configuration for the tool overrides middleware
 */
export interface ToolOverridesConfig {
  cacheEnabled?: boolean;
  cacheTTL?: number; // milliseconds
  persistentCacheOnListTools?: boolean; // if true, cache never expires when set via list tools
}

/**
 * A listing that must know which backend tool each listed name stands for
 * passes a sink on its per-call context, and the list middleware below records
 * into it: for every tool it lists, the listed name (the alias, when the tool
 * is overridden) and the tool's ORIGINAL full name (`<server>__<tool>`, which
 * carries both the backend server and the backend's own tool name).
 *
 * The lean tool listing is the one reader (lean-listing.ts): its read-only
 * verdict is a statement about a tool, and the call chain later resolves a name
 * to a tool of its own accord, so the verdict has to be tied to the tool it was
 * given for. A per-call context field, never module or handler state, so two
 * listings running at once (two sessions, or a client listing beside a search)
 * cannot write into each other's sink. A name listed twice (two overrides that
 * collide) has two entries, which the reader treats as unidentifiable.
 */
export interface ListingOriginsContext extends MetaMCPHandlerContext {
  listingOrigins?: Map<string, string[]>;
  /** Filled at route registration, before another listing can replace that route. */
  listingServerUuids?: Map<string, string>;
}

/**
 * Tool override information
 */
interface ToolOverride {
  overrideName?: string | null;
  overrideTitle?: string | null;
  overrideDescription?: string | null;
  overrideAnnotations?: Record<string, unknown> | null;
}

function mergeAnnotations(
  original: Tool["annotations"],
  namespaceOverrides?: Record<string, unknown> | null,
): Tool["annotations"] | undefined {
  if (!namespaceOverrides || Object.keys(namespaceOverrides).length === 0) {
    return original;
  }

  const baseAnnotations = (original ? { ...original } : {}) as Record<
    string,
    unknown
  >;

  for (const [key, value] of Object.entries(namespaceOverrides)) {
    baseAnnotations[key] = value;
  }

  return baseAnnotations as Tool["annotations"];
}

/**
 * Tool overrides cache for performance
 */
class ToolOverridesCache {
  private overrideCache = new Map<string, ToolOverride>();
  private reverseNameCache = new Map<string, string>(); // (server, overrideName) -> originalName
  private expiry = new Map<string, number>();
  private persistentKeys = new Set<string>(); // keys that never expire
  private ttl: number;
  private generation = 0;

  constructor(ttl: number = 1000) {
    this.ttl = ttl;
  }

  private getCacheKey(
    namespaceUuid: string,
    serverName: string,
    toolName: string,
  ): string {
    return `${namespaceUuid}:${serverName}:${toolName}`;
  }

  /**
   * The reverse key carries the SERVER as well as the override name, because
   * an override name is only unique per server: two servers in one namespace
   * may give different tools the same alias. Keyed by namespace and alias
   * alone, the first server to cache an alias answered for every server, so a
   * call to `serverB__X` was routed to serverA's tool once serverA's `X` was
   * cached (the database path below always checked the server; only the cache
   * hit did not). The server and alias are JSON-encoded so a name containing
   * the `:` separator cannot make two different pairs share a key; the
   * `${namespaceUuid}:` prefix stays plain so `clear(namespaceUuid)` still
   * matches it.
   */
  private getReverseKey(
    namespaceUuid: string,
    serverName: string,
    overrideName: string,
  ): string {
    return `${namespaceUuid}:${JSON.stringify([serverName, overrideName])}`;
  }

  get(
    namespaceUuid: string,
    serverName: string,
    toolName: string,
  ): ToolOverride | null {
    const key = this.getCacheKey(namespaceUuid, serverName, toolName);

    // Check if this is a persistent key that never expires
    if (this.persistentKeys.has(key)) {
      return this.overrideCache.get(key) || null;
    }

    const expiry = this.expiry.get(key);

    if (!expiry || Date.now() > expiry) {
      this.overrideCache.delete(key);
      this.expiry.delete(key);
      return null;
    }

    return this.overrideCache.get(key) || null;
  }

  set(
    namespaceUuid: string,
    serverName: string,
    toolName: string,
    override: ToolOverride,
    isPersistent: boolean = false,
  ): void {
    const key = this.getCacheKey(namespaceUuid, serverName, toolName);
    this.overrideCache.set(key, override);

    if (isPersistent) {
      // Mark as persistent - never expires
      this.persistentKeys.add(key);
    } else {
      // Set normal expiry
      this.expiry.set(key, Date.now() + this.ttl);
    }

    // Also cache reverse lookup if there's an override name
    if (override.overrideName) {
      const reverseKey = this.getReverseKey(
        namespaceUuid,
        serverName,
        override.overrideName,
      );
      this.reverseNameCache.set(reverseKey, `${serverName}__${toolName}`);
    }
  }

  getOriginalName(
    namespaceUuid: string,
    serverName: string,
    overrideName: string,
  ): string | null {
    const reverseKey = this.getReverseKey(
      namespaceUuid,
      serverName,
      overrideName,
    );
    return this.reverseNameCache.get(reverseKey) || null;
  }

  setOriginalName(
    namespaceUuid: string,
    serverName: string,
    overrideName: string,
    originalName: string,
  ): void {
    const reverseKey = this.getReverseKey(
      namespaceUuid,
      serverName,
      overrideName,
    );
    this.reverseNameCache.set(reverseKey, originalName);
  }

  getGeneration(): number {
    return this.generation;
  }

  clear(namespaceUuid?: string): void {
    this.generation += 1;
    if (namespaceUuid) {
      for (const key of this.overrideCache.keys()) {
        if (key.startsWith(`${namespaceUuid}:`)) {
          this.overrideCache.delete(key);
          this.expiry.delete(key);
          this.persistentKeys.delete(key);
        }
      }
      for (const key of this.reverseNameCache.keys()) {
        if (key.startsWith(`${namespaceUuid}:`)) {
          this.reverseNameCache.delete(key);
        }
      }
    } else {
      this.overrideCache.clear();
      this.reverseNameCache.clear();
      this.expiry.clear();
      this.persistentKeys.clear();
    }
  }
}

// Global cache instance
const toolOverridesCache = new ToolOverridesCache();

/**
 * Get tool overrides from database with caching
 */
async function getToolOverrides(
  namespaceUuid: string,
  serverName: string,
  toolName: string,
  useCache: boolean = true,
  isPersistent: boolean = false,
): Promise<ToolOverride | null | undefined> {
  // Check cache first
  if (useCache) {
    const cached = toolOverridesCache.get(namespaceUuid, serverName, toolName);
    if (cached !== null) {
      return cached;
    }
  }

  const generation = toolOverridesCache.getGeneration();
  try {
    // The server this prefix means IN THIS NAMESPACE (upstream
    // metatool-ai/metamcp#364, see namespace-server-lookup.ts). Resolved by
    // name alone, the lookup could land on another owner's same-named server,
    // find no mapping row there, and silently drop this namespace's override.
    // Every mount, whatever its status: this only maps an alias to its tool.
    // The filter, composed inside this middleware, decides whether an INACTIVE
    // mount may serve it.
    const serverUuids = await findNamespaceServerUuidsByName(
      namespaceUuid,
      serverName,
      "any",
    );

    if (serverUuids.length !== 1) {
      if (serverUuids.length > 1) {
        // Two mounted servers share the name, so which one's override applies
        // cannot be told from the prefix; the routing maps already warn about
        // the collision. Apply none rather than pick by heap order: the tool
        // then shows under its real name, and the filter judges it against
        // both servers.
        logger.warn(
          `Tool overrides skipped for ${serverName}__${toolName} in namespace ${namespaceUuid}: ${serverUuids.length} mounted servers share the name "${serverName}"`,
        );
      }
      return null;
    }
    const server = { uuid: serverUuids[0] };

    // Query database for tool overrides
    const [toolMapping] = await db
      .select({
        overrideName: namespaceToolMappingsTable.override_name,
        overrideTitle: namespaceToolMappingsTable.override_title,
        overrideDescription: namespaceToolMappingsTable.override_description,
        overrideAnnotations: namespaceToolMappingsTable.override_annotations,
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
          eq(namespaceToolMappingsTable.mcp_server_uuid, server.uuid),
        ),
      );

    const override: ToolOverride = {
      overrideName: toolMapping?.overrideName || null,
      overrideTitle:
        typeof toolMapping?.overrideTitle !== "undefined"
          ? toolMapping.overrideTitle
          : undefined,
      overrideDescription: toolMapping?.overrideDescription || null,
      overrideAnnotations: toolMapping?.overrideAnnotations || null,
    };

    // Cache the result if found and caching is enabled
    // A read already in flight when the setter clears must not resurrect its
    // old annotations or aliases, especially in the persistent listing cache.
    if (
      toolMapping &&
      useCache &&
      generation === toolOverridesCache.getGeneration()
    ) {
      toolOverridesCache.set(
        namespaceUuid,
        serverName,
        toolName,
        override,
        isPersistent,
      );
    }

    return override;
  } catch (error) {
    logger.error(
      `Error fetching tool overrides for ${toolName} in namespace ${namespaceUuid}:`,
      error,
    );
    return undefined;
  }
}

// parseToolName is now imported from shared utility

/**
 * Apply overrides to tools
 */
async function applyToolOverrides(
  tools: Tool[],
  namespaceUuid: string,
  useCache: boolean = true,
  isPersistent: boolean = false,
  origins?: Map<string, string[]>,
): Promise<Tool[]> {
  if (!tools || tools.length === 0) {
    return tools;
  }

  const generation = toolOverridesCache.getGeneration();
  const overriddenTools: Tool[] = [];
  // Every tool leaves through here, so the sink (ListingOriginsContext) hears
  // of each one exactly once, under the name the listing shows it by.
  const emit = (listed: Tool, originalName?: string): void => {
    overriddenTools.push(listed);
    if (originalName === undefined) return;
    const known = origins?.get(listed.name);
    if (known) known.push(originalName);
    else origins?.set(listed.name, [originalName]);
  };

  await Promise.allSettled(
    tools.map(async (tool) => {
      try {
        const parsed = parseToolName(tool.name);
        if (!parsed) {
          // If tool name doesn't follow expected format, include as-is
          emit(tool, tool.name);
          return;
        }

        const override = await getToolOverrides(
          namespaceUuid,
          parsed.serverName,
          parsed.originalToolName,
          useCache,
          isPersistent,
        );

        if (!override) {
          // Failed lookups keep the direct listing's fallback, but cannot
          // establish effective hints for the read-only lean call tool.
          emit(tool, override === undefined ? undefined : tool.name);
          return;
        }

        // Apply overrides - preserve server prefix format
        // For name: only apply if overrideName is not null and not empty
        const overriddenName =
          override.overrideName && override.overrideName.trim() !== ""
            ? `${parsed.serverName}__${override.overrideName}`
            : tool.name;

        // For description: apply override if it's not null, even if empty string
        // This allows users to explicitly set empty descriptions
        const overriddenDescription =
          override.overrideDescription !== null
            ? override.overrideDescription
            : tool.description;

        // For title: apply override if provided (null means no override)
        let overriddenTitle: string | undefined = tool.title;
        if (typeof override.overrideTitle !== "undefined") {
          overriddenTitle =
            override.overrideTitle === null
              ? undefined
              : override.overrideTitle;
        }

        let overriddenAnnotations =
          tool.annotations && Object.keys(tool.annotations).length > 0
            ? { ...tool.annotations }
            : undefined;

        if (overriddenAnnotations && "title" in overriddenAnnotations) {
          // Strip legacy title hint to avoid conflicting with top-level title

          const { title: _removed, ...rest } = overriddenAnnotations;
          overriddenAnnotations =
            Object.keys(rest).length > 0 ? rest : undefined;
        }

        overriddenAnnotations = mergeAnnotations(
          overriddenAnnotations,
          override.overrideAnnotations,
        );

        const overriddenTool: Tool = {
          ...tool,
          name: overriddenName,
          title: overriddenTitle,
          description: overriddenDescription,
          annotations: overriddenAnnotations,
        };

        // Update reverse mapping cache for the new full override name
        if (
          override.overrideName &&
          useCache &&
          generation === toolOverridesCache.getGeneration()
        ) {
          toolOverridesCache.setOriginalName(
            namespaceUuid,
            parsed.serverName,
            override.overrideName,
            tool.name,
          );
        }

        emit(overriddenTool, tool.name);
      } catch (error) {
        logger.error(`Error applying overrides for tool ${tool.name}:`, error);
        // Preserve the ordinary listing, without a read-only identity proof.
        emit(tool);
      }
    }),
  );

  return overriddenTools;
}

/**
 * Map override name back to original name for tool calls
 */
export async function mapOverrideNameToOriginal(
  toolName: string,
  namespaceUuid: string,
  useCache: boolean = true,
): Promise<string> {
  // Parse the tool name to extract server and tool parts
  const parsed = parseToolName(toolName);
  if (!parsed) {
    // If tool name doesn't follow expected format, return as-is
    return toolName;
  }

  // First check if this might be an override name ON THIS SERVER (the server
  // prefix is part of the key; see getReverseKey)
  if (useCache) {
    const originalName = toolOverridesCache.getOriginalName(
      namespaceUuid,
      parsed.serverName,
      parsed.originalToolName,
    );
    if (originalName) {
      return originalName;
    }
  }

  // If not found in cache or cache disabled, query database
  const generation = toolOverridesCache.getGeneration();
  try {
    const [toolMapping] = await db
      .select({
        originalName: toolsTable.name,
        serverName: mcpServersTable.name,
      })
      .from(namespaceToolMappingsTable)
      .innerJoin(
        toolsTable,
        eq(toolsTable.uuid, namespaceToolMappingsTable.tool_uuid),
      )
      .innerJoin(
        mcpServersTable,
        eq(mcpServersTable.uuid, namespaceToolMappingsTable.mcp_server_uuid),
      )
      .where(
        and(
          eq(namespaceToolMappingsTable.namespace_uuid, namespaceUuid),
          eq(namespaceToolMappingsTable.override_name, parsed.originalToolName),
          eq(mcpServersTable.name, parsed.serverName),
        ),
      );

    if (toolMapping) {
      const originalFullName = `${toolMapping.serverName}__${toolMapping.originalName}`;

      // Cache the reverse mapping under the server prefix and the tool part
      if (useCache && generation === toolOverridesCache.getGeneration()) {
        toolOverridesCache.setOriginalName(
          namespaceUuid,
          parsed.serverName,
          parsed.originalToolName,
          originalFullName,
        );
      }

      return originalFullName;
    }
  } catch (error) {
    logger.error(
      `Error mapping override name ${toolName} to original in namespace ${namespaceUuid}:`,
      error,
    );
  }

  // If no mapping found, return the original name
  return toolName;
}

/**
 * Creates a List Tools middleware that applies tool name/description overrides
 */
export function createToolOverridesListToolsMiddleware(
  config: ToolOverridesConfig = {},
): ListToolsMiddleware {
  const useCache = config.cacheEnabled ?? true;
  const isPersistent = config.persistentCacheOnListTools ?? false;

  return (handler) => {
    return async (request, context) => {
      // Call the original handler to get the tools
      const response = await handler(request, context);

      // Apply overrides to the tools
      if (response.tools) {
        const overriddenTools = await applyToolOverrides(
          response.tools,
          context.namespaceUuid,
          useCache,
          isPersistent,
          (context as ListingOriginsContext).listingOrigins,
        );

        return {
          ...response,
          tools: overriddenTools,
        };
      }

      return response;
    };
  };
}

/**
 * Creates a Call Tool middleware that maps override names back to original names
 */
export function createToolOverridesCallToolMiddleware(
  config: ToolOverridesConfig = {},
): CallToolMiddleware {
  const useCache = config.cacheEnabled ?? true;

  return (handler) => {
    return async (request, context) => {
      // Map override name back to original name if needed
      const originalToolName = await mapOverrideNameToOriginal(
        request.params.name,
        context.namespaceUuid,
        useCache,
      );

      // Create a new request with the original tool name
      const modifiedRequest = {
        ...request,
        params: {
          ...request.params,
          name: originalToolName,
        },
      };

      // Call the original handler with the modified request
      return handler(modifiedRequest, context);
    };
  };
}

/**
 * Who wants to hear that a namespace's overrides changed: the lean tool
 * listing's snapshot, which holds each tool's name, hints and identity as the
 * overrides had them (lean-listing.ts).
 */
const overrideChangeListeners = new Map<string, Set<() => void>>();

/**
 * Run `listener` whenever the override cache of `namespaceUuid`, or of every
 * namespace, is cleared. Returns the function that removes it.
 */
export function onOverrideCacheCleared(
  namespaceUuid: string,
  listener: () => void,
): () => void {
  let set = overrideChangeListeners.get(namespaceUuid);
  if (!set) {
    set = new Set();
    overrideChangeListeners.set(namespaceUuid, set);
  }
  set.add(listener);
  return () => {
    const current = overrideChangeListeners.get(namespaceUuid);
    if (!current) return;
    current.delete(listener);
    if (current.size === 0) overrideChangeListeners.delete(namespaceUuid);
  };
}

/** Test seam: how many listeners a namespace holds. */
export function overrideChangeListenerCount(namespaceUuid: string): number {
  return overrideChangeListeners.get(namespaceUuid)?.size ?? 0;
}

/**
 * Utility function to clear override cache.
 *
 * It is also the signal that overrides CHANGED: every path that writes an
 * override name, a title, a description or an annotation override, or that
 * adds, renames or removes the server the overrides belong to, already calls
 * it after the write so alias resolution and the listing re-read the table
 * (`namespaces.updateToolOverrides`, the namespace and server updates and
 * deletions). Hanging the lean snapshot's drop on this one call covers all of
 * them, and any path added later that clears the cache correctly, without a
 * second list of setters to keep in step. It does not fire for a policy change
 * (`clearFilterCache`): a snapshot may lag a policy change, and says so.
 *
 * A listener that throws is logged and does not stop the others or the caller,
 * which is an admin write that has already committed.
 */
export function clearOverrideCache(namespaceUuid?: string): void {
  toolOverridesCache.clear(namespaceUuid);
  const heard =
    namespaceUuid === undefined
      ? Array.from(overrideChangeListeners.values()).flatMap((set) =>
          Array.from(set),
        )
      : Array.from(overrideChangeListeners.get(namespaceUuid) ?? []);
  for (const listener of heard) {
    try {
      listener();
    } catch (error) {
      logger.error(
        "A live lean session failed to drop its tool snapshot after an override change; its next search may show the previous overrides until the snapshot expires:",
        error,
      );
    }
  }
}
