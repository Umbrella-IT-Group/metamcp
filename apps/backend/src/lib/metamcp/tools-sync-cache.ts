import crypto from "crypto";

/**
 * The subset of a tool definition that participates in the sync hash.
 * A backend can change a tool's schema or description WITHOUT renaming it
 * (e.g. a new required arg, a reworded description), so all three fields —
 * not just the name — must feed the hash or such a change never resyncs.
 */
export interface ToolDefinition {
  name: string;
  description?: string | null;
  inputSchema?: unknown;
}

/**
 * Deterministic JSON serialization: object keys are emitted in sorted order at
 * every depth so that two structurally-equal definitions produce byte-identical
 * output regardless of the key order the backend happened to send. Arrays keep
 * their order (element order is semantically meaningful, e.g. `required`), so
 * tool-array ordering is normalized separately by sorting on name in hashTools.
 */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return "[" + value.map(stableStringify).join(",") + "]";
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return (
    "{" +
    keys
      .map((k) => JSON.stringify(k) + ":" + stableStringify(record[k]))
      .join(",") +
    "}"
  );
}

/**
 * Simple in-memory cache for tool synchronization
 * Tracks the hash of tools per MCP server to avoid unnecessary DB operations
 */
export class ToolsSyncCache {
  private cache: Map<string, string> = new Map();

  /**
   * Generate a hash from the FULL tool definitions (name + description +
   * inputSchema), not names alone. Name-only hashing was a bug: a backend that
   * changed a tool's schema or description while keeping the same name produced
   * an identical hash, so the change was never persisted to the DB and never
   * propagated to clients. Each tool is reduced to its {name, description,
   * inputSchema}, canonicalized with stable key order, and the set is sorted by
   * name so array ordering does not affect the result.
   */
  hashTools(tools: ToolDefinition[]): string {
    const canonical = [...tools]
      .map((tool) => ({
        name: tool.name,
        description: tool.description ?? null,
        inputSchema: tool.inputSchema ?? null,
      }))
      .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
      .map((tool) => stableStringify(tool))
      .join("|");
    return crypto.createHash("sha256").update(canonical).digest("hex");
  }

  /**
   * Check if tools have changed since last sync
   * @returns true if tools changed or no cache exists, false if unchanged
   */
  hasChanged(mcpServerUuid: string, tools: ToolDefinition[]): boolean {
    const currentHash = this.hashTools(tools);
    const cachedHash = this.cache.get(mcpServerUuid);

    return cachedHash !== currentHash;
  }

  /**
   * Update the cache with current tool state
   */
  update(mcpServerUuid: string, tools: ToolDefinition[]): void {
    const hash = this.hashTools(tools);
    this.cache.set(mcpServerUuid, hash);
  }

  /**
   * Check if sync is needed and update cache if it is
   * @returns true if sync needed, false if cache hit
   */
  shouldSync(mcpServerUuid: string, tools: ToolDefinition[]): boolean {
    const needsSync = this.hasChanged(mcpServerUuid, tools);

    if (needsSync) {
      this.update(mcpServerUuid, tools);
    }

    return needsSync;
  }

  /**
   * Clear cache for specific server or entire cache
   */
  clear(mcpServerUuid?: string): void {
    if (mcpServerUuid) {
      this.cache.delete(mcpServerUuid);
    } else {
      this.cache.clear();
    }
  }

  /**
   * Get cache statistics
   */
  getStats(): {
    size: number;
    servers: string[];
  } {
    return {
      size: this.cache.size,
      servers: Array.from(this.cache.keys()),
    };
  }
}

// Singleton instance
export const toolsSyncCache = new ToolsSyncCache();
