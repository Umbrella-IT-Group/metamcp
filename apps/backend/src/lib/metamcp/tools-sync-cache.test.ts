import { beforeEach, describe, expect, it } from "vitest";

import { ToolDefinition, ToolsSyncCache } from "./tools-sync-cache";

// Build a full tool definition. Callers pass real tool objects (name +
// description + inputSchema), so the tests exercise the same surface.
function tool(
  name: string,
  description: string | null = `${name} description`,
  inputSchema: unknown = {
    type: "object",
    properties: { a: { type: "string" } },
  },
): ToolDefinition {
  return { name, description, inputSchema };
}

function tools(...names: string[]): ToolDefinition[] {
  return names.map((n) => tool(n));
}

describe("ToolsSyncCache", () => {
  let cache: ToolsSyncCache;

  beforeEach(() => {
    cache = new ToolsSyncCache();
  });

  describe("hashTools", () => {
    it("should generate consistent hash for same tools", () => {
      const t = tools("tool1", "tool2", "tool3");
      const hash1 = cache.hashTools(t);
      const hash2 = cache.hashTools(t);

      expect(hash1).toBe(hash2);
    });

    it("should generate same hash regardless of array order", () => {
      const t1 = [tool("tool1"), tool("tool2"), tool("tool3")];
      const t2 = [tool("tool3"), tool("tool1"), tool("tool2")];
      const hash1 = cache.hashTools(t1);
      const hash2 = cache.hashTools(t2);

      expect(hash1).toBe(hash2);
    });

    it("should generate same hash regardless of inputSchema key order", () => {
      const t1 = [
        {
          name: "tool1",
          description: "d",
          inputSchema: {
            type: "object",
            properties: { a: { type: "string" }, b: { type: "number" } },
            required: ["a"],
          },
        },
      ];
      // Same definition, object keys emitted in a different order.
      const t2 = [
        {
          name: "tool1",
          inputSchema: {
            required: ["a"],
            properties: { b: { type: "number" }, a: { type: "string" } },
            type: "object",
          },
          description: "d",
        },
      ];

      expect(cache.hashTools(t1)).toBe(cache.hashTools(t2));
    });

    it("should generate different hash when a tool NAME changes", () => {
      const hash1 = cache.hashTools([tool("tool1"), tool("tool2")]);
      const hash2 = cache.hashTools([tool("tool1"), tool("tool3")]);

      expect(hash1).not.toBe(hash2);
    });

    it("should flip the hash on a DESCRIPTION-only change (same name + schema)", () => {
      const schema = { type: "object", properties: { a: { type: "string" } } };
      const hash1 = cache.hashTools([
        { name: "tool1", description: "old", inputSchema: schema },
      ]);
      const hash2 = cache.hashTools([
        { name: "tool1", description: "new", inputSchema: schema },
      ]);

      expect(hash1).not.toBe(hash2);
    });

    it("should flip the hash on an inputSchema-only change (same name + description)", () => {
      const hash1 = cache.hashTools([
        {
          name: "tool1",
          description: "d",
          inputSchema: {
            type: "object",
            properties: { a: { type: "string" } },
          },
        },
      ]);
      const hash2 = cache.hashTools([
        {
          name: "tool1",
          description: "d",
          inputSchema: {
            type: "object",
            properties: {
              a: { type: "string" },
              b: { type: "number" }, // new required-less field: schema changed
            },
          },
        },
      ]);

      expect(hash1).not.toBe(hash2);
    });

    it("should treat missing/undefined description as null (stable)", () => {
      const withUndefined = cache.hashTools([
        { name: "tool1", inputSchema: {} },
      ]);
      const withNull = cache.hashTools([
        { name: "tool1", description: null, inputSchema: {} },
      ]);

      expect(withUndefined).toBe(withNull);
    });

    it("should handle empty array", () => {
      const hash = cache.hashTools([]);
      expect(hash).toBeDefined();
      expect(typeof hash).toBe("string");
    });
  });

  describe("hasChanged", () => {
    it("should return true when no cache exists", () => {
      const changed = cache.hasChanged(
        "server-uuid-1",
        tools("tool1", "tool2"),
      );

      expect(changed).toBe(true);
    });

    it("should return false when tools are unchanged", () => {
      const t = tools("tool1", "tool2");
      const serverUuid = "server-uuid-1";

      cache.update(serverUuid, t);
      const changed = cache.hasChanged(serverUuid, t);

      expect(changed).toBe(false);
    });

    it("should return true when a tool is added", () => {
      const serverUuid = "server-uuid-1";

      cache.update(serverUuid, tools("tool1", "tool2"));
      const changed = cache.hasChanged(
        serverUuid,
        tools("tool1", "tool2", "tool3"),
      );

      expect(changed).toBe(true);
    });

    it("should return true when only a description changed", () => {
      const serverUuid = "server-uuid-1";
      const schema = { type: "object", properties: {} };

      cache.update(serverUuid, [
        { name: "tool1", description: "old", inputSchema: schema },
      ]);
      const changed = cache.hasChanged(serverUuid, [
        { name: "tool1", description: "new", inputSchema: schema },
      ]);

      expect(changed).toBe(true);
    });

    it("should return false when tools are reordered but same", () => {
      const serverUuid = "server-uuid-1";

      cache.update(serverUuid, [tool("tool1"), tool("tool2"), tool("tool3")]);
      const changed = cache.hasChanged(serverUuid, [
        tool("tool3"),
        tool("tool1"),
        tool("tool2"),
      ]);

      expect(changed).toBe(false);
    });
  });

  describe("shouldSync", () => {
    it("should return true and update cache on first call", () => {
      const t = tools("tool1", "tool2");
      const serverUuid = "server-uuid-1";

      const shouldSync = cache.shouldSync(serverUuid, t);

      expect(shouldSync).toBe(true);
      expect(cache.hasChanged(serverUuid, t)).toBe(false);
    });

    it("should return false on second call with same tools", () => {
      const t = tools("tool1", "tool2");
      const serverUuid = "server-uuid-1";

      cache.shouldSync(serverUuid, t);
      const shouldSync = cache.shouldSync(serverUuid, t);

      expect(shouldSync).toBe(false);
    });

    it("should return true when tools change", () => {
      const serverUuid = "server-uuid-1";

      cache.shouldSync(serverUuid, tools("tool1", "tool2"));
      const shouldSync = cache.shouldSync(
        serverUuid,
        tools("tool1", "tool2", "tool3"),
      );

      expect(shouldSync).toBe(true);
    });

    it("should handle multiple servers independently", () => {
      const t1 = tools("tool1", "tool2");
      const t2 = tools("tool3", "tool4");

      expect(cache.shouldSync("server-1", t1)).toBe(true);
      expect(cache.shouldSync("server-2", t2)).toBe(true);

      // Second calls should not need sync
      expect(cache.shouldSync("server-1", t1)).toBe(false);
      expect(cache.shouldSync("server-2", t2)).toBe(false);
    });
  });

  describe("clear", () => {
    it("should clear specific server cache", () => {
      const t = tools("tool1", "tool2");
      cache.update("server-1", t);
      cache.update("server-2", t);

      cache.clear("server-1");

      expect(cache.hasChanged("server-1", t)).toBe(true);
      expect(cache.hasChanged("server-2", t)).toBe(false);
    });

    it("should clear all cache when no uuid provided", () => {
      const t = tools("tool1", "tool2");
      cache.update("server-1", t);
      cache.update("server-2", t);

      cache.clear();

      expect(cache.hasChanged("server-1", t)).toBe(true);
      expect(cache.hasChanged("server-2", t)).toBe(true);
    });
  });

  describe("getStats", () => {
    it("should return empty stats initially", () => {
      const stats = cache.getStats();

      expect(stats.size).toBe(0);
      expect(stats.servers).toEqual([]);
    });

    it("should return correct stats after updates", () => {
      cache.update("server-1", tools("tool1"));
      cache.update("server-2", tools("tool2"));

      const stats = cache.getStats();

      expect(stats.size).toBe(2);
      expect(stats.servers).toContain("server-1");
      expect(stats.servers).toContain("server-2");
    });
  });

  describe("real-world scenarios", () => {
    it("should handle tool removal correctly", () => {
      const serverUuid = "server-uuid-1";

      expect(
        cache.shouldSync(serverUuid, tools("tool1", "tool2", "tool3")),
      ).toBe(true);
      expect(cache.shouldSync(serverUuid, tools("tool1", "tool2"))).toBe(true);
      expect(cache.shouldSync(serverUuid, tools("tool1", "tool2"))).toBe(false);
    });

    it("should handle all tools removed (empty array)", () => {
      const serverUuid = "server-uuid-1";

      expect(cache.shouldSync(serverUuid, tools("tool1", "tool2"))).toBe(true);
      expect(cache.shouldSync(serverUuid, [])).toBe(true);
      expect(cache.shouldSync(serverUuid, [])).toBe(false);
    });

    it("should handle tool addition correctly", () => {
      const serverUuid = "server-uuid-1";

      expect(cache.shouldSync(serverUuid, tools("tool1"))).toBe(true);
      expect(
        cache.shouldSync(serverUuid, tools("tool1", "tool2", "tool3")),
      ).toBe(true);
      expect(
        cache.shouldSync(serverUuid, tools("tool1", "tool2", "tool3")),
      ).toBe(false);
    });

    it("should resync when a backend reworks a tool's schema in place", () => {
      const serverUuid = "server-uuid-1";
      const v1 = [
        {
          name: "search",
          description: "Search records",
          inputSchema: {
            type: "object",
            properties: { q: { type: "string" } },
          },
        },
      ];
      // Same name + description, a new required argument added — the exact
      // shape name-only hashing missed.
      const v2 = [
        {
          name: "search",
          description: "Search records",
          inputSchema: {
            type: "object",
            properties: {
              q: { type: "string" },
              limit: { type: "number" },
            },
            required: ["limit"],
          },
        },
      ];

      expect(cache.shouldSync(serverUuid, v1)).toBe(true);
      expect(cache.shouldSync(serverUuid, v2)).toBe(true);
      expect(cache.shouldSync(serverUuid, v2)).toBe(false);
    });

    it("should handle rapid reconnections efficiently", () => {
      const serverUuid = "server-uuid-1";
      const t = tools("tool1", "tool2", "tool3");

      let syncCount = 0;
      for (let i = 0; i < 100; i++) {
        if (cache.shouldSync(serverUuid, t)) {
          syncCount++;
        }
      }

      // Only the first call should trigger sync
      expect(syncCount).toBe(1);
    });
  });
});
