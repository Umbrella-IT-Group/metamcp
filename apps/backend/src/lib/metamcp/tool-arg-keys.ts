/**
 * Per-proxy record of each exposed tool's top-level argument names, taken
 * from the `inputSchema` the backend publishes in tools/list.
 *
 * WHY THIS EXISTS. `tool_call_audit.args_shape` stores argument KEY NAMES. A key
 * name is caller-chosen before any tool validates it, so identifier syntax alone
 * cannot stop a caller from writing `Alice_Smith` or `client_secret_x` into an
 * immutable audit row (Sol review, 2026-10-02). Recording only the names a tool's
 * own schema declares closes that channel: a caller can choose which declared
 * parameters to send, never what the stored names are.
 *
 * Keyed by the final exposed name exactly as this proxy's clients call it.
 * A process-global name map is unsafe: namespaces can have different servers
 * with the same name, and even two proxies in one namespace can have different
 * routing winners. Each proxy owns a complete post-middleware listing snapshot.
 * Unlisted paths (including the OpenAPI bridge) store counts only.
 *
 * PURE apart from the registry map, never throws, and bounded: past MAX_TOOLS the
 * oldest entry is evicted (Map keeps insertion order; a re-record moves a tool to
 * the end).
 */

import {
  KEY_MAX_LEN,
  SELECTOR_KEYS,
  SELECTOR_VALUE_MAX,
} from "./metamcp-middleware/audit-args-shape";

export interface ToolArgSchema {
  /** Declared top-level property names. */
  keys: ReadonlySet<string>;
  /** Per selector, declared string values; an empty set means no value is verified. */
  enums: ReadonlyMap<string, ReadonlySet<string>>;
}

export const MAX_TOOLS = 5000;
export const MAX_SCHEMA_KEYS = 256;
export const MAX_ENUM_VALUES = 256;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Build the allowlist entry for one inputSchema; undefined when it has no properties object. */
export function schemaFromInputSchema(
  inputSchema: unknown,
): ToolArgSchema | undefined {
  try {
    if (!isRecord(inputSchema)) return undefined;
    const props = inputSchema.properties;
    if (!isRecord(props)) return undefined;
    // A tool-count cap alone does not bound retained schema data. Oversized
    // schemas remain unknown rather than retaining unbounded names or enums.
    const names = Object.keys(props);
    if (names.length > MAX_SCHEMA_KEYS) return undefined;
    const keys = new Set<string>();
    const enums = new Map<string, ReadonlySet<string>>();
    for (const name of names) {
      if (name.length > KEY_MAX_LEN) continue;
      keys.add(name);
      // Only these six values can ever be stored; other property enums need
      // not consume cache space or be inspected.
      if (!(SELECTOR_KEYS as readonly string[]).includes(name)) continue;
      const def = props[name];
      if (!isRecord(def)) {
        if (def !== true) enums.set(name, new Set());
        continue;
      }
      // An enum may sit on the property itself or on an anyOf branch
      // (FastMCP renders `Literal[...] | None` as anyOf [{enum}, {type: null}]).
      const anyOf = Array.isArray(def.anyOf) ? def.anyOf : [];
      if (anyOf.length >= MAX_ENUM_VALUES) {
        enums.set(name, new Set());
        continue;
      }
      const branches: unknown[] = [def, ...anyOf];
      const values = new Set<string>();
      let restricted = false;
      let unsupported = false;
      for (const branch of branches) {
        if (!isRecord(branch)) {
          unsupported = true;
          break;
        }
        // Never treat an unresolved reference/composition as "no enum": that
        // would let invalid caller-chosen values bypass a declared restriction.
        if (
          ["$ref", "oneOf", "allOf", "not", "if", "then", "else"].some((key) =>
            Object.prototype.hasOwnProperty.call(branch, key),
          ) ||
          (branch !== def &&
            Object.prototype.hasOwnProperty.call(branch, "anyOf"))
        ) {
          unsupported = true;
          break;
        }
        if (Object.prototype.hasOwnProperty.call(branch, "const")) {
          restricted = true;
          if (
            typeof branch.const === "string" &&
            branch.const.length <= SELECTOR_VALUE_MAX
          ) {
            values.add(branch.const);
          }
        }
        if (!Object.prototype.hasOwnProperty.call(branch, "enum")) continue;
        restricted = true;
        if (
          !Array.isArray(branch.enum) ||
          branch.enum.length > MAX_ENUM_VALUES
        ) {
          unsupported = true;
          break;
        }
        for (const v of branch.enum) {
          if (typeof v === "string" && v.length <= SELECTOR_VALUE_MAX)
            values.add(v);
        }
        if (values.size > MAX_ENUM_VALUES) {
          unsupported = true;
          break;
        }
      }
      // An empty enum still forbids arbitrary string values. Unsupported
      // schemas keep the key but record only the misuse marker for its value.
      if (restricted || unsupported)
        enums.set(name, unsupported ? new Set() : values);
    }
    return { keys, enums };
  } catch {
    return undefined;
  }
}

/** One routing instance's bounded schema snapshot. Never shared with another proxy. */
export class ToolArgSchemaRegistry {
  private readonly schemas = new Map<string, ToolArgSchema>();

  /** Record (or refresh) one exposed tool's schema. Never throws. */
  record(exposedName: string, inputSchema: unknown): void {
    try {
      const entry = schemaFromInputSchema(inputSchema);
      this.schemas.delete(exposedName);
      if (!entry || exposedName.length > 256) return;
      this.schemas.set(exposedName, entry);
      while (this.schemas.size > MAX_TOOLS) {
        const oldest = this.schemas.keys().next().value;
        if (oldest === undefined) break;
        this.schemas.delete(oldest);
      }
    } catch {
      // A schema the gateway cannot read leaves the tool unknown (counts only).
      this.schemas.delete(exposedName);
    }
  }

  /** Replace after a complete final listing; removed names and duplicates are unknown. */
  replace(tools: ReadonlyArray<{ name: string; inputSchema: unknown }>): void {
    this.schemas.clear();
    try {
      if (tools.length > MAX_TOOLS) return;
      const seen = new Set<string>();
      for (const tool of tools) {
        if (seen.has(tool.name)) {
          // Overrides can create an ambiguous exposed name after raw routing
          // collision checks. Neither schema is safe to attribute to that call.
          this.schemas.delete(tool.name);
          continue;
        }
        seen.add(tool.name);
        this.record(tool.name, tool.inputSchema);
      }
    } catch {
      // Do not retain a partly read snapshot, and never interrupt tools/list.
      this.schemas.clear();
    }
  }

  get(exposedName: string): ToolArgSchema | undefined {
    return this.schemas.get(exposedName);
  }
}
