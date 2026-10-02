/**
 * Process-global record of each exposed tool's top-level argument names, taken
 * from the `inputSchema` the backend publishes in tools/list.
 *
 * WHY THIS EXISTS. `tool_call_audit.args_shape` stores argument KEY NAMES. A key
 * name is caller-chosen before any tool validates it, so identifier syntax alone
 * cannot stop a caller from writing `Alice_Smith` or `client_secret_x` into an
 * immutable audit row (Sol review, 2026-10-02). Recording only the names a tool's
 * own schema declares closes that channel: a caller can choose which declared
 * parameters to send, never what the stored names are.
 *
 * Keyed by the exposed name exactly as clients call it (`<server>__<tool>`), which
 * is the name the auditing middleware sees. Any session's tools/list teaches the
 * whole process, so a path that never lists tools itself (the OpenAPI bridge)
 * still finds the schema once any client has listed. Until then the tool is
 * unknown and `args_shape` stores counts only.
 *
 * PURE apart from the module map, never throws, and bounded: past MAX_TOOLS the
 * oldest entry is evicted (Map keeps insertion order; a re-record moves a tool to
 * the end).
 */

export interface ToolArgSchema {
  /** Declared top-level property names. */
  keys: ReadonlySet<string>;
  /** Per property, its declared string enum values (only when the schema has one). */
  enums: ReadonlyMap<string, ReadonlySet<string>>;
}

export const MAX_TOOLS = 5000;

const schemas = new Map<string, ToolArgSchema>();

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
    const keys = new Set<string>();
    const enums = new Map<string, ReadonlySet<string>>();
    for (const [name, def] of Object.entries(props)) {
      keys.add(name);
      if (!isRecord(def)) continue;
      // An enum may sit on the property itself or on an anyOf branch
      // (FastMCP renders `Literal[...] | None` as anyOf [{enum}, {type: null}]).
      const branches: unknown[] = [
        def,
        ...(Array.isArray(def.anyOf) ? def.anyOf : []),
      ];
      const values = new Set<string>();
      for (const branch of branches) {
        if (!isRecord(branch) || !Array.isArray(branch.enum)) continue;
        for (const v of branch.enum) if (typeof v === "string") values.add(v);
      }
      if (values.size > 0) enums.set(name, values);
    }
    return { keys, enums };
  } catch {
    return undefined;
  }
}

/** Record (or refresh) one exposed tool's schema. Never throws. */
export function recordToolArgSchema(
  exposedName: string,
  inputSchema: unknown,
): void {
  try {
    const entry = schemaFromInputSchema(inputSchema);
    if (!entry) {
      schemas.delete(exposedName);
      return;
    }
    schemas.delete(exposedName);
    schemas.set(exposedName, entry);
    while (schemas.size > MAX_TOOLS) {
      const oldest = schemas.keys().next().value;
      if (oldest === undefined) break;
      schemas.delete(oldest);
    }
  } catch {
    // A schema the gateway cannot read leaves the tool unknown (counts only).
  }
}

/** The recorded schema for an exposed tool name, or undefined when unknown. */
export function toolArgSchema(exposedName: string): ToolArgSchema | undefined {
  return schemas.get(exposedName);
}

/** Test hook. */
export function resetToolArgSchemasForTest(): void {
  schemas.clear();
}
