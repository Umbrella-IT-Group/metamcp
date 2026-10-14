/**
 * An in-memory stand-in for the three tables the tool-status filter and the
 * tool-override middleware read (`mcp_servers`, `tools`,
 * `namespace_tool_mappings`), for tests that need both middlewares REAL.
 *
 * The stand-in evaluates the queries rather than routing by call shape, so a
 * test can hold one set of rows and let every lookup (server by name, tool
 * status, overrides, the override-name reverse lookup) answer from it the way
 * the database would. It works by replacing three seams, which a test wires
 * with `vi.mock`:
 *   - the schema module, with tables whose columns are plain ids
 *     (`"ntm.status"`, `"servers.name"`, ...);
 *   - drizzle's `eq` and `and`, with builders that keep the column id and the
 *     value readable;
 *   - the db module, with `createToolMappingDb(state)`.
 * A `where` keeps the rows whose columns equal every `eq` it was given, and
 * the `select` field map projects them. Join conditions are ignored: every
 * mapping row is pre-joined to its tool name and its server.
 *
 * Nothing here imports the db, the schema or drizzle, so a `vi.mock` factory
 * can import it without loading the modules it stands in for.
 */

export interface FakeServerRow {
  uuid: string;
  name: string;
}

export interface FakeMappingRow {
  namespaceUuid: string;
  serverUuid: string;
  toolName: string;
  status: "ACTIVE" | "INACTIVE";
  overrideName?: string | null;
}

export interface FakeToolMappingState {
  servers: FakeServerRow[];
  mappings: FakeMappingRow[];
}

/** One query the stand-in answered: its base table and its `eq` filters. */
export interface FakeQuery {
  table: "servers" | "mappings";
  where: Record<string, unknown>;
}

export const toolMappingSchemaStub = {
  mcpServersTable: { uuid: "servers.uuid", name: "servers.name" },
  toolsTable: { uuid: "tools.uuid", name: "tools.name" },
  namespaceToolMappingsTable: {
    namespace_uuid: "ntm.namespace_uuid",
    tool_uuid: "ntm.tool_uuid",
    mcp_server_uuid: "ntm.mcp_server_uuid",
    status: "ntm.status",
    override_name: "ntm.override_name",
    override_title: "ntm.override_title",
    override_description: "ntm.override_description",
    override_annotations: "ntm.override_annotations",
  },
};

interface EqCondition {
  eq: [unknown, unknown];
}

interface AndCondition {
  and: unknown[];
}

export const drizzleConditionStubs = {
  eq: (column: unknown, value: unknown): EqCondition => ({
    eq: [column, value],
  }),
  and: (...conditions: unknown[]): AndCondition => ({ and: conditions }),
};

const flatten = (
  condition: unknown,
  into: Record<string, unknown> = {},
): Record<string, unknown> => {
  if (condition && typeof condition === "object" && "and" in condition) {
    for (const part of (condition as AndCondition).and) flatten(part, into);
  } else if (condition && typeof condition === "object" && "eq" in condition) {
    const [column, value] = (condition as EqCondition).eq;
    into[String(column)] = value;
  } else {
    throw new Error(`fake db: unsupported condition ${String(condition)}`);
  }
  return into;
};

const rowsFor = (
  state: FakeToolMappingState,
  table: FakeQuery["table"],
): Record<string, unknown>[] => {
  if (table === "servers") {
    return state.servers.map((server) => ({
      "servers.uuid": server.uuid,
      "servers.name": server.name,
    }));
  }
  return state.mappings.map((mapping) => {
    const server = state.servers.find((s) => s.uuid === mapping.serverUuid);
    return {
      "ntm.namespace_uuid": mapping.namespaceUuid,
      "ntm.mcp_server_uuid": mapping.serverUuid,
      "ntm.status": mapping.status,
      "ntm.override_name": mapping.overrideName ?? null,
      "ntm.override_title": null,
      "ntm.override_description": null,
      "ntm.override_annotations": null,
      "tools.name": mapping.toolName,
      "servers.uuid": server?.uuid,
      "servers.name": server?.name,
    };
  });
};

export function createToolMappingDb(
  state: FakeToolMappingState,
  queries: FakeQuery[] = [],
) {
  return {
    select: (fields: Record<string, unknown>) => {
      let table: FakeQuery["table"] = "mappings";
      const query = {
        from: (source: unknown) => {
          table =
            source === toolMappingSchemaStub.mcpServersTable
              ? "servers"
              : "mappings";
          return query;
        },
        innerJoin: () => query,
        where: async (condition: unknown) => {
          const where = flatten(condition);
          queries.push({ table, where });
          return rowsFor(state, table)
            .filter((row) =>
              Object.entries(where).every(([column, value]) => {
                if (!(column in row)) {
                  throw new Error(`fake db: unknown column ${column}`);
                }
                return row[column] === value;
              }),
            )
            .map((row) =>
              Object.fromEntries(
                Object.entries(fields).map(([key, column]) => [
                  key,
                  row[String(column)],
                ]),
              ),
            );
        },
      };
      return query;
    },
  };
}
