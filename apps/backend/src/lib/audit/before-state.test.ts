/**
 * The before-state of an update (lib/audit/before-state), without a database:
 * what is recorded of a changed field, and the rule that a field which can
 * hold a credential is recorded as changed and never by value. The field
 * lists are compared with the tables' columns so a column added later cannot
 * become a recorded value by default. The rows themselves, read back through
 * audit.list from Postgres, are pinned in trpc/admin-plane-rails.integration.
 */
import { getTableColumns } from "drizzle-orm";
import { describe, expect, it } from "vitest";

import {
  accessGroupsTable,
  endpointsTable,
  mcpServersTable,
  namespacesTable,
} from "../../db/schema";
import {
  ACCESS_GROUP_UPDATE_FIELDS,
  describeUpdate,
  ENDPOINT_UPDATE_FIELDS,
  MCP_SERVER_UPDATE_FIELDS,
  NAMESPACE_UPDATE_FIELDS,
} from "./before-state";

const FIELDS = { plain: ["name", "enabled"], credential: ["secret", "token"] };

describe("describeUpdate", () => {
  it("records the previous and new value of each changed plain field, and nothing for an unchanged one", () => {
    expect(
      describeUpdate(
        { name: "old", enabled: true, secret: "x", token: "y" },
        { name: "new", enabled: true, secret: "x", token: "y" },
        FIELDS,
      ),
    ).toEqual({
      changed_fields: ["name"],
      old_value: { name: "old" },
      new_value: { name: "new" },
    });
    expect(describeUpdate({ name: "same" }, { name: "same" }, FIELDS)).toEqual({
      changed_fields: [],
      old_value: {},
      new_value: {},
    });
  });

  it("records only the name of a changed credential field, never any form of its value", () => {
    const before = { secret: "SENTINEL-OLD-4f1c", token: "SENTINEL-TOK-9a" };
    const after = { secret: "SENTINEL-NEW-77d2", token: "SENTINEL-TOK-9a" };
    const result = describeUpdate(before, after, FIELDS);
    expect(result.changed_fields).toEqual(["secret"]);
    expect(result.old_value).toEqual({});
    expect(result.new_value).toEqual({});
    const text = JSON.stringify(result);
    for (const part of ["SENTINEL", "4f1c", "77d2"]) {
      expect(text).not.toContain(part);
    }
  });

  it("treats a structure as unchanged when only its key order differs, and as changed otherwise", () => {
    const fields = { plain: [], credential: ["env"] };
    expect(
      describeUpdate(
        { env: { A: "1", B: "2" } },
        { env: { B: "2", A: "1" } },
        fields,
      ).changed_fields,
    ).toEqual([]);
    expect(
      describeUpdate({ env: { A: "1" } }, { env: { A: "2" } }, fields)
        .changed_fields,
    ).toEqual(["env"]);
    expect(
      describeUpdate({ env: {} }, { env: { A: "1" } }, fields).changed_fields,
    ).toEqual(["env"]);
  });

  it("names a camelCase column in snake case and sorts the changed fields", () => {
    const result = describeUpdate(
      { zeta: 1, bearerToken: null, alpha: "a" },
      { zeta: 2, bearerToken: "enc:v1:abc", alpha: "b" },
      { plain: ["zeta", "alpha"], credential: ["bearerToken"] },
    );
    expect(result.changed_fields).toEqual(["alpha", "bearer_token", "zeta"]);
    expect(JSON.stringify(result)).not.toContain("enc:v1");
  });

  it("records a plain field that holds something other than a scalar or a list of strings as changed only", () => {
    const result = describeUpdate(
      { name: { nested: "SENTINEL-OBJ" } },
      { name: { nested: "other" } },
      FIELDS,
    );
    expect(result.changed_fields).toEqual(["name"]);
    expect(result.old_value).toEqual({});
    expect(result.new_value).toEqual({});
    expect(JSON.stringify(result)).not.toContain("SENTINEL-OBJ");
  });

  it("records lists of ids and clamps long text", () => {
    const result = describeUpdate(
      { servers: ["a", "b"], name: "x".repeat(500) },
      { servers: ["b", "c"], name: "y".repeat(500) },
      { plain: ["servers", "name"], credential: [] },
    );
    expect(result.old_value.servers).toEqual(["a", "b"]);
    expect(result.new_value.servers).toEqual(["b", "c"]);
    expect(result.old_value.name).toBe("x".repeat(200));
    expect(result.new_value.name).toBe("y".repeat(200));
  });

  it("treats undefined and null as the same absent value", () => {
    expect(
      describeUpdate({ name: null }, { name: undefined }, FIELDS)
        .changed_fields,
    ).toEqual([]);
    expect(
      describeUpdate({ name: null }, { name: "now set" }, FIELDS),
    ).toMatchObject({
      changed_fields: ["name"],
      old_value: { name: null },
      new_value: { name: "now set" },
    });
  });
});

describe("the update field lists", () => {
  // Columns deliberately not recorded: identity and bookkeeping that an update
  // does not edit, or that its own audit columns already carry.
  const NOT_RECORDED = {
    endpoints: [
      "uuid",
      "restricted",
      "restricted_at",
      "restricted_by_api_key_uuid",
      "created_at",
      "updated_at",
      "user_id",
    ],
    mcp_servers: ["uuid", "created_at", "error_status"],
    namespaces: ["uuid", "created_at", "updated_at", "tool_policy"],
    access_groups: ["uuid", "created_at"],
  };

  const accounted = (
    table: Parameters<typeof getTableColumns>[0],
    fields: { plain: readonly string[]; credential: readonly string[] },
    notRecorded: readonly string[],
    extra: readonly string[] = [],
  ) => {
    const columns = Object.keys(getTableColumns(table)).sort();
    const listed = [
      ...fields.plain,
      ...fields.credential,
      ...notRecorded,
    ].filter((name) => !extra.includes(name));
    return { columns, listed: listed.sort() };
  };

  it("account for every column of the endpoints table, and record none as a credential", () => {
    const { columns, listed } = accounted(
      endpointsTable,
      ENDPOINT_UPDATE_FIELDS,
      NOT_RECORDED.endpoints,
    );
    expect(listed).toEqual(columns);
    expect(ENDPOINT_UPDATE_FIELDS.credential).toEqual([]);
  });

  it("account for every column of the servers table, with every connection field a credential", () => {
    const { columns, listed } = accounted(
      mcpServersTable,
      MCP_SERVER_UPDATE_FIELDS,
      NOT_RECORDED.mcp_servers,
    );
    expect(listed).toEqual(columns);
    expect([...MCP_SERVER_UPDATE_FIELDS.credential].sort()).toEqual(
      ["args", "bearerToken", "command", "env", "headers", "url"].sort(),
    );
    for (const plain of MCP_SERVER_UPDATE_FIELDS.plain) {
      expect(["name", "description", "type", "user_id"]).toContain(plain);
    }
  });

  it("account for every column of the namespaces and access groups tables", () => {
    const namespaces = accounted(
      namespacesTable,
      NAMESPACE_UPDATE_FIELDS,
      NOT_RECORDED.namespaces,
      ["server_uuids"],
    );
    expect(namespaces.listed).toEqual(namespaces.columns);
    const groups = accounted(
      accessGroupsTable,
      ACCESS_GROUP_UPDATE_FIELDS,
      NOT_RECORDED.access_groups,
    );
    expect(groups.listed).toEqual(groups.columns);
  });
});
