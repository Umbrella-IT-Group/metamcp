/**
 * Credential disclosure (#98): the server serializers returned every backend
 * MCP's connection URL and credential material to any authenticated member.
 *
 * `mcpServers.list`, `mcpServers.get` and `namespaces.get` are all
 * `protectedProcedure` — members legitimately see the server inventory in
 * their dashboard, so the fix could not be an RBAC gate without blanking the
 * member UI. Instead the two serializers redact by role, and these tests pin
 * both halves of that contract: a member sees names and metadata but no way
 * to reach or authenticate to anything, and an admin sees everything the
 * response ever carried EXCEPT bearerToken, which is redacted to null on every
 * response now because it is encrypted at rest and read
 * only server-side.
 *
 * Both serializers are covered because they are two independent copies of
 * the same embed — redacting only the mcpServers path would have left the
 * whole disclosure reachable via the namespace that contains the server.
 */

// TEST-EDIT (SPEC): the serializers take a detail level ("full" for a person
// signed in as an administrator, "redacted" for a member) in place of the
// boolean `includeSecrets`; every assertion below is unchanged.
import { DatabaseMcpServer } from "@repo/zod-types";
import { describe, expect, it } from "vitest";

import { McpServersSerializer } from "./mcp-servers.serializer";
import { NamespacesSerializer } from "./namespaces.serializer";

// Shaped like a real row: the internal Docker URL is the connection-URL leak, the
// bearer token / env / headers are #98.
const SECRET_URL = "http://internal-backend:3000";
const SECRET_TOKEN = "sk_live_do_not_disclose";
const SECRET_ENV = { BACKEND_API_KEY: "at_secret_value" };
const SECRET_HEADERS = { "X-Tenant": "umbrella-internal" };
const SECRET_COMMAND = "/usr/local/bin/internal-backend";
const SECRET_ARGS = ["--tenant", "umbrella", "--token", "arg_secret"];

const CREATED_AT = new Date("2026-08-13T12:00:00.000Z");

const dbServer = {
  uuid: "11111111-1111-4111-8111-111111111111",
  name: "internal-backend",
  description: "Internal PSA bridge",
  type: "STREAMABLE_HTTP",
  command: SECRET_COMMAND,
  args: SECRET_ARGS,
  env: SECRET_ENV,
  url: SECRET_URL,
  error_status: undefined,
  created_at: CREATED_AT,
  bearerToken: SECRET_TOKEN,
  headers: SECRET_HEADERS,
  user_id: null,
} as unknown as DatabaseMcpServer;

const dbNamespace = {
  uuid: "22222222-2222-4222-8222-222222222222",
  name: "umbrella-prod",
  description: "Production namespace",
  created_at: CREATED_AT,
  updated_at: CREATED_AT,
  user_id: null,
  servers: [{ ...dbServer, status: "ACTIVE" }],
} as never;

/** Every value that must never reach a non-admin. */
const SECRETS = [
  SECRET_URL,
  SECRET_TOKEN,
  "at_secret_value",
  "BACKEND_API_KEY",
  "umbrella-internal",
  SECRET_COMMAND,
  "arg_secret",
];

/** Fields a member still needs for the dashboard to be usable. */
const expectMetadataIntact = (server: {
  uuid: string;
  name: string;
  description: string | null;
  created_at: string;
}) => {
  expect(server.uuid).toBe(dbServer.uuid);
  expect(server.name).toBe("internal-backend");
  expect(server.description).toBe("Internal PSA bridge");
  expect(server.created_at).toBe(CREATED_AT.toISOString());
};

describe("McpServersSerializer — non-admin", () => {
  it("redacts url, command, args, env, bearerToken and headers", () => {
    const server = McpServersSerializer.serializeMcpServer(
      dbServer,
      "redacted",
    );

    expect(server.url).toBeNull();
    expect(server.command).toBeNull();
    expect(server.args).toEqual([]);
    expect(server.env).toEqual({});
    expect(server.bearerToken).toBeNull();
    expect(server.headers).toEqual({});
  });

  it("keeps the metadata the member dashboard renders", () => {
    // The fix must not be "hide the server" — members still list servers.
    const server = McpServersSerializer.serializeMcpServer(
      dbServer,
      "redacted",
    );

    expectMetadataIntact(server);
    expect(server.type).toBe("STREAMABLE_HTTP");
  });

  it("leaks no secret substring anywhere in the serialised object", () => {
    // Catches a secret surviving under a renamed or newly-added key, which
    // the per-field assertions above would miss.
    const json = JSON.stringify(
      McpServersSerializer.serializeMcpServer(dbServer, "redacted"),
    );

    for (const secret of SECRETS) {
      expect(json).not.toContain(secret);
    }
  });

  it("redacts EVERY row in a list, not just the first", () => {
    // Regression guard for `.map(this.serializeMcpServer)`: Array.map passes
    // the index as the second argument, so index 0 would be redacted and
    // every later row would leak.
    const rows = [dbServer, dbServer, dbServer];
    const servers = McpServersSerializer.serializeMcpServerList(
      rows,
      "redacted",
    );

    expect(servers).toHaveLength(3);
    for (const server of servers) {
      expect(server.url).toBeNull();
      expect(server.bearerToken).toBeNull();
      expect(server.env).toEqual({});
    }
    expect(JSON.stringify(servers)).not.toContain(SECRET_URL);
  });
});

describe("McpServersSerializer — admin", () => {
  it("passes every field through unchanged", () => {
    const server = McpServersSerializer.serializeMcpServer(dbServer, "full");

    expect(server.url).toBe(SECRET_URL);
    expect(server.command).toBe(SECRET_COMMAND);
    expect(server.args).toEqual(SECRET_ARGS);
    expect(server.env).toEqual(SECRET_ENV);
    // bearerToken is the one field an admin no longer gets back: it is redacted
    // to null on EVERY response now, because the value
    // at rest is an encrypted envelope read only server-side to build the
    // upstream header, and echoing it served no client. Every other field is
    // still admin-visible.
    expect(server.bearerToken).toBeNull();
    expect(server.headers).toEqual(SECRET_HEADERS);
  });

  it("passes every row of a list through unchanged", () => {
    const servers = McpServersSerializer.serializeMcpServerList(
      [dbServer, dbServer],
      "full",
    );

    expect(servers).toHaveLength(2);
    for (const server of servers) {
      expect(server.url).toBe(SECRET_URL);
      // Never returned, even to an admin.
      expect(server.bearerToken).toBeNull();
    }
  });
});

describe("NamespacesSerializer — embedded servers follow the same rule", () => {
  it("redacts the embedded server for a non-admin", () => {
    const namespace = NamespacesSerializer.serializeNamespaceWithServers(
      dbNamespace,
      "redacted",
    );
    const [server] = namespace.servers;

    expect(server.url).toBeNull();
    expect(server.command).toBeNull();
    expect(server.args).toEqual([]);
    expect(server.env).toEqual({});
    expect(server.bearerToken).toBeNull();
    expect(server.headers).toEqual({});
  });

  it("keeps the namespace-specific status and the server metadata", () => {
    const namespace = NamespacesSerializer.serializeNamespaceWithServers(
      dbNamespace,
      "redacted",
    );
    const [server] = namespace.servers;

    expect(namespace.name).toBe("umbrella-prod");
    expectMetadataIntact(server);
    expect(server.status).toBe("ACTIVE");
  });

  it("leaks no secret substring through the namespace route", () => {
    const json = JSON.stringify(
      NamespacesSerializer.serializeNamespaceWithServers(
        dbNamespace,
        "redacted",
      ),
    );

    for (const secret of SECRETS) {
      expect(json).not.toContain(secret);
    }
  });

  it("passes the embedded server through unchanged for an admin", () => {
    const namespace = NamespacesSerializer.serializeNamespaceWithServers(
      dbNamespace,
      "full",
    );
    const [server] = namespace.servers;

    expect(server.url).toBe(SECRET_URL);
    // Never returned, even to an admin, through the namespace route either
    // same posture as the mcpServers route above.
    expect(server.bearerToken).toBeNull();
    expect(server.env).toEqual(SECRET_ENV);
    expect(server.command).toBe(SECRET_COMMAND);
    expect(server.args).toEqual(SECRET_ARGS);
    expect(server.headers).toEqual(SECRET_HEADERS);
  });
});

/**
 * Full-management reply shape: an admin-plane API key (either scope) reads
 * server objects at the `names_only` level. Every stored connection value is
 * withheld, whatever field it sits in; what stays is what the tooling works
 * from (uuid, name, description, type, error status) and the NAMES of the
 * environment variables and headers that are configured, each with an empty
 * value. Canary values are distinct per field, so a value that survives
 * under another field's name is still caught.
 */
describe("names_only level (admin-plane callers)", () => {
  const CANARY = {
    command: "canary-command-3f2a91",
    arg: "canary-arg-71be04",
    envValue: "canary-env-value-c05d17",
    headerValue: "canary-header-value-9a44e2",
    userinfo: "canary-user:canary-pass-5be8d3",
    path: "canary-path-d1f60b",
    query: "canary-query-47c3aa",
    fragment: "canary-fragment-e82b59",
  };
  const credentialed = {
    uuid: "33333333-3333-4333-8333-333333333333",
    name: "vendor-bridge",
    description: "Vendor bridge",
    type: "STREAMABLE_HTTP",
    command: CANARY.command,
    args: ["--flag", CANARY.arg],
    env: { VENDOR_TOKEN: CANARY.envValue, REGION: "region-value-12ab" },
    url: `https://${CANARY.userinfo}@vendor.internal:8443/${CANARY.path}/mcp?k=${CANARY.query}#${CANARY.fragment}`,
    error_status: "NONE",
    created_at: CREATED_AT,
    bearerToken: "enc:v1:canary-bearer-ciphertext",
    headers: {
      Authorization: `Bearer ${CANARY.headerValue}`,
      "X-Org": "org-value-77c1",
    },
    user_id: null,
  } as unknown as DatabaseMcpServer;
  const values = [
    ...Object.values(CANARY),
    "region-value-12ab",
    "org-value-77c1",
    "canary-bearer",
  ];

  it("keeps env and header names with empty values and withholds the command, arguments and the whole URL", () => {
    const server = McpServersSerializer.serializeMcpServer(
      credentialed,
      "names_only",
    );

    expect(server.env).toEqual({ VENDOR_TOKEN: "", REGION: "" });
    expect(server.headers).toEqual({ Authorization: "", "X-Org": "" });
    expect(server.command).toBeNull();
    expect(server.args).toEqual([]);
    expect(server.url).toBeNull();
    expect(server.bearerToken).toBeNull();
  });

  it("keeps the identity fields the tooling reads", () => {
    const server = McpServersSerializer.serializeMcpServer(
      credentialed,
      "names_only",
    );

    expect(server).toMatchObject({
      uuid: credentialed.uuid,
      name: "vendor-bridge",
      description: "Vendor bridge",
      type: "STREAMABLE_HTTP",
      user_id: null,
      error_status: "NONE",
      created_at: CREATED_AT.toISOString(),
    });
  });

  it("carries no canary value anywhere in the serialised object, list or embed", () => {
    const single = JSON.stringify(
      McpServersSerializer.serializeMcpServer(credentialed, "names_only"),
    );
    const list = JSON.stringify(
      McpServersSerializer.serializeMcpServerList(
        [credentialed, credentialed],
        "names_only",
      ),
    );
    const embed = JSON.stringify(
      NamespacesSerializer.serializeNamespaceWithServers(
        {
          ...(dbNamespace as object),
          servers: [{ ...credentialed, status: "ACTIVE" }],
        } as never,
        "names_only",
      ),
    );

    for (const text of [single, list, embed]) {
      for (const value of values) expect(text).not.toContain(value);
    }
  });

  it("keeps the embedded server's names, status and metadata, and withholds the same fields", () => {
    const namespace = NamespacesSerializer.serializeNamespaceWithServers(
      {
        ...(dbNamespace as object),
        servers: [{ ...credentialed, status: "INACTIVE" }],
      } as never,
      "names_only",
    );
    const [server] = namespace.servers;

    expect(server).toMatchObject({
      uuid: credentialed.uuid,
      name: "vendor-bridge",
      status: "INACTIVE",
      env: { VENDOR_TOKEN: "", REGION: "" },
      headers: { Authorization: "", "X-Org": "" },
      command: null,
      args: [],
      url: null,
      bearerToken: null,
    });
  });

  it("treats an empty or missing env and headers as empty", () => {
    const bare = {
      ...credentialed,
      env: undefined,
      headers: null,
      args: null,
    } as unknown as DatabaseMcpServer;
    const server = McpServersSerializer.serializeMcpServer(bare, "names_only");

    expect(server.env).toEqual({});
    expect(server.headers).toEqual({});
    expect(server.args).toEqual([]);
  });

  it.each([
    ["a boolean true from a caller still on the old signature", true],
    ["a boolean false", false],
    ["an unknown level", "everything"],
    ["undefined", undefined],
  ])(
    "reads %s as the least level: nothing of the connection",
    (_label, level) => {
      const server = McpServersSerializer.serializeMcpServer(
        credentialed,
        level as never,
      );

      expect(server.env).toEqual({});
      expect(server.headers).toEqual({});
      expect(server.command).toBeNull();
      expect(server.url).toBeNull();
      expect(server.args).toEqual([]);
      const embed = NamespacesSerializer.serializeNamespaceWithServers(
        {
          ...(dbNamespace as object),
          servers: [{ ...credentialed, status: "ACTIVE" }],
        } as never,
        level as never,
      );
      expect(JSON.stringify(embed)).not.toContain(CANARY.envValue);
      expect(JSON.stringify(embed)).not.toContain("VENDOR_TOKEN");
    },
  );
});
