/**
 * Credential disclosure (#98): the server serializers returned every backend
 * MCP's connection URL and credential material to any authenticated member.
 *
 * `mcpServers.list`, `mcpServers.get` and `namespaces.get` are all
 * `protectedProcedure` — members legitimately see the server inventory in
 * their dashboard, so the fix could not be an RBAC gate without blanking the
 * member UI. Instead the two serializers redact by role, and these tests pin
 * both halves of that contract: a member sees names and metadata but no way
 * to reach or authenticate to anything, and an admin's response is byte-for-
 * byte what it always was.
 *
 * Both serializers are covered because they are two independent copies of
 * the same embed — redacting only the mcpServers path would have left the
 * whole disclosure reachable via the namespace that contains the server.
 */

import { DatabaseMcpServer } from "@repo/zod-types";
import { describe, expect, it } from "vitest";

import { McpServersSerializer } from "./mcp-servers.serializer";
import { NamespacesSerializer } from "./namespaces.serializer";

// Shaped like a real row: the internal Docker URL is the connection-URL leak, the
// bearer token / env / headers are #98.
const SECRET_URL = "http://mcp-autotask:3000";
const SECRET_TOKEN = "sk_live_do_not_disclose";
const SECRET_ENV = { AUTOTASK_API_KEY: "at_secret_value" };
const SECRET_HEADERS = { "X-Tenant": "umbrella-internal" };
const SECRET_COMMAND = "/usr/local/bin/mcp-autotask";
const SECRET_ARGS = ["--tenant", "umbrella", "--token", "arg_secret"];

const CREATED_AT = new Date("2026-08-13T12:00:00.000Z");

const dbServer = {
  uuid: "11111111-1111-4111-8111-111111111111",
  name: "mcp-autotask",
  description: "Autotask PSA bridge",
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
  "AUTOTASK_API_KEY",
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
  expect(server.name).toBe("mcp-autotask");
  expect(server.description).toBe("Autotask PSA bridge");
  expect(server.created_at).toBe(CREATED_AT.toISOString());
};

describe("McpServersSerializer — non-admin", () => {
  it("redacts url, command, args, env, bearerToken and headers", () => {
    const server = McpServersSerializer.serializeMcpServer(dbServer, false);

    expect(server.url).toBeNull();
    expect(server.command).toBeNull();
    expect(server.args).toEqual([]);
    expect(server.env).toEqual({});
    expect(server.bearerToken).toBeNull();
    expect(server.headers).toEqual({});
  });

  it("keeps the metadata the member dashboard renders", () => {
    // The fix must not be "hide the server" — members still list servers.
    const server = McpServersSerializer.serializeMcpServer(dbServer, false);

    expectMetadataIntact(server);
    expect(server.type).toBe("STREAMABLE_HTTP");
  });

  it("leaks no secret substring anywhere in the serialised object", () => {
    // Catches a secret surviving under a renamed or newly-added key, which
    // the per-field assertions above would miss.
    const json = JSON.stringify(
      McpServersSerializer.serializeMcpServer(dbServer, false),
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
    const servers = McpServersSerializer.serializeMcpServerList(rows, false);

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
    const server = McpServersSerializer.serializeMcpServer(dbServer, true);

    expect(server.url).toBe(SECRET_URL);
    expect(server.command).toBe(SECRET_COMMAND);
    expect(server.args).toEqual(SECRET_ARGS);
    expect(server.env).toEqual(SECRET_ENV);
    expect(server.bearerToken).toBe(SECRET_TOKEN);
    expect(server.headers).toEqual(SECRET_HEADERS);
  });

  it("passes every row of a list through unchanged", () => {
    const servers = McpServersSerializer.serializeMcpServerList(
      [dbServer, dbServer],
      true,
    );

    expect(servers).toHaveLength(2);
    for (const server of servers) {
      expect(server.url).toBe(SECRET_URL);
      expect(server.bearerToken).toBe(SECRET_TOKEN);
    }
  });
});

describe("NamespacesSerializer — embedded servers follow the same rule", () => {
  it("redacts the embedded server for a non-admin", () => {
    const namespace = NamespacesSerializer.serializeNamespaceWithServers(
      dbNamespace,
      false,
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
      false,
    );
    const [server] = namespace.servers;

    expect(namespace.name).toBe("umbrella-prod");
    expectMetadataIntact(server);
    expect(server.status).toBe("ACTIVE");
  });

  it("leaks no secret substring through the namespace route", () => {
    const json = JSON.stringify(
      NamespacesSerializer.serializeNamespaceWithServers(dbNamespace, false),
    );

    for (const secret of SECRETS) {
      expect(json).not.toContain(secret);
    }
  });

  it("passes the embedded server through unchanged for an admin", () => {
    const namespace = NamespacesSerializer.serializeNamespaceWithServers(
      dbNamespace,
      true,
    );
    const [server] = namespace.servers;

    expect(server.url).toBe(SECRET_URL);
    expect(server.bearerToken).toBe(SECRET_TOKEN);
    expect(server.env).toEqual(SECRET_ENV);
    expect(server.command).toBe(SECRET_COMMAND);
    expect(server.args).toEqual(SECRET_ARGS);
    expect(server.headers).toEqual(SECRET_HEADERS);
  });
});
