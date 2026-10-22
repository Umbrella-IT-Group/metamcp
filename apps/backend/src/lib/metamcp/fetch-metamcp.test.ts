/**
 * The namespace lookups tools/list and every other handler read.
 *
 * `getMcpServers` answers the routable servers and swallows a database error
 * into `{}`; tools/call routing, prompts, resources and the OpenAPI bridge
 * rely on that, and it is pinned unchanged here. tools/list must not: an
 * error-gated server it filters out, or a failed read, looked like "this
 * namespace mounts nothing" and produced a successful empty listing.
 * `getNamespaceListingServers` is the tools/list read: it keeps the
 * error-gated servers (apart from the routable ones) and lets a database
 * error propagate.
 *
 * The database is a chain stub (this fork has no live-database test
 * harness); `eq` and `and` record their arguments so the filters each read
 * applies can be asserted without generating SQL.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const { whereMock, oauthMock } = vi.hoisted(() => ({
  whereMock: vi.fn(),
  oauthMock: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

vi.mock("drizzle-orm", () => ({
  eq: (column: unknown, value: unknown) => ({ eq: [column, value] }),
  and: (...conditions: unknown[]) => ({ and: conditions }),
}));

vi.mock("../../db/index", () => {
  const chain = {
    from: () => chain,
    innerJoin: () => chain,
    where: whereMock,
  };
  return { db: { select: () => chain } };
});

vi.mock("../../db/schema", () => ({
  mcpServersTable: {
    uuid: "mcp_servers.uuid",
    name: "mcp_servers.name",
    description: "mcp_servers.description",
    type: "mcp_servers.type",
    command: "mcp_servers.command",
    args: "mcp_servers.args",
    env: "mcp_servers.env",
    url: "mcp_servers.url",
    created_at: "mcp_servers.created_at",
    bearerToken: "mcp_servers.bearerToken",
    headers: "mcp_servers.headers",
    error_status: "mcp_servers.error_status",
  },
  namespaceServerMappingsTable: {
    namespace_uuid: "mappings.namespace_uuid",
    mcp_server_uuid: "mappings.mcp_server_uuid",
    status: "mappings.status",
  },
}));

vi.mock("../../db/repositories/index", () => ({
  oauthSessionsRepository: { findByMcpServerUuid: oauthMock },
}));

vi.mock("./utils", () => ({
  getDefaultEnvironment: () => ({ PATH: "/usr/bin" }),
}));

import { getMcpServers, getNamespaceListingServers } from "./fetch-metamcp";

const NAMESPACE_EQ = { eq: ["mappings.namespace_uuid", "ns-1"] };
const ACTIVE_EQ = { eq: ["mappings.status", "ACTIVE"] };
const NOT_GATED_EQ = { eq: ["mcp_servers.error_status", "NONE"] };

const row = (uuid: string, name: string, errorStatus: "NONE" | "ERROR") => ({
  uuid,
  name,
  description: null,
  type: "STREAMABLE_HTTP",
  command: null,
  args: [],
  env: {},
  url: `http://${name}:3000/mcp`,
  created_at: new Date("2026-10-21T00:00:00Z"),
  bearerToken: null,
  headers: {},
  status: "ACTIVE",
  error_status: errorStatus,
});

beforeEach(() => {
  whereMock.mockReset();
  oauthMock.mockReset();
  oauthMock.mockResolvedValue(undefined);
});

describe("getNamespaceListingServers (the tools/list read)", () => {
  it("keeps error-gated servers, apart from the routable ones", async () => {
    whereMock.mockResolvedValue([
      row("s-ninja", "ninja", "ERROR"),
      row("s-itglue", "itglue", "NONE"),
    ]);

    const listing = await getNamespaceListingServers("ns-1");

    expect(Object.keys(listing.routable)).toEqual(["s-itglue"]);
    expect(Object.keys(listing.errorGated)).toEqual(["s-ninja"]);
    // Full parameters, built as getMcpServers builds them: the watch needs
    // them to probe the server once its gate is reset.
    expect(listing.errorGated["s-ninja"]).toMatchObject({
      uuid: "s-ninja",
      name: "ninja",
      type: "STREAMABLE_HTTP",
      url: "http://ninja:3000/mcp",
      status: "active",
      error_status: "error",
    });
  });

  it("applies the mount filter but not the error gate", async () => {
    whereMock.mockResolvedValue([]);

    await getNamespaceListingServers("ns-1");
    expect(whereMock).toHaveBeenLastCalledWith({
      and: [NAMESPACE_EQ, ACTIVE_EQ],
    });

    await getNamespaceListingServers("ns-1", true);
    expect(whereMock).toHaveBeenLastCalledWith({ and: [NAMESPACE_EQ] });
  });

  it("lets a failed read propagate instead of answering an empty namespace", async () => {
    whereMock.mockRejectedValue(new Error("connection terminated"));
    await expect(getNamespaceListingServers("ns-1")).rejects.toThrow(
      "connection terminated",
    );
  });

  it("lets a failed credential read propagate too", async () => {
    whereMock.mockResolvedValue([row("s-ninja", "ninja", "NONE")]);
    oauthMock.mockRejectedValue(new Error("connection terminated"));
    await expect(getNamespaceListingServers("ns-1")).rejects.toThrow(
      "connection terminated",
    );
  });
});

describe("getMcpServers (every other caller), unchanged", () => {
  it("filters the error gate in the query and answers the routable servers", async () => {
    whereMock.mockResolvedValue([row("s-itglue", "itglue", "NONE")]);

    const servers = await getMcpServers("ns-1");

    expect(whereMock).toHaveBeenLastCalledWith({
      and: [NAMESPACE_EQ, ACTIVE_EQ, NOT_GATED_EQ],
    });
    expect(Object.keys(servers)).toEqual(["s-itglue"]);
    expect(servers["s-itglue"]).toMatchObject({
      status: "active",
      error_status: "none",
    });

    await getMcpServers("ns-1", true);
    expect(whereMock).toHaveBeenLastCalledWith({
      and: [NAMESPACE_EQ, NOT_GATED_EQ],
    });
  });

  it("still answers {} when the read fails", async () => {
    whereMock.mockRejectedValue(new Error("connection terminated"));
    await expect(getMcpServers("ns-1")).resolves.toEqual({});
  });
});
