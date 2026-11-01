/**
 * The grammar of a public MCP resource path, shared by RFC 9728 discovery and
 * the 401 challenge. Both copy the matched path into something a client
 * trusts (the served `resource`, the quoted `resource_metadata` header
 * parameter), so the cases here are the near misses: each one is a path a
 * loose prefix match would have reflected.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  matchPublicMcpResourcePath,
  PUBLIC_MCP_MOUNT,
  PUBLIC_MCP_TRANSPORTS,
} from "./public-mcp-resource";

describe("matchPublicMcpResourcePath accepts exactly /metamcp/<name>/(mcp|sse|api)", () => {
  it.each(PUBLIC_MCP_TRANSPORTS)("matches the %s transport", (transport) => {
    expect(
      matchPublicMcpResourcePath(`/metamcp/claude-connector/${transport}`),
    ).toEqual({
      path: `/metamcp/claude-connector/${transport}`,
      name: "claude-connector",
      transport,
    });
  });

  it("matches every character the endpoint name schema allows", () => {
    // `^[a-zA-Z0-9_-]+$` in @repo/zod-types: no creatable name needs escaping.
    expect(matchPublicMcpResourcePath("/metamcp/Az09_-x/mcp")?.name).toBe(
      "Az09_-x",
    );
  });

  it("keeps the request's percent-encoded spelling in the path and decodes the name", () => {
    // A strict client compares the advertised `resource` with the URL it
    // used, so the spelling is kept; the endpoint lookup needs the decoded
    // name, the same value `req.params.endpoint_name` carries.
    expect(matchPublicMcpResourcePath("/metamcp/my%20endpoint/sse")).toEqual({
      path: "/metamcp/my%20endpoint/sse",
      name: "my endpoint",
      transport: "sse",
    });
  });

  it("admits an encoded quote only in its encoded, inert form", () => {
    const match = matchPublicMcpResourcePath("/metamcp/a%22b/mcp");
    expect(match?.path).toBe("/metamcp/a%22b/mcp");
    expect(match?.path).not.toContain('"');
  });
});

describe("matchPublicMcpResourcePath refuses everything else", () => {
  it.each([
    // Extra or missing segments: the suffix a prefix match reflected.
    ["a suffix after the transport", "/metamcp/claude-connector/mcp/extra"],
    ["a deep suffix", "/metamcp/claude-connector/mcp/a/b/c"],
    ["a trailing slash", "/metamcp/claude-connector/mcp/"],
    ["no transport", "/metamcp/claude-connector"],
    ["no name", "/metamcp//mcp"],
    ["the bare mount", "/metamcp"],
    ["a doubled leading slash", "//metamcp/claude-connector/mcp"],
    ["no leading slash", "metamcp/claude-connector/mcp"],
    ["the empty path", ""],
    // Other routes under the mount that are not OAuth resources.
    ["the SSE message leg", "/metamcp/claude-connector/message"],
    ["an OpenAPI tool call", "/metamcp/claude-connector/api/some_tool"],
    ["the OpenAPI schema", "/metamcp/claude-connector/api/openapi.json"],
    ["an admin route", "/metamcp/claude-connector/admin/error-status"],
    // Another mount, or one that only starts like ours.
    ["the internal proxy mount", "/mcp-proxy/claude-connector/mcp"],
    ["a lookalike mount", "/metamcpx/claude-connector/mcp"],
    ["a transport in another case", "/metamcp/claude-connector/MCP"],
    [
      "an encoded slash in the transport",
      "/metamcp/claude-connector/mcp%2Fextra",
    ],
    // Names with characters that mean something in a URL or a header.
    ["a raw double quote", '/metamcp/a"b/mcp'],
    ["a header-parameter breakout", '/metamcp/x",error="y/mcp'],
    ["a backslash", "/metamcp/a\\b/mcp"],
    ["a comma", "/metamcp/a,b/mcp"],
    ["a semicolon", "/metamcp/a;b/mcp"],
    ["a space", "/metamcp/a b/mcp"],
    ["a control character", "/metamcp/a\u0001b/mcp"],
    ["DEL", "/metamcp/a\u007fb/mcp"],
    ["non-ASCII", "/metamcp/café/mcp"],
    ["angle brackets", "/metamcp/<x>/mcp"],
    ["a sub-delimiter", "/metamcp/a=b/mcp"],
    // Encodings that do not decode.
    ["a bare percent sign", "/metamcp/a%/mcp"],
    ["a non-hex escape", "/metamcp/a%zz/mcp"],
    ["an invalid UTF-8 sequence", "/metamcp/%C3%28/mcp"],
    // Dot segments, which a URL resolver collapses into another path.
    ["a single dot", "/metamcp/./mcp"],
    ["a double dot", "/metamcp/../mcp"],
    ["an encoded double dot", "/metamcp/%2e%2e/mcp"],
    ["an upper-case encoded double dot", "/metamcp/%2E%2E/mcp"],
    ["a mixed double dot", "/metamcp/.%2e/mcp"],
    ["an encoded single dot", "/metamcp/%2e/mcp"],
  ])("refuses %s", (_label, path) => {
    expect(matchPublicMcpResourcePath(path)).toBeNull();
  });
});

describe("drift guards: the grammar names routes that exist", () => {
  const read = (relative: string) =>
    readFileSync(fileURLToPath(new URL(relative, import.meta.url)), "utf8");

  it("matches the mount index.ts gives the public MCP router", () => {
    expect(read("../index.ts")).toContain(
      `app.use("${PUBLIC_MCP_MOUNT}", publicEndpointsRouter)`,
    );
  });

  it.each([
    ["mcp", "../routers/public-metamcp/streamable-http.ts"],
    ["sse", "../routers/public-metamcp/sse.ts"],
    ["api", "../routers/public-metamcp/openapi/routes.ts"],
  ])("still serves a public endpoint on /%s", (transport, file) => {
    expect(PUBLIC_MCP_TRANSPORTS).toContain(transport);
    expect(read(file)).toContain(`"/:endpoint_name/${transport}"`);
  });

  it("lists no transport without a route behind it", () => {
    expect([...PUBLIC_MCP_TRANSPORTS].sort()).toEqual(["api", "mcp", "sse"]);
  });
});
