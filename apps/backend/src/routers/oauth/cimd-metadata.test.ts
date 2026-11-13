/**
 * The authorization server metadata advertises client metadata document
 * support only while an allowlist is set.
 *
 * Oracle: the MCP authorization spec (2025-11-25), "Discovery": an
 * authorization server advertises support by including
 * `"client_id_metadata_document_supported": true` in its metadata, and the
 * SDK client (`shared/auth.js`) parses it as an optional boolean and uses a
 * URL client id only when it is exactly `true`. Advertising it is not
 * harmless, which is the design decision under test: a client that sees the
 * flag and has a metadata URL uses it instead of registering, and the SDK does
 * not fall back to registration when the URL is refused. So with no
 * allowlist the member must be absent and clients keep registering.
 */
import type express from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));
vi.mock("../../db/repositories", () => ({
  endpointsRepository: {
    findByName: vi.fn(),
    hasOAuthEnabledEndpoint: vi.fn().mockResolvedValue(true),
  },
}));

process.env.APP_URL = "https://mcp.example.test";

const { default: metadataRouter } = await import("./metadata");
const { OAUTH_CIMD_ALLOWED_CLIENTS_ENV, resetCimdConfigForTesting } =
  await import("./cimd-config");

async function authorizationServerMetadata(): Promise<Record<string, unknown>> {
  const path = "/.well-known/oauth-authorization-server";
  const req = {
    method: "GET",
    url: path,
    originalUrl: path,
    baseUrl: "",
    path,
    query: {},
    headers: {},
  } as unknown as express.Request;
  let body: Record<string, unknown> | undefined;
  let settle!: () => void;
  const settled = new Promise<void>((resolve) => (settle = resolve));
  const res = {
    status: () => res,
    set: () => res,
    json: (payload: Record<string, unknown>) => {
      body = payload;
      settle();
      return res;
    },
  };
  await new Promise<void>((resolve, reject) => {
    (metadataRouter as unknown as express.RequestHandler)(
      req,
      res as unknown as express.Response,
      (err?: unknown) => (err ? reject(err) : resolve()),
    );
    void settled.then(resolve);
  });
  if (!body) throw new Error("metadata handler settled without a body");
  return body;
}

beforeEach(() => {
  delete process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV];
  resetCimdConfigForTesting();
});

describe("client_id_metadata_document_supported", () => {
  it("is absent while the allowlist is empty (characterization: today's document)", async () => {
    const metadata = await authorizationServerMetadata();

    expect("client_id_metadata_document_supported" in metadata).toBe(false);
    // Registration is still advertised: clients keep registering.
    expect(metadata.registration_endpoint).toBe(
      "https://mcp.example.test/oauth/register",
    );
  });

  it("is absent when every allowlist entry is one that is not understood", async () => {
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = "claude.ai, http://x";
    expect(
      "client_id_metadata_document_supported" in
        (await authorizationServerMetadata()),
    ).toBe(false);
  });

  it.each([
    ["an exact URL", "https://app.example.com/oauth/client.json"],
    ["an origin", "https://app.example.com"],
  ])("is true for %s", async (_name, entry) => {
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = entry;

    const metadata = await authorizationServerMetadata();

    expect(metadata.client_id_metadata_document_supported).toBe(true);
    // Advertising it changes nothing else in the document.
    expect(metadata.registration_endpoint).toBe(
      "https://mcp.example.test/oauth/register",
    );
    expect(metadata.code_challenge_methods_supported).toEqual(["S256"]);
  });

  it("follows the setting back to absent when the list is cleared", async () => {
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = "https://app.example.com";
    expect(
      (await authorizationServerMetadata())
        .client_id_metadata_document_supported,
    ).toBe(true);

    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = "";
    expect(
      "client_id_metadata_document_supported" in
        (await authorizationServerMetadata()),
    ).toBe(false);
  });
});
