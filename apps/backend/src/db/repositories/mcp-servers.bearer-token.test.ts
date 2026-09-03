/**
 * The bearer-token write contract of the MCP servers repository.
 *
 * Two properties are pinned, and the second is a live-outage guard:
 *
 * 1. CREATE and a re-typed UPDATE store the bearer as an `enc:v1:` envelope,
 *    never the plaintext.
 * 2. An UPDATE that carries an EMPTY bearer leaves the stored value alone. The
 *    serializer redacts bearer_token to null on every response, so the edit
 *    form re-submits an empty field on every save that did not re-type the
 *    secret; writing that empty value would blank the credential and break the
 *    upstream connection. The empty value must be dropped from the SET, not
 *    written. This test fails if update() ever writes an empty bearer again.
 *
 * Runs against a Drizzle mock (the repo destructures `db` at module load), so
 * it asserts the call SHAPE the repo produces, not the postgres engine.
 */
import { randomBytes } from "node:crypto";

import { beforeEach, describe, expect, it, vi } from "vitest";

const loggerMock = vi.hoisted(() => ({
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

const insertChain = {
  values: vi.fn().mockReturnThis(),
  returning: vi.fn().mockResolvedValue([{ uuid: "srv-1" }]),
};
const updateChain = {
  set: vi.fn().mockReturnThis(),
  where: vi.fn().mockReturnThis(),
  returning: vi.fn().mockResolvedValue([{ uuid: "srv-1" }]),
};

vi.mock("../index", () => ({
  db: {
    insert: vi.fn(() => insertChain),
    update: vi.fn(() => updateChain),
  },
}));

// schema.ts pulls @repo/zod-types, which vitest cannot resolve in unit mode;
// stub the one table the repo touches, with the fields used in the query shape.
vi.mock("../schema", () => ({
  mcpServersTable: {
    uuid: { name: "uuid" },
    name: { name: "name" },
    bearerToken: { name: "bearer_token" },
    created_at: { name: "created_at" },
    user_id: { name: "user_id" },
  },
}));

import { BEARER_ENVELOPE_PREFIX } from "@/lib/metamcp/server-bearer-crypto";

import { mcpServersRepository } from "./mcp-servers.repo";

const VALID_KEK = randomBytes(32).toString("base64");

beforeEach(() => {
  vi.clearAllMocks();
  updateChain.set.mockReturnThis();
  updateChain.where.mockReturnThis();
  updateChain.returning.mockResolvedValue([{ uuid: "srv-1" }]);
  insertChain.values.mockReturnThis();
  insertChain.returning.mockResolvedValue([{ uuid: "srv-1" }]);
  process.env.M365_TOKEN_KEK = VALID_KEK;
  delete process.env.M365_KEK_ID;
});

describe("McpServersRepository bearer-token write contract", () => {
  it("stores a created bearer token as an enc:v1: envelope, not plaintext", async () => {
    await mcpServersRepository.create({
      name: "srv",
      type: "STREAMABLE_HTTP",
      bearerToken: "mcp_endpoint_key_abc123",
    } as never);

    const stored = insertChain.values.mock.calls[0][0].bearerToken;
    expect(stored.startsWith(BEARER_ENVELOPE_PREFIX)).toBe(true);
    expect(stored).not.toContain("mcp_endpoint_key_abc123");
  });

  it("stores a re-typed bearer token on update as an enc:v1: envelope", async () => {
    await mcpServersRepository.update({
      uuid: "srv-1",
      name: "srv",
      bearerToken: "mcp_new_endpoint_key",
    } as never);

    const setArg = updateChain.set.mock.calls[0][0];
    expect(setArg.bearerToken.startsWith(BEARER_ENVELOPE_PREFIX)).toBe(true);
    expect(setArg.bearerToken).not.toContain("mcp_new_endpoint_key");
  });

  it("does NOT write bearer_token on update when the field is empty", async () => {
    await mcpServersRepository.update({
      uuid: "srv-1",
      name: "srv",
      bearerToken: "",
    } as never);

    const setArg = updateChain.set.mock.calls[0][0];
    // The empty value is dropped, so drizzle leaves the stored ciphertext
    // untouched rather than blanking it. Other fields still update.
    expect(setArg).not.toHaveProperty("bearerToken");
    expect(setArg.name).toBe("srv");
  });

  it("does NOT write bearer_token on update when the field is absent", async () => {
    await mcpServersRepository.update({
      uuid: "srv-1",
      name: "srv",
    } as never);

    const setArg = updateChain.set.mock.calls[0][0];
    expect(setArg).not.toHaveProperty("bearerToken");
  });
});
