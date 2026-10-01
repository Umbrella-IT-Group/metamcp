/**
 * The OpenAPI bridge answers a retired tool name with the redirect, and a
 * gateway timeout with the adjudication hint, through the REAL chain and the
 * REAL HTTP mapping in `executeToolWithMiddleware`.
 *
 * Why this surface matters: automation workflows reach the gateway through this
 * bridge, and a swallowed failure there is invisible. The bridge routes by
 * server prefix only, so a retired name on a live server is forwarded to the
 * backend, which answers an isError "Unknown tool"; the redirect turns that into
 * the bridge's usual 403 body. An unmapped unknown name keeps its 404.
 *
 * Only the DB-touching boundary is mocked, as in the neighbouring bridge tests;
 * the audit, redirect and timeout-hint middleware and `compose` run for real.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { requestMock } = vi.hoisted(() => ({ requestMock: vi.fn() }));

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

vi.mock("../../../db/index", () => ({ db: {}, pool: {} }));

vi.mock(
  "../../../lib/metamcp/metamcp-middleware/filter-tools.functional",
  () => ({
    createFilterCallToolMiddleware: () => (h: unknown) => h,
    createFilterListToolsMiddleware: () => (h: unknown) => h,
  }),
);
vi.mock(
  "../../../lib/metamcp/metamcp-middleware/tool-overrides.functional",
  () => ({
    createToolOverridesCallToolMiddleware: () => (h: unknown) => h,
    createToolOverridesListToolsMiddleware: () => (h: unknown) => h,
  }),
);

vi.mock("../../../lib/metamcp/fetch-metamcp", () => ({
  getMcpServers: vi
    .fn()
    .mockResolvedValue({ "server-ninja": { name: "ninja" } }),
}));
vi.mock("../../../db/repositories/namespaces.repo", () => ({
  namespacesRepository: {
    findServersForNamespaceToolName: vi.fn().mockResolvedValue([]),
  },
}));
vi.mock("../../../lib/config.service", () => ({
  configService: {
    getMcpResetTimeoutOnProgress: vi.fn().mockResolvedValue(false),
    getMcpTimeout: vi.fn().mockResolvedValue(60000),
    getMcpMaxTotalTimeout: vi.fn().mockResolvedValue(60000),
    getMcpToolCallReconnectWarmupTimeout: vi.fn().mockResolvedValue(0),
  },
}));
vi.mock("../../../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: vi.fn().mockResolvedValue({
      client: {
        request: requestMock,
        getServerCapabilities: () => ({ tools: {} }),
        getServerVersion: () => ({ name: "ninja", version: "1.0.0" }),
      },
    }),
    invalidateServerConnection: vi.fn(),
  },
}));
vi.mock("../../../lib/metamcp/tool-call-warmup", () => ({
  acquireSessionWithBoundedWarmup: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../../../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: { getOpenApiServer: vi.fn().mockResolvedValue({}) },
}));
vi.mock("../../../lib/metamcp/caller-context", () => ({
  resolveCallerContext: vi.fn().mockReturnValue({}),
}));
vi.mock("../../../lib/metamcp/consumer-identity-resolver", () => ({
  resolveClientIdentity: vi.fn().mockResolvedValue({ name: "test-consumer" }),
}));

import {
  RetiredToolsRegistry,
  setRetiredToolsRegistryForTesting,
} from "../../../lib/metamcp/retired-tools";
import { executeToolWithMiddleware } from "./tool-execution";

let dir: string;

function makeRes() {
  const res = {
    statusCode: 200,
    body: undefined as unknown,
    status: vi.fn((code: number) => {
      res.statusCode = code;
      return res;
    }),
    json: vi.fn((body: unknown) => {
      res.body = body;
      return res;
    }),
  };
  return res;
}

const run = async (toolName: string) => {
  const res = makeRes();
  await executeToolWithMiddleware(
    { namespaceUuid: "ns-1", params: { tool_name: toolName } } as never,
    res as never,
    {},
  );
  return res;
};

beforeEach(() => {
  requestMock.mockReset();
  dir = mkdtempSync(path.join(tmpdir(), "retired-bridge-"));
  const file = path.join(dir, "retired-tools.json");
  writeFileSync(
    file,
    JSON.stringify({
      version: 1,
      retired: {
        ninja__add_note: {
          since: "2026-09-02",
          replacement: "ninja__ticket_manage",
          args: { mode: "note_add" },
        },
      },
    }),
  );
  setRetiredToolsRegistryForTesting(
    new RetiredToolsRegistry({ path: file, reloadSeconds: 30 }),
  );
});

afterEach(() => {
  setRetiredToolsRegistryForTesting(undefined);
  rmSync(dir, { recursive: true, force: true });
});

describe("OpenAPI bridge: retired names", () => {
  it("a listed retired name on a live server is forwarded, answered unknown by the backend, and returned as the 403 redirect", async () => {
    requestMock.mockResolvedValue({
      isError: true,
      content: [{ type: "text", text: "Unknown tool: 'add_note'" }],
    });

    const res = await run("ninja__add_note");

    expect(res.statusCode).toBe(403);
    const body = res.body as { error: string; message: string };
    expect(body.error).toBe("Tool access denied");
    const envelope = JSON.parse(body.message);
    expect(envelope).toMatchObject({
      error: true,
      code: "tool_retired",
      context: {
        replacement: "ninja__ticket_manage",
        replacement_call: 'ninja__ticket_manage(mode="note_add")',
      },
    });
  });

  it("an unlisted name the backend answers as unknown keeps the backend's own text in the 403", async () => {
    requestMock.mockResolvedValue({
      isError: true,
      content: [{ type: "text", text: "Unknown tool: 'never_existed'" }],
    });

    const res = await run("ninja__never_existed");

    // The backend's own answer is an isError result, so the bridge's isError
    // branch maps it to 403 with the backend's text, exactly as before. Only a
    // name in the retired map is rewritten.
    expect(res.statusCode).toBe(403);
    const body = res.body as { error: string; message: string };
    expect(body.message).toBe("Unknown tool: 'never_existed'");
  });

  it("a thrown unknown tool for an unlisted name keeps the 404 'Tool not found'", async () => {
    // No server with this prefix, so the bridge handler throws its own error.
    const res = await run("nosuchserver__anything");

    expect(res.statusCode).toBe(404);
    expect(res.body).toMatchObject({ error: "Tool not found" });
  });

  it("a thrown unknown tool for a listed name becomes the redirect", async () => {
    setRetiredToolsRegistryForTesting(undefined);
    const file = path.join(dir, "retired-tools.json");
    writeFileSync(
      file,
      JSON.stringify({
        version: 1,
        retired: {
          nosuchserver__lookup: {
            since: "2026-09-28",
            replacement: "ninja__other",
          },
        },
      }),
    );
    setRetiredToolsRegistryForTesting(
      new RetiredToolsRegistry({ path: file, reloadSeconds: 30 }),
    );

    const res = await run("nosuchserver__lookup");

    expect(res.statusCode).toBe(403);
    const envelope = JSON.parse((res.body as { message: string }).message);
    expect(envelope.code).toBe("tool_retired");
  });

  it("a normal successful call is untouched", async () => {
    requestMock.mockResolvedValue({
      content: [{ type: "text", text: "fine" }],
    });

    const res = await run("ninja__list_things");

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ content: [{ type: "text", text: "fine" }] });
  });
});

describe("OpenAPI bridge: gateway timeout hint", () => {
  it("a gateway timeout surfaces as the usual 500 with the adjudication hint in the message", async () => {
    requestMock.mockRejectedValue(
      McpError.fromError(ErrorCode.RequestTimeout, "Request timed out", {
        timeout: 60_000,
      }),
    );

    const res = await run("ninja__list_things");

    expect(res.statusCode).toBe(500);
    const body = res.body as { error: string; message: string };
    expect(body.error).toBe("Tool execution failed");
    expect(body.message).toContain("Request timed out");
    expect(body.message).toContain("the backend may still be running it");
    expect(body.message).toContain(
      "read the target's current state before retrying",
    );
    // Not replayed: the bridge sent the call once.
    expect(requestMock).toHaveBeenCalledTimes(1);
  });
});
