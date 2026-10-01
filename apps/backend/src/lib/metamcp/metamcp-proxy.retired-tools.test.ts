/**
 * Retired-tool redirect and audit classification, driven end to end through
 * `createServer`.
 *
 * A real SDK consumer `Client` talks to the gateway's own `Server`. Backend
 * sessions are SDK `Client`/`Server` pairs over `InMemoryTransport`, and the
 * backend counts how many times its one real tool actually executed. The audit
 * middleware and the retired-tool middleware are the REAL
 * ones; only the filter (which needs the database) is replaced by a small fake
 * that reproduces its fail-closed denial for an unresolvable server prefix, and
 * the override middleware is pass-through.
 *
 * What it pins:
 *   - a retired name gets the redirect and the backend executes nothing;
 *   - a name that is in the map but IS served still executes exactly once;
 *   - the three ways a retired call fails today all end in the redirect;
 *   - a timeout on a listed name is neither rewritten as a redirect nor
 *     replayed;
 *   - tools/list is unchanged;
 *   - the audit rows say tool_retired, unknown_tool and inband_error.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  CallToolResult,
  CallToolResultSchema,
  ErrorCode,
  ListToolsRequestSchema,
  ListToolsResultSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ConnectedClient } from "./client";

const {
  getSessionMock,
  invalidateServerConnectionMock,
  findServersMock,
  config,
} = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  invalidateServerConnectionMock: vi.fn(),
  findServersMock: vi.fn(),
  config: { mcpTimeoutMs: 5_000 },
}));

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

vi.mock("../../db", () => ({ db: {} }));
vi.mock("../../db/schema", () => ({}));
vi.mock("../../db/repositories/namespaces.repo", () => ({
  namespacesRepository: { findServersForNamespaceToolName: findServersMock },
}));
vi.mock("../../db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: {},
}));
vi.mock("../../trpc/tools.impl", () => ({
  toolsImplementations: { sync: vi.fn().mockResolvedValue(undefined) },
}));

vi.mock("../config.service", () => ({
  configService: {
    getMcpResetTimeoutOnProgress: async () => false,
    getMcpTimeout: async () => config.mcpTimeoutMs,
    getMcpMaxTotalTimeout: async () => 60_000,
    getMcpToolCallReconnectWarmupTimeout: async () => 0,
  },
}));

vi.mock("./fetch-metamcp", () => ({
  getMcpServers: vi.fn(async () => ({ "server-ninja": { name: "ninja" } })),
}));

vi.mock("./mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: getSessionMock,
    invalidateServerConnection: invalidateServerConnectionMock,
    cleanupSession: vi.fn(),
    // tools/list only: a warm pool, so it does not try to warm one up.
    getPoolStatus: () => ({ idle: 1, active: 1 }),
  },
}));

// The filter needs the database. This fake reproduces only what matters here:
// the fail-closed denial for a server prefix that no longer resolves.
vi.mock("./metamcp-middleware/filter-tools.functional", () => ({
  createFilterCallToolMiddleware:
    () =>
    (
      next: (
        request: { params: { name: string } },
        context: unknown,
      ) => Promise<CallToolResult>,
    ) =>
    async (request: { params: { name: string } }, context: unknown) => {
      if (request.params.name.startsWith("gone__")) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: `Access denied to tool "${request.params.name}": server could not be resolved`,
            },
          ],
        } satisfies CallToolResult;
      }
      return next(request, context);
    },
  createFilterListToolsMiddleware: () => (next: unknown) => next,
}));
vi.mock("./metamcp-middleware/tool-overrides.functional", () => ({
  createToolOverridesCallToolMiddleware: () => (next: unknown) => next,
  createToolOverridesListToolsMiddleware: () => (next: unknown) => next,
  mapOverrideNameToOriginal: vi.fn(async (name: string) => name),
}));
vi.mock("./cold-connect-broker-fallback", () => ({
  resolveColdConnectBrokerFallback: () => undefined,
}));
vi.mock("./tool-call-warmup", () => ({
  acquireSessionWithBoundedWarmup: vi.fn(async (args: { serverUuid: string }) =>
    warmSessions.get(args.serverUuid),
  ),
}));

import { setAuditRecorderForTesting } from "./metamcp-middleware/auditing.functional";
import { createServer } from "./metamcp-proxy";
import {
  RetiredToolsRegistry,
  setRetiredToolsRegistryForTesting,
} from "./retired-tools";

const warmSessions = new Map<string, ConnectedClient>();

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

const REAL_TOOL = "ninja__list_things";
const real: CallToolResult = {
  content: [{ type: "text", text: "a real answer" }],
};

interface Backend {
  session: ConnectedClient;
  /** How many times the one real tool executed. */
  executions: () => number;
  /** How many tools/call requests reached the backend, of any name. */
  requests: () => number;
}

const cleanups: Array<() => Promise<unknown>> = [];

async function backend(
  onReal: () => Promise<CallToolResult> = async () => real,
): Promise<Backend> {
  const server = new Server(
    { name: "ninja", version: "1.0.0" },
    { capabilities: { tools: {} } },
  );
  let executions = 0;
  let requests = 0;
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [{ name: "list_things", inputSchema: { type: "object" } }],
  }));
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    requests += 1;
    if (request.params.name === "list_things") {
      executions += 1;
      return onReal();
    }
    // What a FastMCP backend answers for a name it does not serve.
    return {
      isError: true,
      content: [
        { type: "text", text: `Unknown tool: '${request.params.name}'` },
      ],
    };
  });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await server.connect(serverSide);
  const client = new Client({ name: "metamcp", version: "1.0.0" });
  await client.connect(clientSide);
  cleanups.push(() => client.close());
  return {
    session: {
      client,
      cleanup: () => client.close(),
      listChangedSubscribers: new Set(),
    },
    executions: () => executions,
    requests: () => requests,
  };
}

async function connectConsumer(): Promise<Client> {
  const { server } = await createServer("ns-1", "sess-1");
  const [consumerSide, gatewaySide] = InMemoryTransport.createLinkedPair();
  await server.connect(gatewaySide);
  const consumer = new Client({ name: "consumer", version: "1.0.0" });
  await consumer.connect(consumerSide);
  cleanups.push(() => consumer.close());
  return consumer;
}

const call = (
  consumer: Client,
  name: string,
  args: Record<string, unknown> = {},
) =>
  consumer.request(
    { method: "tools/call", params: { name, arguments: args } },
    CallToolResultSchema,
    { timeout: 10_000 },
  );

const envelopeOf = (result: {
  content: Array<{ type: string; text?: string }>;
}) => JSON.parse(result.content[0].text ?? "{}");

let dir: string;

function installMap() {
  dir = mkdtempSync(path.join(tmpdir(), "retired-e2e-"));
  const file = path.join(dir, "retired-tools.json");
  writeFileSync(
    file,
    JSON.stringify({
      version: 1,
      retired: {
        ninja__add_note: {
          since: "2026-09-02",
          replacement: "ninja__list_things",
          args: { mode: "note_add" },
          hint: "pass ticket and note",
        },
        gone__lookup: {
          since: "2026-09-28",
          replacement: "ninja__list_things",
          also: ["ninja__other"],
        },
        // Listed, and also actually served: it must keep working.
        [REAL_TOOL]: {
          since: "2026-09-02",
          replacement: "ninja__other",
          hint: "wrongly listed",
        },
      },
    }),
  );
  setRetiredToolsRegistryForTesting(
    new RetiredToolsRegistry({ path: file, reloadSeconds: 30 }),
  );
}

beforeEach(() => {
  getSessionMock.mockReset();
  invalidateServerConnectionMock.mockReset();
  invalidateServerConnectionMock.mockResolvedValue(undefined);
  findServersMock.mockReset();
  findServersMock.mockResolvedValue([]);
  warmSessions.clear();
  config.mcpTimeoutMs = 5_000;
  installMap();
});

afterEach(async () => {
  setRetiredToolsRegistryForTesting(undefined);
  setAuditRecorderForTesting(null);
  rmSync(dir, { recursive: true, force: true });
  while (cleanups.length > 0) {
    await cleanups
      .pop()?.()
      .catch(() => undefined);
  }
});

describe("retired names through the gateway", () => {
  it("(a) a retired name the backend does not serve gets the redirect and executes nothing", async () => {
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);

    const result = await call(await connectConsumer(), "ninja__add_note", {
      ticket: 1,
    });

    expect(result.isError).toBe(true);
    const envelope = envelopeOf(result);
    expect(envelope).toMatchObject({
      error: true,
      code: "tool_retired",
      context: {
        retired: "ninja__add_note",
        replacement: "ninja__list_things",
        replacement_call: 'ninja__list_things(mode="note_add")',
      },
    });
    expect(target.executions()).toBe(0);
    // Routing found no such tool, so nothing was even sent to the backend.
    expect(target.requests()).toBe(0);
  });

  it("(b) a name that is in the map but IS served still executes exactly once", async () => {
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);

    const result = await call(await connectConsumer(), REAL_TOOL);

    expect(result.content).toEqual(real.content);
    expect(result.isError).toBeFalsy();
    expect(target.executions()).toBe(1);
  });

  it("(c) a retired name with a stale routing row is forwarded, the backend says unknown, the client gets the redirect", async () => {
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);
    // A stale tools + mapping row: the reconnect-window fallback finds a server
    // for the retired name and the call is forwarded.
    findServersMock.mockResolvedValue([
      { serverUuid: "server-ninja", serverName: "ninja" },
    ]);
    warmSessions.set("server-ninja", target.session);

    const result = await call(await connectConsumer(), "ninja__add_note");

    expect(envelopeOf(result).code).toBe("tool_retired");
    // The backend was asked and answered "Unknown tool"; it ran nothing.
    expect(target.requests()).toBe(1);
    expect(target.executions()).toBe(0);
  });

  it("(d) an unresolvable server prefix (the filter's denial) gets the redirect", async () => {
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);

    const result = await call(await connectConsumer(), "gone__lookup");

    const envelope = envelopeOf(result);
    expect(envelope.code).toBe("tool_retired");
    expect(envelope.context.also).toEqual(["ninja__other"]);
    expect(target.requests()).toBe(0);
  });

  it("an unmapped unknown name keeps the bare gateway answer", async () => {
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);
    const consumer = await connectConsumer();

    await expect(call(consumer, "ninja__never_existed")).rejects.toThrow(
      "Unknown tool",
    );
  });

  it("(e) a timeout on a listed name is not rewritten as a redirect and not replayed", async () => {
    config.mcpTimeoutMs = 50;
    let release: () => void = () => undefined;
    const target = await backend(
      () =>
        new Promise((resolve) => {
          release = () => resolve(real);
        }),
    );
    cleanups.push(async () => release());
    getSessionMock.mockResolvedValue(target.session);

    let error: McpError | undefined;
    try {
      await call(await connectConsumer(), REAL_TOOL);
    } catch (caught) {
      error = caught as McpError;
    }

    expect(error).toBeInstanceOf(McpError);
    expect(error?.code).toBe(ErrorCode.RequestTimeout);
    // Not a redirect: the name is listed, but the failure is a timeout.
    expect(error?.message).not.toContain("tool_retired");
    expect(error?.message).toContain("Request timed out");
    expect(target.executions()).toBe(1);
    expect(invalidateServerConnectionMock).not.toHaveBeenCalled();
    expect(getSessionMock).toHaveBeenCalledTimes(1);
  });

  it("(f) tools/list is unchanged", async () => {
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);
    const consumer = await connectConsumer();

    const listed = await consumer.request(
      { method: "tools/list", params: {} },
      ListToolsResultSchema,
    );

    expect(listed.tools.map((tool) => tool.name)).toEqual([REAL_TOOL]);
  });
});

describe("the audit rows for those outcomes", () => {
  const rowsFor = async (
    run: (consumer: Client) => Promise<unknown>,
    target: Backend,
  ) => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    getSessionMock.mockResolvedValue(target.session);
    const consumer = await connectConsumer();
    await run(consumer).catch(() => undefined);
    await flush();
    return recorder.mock.calls.map((callArgs) => callArgs[0]);
  };

  it("a redirect is recorded tool_retired with the argument shape", async () => {
    const [row] = await rowsFor(
      (consumer) =>
        call(consumer, "ninja__add_note", { mode: "x1", ticket: 5 }),
      await backend(),
    );

    expect(row).toMatchObject({
      server_name: "ninja",
      tool_name: "add_note",
      success: false,
      error_code: "tool_retired",
      args_shape: { sel: { mode: "x1" }, keys: ["mode", "ticket"] },
    });
  });

  it("an unmapped unknown name is recorded unknown_tool", async () => {
    const [row] = await rowsFor(
      (consumer) => call(consumer, "ninja__never_existed"),
      await backend(),
    );
    expect(row).toMatchObject({
      success: false,
      error_code: "unknown_tool",
    });
  });

  it("the filter's unresolved-server denial for an unmapped name is unknown_tool", async () => {
    const [row] = await rowsFor(
      (consumer) => call(consumer, "gone__unlisted"),
      await backend(),
    );
    expect(row).toMatchObject({ success: false, error_code: "unknown_tool" });
  });

  it("an in-band refusal from a real backend is inband_error with its code", async () => {
    const refusing = await backend(async () => ({
      content: [
        {
          type: "text",
          text: JSON.stringify({ error: true, code: "invalid_input" }),
        },
      ],
      structuredContent: { error: true, code: "invalid_input", message: "m" },
    }));
    const [row] = await rowsFor(
      (consumer) => call(consumer, REAL_TOOL, { mode: "list" }),
      refusing,
    );

    expect(row).toMatchObject({
      success: false,
      error_code: "inband_error",
      error_detail: "invalid_input",
      args_shape: { sel: { mode: "list" }, keys: ["mode"] },
    });
  });

  it("a real backend's in-band refusal reaches the client exactly as the backend sent it", async () => {
    const body = { error: true, code: "invalid_input", message: "m" };
    const refusing = await backend(async () => ({
      content: [{ type: "text", text: JSON.stringify(body) }],
      structuredContent: body,
    }));
    getSessionMock.mockResolvedValue(refusing.session);

    const result = await call(await connectConsumer(), REAL_TOOL);

    // The classifier is observation only: the wire is the backend's own bytes.
    expect(result.isError).toBeFalsy();
    expect(result.structuredContent).toEqual(body);
    expect(JSON.parse((result.content[0] as { text: string }).text)).toEqual(
      body,
    );
  });

  it("a success is recorded success with no error class", async () => {
    const [row] = await rowsFor(
      (consumer) => call(consumer, REAL_TOOL),
      await backend(),
    );
    expect(row).toMatchObject({ success: true });
    expect(row.error_code).toBeUndefined();
  });

  it("a timeout is recorded with the numeric code, unchanged by the hint", async () => {
    config.mcpTimeoutMs = 50;
    let release: () => void = () => undefined;
    const slow = await backend(
      () =>
        new Promise((resolve) => {
          release = () => resolve(real);
        }),
    );
    cleanups.push(async () => release());
    const [row] = await rowsFor((consumer) => call(consumer, REAL_TOOL), slow);
    expect(row).toMatchObject({ success: false, error_code: "-32001" });
  });
});
