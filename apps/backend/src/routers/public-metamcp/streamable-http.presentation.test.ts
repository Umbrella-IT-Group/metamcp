/**
 * What the StreamableHTTP router does with an endpoint's presentation settings,
 * driven through the REAL router over a real socket (the harness of
 * streamable-http.ceiling-evict.test.ts) with the real resolver. Faked: the
 * DB-touching boundaries (`mcp_sessions` as an in-memory table, the
 * endpoint-presentation repository, `@/db`, the server pool's bookkeeping), the
 * express auth middlewares and the durable event sink.
 *
 * The contract under test, from the design:
 *  - A NEW session resolves the endpoint's settings once, hands them to the
 *    pool as the fourth `getServer` argument and persists a minimal pin
 *    (`{ presentation: { v: 1, lean, omit } }`) in `init_params`.
 *  - A session with nothing to present makes the same two-argument
 *    `getServer(id, namespace)` call and persists `{}` exactly as before.
 *  - A resolver failure never blocks `initialize`: the session is created with
 *    the defaults and one WARN that carries no text.
 *  - Lazy RECOVERY restores the pin from the stored row and never reads the
 *    endpoint's current settings: no repository read at all. A row with no pin,
 *    or an unknown pin, recovers as it always did, and the kill switch wins.
 *  - A request on an existing session makes no resolver call.
 *
 * Oracle: the MCP Streamable HTTP session-management text (`initialize` only
 * at session start; a recovered session skips it) plus the design's contract
 * above. Cases marked "pin" pass on the parent by design.
 */
import type { Server as HttpServer } from "node:http";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import express from "express";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

const h = vi.hoisted(() => {
  const rows = new Map<string, Record<string, unknown>>();
  return {
    rows,
    logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
    record: vi.fn(),
    getServer: vi.fn(),
    cleanupSession: vi.fn(),
    persist: vi.fn(async (row: { session_id: string }) => {
      rows.set(row.session_id, {
        ...row,
        created_at: new Date(),
        last_seen_at: new Date(),
      });
    }),
    findById: vi.fn(async (sessionId: string) => rows.get(sessionId) ?? null),
    deleteRow: vi.fn(async (sessionId: string) => {
      rows.delete(sessionId);
    }),
    // The endpoint-presentation repository: one stored row per endpoint uuid.
    presentationRows: new Map<string, Record<string, unknown>>(),
    findPresentation: vi.fn(),
  };
});

vi.mock("@/utils/logger", () => ({ default: h.logger }));

vi.mock("../../lib/health-upstream", () => ({
  isAdminHealthRequest: vi.fn().mockResolvedValue(false),
}));

vi.mock("@/db", () => ({ db: {}, pool: { on: vi.fn() } }));

vi.mock("@/middleware/api-key-oauth.middleware", () => ({
  authenticateApiKey: vi.fn(),
}));
vi.mock("@/middleware/lookup-endpoint-middleware", () => ({
  lookupEndpoint: vi.fn(),
}));
vi.mock("@/middleware/rate-limit.middleware", () => ({
  rateLimitMiddleware: vi.fn(),
}));

vi.mock("@/db/repositories/mcp-sessions.repo", () => ({
  mcpSessionsRepository: {
    persist: h.persist,
    findById: h.findById,
    touch: vi.fn().mockResolvedValue(undefined),
    delete: h.deleteRow,
    pruneOlderThan: vi.fn().mockResolvedValue(0),
  },
}));

// The resolver imports this lazily; the mock stands in at the database
// boundary, so the real resolver, its kill switch and its fail-open path run.
vi.mock("../../db/repositories/endpoint-presentation.repo", () => ({
  endpointPresentationRepository: {
    findByEndpointUuid: h.findPresentation,
  },
}));

vi.mock("../../lib/metamcp/consumer-identity-resolver", () => ({
  resolveClientIdentity: vi.fn().mockResolvedValue({ name: "test-consumer" }),
}));

vi.mock("../../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {
    getServer: h.getServer,
    getServerInstance: vi.fn(),
    cleanupSession: h.cleanupSession,
    getMcpServerPoolStatus: vi.fn().mockReturnValue({ idle: 0, active: 0 }),
    getPoolStatus: vi.fn().mockReturnValue({ idle: 0, active: 0 }),
  },
}));

vi.mock("../../lib/metamcp/log-store", () => ({
  metamcpLogStore: { record: h.record },
}));

import type { ApiKeyAuthenticatedRequest } from "@/middleware/api-key-oauth.middleware";
import { authenticateApiKey } from "@/middleware/api-key-oauth.middleware";
import { lookupEndpoint } from "@/middleware/lookup-endpoint-middleware";
import { rateLimitMiddleware } from "@/middleware/rate-limit.middleware";

import {
  GATEWAY_BOOT_ID,
  GATEWAY_CAPABILITY_HASH,
} from "../../lib/metamcp/gateway-boot-id";
import { hashAuthPrincipal } from "../../lib/metamcp/session-auth";
import streamableHttpRouter, {
  publicSessionSweeper,
  recoverPersistedSession,
} from "./streamable-http";

const PROTOCOL_VERSION = "2025-06-18";
const SAVED_SWITCH = process.env.MCP_ENDPOINT_PRESENTATION;
const TITLE = "Presentation test title";
const INSTRUCTIONS = "Presentation test instructions, do not log me.";

let keyCounter = 0;
let rawKey = "";
let httpServer: HttpServer;
let baseUrl = "";

function makeServerInstance() {
  return {
    server: new Server(
      { name: "presentation-test-gateway", version: "0.0.0" },
      { capabilities: {} },
    ),
    cleanup: vi.fn().mockResolvedValue(undefined),
    handlerContext: {} as Record<string, unknown>,
  };
}

const storedRow = (over: Record<string, unknown> = {}) => ({
  title: null,
  instructions: null,
  tool_listing: "full",
  omit_output_schemas: false,
  ...over,
});

function initialize(endpoint = "ep-1"): Promise<Response> {
  return fetch(`${baseUrl}/metamcp/${endpoint}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "x-api-key": rawKey,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: "presentation-test-client", version: "0.0.0" },
      },
    }),
  });
}

async function openSession(endpoint = "ep-1"): Promise<string> {
  const response = await initialize(endpoint);
  expect(response.status).toBe(200);
  await response.text();
  const sessionId = response.headers.get("mcp-session-id");
  if (!sessionId) throw new Error("initialize returned no Mcp-Session-Id");
  return sessionId;
}

let pingId = 0;
function ping(sessionId: string, endpoint = "ep-1"): Promise<Response> {
  return fetch(`${baseUrl}/metamcp/${endpoint}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "x-api-key": rawKey,
      "mcp-session-id": sessionId,
      "mcp-protocol-version": PROTOCOL_VERSION,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: (pingId += 1),
      method: "ping",
    }),
  });
}

/** The row `persist` was given for a session. */
const persistedFor = (sessionId: string) =>
  h.persist.mock.calls
    .map((call) => call[0] as Record<string, unknown>)
    .find((row) => row.session_id === sessionId);

const warnLines = () => h.logger.warn.mock.calls.map((call) => String(call[0]));
const infoLines = () => h.logger.info.mock.calls.map((call) => String(call[0]));
const everyLogLine = () =>
  JSON.stringify([
    ...h.logger.info.mock.calls,
    ...h.logger.warn.mock.calls,
    ...h.logger.error.mock.calls,
    ...h.logger.debug.mock.calls,
  ]);

beforeAll(async () => {
  vi.mocked(lookupEndpoint).mockImplementation(((
    req: express.Request,
    _res: express.Response,
    next: () => void,
  ) => {
    const endpoint = String(req.params.endpoint_name);
    Object.assign(req, {
      namespaceUuid: `ns-${endpoint}`,
      endpointName: endpoint,
      endpoint: { uuid: `uuid-${endpoint}`, name: endpoint },
      authMethod: "api_key",
      apiKeyUuid: `3f7f8a1e-0000-4000-8000-${String(keyCounter).padStart(12, "0")}`,
      auditRequestId: "req-presentation",
      auditClientIp: "203.0.113.30",
    });
    next();
  }) as never);
  vi.mocked(authenticateApiKey).mockImplementation(((
    _req: express.Request,
    _res: express.Response,
    next: () => void,
  ) => next()) as never);
  vi.mocked(rateLimitMiddleware).mockImplementation(((
    _req: express.Request,
    _res: express.Response,
    next: () => void,
  ) => next()) as never);

  const app = express();
  app.use("/metamcp", streamableHttpRouter);
  await new Promise<void>((resolve) => {
    httpServer = app.listen(0, "127.0.0.1", resolve);
  });
  const address = httpServer.address();
  if (typeof address === "object" && address) {
    baseUrl = `http://127.0.0.1:${address.port}`;
  }
});

afterAll(async () => {
  await new Promise<void>((resolve) => httpServer.close(() => resolve()));
});

beforeEach(() => {
  vi.clearAllMocks();
  h.rows.clear();
  h.presentationRows.clear();
  delete process.env.MCP_ENDPOINT_PRESENTATION;
  keyCounter += 1;
  rawKey = `presentation-test-key-${keyCounter}`;
  h.getServer.mockImplementation(async () => makeServerInstance());
  h.cleanupSession.mockResolvedValue(undefined);
  h.findPresentation.mockImplementation(
    async (endpointUuid: string) =>
      h.presentationRows.get(endpointUuid) ?? undefined,
  );
});

afterEach(() => {
  if (SAVED_SWITCH === undefined) delete process.env.MCP_ENDPOINT_PRESENTATION;
  else process.env.MCP_ENDPOINT_PRESENTATION = SAVED_SWITCH;
});

describe("a new session", () => {
  it("resolves the endpoint's settings once, hands them to the pool and pins them in init_params", async () => {
    h.presentationRows.set(
      "uuid-ep-1",
      storedRow({
        title: TITLE,
        instructions: INSTRUCTIONS,
        omit_output_schemas: true,
      }),
    );

    const sessionId = await openSession("ep-1");

    expect(h.findPresentation).toHaveBeenCalledTimes(1);
    expect(h.findPresentation).toHaveBeenCalledWith("uuid-ep-1");
    expect(h.getServer).toHaveBeenCalledTimes(1);
    expect(h.getServer).toHaveBeenCalledWith(sessionId, "ns-ep-1", false, {
      title: TITLE,
      instructions: INSTRUCTIONS,
      toolListing: "full",
      omitOutputSchemas: true,
    });
    // Only the behavioural bits are pinned: never the title or the text.
    const persisted = persistedFor(sessionId);
    expect(persisted?.init_params).toEqual({
      presentation: { v: 1, lean: false, omit: true },
    });
    expect(JSON.stringify(persisted)).not.toContain(TITLE);
    expect(JSON.stringify(persisted)).not.toContain(INSTRUCTIONS);
  });

  it("logs flags and counts for a presentation session, never its text", async () => {
    h.presentationRows.set(
      "uuid-ep-1",
      storedRow({ title: TITLE, instructions: INSTRUCTIONS }),
    );

    await openSession("ep-1");

    expect(
      infoLines().filter((line) => line.includes("presents custom settings")),
    ).toHaveLength(1);
    expect(everyLogLine()).not.toContain(TITLE);
    expect(everyLogLine()).not.toContain(INSTRUCTIONS);
  });

  it("pin: an endpoint with no row gets the two-argument getServer call and persists {}", async () => {
    const sessionId = await openSession("ep-1");

    expect(h.getServer).toHaveBeenCalledTimes(1);
    expect(h.getServer.mock.calls[0]).toEqual([sessionId, "ns-ep-1"]);
    expect(persistedFor(sessionId)?.init_params).toEqual({});
  });

  it("pin: a stored row of defaults is the same as no row", async () => {
    h.presentationRows.set("uuid-ep-1", storedRow());

    const sessionId = await openSession("ep-1");

    expect(h.getServer.mock.calls[0]).toEqual([sessionId, "ns-ep-1"]);
    expect(persistedFor(sessionId)?.init_params).toEqual({});
  });

  it("a stored lean row is served as the ordinary listing in this release: no presentation, no pin", async () => {
    h.presentationRows.set("uuid-ep-1", storedRow({ tool_listing: "lean" }));

    const sessionId = await openSession("ep-1");

    expect(h.getServer.mock.calls[0]).toEqual([sessionId, "ns-ep-1"]);
    expect(persistedFor(sessionId)?.init_params).toEqual({});
  });

  it("a failure reading the settings still creates the session with the defaults and logs one WARN", async () => {
    h.findPresentation.mockRejectedValue(new Error("connection refused"));

    const sessionId = await openSession("ep-1");

    expect(h.getServer.mock.calls[0]).toEqual([sessionId, "ns-ep-1"]);
    expect(persistedFor(sessionId)?.init_params).toEqual({});
    expect(
      warnLines().filter((line) =>
        line.startsWith("Endpoint presentation could not be read"),
      ),
    ).toHaveLength(1);
  });

  it("with MCP_ENDPOINT_PRESENTATION off the settings are not even read", async () => {
    process.env.MCP_ENDPOINT_PRESENTATION = "off";
    h.presentationRows.set(
      "uuid-ep-1",
      storedRow({ title: TITLE, omit_output_schemas: true }),
    );

    const sessionId = await openSession("ep-1");

    expect(h.findPresentation).not.toHaveBeenCalled();
    expect(h.getServer.mock.calls[0]).toEqual([sessionId, "ns-ep-1"]);
    expect(persistedFor(sessionId)?.init_params).toEqual({});
  });

  it("settings follow the endpoint, not the namespace: two endpoints on different settings get different calls", async () => {
    h.presentationRows.set(
      "uuid-ep-1",
      storedRow({ omit_output_schemas: true }),
    );

    const trimmed = await openSession("ep-1");
    const plain = await openSession("ep-2");

    expect(h.getServer.mock.calls[0]).toEqual([
      trimmed,
      "ns-ep-1",
      false,
      { toolListing: "full", omitOutputSchemas: true },
    ]);
    expect(h.getServer.mock.calls[1]).toEqual([plain, "ns-ep-2"]);
  });

  it("a request on an existing session makes no resolver call", async () => {
    h.presentationRows.set(
      "uuid-ep-1",
      storedRow({ omit_output_schemas: true }),
    );
    const sessionId = await openSession("ep-1");
    expect(h.findPresentation).toHaveBeenCalledTimes(1);

    const pinged = await ping(sessionId, "ep-1");
    await pinged.text();

    expect(pinged.status).toBe(200);
    expect(h.findPresentation).toHaveBeenCalledTimes(1);
    expect(h.getServer).toHaveBeenCalledTimes(1);
  });
});

describe("lazy recovery", () => {
  const rawToken = "recovery-test-key";

  /** A persisted row as `findById` returns it. */
  function storeRow(sessionId: string, initParams: Record<string, unknown>) {
    h.rows.set(sessionId, {
      session_id: sessionId,
      namespace_uuid: "ns-ep-1",
      endpoint_name: "ep-1",
      auth_principal: hashAuthPrincipal(rawToken, "api_key"),
      auth_method: "api_key",
      init_params: initParams,
      created_at: new Date(),
      last_seen_at: new Date(),
      gateway_boot_id: GATEWAY_BOOT_ID,
      capability_hash: GATEWAY_CAPABILITY_HASH,
    });
  }

  const recover = (sessionId: string) =>
    recoverPersistedSession(sessionId, {
      headers: { "x-api-key": rawToken },
      query: {},
      namespaceUuid: "ns-ep-1",
      endpointName: "ep-1",
      endpoint: { uuid: "uuid-ep-1", name: "ep-1" },
      authMethod: "api_key",
    } as unknown as ApiKeyAuthenticatedRequest);

  // A fresh id per test: the router's session manager is module state shared
  // by the whole file, and a recovered session stays resident in it.
  let sessionId = "";
  let recoveryCounter = 0;
  beforeEach(() => {
    recoveryCounter += 1;
    sessionId = `sess-recovery-${recoveryCounter}`;
  });
  afterEach(() => {
    publicSessionSweeper.forget(sessionId);
  });

  it("restores the pin from the stored row, and reads no settings at all", async () => {
    storeRow(sessionId, { presentation: { v: 1, lean: false, omit: true } });
    // The endpoint's CURRENT settings differ from the pin, and must be ignored.
    h.presentationRows.set(
      "uuid-ep-1",
      storedRow({ title: TITLE, omit_output_schemas: false }),
    );

    const result = await recover(sessionId);

    expect(result.status).toBe("recovered");
    expect(h.getServer).toHaveBeenCalledWith(sessionId, "ns-ep-1", false, {
      toolListing: "full",
      omitOutputSchemas: true,
    });
    expect(h.findPresentation).not.toHaveBeenCalled();
  });

  it("a row with no pin recovers as it always did, even when the endpoint now has settings", async () => {
    storeRow(sessionId, {});
    h.presentationRows.set(
      "uuid-ep-1",
      storedRow({ title: TITLE, omit_output_schemas: true }),
    );

    const result = await recover(sessionId);

    expect(result.status).toBe("recovered");
    expect(h.getServer.mock.calls[0]).toEqual([sessionId, "ns-ep-1"]);
    expect(h.findPresentation).not.toHaveBeenCalled();
  });

  it("a pin of an unknown version recovers as an ordinary session", async () => {
    storeRow(sessionId, {
      presentation: { v: 2, lean: false, omit: true },
    });

    await recover(sessionId);

    expect(h.getServer.mock.calls[0]).toEqual([sessionId, "ns-ep-1"]);
  });

  it("the kill switch wins over a pin", async () => {
    process.env.MCP_ENDPOINT_PRESENTATION = "off";
    storeRow(sessionId, { presentation: { v: 1, lean: false, omit: true } });

    await recover(sessionId);

    expect(h.getServer.mock.calls[0]).toEqual([sessionId, "ns-ep-1"]);
    expect(h.findPresentation).not.toHaveBeenCalled();
  });
});
