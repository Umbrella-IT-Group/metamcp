/**
 * What the legacy SSE router does with an endpoint's presentation settings, over
 * a real socket with the real resolver (harness of
 * sse.ceiling-evict.test.ts). A new SSE connection resolves the endpoint's
 * settings once and hands them to the pool as the fourth `getServer` argument;
 * an endpoint with nothing to present keeps the two-argument call. SSE sessions
 * are not persisted and have no recovery path, so there is no pin to write and
 * nothing here touches `mcp_sessions`.
 *
 * Oracle: the design's contract (the SSE twin of the StreamableHTTP new-session
 * path) and the SSE transport: `initialize` happens once, at connection.
 */
import type { Server } from "node:http";

import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
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

const h = vi.hoisted(() => ({
  logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
  getServer: vi.fn(),
  findPresentation: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({ default: h.logger }));

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

// Stands in at the database boundary; the real resolver runs.
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
    cleanupSession: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../lib/metamcp/log-store", () => ({
  metamcpLogStore: { record: vi.fn() },
}));

import { authenticateApiKey } from "@/middleware/api-key-oauth.middleware";
import { lookupEndpoint } from "@/middleware/lookup-endpoint-middleware";
import { rateLimitMiddleware } from "@/middleware/rate-limit.middleware";

import { countLiveSessionsForIdentity } from "../../lib/metamcp/credential-session-quota";
import type { SessionIdentity } from "../../lib/metamcp/session-auth";
import sseRouter from "./sse";

const KEY_UUID = "3f7f8a1e-0000-4000-8000-0000000000bb";
const IDENTITY: SessionIdentity = { method: "api_key", credentialId: KEY_UUID };
const SAVED_SWITCH = process.env.MCP_ENDPOINT_PRESENTATION;
const SAVED_LEAN_SWITCH = process.env.MCP_LEAN_LISTING;

let server: Server;
let baseUrl = "";
const opened: AbortController[] = [];

function makeInstance() {
  return {
    server: {
      // The real SDK `Server.connect` starts the transport, which writes the
      // SSE headers and the `endpoint` frame the client waits for.
      connect: vi.fn(async (transport: Transport) => {
        await transport.start();
      }),
    },
    cleanup: vi.fn().mockResolvedValue(undefined),
    handlerContext: {} as Record<string, unknown>,
  };
}

/** Open the SSE stream and wait for its `endpoint` frame. */
async function openStream(): Promise<number> {
  const abort = new AbortController();
  opened.push(abort);
  const response = await fetch(`${baseUrl}/metamcp/ep-1/sse`, {
    signal: abort.signal,
  });
  if (response.body) {
    await response.body.getReader().read();
  }
  return response.status;
}

beforeAll(async () => {
  vi.mocked(lookupEndpoint).mockImplementation(((
    req: express.Request,
    _res: express.Response,
    next: () => void,
  ) => {
    Object.assign(req, {
      namespaceUuid: "ns-1",
      endpointName: "ep-1",
      endpoint: { uuid: "uuid-ep-1", name: "ep-1" },
      authMethod: "api_key",
      apiKeyUuid: KEY_UUID,
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
  app.use("/metamcp", sseRouter);
  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (typeof address === "object" && address) {
    baseUrl = `http://127.0.0.1:${address.port}`;
  }
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(() => {
  vi.clearAllMocks();
  delete process.env.MCP_ENDPOINT_PRESENTATION;
  delete process.env.MCP_LEAN_LISTING;
  h.getServer.mockImplementation(async () => makeInstance());
  h.findPresentation.mockResolvedValue(undefined);
});

afterEach(async () => {
  if (SAVED_SWITCH === undefined) delete process.env.MCP_ENDPOINT_PRESENTATION;
  else process.env.MCP_ENDPOINT_PRESENTATION = SAVED_SWITCH;
  if (SAVED_LEAN_SWITCH === undefined) delete process.env.MCP_LEAN_LISTING;
  else process.env.MCP_LEAN_LISTING = SAVED_LEAN_SWITCH;
  for (const abort of opened.splice(0)) abort.abort();
  await vi.waitFor(() =>
    expect(countLiveSessionsForIdentity(IDENTITY)).toBe(0),
  );
});

describe("GET /sse", () => {
  it("resolves the endpoint's settings and hands them to the pool as the fourth argument", async () => {
    h.findPresentation.mockResolvedValue({
      title: "Desk",
      instructions: "Be brief.",
      tool_listing: "full",
      omit_output_schemas: true,
    });

    expect(await openStream()).toBe(200);

    expect(h.findPresentation).toHaveBeenCalledTimes(1);
    expect(h.findPresentation).toHaveBeenCalledWith("uuid-ep-1");
    expect(h.getServer).toHaveBeenCalledTimes(1);
    expect(h.getServer).toHaveBeenCalledWith(
      expect.any(String),
      "ns-1",
      false,
      {
        title: "Desk",
        instructions: "Be brief.",
        toolListing: "full",
        omitOutputSchemas: true,
      },
    );
  });

  it("hands a lean endpoint to the pool as a lean presentation, and as an ordinary session while the lean switch is off", async () => {
    h.findPresentation.mockResolvedValue({
      title: null,
      instructions: null,
      tool_listing: "lean",
      omit_output_schemas: false,
    });

    expect(await openStream()).toBe(200);

    expect(h.getServer).toHaveBeenLastCalledWith(
      expect.any(String),
      "ns-1",
      false,
      { toolListing: "lean", omitOutputSchemas: false },
    );

    process.env.MCP_LEAN_LISTING = "off";
    expect(await openStream()).toBe(200);

    expect(h.getServer.mock.calls[1]).toEqual([expect.any(String), "ns-1"]);
  });

  it("pin: an endpoint with no settings gets the two-argument getServer call", async () => {
    expect(await openStream()).toBe(200);

    expect(h.getServer).toHaveBeenCalledTimes(1);
    expect(h.getServer.mock.calls[0]).toEqual([expect.any(String), "ns-1"]);
  });

  it("a failure reading the settings still opens the stream with the defaults", async () => {
    h.findPresentation.mockRejectedValue(new Error("connection refused"));

    expect(await openStream()).toBe(200);

    expect(h.getServer.mock.calls[0]).toEqual([expect.any(String), "ns-1"]);
  });

  it("with MCP_ENDPOINT_PRESENTATION off the settings are not read", async () => {
    process.env.MCP_ENDPOINT_PRESENTATION = "off";
    h.findPresentation.mockResolvedValue({
      title: "Desk",
      instructions: null,
      tool_listing: "full",
      omit_output_schemas: true,
    });

    expect(await openStream()).toBe(200);

    expect(h.findPresentation).not.toHaveBeenCalled();
    expect(h.getServer.mock.calls[0]).toEqual([expect.any(String), "ns-1"]);
  });
});
