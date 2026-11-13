/**
 * The router's own failure lines (tool-call-routing.ts) for a backend that
 * answered HTTP 401 or 403: shared by the MCP proxy and the OpenAPI bridge, so
 * a refusal's response body must stay out of them too. The shapes are the
 * SDK's real `StreamableHTTPError` for a refused POST
 * (client/streamableHttp.js); a 502 is the control and keeps its diagnostic.
 */
import { inspect } from "node:util";

import { StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));
vi.mock("../../db/index", () => ({ db: {}, pool: {} }));
vi.mock("../../db/repositories/namespaces.repo", () => ({
  namespacesRepository: {
    findServersForNamespaceToolName: vi.fn().mockResolvedValue([]),
  },
}));
vi.mock("../config.service", () => ({
  configService: {
    getMcpToolCallReconnectWarmupTimeout: vi.fn().mockResolvedValue(0),
  },
}));
vi.mock("./fetch-metamcp", () => ({
  getNamespaceServerStates: vi.fn().mockResolvedValue([]),
}));
vi.mock("./tool-call-warmup", () => ({
  acquireSessionWithBoundedWarmup: vi.fn().mockResolvedValue(undefined),
}));

import logger from "@/utils/logger";

import type { ConnectedClient } from "./client";
import { routeUnmappedToolCall } from "./tool-call-routing";

const BODY_SECRET = "backend-body-text-that-must-not-be-logged";
const session = { client: {} } as unknown as ConnectedClient;

const refusal = (status: number) =>
  new StreamableHTTPError(status, `Error POSTing to endpoint: ${BODY_SECRET}`);

const route = (options: {
  getSession?: () => Promise<ConnectedClient | undefined>;
  probe?: () => Promise<never>;
}) =>
  routeUnmappedToolCall({
    namespaceUuid: "ns-1",
    sessionId: "sess-1",
    toolName: "ninja__job",
    serverPrefix: "ninja",
    originalToolName: "job",
    serverParams: { "server-1": { uuid: "server-1", name: "ninja" } as never },
    isAllowedServer: () => true,
    toolPolicy: undefined,
    includeInactiveServers: false,
    unknownToolMessage: "Unknown tool: ninja__job",
    pool: {
      getSession: options.getSession ?? (async () => session),
    } as never,
    probe: options.probe ?? (async () => ({ kind: "absent" }) as never),
  });

const logged = () =>
  inspect(
    [logger.error, logger.warn, logger.info, logger.debug].flatMap(
      (fn) => vi.mocked(fn).mock.calls,
    ),
    { depth: null },
  );

afterEach(() => {
  [logger.error, logger.warn, logger.info, logger.debug].forEach((fn) =>
    vi.mocked(fn).mockClear(),
  );
});

describe("routeUnmappedToolCall logs a backend refusal by status only", () => {
  it.each([401, 403] as const)(
    "a probe that rejects with HTTP %s",
    async (status) => {
      await expect(
        route({
          probe: async () => {
            throw refusal(status);
          },
        }),
      ).rejects.toMatchObject({ name: "BackendUnavailableError" });

      expect(logged()).toContain(`HTTP ${status}`);
      expect(logged()).not.toContain(BODY_SECRET);
    },
  );

  it.each([401, 403] as const)(
    "a session acquisition that rejects with HTTP %s",
    async (status) => {
      await expect(
        route({
          getSession: async () => {
            throw refusal(status);
          },
        }),
      ).rejects.toMatchObject({ name: "BackendUnavailableError" });

      expect(logged()).toContain(`HTTP ${status}`);
      expect(logged()).not.toContain(BODY_SECRET);
    },
  );

  it("keeps the diagnostic error for a 502 (negative control)", async () => {
    await expect(
      route({
        probe: async () => {
          throw refusal(502);
        },
      }),
    ).rejects.toMatchObject({ name: "BackendUnavailableError" });

    expect(logged()).toContain(BODY_SECRET);
  });
});
