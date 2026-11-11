/**
 * `mcpServers.update` and the stored credentials:
 *   - a refusal from the repository (a URL change that neither replaces nor
 *     clears a stored credential, planServerUpdate) answers success:false with
 *     the repository's value-free message, and touches no connection and no
 *     audit row;
 *   - an accepted update that changed the destination or a credential retires
 *     every pooled connection of the server before it returns, so no live
 *     connection keeps presenting the old credential or talking to the old
 *     address;
 *   - an accepted update that changed neither (the sync's routine re-save)
 *     leaves live connections alone.
 *
 * Repositories and pools are mocked so the unit needs no postgres; the
 * repository rule itself runs against Postgres in
 * mcp-servers.credential-retention.integration.test.ts.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const { order } = vi.hoisted(() => ({ order: [] as string[] }));

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

vi.mock("../db/repositories", () => ({
  mcpServersRepository: {
    findByUuid: vi.fn(),
    updateReportingChange: vi.fn(),
  },
  namespaceMappingsRepository: {
    findNamespacesByServerUuid: vi.fn(async () => []),
  },
}));

vi.mock("../lib/audit/admin-event", () => ({ emitAdminEvent: vi.fn() }));

vi.mock("../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    invalidateServerConnection: vi.fn(async () => {
      order.push("cascade");
    }),
    invalidateIdleSession: vi.fn(async () => undefined),
  },
}));
vi.mock("../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {
    invalidateIdleServers: vi.fn(async () => undefined),
    invalidateOpenApiSessions: vi.fn(async () => undefined),
  },
}));
vi.mock("../lib/metamcp/metamcp-middleware/tool-overrides.functional", () => ({
  clearOverrideCache: vi.fn(),
}));
vi.mock("../lib/metamcp/server-error-tracker", () => ({
  serverErrorTracker: { resetServerErrorState: vi.fn(async () => undefined) },
}));
vi.mock("../lib/metamcp/utils", () => ({
  convertDbServerToParams: vi.fn(async () => undefined),
}));

import { mcpServersRepository } from "../db/repositories";
import {
  ServerCredentialRetentionError,
  URL_CHANGE_NEEDS_BEARER_DECISION,
} from "../db/repositories/mcp-server-update-plan";
import { emitAdminEvent } from "../lib/audit/admin-event";
import { mcpServerPool } from "../lib/metamcp/mcp-server-pool";
import { mcpServersImplementations } from "./mcp-servers.impl";

const UUID = "11111111-1111-4111-8111-111111111111";

const row = (overrides: Record<string, unknown> = {}) =>
  ({
    uuid: UUID,
    name: "vendor",
    description: null,
    type: "STREAMABLE_HTTP",
    command: null,
    args: [],
    env: {},
    url: "http://mcp-vendor:3000/mcp",
    bearerToken: "enc:v1:stored",
    headers: {},
    error_status: "NONE",
    created_at: new Date("2026-11-01T00:00:00Z"),
    user_id: null,
    ...overrides,
  }) as never;

const update = (input: Record<string, unknown>) =>
  mcpServersImplementations.update(
    {
      uuid: UUID,
      name: "vendor",
      type: "STREAMABLE_HTTP",
      url: "http://mcp-vendor:3000/mcp",
      ...input,
    } as never,
    "admin-1",
    {
      actor_id: "admin-1",
      actor_label: "admin@example.invalid",
      actor_ip: null,
      actor_user_agent: null,
      request_id: null,
    },
  );

beforeEach(() => {
  vi.clearAllMocks();
  order.length = 0;
  vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue(row());
});

describe("mcpServers.update and the stored credentials", () => {
  it("a refused URL change answers the repository's message and touches nothing else", async () => {
    vi.mocked(mcpServersRepository.updateReportingChange).mockRejectedValue(
      new ServerCredentialRetentionError(URL_CHANGE_NEEDS_BEARER_DECISION),
    );

    const result = await update({ url: "http://mcp-other:3000/mcp" });

    expect(result).toEqual({
      success: false,
      message: URL_CHANGE_NEEDS_BEARER_DECISION,
    });
    expect(mcpServerPool.invalidateServerConnection).not.toHaveBeenCalled();
    expect(mcpServerPool.invalidateIdleSession).not.toHaveBeenCalled();
    expect(emitAdminEvent).not.toHaveBeenCalled();
  });

  it("the clear flag reaches the repository", async () => {
    vi.mocked(mcpServersRepository.updateReportingChange).mockResolvedValue({
      server: row({ bearerToken: null }),
      destinationOrCredentialChanged: true,
    });
    await update({ url: "http://mcp-other:3000/mcp", clearBearerToken: true });
    expect(mcpServersRepository.updateReportingChange).toHaveBeenCalledWith(
      expect.objectContaining({
        uuid: UUID,
        url: "http://mcp-other:3000/mcp",
        clearBearerToken: true,
      }),
    );
  });

  it("an accepted change of destination or credential retires the pooled connections before it returns", async () => {
    vi.mocked(mcpServersRepository.updateReportingChange).mockResolvedValue({
      server: row({ url: "http://mcp-other:3000/mcp", bearerToken: null }),
      destinationOrCredentialChanged: true,
    });

    const result = await update({
      url: "http://mcp-other:3000/mcp",
      clearBearerToken: true,
    });
    order.push("returned");

    expect(result.success).toBe(true);
    expect(mcpServerPool.invalidateServerConnection).toHaveBeenCalledTimes(1);
    expect(mcpServerPool.invalidateServerConnection).toHaveBeenCalledWith(
      "<update-trigger>",
      UUID,
    );
    expect(order).toEqual(["cascade", "returned"]);
  });

  it("an accepted update that changed neither leaves live connections alone", async () => {
    vi.mocked(mcpServersRepository.updateReportingChange).mockResolvedValue({
      server: row({ description: "Vendor tools" }),
      destinationOrCredentialChanged: false,
    });

    const result = await update({ description: "Vendor tools" });

    expect(result.success).toBe(true);
    expect(mcpServerPool.invalidateServerConnection).not.toHaveBeenCalled();
  });

  it("any other repository failure is still a failed update, not a refusal", async () => {
    vi.mocked(mcpServersRepository.updateReportingChange).mockRejectedValue(
      new Error(
        "Failed to update MCP server. Please check your input and try again.",
      ),
    );
    const result = await update({ description: "x" });
    expect(result.success).toBe(false);
    expect(mcpServerPool.invalidateServerConnection).not.toHaveBeenCalled();
  });
});
