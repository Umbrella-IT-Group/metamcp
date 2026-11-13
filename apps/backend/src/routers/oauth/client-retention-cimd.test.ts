/**
 * The retention sweep for client metadata document (`cimd`) rows. The SQL
 * (what is kept, what is deleted) is proven against Postgres in
 * ../../db/repositories/oauth-cimd.integration.test.ts; what is pinned here is
 * what decides WHETHER and with WHAT the delete runs, and the promise that a
 * failure cannot take down the shared interval the sweep rides on (a
 * rejection in that timer callback is an unhandled rejection nobody sees).
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  logger: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  pruneUnusedCimdClients: vi.fn(),
}));
vi.mock("@/utils/logger", () => ({ default: h.logger }));
vi.mock("../../db/repositories", () => ({
  oauthRepository: {
    pruneUnusedCimdClients: h.pruneUnusedCimdClients,
    pruneUnapprovedDcrClients: vi.fn(),
  },
}));

const { sweepUnusedCimdClients } = await import("./client-retention");

beforeEach(() => {
  vi.clearAllMocks();
  h.pruneUnusedCimdClients.mockResolvedValue(0);
});

describe("sweepUnusedCimdClients", () => {
  it("asks for rows unused for 30 days, and nothing else", async () => {
    await sweepUnusedCimdClients();

    expect(h.pruneUnusedCimdClients).toHaveBeenCalledTimes(1);
    expect(h.pruneUnusedCimdClients).toHaveBeenCalledWith(30);
  });

  it("reports what it removed, and stays quiet when there was nothing", async () => {
    await sweepUnusedCimdClients();
    expect(h.logger.info).not.toHaveBeenCalled();

    h.pruneUnusedCimdClients.mockResolvedValue(3);
    await expect(sweepUnusedCimdClients()).resolves.toBe(3);
    expect(h.logger.info).toHaveBeenCalledWith(
      expect.stringContaining("swept 3"),
    );
  });

  it("never rejects", async () => {
    h.pruneUnusedCimdClients.mockRejectedValue(
      new Error("connection terminated"),
    );

    await expect(sweepUnusedCimdClients()).resolves.toBe(0);
    expect(h.logger.error).toHaveBeenCalledTimes(1);
  });
});
