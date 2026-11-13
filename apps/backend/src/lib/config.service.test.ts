/**
 * The MCP timeout settings the gateway reads for every backend call.
 *
 * Oracle: the setters store `enabled.toString()` / `timeout.toString()`
 * (config.service.ts), so "true" and "false" are the only values the
 * reset-on-progress row ever holds; the SDK reads `resetTimeoutOnProgress`
 * (shared/protocol.js) and the total cap only when a progress notification
 * resets the timer.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const { getConfig } = vi.hoisted(() => ({ getConfig: vi.fn() }));

vi.mock("../db/repositories/config.repo", () => ({
  configRepo: { getConfig, setConfig: vi.fn() },
}));

import {
  configService,
  DEFAULT_MCP_MAX_TOTAL_TIMEOUT_MS,
} from "./config.service";

const stored = (value: string | undefined) =>
  getConfig.mockResolvedValue(value === undefined ? undefined : { value });

beforeEach(() => {
  getConfig.mockReset();
});

describe("getMcpResetTimeoutOnProgress", () => {
  it("honours a stored false", async () => {
    stored("false");
    expect(await configService.getMcpResetTimeoutOnProgress()).toBe(false);
  });

  it.each([["true"], [undefined], ["garbage"], [""]])(
    "stays on for %j (the default)",
    async (value) => {
      stored(value);
      expect(await configService.getMcpResetTimeoutOnProgress()).toBe(true);
    },
  );
});

describe("getMcpMaxTotalTimeout", () => {
  it("defaults to ten minutes when nothing is stored", async () => {
    stored(undefined);
    expect(await configService.getMcpMaxTotalTimeout()).toBe(600_000);
    expect(DEFAULT_MCP_MAX_TOTAL_TIMEOUT_MS).toBe(600_000);
  });

  it("returns an explicitly stored value, even the old 60000", async () => {
    stored("120000");
    expect(await configService.getMcpMaxTotalTimeout()).toBe(120_000);
    stored("60000");
    expect(await configService.getMcpMaxTotalTimeout()).toBe(60_000);
  });
});

describe("getMcpTimeout", () => {
  it("is unchanged: 60 seconds when nothing is stored", async () => {
    stored(undefined);
    expect(await configService.getMcpTimeout()).toBe(60_000);
  });
});
