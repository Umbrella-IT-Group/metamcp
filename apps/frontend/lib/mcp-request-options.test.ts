import { describe, expect, it } from "vitest";

import {
  DEFAULT_MCP_MAX_TOTAL_TIMEOUT_MS,
  DEFAULT_MCP_TIMEOUT_MS,
  resolveRequestTimeouts,
} from "./mcp-request-options";

// The gateway's total cap is ten minutes (600000 ms) and its per-request
// timeout is one minute. These are only the fallbacks for a setting that has
// not loaded: a value an administrator stored is always used as stored.
describe("resolveRequestTimeouts", () => {
  it("falls back to a 60 second request timeout and a 600 second total cap", () => {
    expect(DEFAULT_MCP_TIMEOUT_MS).toBe(60_000);
    expect(DEFAULT_MCP_MAX_TOTAL_TIMEOUT_MS).toBe(600_000);
    expect(resolveRequestTimeouts({})).toEqual({
      timeout: 60_000,
      maxTotalTimeout: 600_000,
      resetTimeoutOnProgress: true,
    });
  });

  it("does not override a stored setting, even one equal to the old default", () => {
    expect(
      resolveRequestTimeouts({
        timeout: 60_000,
        maxTotalTimeout: 60_000,
        resetTimeoutOnProgress: false,
      }),
    ).toEqual({
      timeout: 60_000,
      maxTotalTimeout: 60_000,
      resetTimeoutOnProgress: false,
    });
    expect(
      resolveRequestTimeouts({ maxTotalTimeout: 1_200_000 }).maxTotalTimeout,
    ).toBe(1_200_000);
  });

  it("lets a caller's own option win over the stored setting", () => {
    expect(
      resolveRequestTimeouts(
        {
          timeout: 60_000,
          maxTotalTimeout: 600_000,
          resetTimeoutOnProgress: true,
        },
        {
          timeout: 5_000,
          maxTotalTimeout: 7_000,
          resetTimeoutOnProgress: false,
        },
      ),
    ).toEqual({
      timeout: 5_000,
      maxTotalTimeout: 7_000,
      resetTimeoutOnProgress: false,
    });
  });

  it("fills only the missing pieces", () => {
    expect(resolveRequestTimeouts({ timeout: 90_000 })).toEqual({
      timeout: 90_000,
      maxTotalTimeout: 600_000,
      resetTimeoutOnProgress: true,
    });
  });
});
