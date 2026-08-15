/**
 * The retention sweep for never-used dynamically-registered clients.
 *
 * `POST /oauth/register` needs no credential, so `oauth_clients` is the one
 * table an anonymous caller can grow and nothing could shrink; 45 junk rows
 * had accumulated. The sweep is the prune path.
 *
 * The SQL anti-join itself lives in the repository and needs a real postgres
 * to exercise (see access-queries.integration.test.ts for that harness). What
 * is pinned here is everything around it that decides WHETHER and with WHAT
 * the delete runs: the window resolution, the disable switch, and the promise
 * that a sweep failure cannot take down the interval it rides on.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const loggerMock = {
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
};

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

const oauthRepositoryMock = {
  pruneUnusedClients: vi.fn(),
};

vi.mock("../../db/repositories", () => ({
  oauthRepository: oauthRepositoryMock,
}));

const {
  DCR_CLIENT_RETENTION_DAYS_ENV,
  DEFAULT_DCR_CLIENT_RETENTION_DAYS,
  resolveDcrClientRetentionDays,
  sweepUnusedDcrClients,
} = await import("./client-retention");

const originalEnv = process.env[DCR_CLIENT_RETENTION_DAYS_ENV];

beforeEach(() => {
  vi.clearAllMocks();
  oauthRepositoryMock.pruneUnusedClients.mockResolvedValue(0);
  delete process.env[DCR_CLIENT_RETENTION_DAYS_ENV];
});

afterEach(() => {
  if (originalEnv === undefined) {
    delete process.env[DCR_CLIENT_RETENTION_DAYS_ENV];
  } else {
    process.env[DCR_CLIENT_RETENTION_DAYS_ENV] = originalEnv;
  }
});

describe("resolveDcrClientRetentionDays", () => {
  it("defaults to 7 days when unset", () => {
    expect(resolveDcrClientRetentionDays()).toBe(7);
    expect(DEFAULT_DCR_CLIENT_RETENTION_DAYS).toBe(7);
  });

  it("treats an empty value as unset rather than as a disable", () => {
    // Contrast DCR_REDIRECT_URI_ALLOWED_HOSTS, where empty MEANS something
    // (loopback only). Here an empty string is a deployment that set the
    // variable and gave it no value, and silently switching a retention
    // control off on that is the wrong reading.
    process.env[DCR_CLIENT_RETENTION_DAYS_ENV] = "   ";
    expect(resolveDcrClientRetentionDays()).toBe(7);
  });

  it("honours an operator override", () => {
    process.env[DCR_CLIENT_RETENTION_DAYS_ENV] = "30";
    expect(resolveDcrClientRetentionDays()).toBe(30);
  });

  it("falls back to the default on an unparseable value, and says so", () => {
    process.env[DCR_CLIENT_RETENTION_DAYS_ENV] = "seven";
    expect(resolveDcrClientRetentionDays()).toBe(7);
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
  });
});

describe("sweepUnusedDcrClients", () => {
  it("passes the resolved window to the repository", async () => {
    process.env[DCR_CLIENT_RETENTION_DAYS_ENV] = "14";
    await sweepUnusedDcrClients();
    expect(oauthRepositoryMock.pruneUnusedClients).toHaveBeenCalledWith(14);
  });

  it("does not touch the table at all when disabled", async () => {
    // The escape hatch has to be a real one: an operator who sets this to 0
    // must get zero DELETEs, not a DELETE with a zero-day cutoff — which
    // would sweep every client registered more than an instant ago.
    for (const value of ["0", "-1"]) {
      process.env[DCR_CLIENT_RETENTION_DAYS_ENV] = value;
      await expect(sweepUnusedDcrClients()).resolves.toBe(0);
    }
    expect(oauthRepositoryMock.pruneUnusedClients).not.toHaveBeenCalled();
  });

  it("reports what it removed", async () => {
    oauthRepositoryMock.pruneUnusedClients.mockResolvedValue(45);
    await expect(sweepUnusedDcrClients()).resolves.toBe(45);
    expect(loggerMock.info).toHaveBeenCalledWith(
      expect.stringContaining("swept 45"),
    );
  });

  it("stays quiet when there was nothing to sweep", async () => {
    // Every five minutes, forever. A "removed 0" line here is what makes an
    // operator stop reading this log.
    await sweepUnusedDcrClients();
    expect(loggerMock.info).not.toHaveBeenCalled();
  });

  it("never rejects, because it runs inside a timer callback", async () => {
    // It rides the shared 5-minute cleanup interval in ./index.ts. A rejection
    // there is an unhandled rejection in a callback nobody awaits, not a
    // failed request someone can see.
    oauthRepositoryMock.pruneUnusedClients.mockRejectedValue(
      new Error("connection terminated"),
    );

    await expect(sweepUnusedDcrClients()).resolves.toBe(0);
    expect(loggerMock.error).toHaveBeenCalledTimes(1);
  });
});
