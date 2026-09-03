/**
 * Boot-time surfacing of endpoints left in the unpaired state
 * (restricted=true, require_scoped_api_key=false). Pre-existing rows are warned
 * about, never auto-migrated, so an operator closes the still-open API-key path
 * knowing which consumer each change affects.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const { findAllMock, loggerMock } = vi.hoisted(() => ({
  findAllMock: vi.fn(),
  loggerMock: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

vi.mock("../db/repositories", () => ({
  endpointsRepository: { findAll: findAllMock },
}));

vi.mock("../utils/logger", () => ({ default: loggerMock }));

import {
  findUnpairedRestrictedEndpoints,
  warnOnUnpairedRestrictedEndpoints,
} from "./endpoint-pairing-check";

const row = (overrides: Record<string, unknown>) => ({
  uuid: "e-1",
  name: "endpoint",
  restricted: false,
  require_scoped_api_key: false,
  ...overrides,
});

beforeEach(() => {
  vi.clearAllMocks();
});

describe("findUnpairedRestrictedEndpoints", () => {
  it("returns only endpoints that are restricted but do not require scoped keys", async () => {
    findAllMock.mockResolvedValue([
      row({
        uuid: "open",
        name: "open",
        restricted: true,
        require_scoped_api_key: false,
      }),
      row({
        uuid: "paired",
        name: "paired",
        restricted: true,
        require_scoped_api_key: true,
      }),
      row({
        uuid: "unrestricted",
        name: "unrestricted",
        restricted: false,
        require_scoped_api_key: false,
      }),
    ]);

    const unpaired = await findUnpairedRestrictedEndpoints();

    expect(unpaired).toEqual([{ uuid: "open", name: "open" }]);
  });

  it("returns an empty list when every restricted endpoint is paired", async () => {
    findAllMock.mockResolvedValue([
      row({
        uuid: "paired",
        name: "paired",
        restricted: true,
        require_scoped_api_key: true,
      }),
      row({ uuid: "unrestricted", name: "unrestricted" }),
    ]);

    expect(await findUnpairedRestrictedEndpoints()).toEqual([]);
  });
});

describe("warnOnUnpairedRestrictedEndpoints", () => {
  it("logs a WARN naming each unpaired endpoint", async () => {
    findAllMock.mockResolvedValue([
      row({
        uuid: "open",
        name: "open-endpoint",
        restricted: true,
        require_scoped_api_key: false,
      }),
    ]);

    const result = await warnOnUnpairedRestrictedEndpoints();

    expect(result).toEqual([{ uuid: "open", name: "open-endpoint" }]);
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(loggerMock.warn.mock.calls[0][0]).toContain("open-endpoint");
  });

  it("does not warn when there is nothing to fix", async () => {
    findAllMock.mockResolvedValue([
      row({ restricted: true, require_scoped_api_key: true }),
    ]);

    await warnOnUnpairedRestrictedEndpoints();

    expect(loggerMock.warn).not.toHaveBeenCalled();
  });

  it("is non-fatal: a repository failure is swallowed after logging", async () => {
    findAllMock.mockRejectedValue(new Error("db down"));

    const result = await warnOnUnpairedRestrictedEndpoints();

    expect(result).toEqual([]);
    expect(loggerMock.error).toHaveBeenCalledTimes(1);
  });
});
