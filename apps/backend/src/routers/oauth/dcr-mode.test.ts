/**
 * OAUTH_DCR_MODE resolution: strict values, `open` only in development or
 * test, and anything unrecognized resolves to `off` (closed) with a warning,
 * never to the default. Resolved and latched at startup.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const loggerMock = {
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
};
vi.mock("@/utils/logger", () => ({ default: loggerMock }));

const {
  getOAuthDcrMode,
  initOAuthDcrMode,
  OAUTH_DCR_MODE_ENV,
  resetOAuthDcrModeForTests,
  resolveOAuthDcrMode,
} = await import("./dcr-mode");

const env = (mode: string | undefined, nodeEnv?: string): NodeJS.ProcessEnv => {
  const e: NodeJS.ProcessEnv = {};
  if (mode !== undefined) e[OAUTH_DCR_MODE_ENV] = mode;
  if (nodeEnv !== undefined) e.NODE_ENV = nodeEnv;
  return e;
};

beforeEach(() => {
  vi.clearAllMocks();
  resetOAuthDcrModeForTests();
});

describe("resolveOAuthDcrMode", () => {
  it("defaults to pending when unset, without a warning", () => {
    expect(resolveOAuthDcrMode(env(undefined, "production"))).toEqual({
      mode: "pending",
      warning: null,
      error: null,
    });
  });

  it.each(["pending", "off"])("accepts %s exactly", (mode) => {
    expect(resolveOAuthDcrMode(env(mode, "production"))).toEqual({
      mode,
      warning: null,
      error: null,
    });
  });

  it.each(["development", "test"])(
    "permits open under NODE_ENV=%s, with a warning",
    (nodeEnv) => {
      const resolution = resolveOAuthDcrMode(env("open", nodeEnv));
      expect(resolution.mode).toBe("open");
      expect(resolution.error).toBeNull();
      expect(resolution.warning).toContain("Local development only");
    },
  );

  it.each([["production"], [""], [undefined]])(
    "refuses open under NODE_ENV=%s, resolving to off",
    (nodeEnv) => {
      const resolution = resolveOAuthDcrMode(env("open", nodeEnv));
      expect(resolution.mode).toBe("off");
      expect(resolution.error).toContain("permitted only when NODE_ENV");
    },
  );

  it.each(["", "Pending", "OFF", " pending", "pending ", "closed", "true"])(
    "resolves %j to off with a warning, not to the default",
    (value) => {
      const resolution = resolveOAuthDcrMode(env(value, "production"));
      expect(resolution.mode).toBe("off");
      expect(resolution.error).toBeNull();
      expect(resolution.warning).toContain("self-registration is OFF");
    },
  );
});

describe("initOAuthDcrMode and getOAuthDcrMode", () => {
  it("stops startup when open is set outside development or test", () => {
    expect(() => initOAuthDcrMode(env("open", "production"))).toThrow(
      "permitted only when NODE_ENV",
    );
  });

  it("logs a warning once at startup and latches the mode", () => {
    expect(initOAuthDcrMode(env("bogus", "production"))).toBe("off");
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(loggerMock.info).toHaveBeenCalledWith(
      "[oauth] client self-registration: OAUTH_DCR_MODE=off",
    );
    // Later environment changes do not move a latched mode.
    process.env[OAUTH_DCR_MODE_ENV] = "pending";
    try {
      expect(getOAuthDcrMode()).toBe("off");
      expect(getOAuthDcrMode()).toBe("off");
      expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    } finally {
      delete process.env[OAUTH_DCR_MODE_ENV];
    }
  });

  it("resolves once on first use when startup never ran, failing closed on a fatal value", () => {
    const previousNodeEnv = process.env.NODE_ENV;
    process.env[OAUTH_DCR_MODE_ENV] = "open";
    process.env.NODE_ENV = "production";
    try {
      expect(getOAuthDcrMode()).toBe("off");
      expect(loggerMock.error).toHaveBeenCalledTimes(1);
    } finally {
      delete process.env[OAUTH_DCR_MODE_ENV];
      process.env.NODE_ENV = previousNodeEnv;
    }
  });
});
