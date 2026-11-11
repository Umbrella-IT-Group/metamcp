/**
 * The shared stdio policy every gate reads (create, update, bulk import, the
 * pool's transport factory, the admin proxy and boot), and its boot warning.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { loggerMock } = vi.hoisted(() => ({
  loggerMock: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));
vi.mock("@/utils/logger", () => ({ default: loggerMock }));

import {
  __resetStdioAllowedWarningForTesting,
  assertStdioServersAllowed,
  isStdioServerType,
  STDIO_SERVERS_DISABLED_MESSAGE,
  stdioServersAllowed,
  StdioServersDisabledError,
  warnIfStdioServersAllowed,
} from "./stdio-policy";

beforeEach(() => {
  vi.clearAllMocks();
  __resetStdioAllowedWarningForTesting();
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("ALLOW_STDIO_SERVERS parse", () => {
  it.each([
    ["unset", undefined],
    ["empty", ""],
    ["false", "false"],
    ["TRUE", "TRUE"],
    ["True", "True"],
    ["1", "1"],
    ["yes", "yes"],
    ["on", "on"],
    ["padded ' true'", " true"],
    ["padded 'true '", "true "],
  ])("refuses when the value is %s", (_label, value) => {
    vi.stubEnv("ALLOW_STDIO_SERVERS", value);

    expect(stdioServersAllowed()).toBe(false);
    expect(() => assertStdioServersAllowed()).toThrow(
      StdioServersDisabledError,
    );
  });

  it('allows only the exact string "true"', () => {
    vi.stubEnv("ALLOW_STDIO_SERVERS", "true");

    expect(stdioServersAllowed()).toBe(true);
    expect(() => assertStdioServersAllowed()).not.toThrow();
  });

  it("reads the environment on every call", () => {
    vi.stubEnv("ALLOW_STDIO_SERVERS", "true");
    expect(stdioServersAllowed()).toBe(true);
    vi.stubEnv("ALLOW_STDIO_SERVERS", "false");
    expect(stdioServersAllowed()).toBe(false);
  });

  it("refuses with a typed error carrying the shared message", () => {
    vi.stubEnv("ALLOW_STDIO_SERVERS", undefined);

    let caught: unknown;
    try {
      assertStdioServersAllowed();
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(StdioServersDisabledError);
    expect((caught as StdioServersDisabledError).code).toBe(
      "stdio_servers_disabled",
    );
    expect((caught as Error).message).toBe(STDIO_SERVERS_DISABLED_MESSAGE);
  });
});

describe("isStdioServerType", () => {
  it.each([
    ["STDIO", true],
    [undefined, true],
    [null, true],
    ["", true],
    ["SSE", false],
    ["STREAMABLE_HTTP", false],
  ] as const)("%s is stdio: %s", (type, expected) => {
    expect(isStdioServerType(type)).toBe(expected);
  });
});

describe("warnIfStdioServersAllowed", () => {
  it("logs exactly one boot warning when set, however often it is called", () => {
    vi.stubEnv("ALLOW_STDIO_SERVERS", "true");

    warnIfStdioServersAllowed();
    warnIfStdioServersAllowed();

    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(String(loggerMock.warn.mock.calls[0][0])).toContain(
      "ALLOW_STDIO_SERVERS=true",
    );
  });

  it.each([
    ["unset", undefined],
    ["empty", ""],
    ["TRUE", "TRUE"],
    ["1", "1"],
  ])("logs nothing when the flag is %s", (_label, value) => {
    vi.stubEnv("ALLOW_STDIO_SERVERS", value);

    warnIfStdioServersAllowed();

    expect(loggerMock.warn).not.toHaveBeenCalled();
  });
});

/**
 * The boot warning is worth nothing if the boot never calls it. `index.ts`
 * starts the server at import, so the wiring is pinned against its source,
 * the technique `admin-converge.test.ts` uses.
 */
describe("boot wiring", () => {
  const INDEX = readFileSync(
    path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      "../../index.ts",
    ),
    "utf8",
  );

  it("index.ts calls warnIfStdioServersAllowed() before the server listens", () => {
    const warn = INDEX.indexOf("\n  warnIfStdioServersAllowed();");
    const listen = INDEX.indexOf("app.listen(12009");

    expect(INDEX).toContain(
      'import { warnIfStdioServersAllowed } from "./lib/metamcp/stdio-policy";',
    );
    expect(warn).toBeGreaterThan(-1);
    expect(listen).toBeGreaterThan(warn);
  });
});
