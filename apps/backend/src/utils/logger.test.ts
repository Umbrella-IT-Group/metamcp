/**
 * Tests for the observability fixes in `logger.ts` (Track C2):
 *
 *  1. Console-mirror THRESHOLD semantics — each mode mirrors its own level
 *     AND everything more severe. Regression guard for the 2026-07-14
 *     incident where LOG_LEVEL=info showed a clean `docker logs` while
 *     app.log carried 278 cap-refusal WARNs (old "info" mode mirrored ONLY
 *     level==="INFO").
 *  2. Size-based, dependency-free, crash-safe log rotation.
 *  3. Boot-safe file open — a missing/read-only log directory falls back to
 *     console-only logging instead of crashing the process at module import
 *     (2026-07-14 audit follow-up; see logger.ts openStream()).
 *
 * These exercise the real filesystem (temp dir) and real WriteStreams —
 * the unit under test is the rotation + mirror logic, not a mock of it.
 * The rotate()-reopen-failure recovery path (item A3) needs `fs.openSync`
 * itself to fail mid-rotation, which needs a module mock — that lives in
 * its own file, `logger-rotation-reopen-failure.test.ts`, so this file's
 * other suites stay real-filesystem, mock-free.
 */

import { existsSync, mkdirSync, mkdtempSync, readFileSync, statSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Logger } from "./logger";

// WriteStream flushes to disk asynchronously; poll rather than sleep a fixed
// interval so the assertions are deterministic, not timing-lucky.
async function waitFor(cond: () => boolean, timeoutMs = 2000): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) {
      throw new Error("timeout waiting for filesystem condition");
    }
    await new Promise((r) => setTimeout(r, 5));
  }
}

function fileSize(p: string): number {
  try {
    return statSync(p).size;
  } catch {
    return 0;
  }
}

describe("Logger — console-mirror threshold semantics", () => {
  let dir: string;
  let logPath: string;
  let errorPath: string;
  let spies: {
    log: ReturnType<typeof vi.spyOn>;
    info: ReturnType<typeof vi.spyOn>;
    warn: ReturnType<typeof vi.spyOn>;
    error: ReturnType<typeof vi.spyOn>;
  };

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "logger-mode-"));
    logPath = join(dir, "app.log");
    errorPath = join(dir, "error.log");
    spies = {
      log: vi.spyOn(console, "log").mockImplementation(() => {}),
      info: vi.spyOn(console, "info").mockImplementation(() => {}),
      warn: vi.spyOn(console, "warn").mockImplementation(() => {}),
      error: vi.spyOn(console, "error").mockImplementation(() => {}),
    };
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  function makeLogger(mode: "all" | "info" | "errors-only" | "none"): Logger {
    return new Logger({
      logFilePath: logPath,
      errorFilePath: errorPath,
      shouldConsoleLog: mode,
    });
  }

  // [level, which console method it dispatches to]. DEBUG has no dedicated
  // console.debug in the logger — it falls through to console.log.
  const dispatch = {
    DEBUG: "log",
    INFO: "info",
    WARN: "warn",
    ERROR: "error",
  } as const;

  // For each mode: the set of levels that MUST reach the console.
  const matrix: Array<{
    mode: "all" | "info" | "errors-only" | "none";
    mirrored: Array<keyof typeof dispatch>;
  }> = [
    { mode: "all", mirrored: ["DEBUG", "INFO", "WARN", "ERROR"] },
    { mode: "info", mirrored: ["INFO", "WARN", "ERROR"] },
    { mode: "errors-only", mirrored: ["WARN", "ERROR"] },
    { mode: "none", mirrored: [] },
  ];

  for (const { mode, mirrored } of matrix) {
    it(`mode "${mode}" mirrors exactly ${JSON.stringify(mirrored)}`, () => {
      const logger = makeLogger(mode);
      logger.debug("d-msg");
      logger.info("i-msg");
      logger.warn("w-msg");
      logger.error("e-msg");

      for (const level of ["DEBUG", "INFO", "WARN", "ERROR"] as const) {
        const method = dispatch[level];
        if (mirrored.includes(level)) {
          expect(
            spies[method],
            `${mode}: ${level} should mirror via console.${method}`,
          ).toHaveBeenCalled();
        }
      }

      // The specific regression: "info" MUST carry WARN and ERROR.
      if (mode === "info") {
        expect(spies.warn).toHaveBeenCalled();
        expect(spies.error).toHaveBeenCalled();
      }
      // "none" mirrors nothing at all.
      if (mode === "none") {
        expect(spies.log).not.toHaveBeenCalled();
        expect(spies.info).not.toHaveBeenCalled();
        expect(spies.warn).not.toHaveBeenCalled();
        expect(spies.error).not.toHaveBeenCalled();
      }
    });
  }

  it("does NOT mirror levels below the mode's floor", () => {
    const logger = makeLogger("info");
    logger.debug("d-msg"); // DEBUG is below the "info" floor
    expect(spies.log).not.toHaveBeenCalled();

    const errorsOnly = makeLogger("errors-only");
    errorsOnly.info("i-msg"); // INFO is below the "errors-only" floor
    expect(spies.info).not.toHaveBeenCalled();
  });

  it("file writes are unaffected by console mode (none still writes to disk)", async () => {
    const logger = makeLogger("none");
    logger.info("to-app-log");
    logger.error("to-error-log");
    logger.close();

    await waitFor(() => fileSize(logPath) > 0 && fileSize(errorPath) > 0);
    expect(readFileSync(logPath, "utf8")).toContain("[INFO]");
    expect(readFileSync(logPath, "utf8")).toContain("to-app-log");
    expect(readFileSync(errorPath, "utf8")).toContain("[ERROR]");
    expect(readFileSync(errorPath, "utf8")).toContain("to-error-log");
  });

  it("preserves the exact line format operators grep for", async () => {
    const logger = makeLogger("all");
    logger.warn("cap refusal");
    logger.close();

    await waitFor(() => fileSize(logPath) > 0);
    // `[WARN] YYYY/MM/DD - HH:MM:SS | <msg>` — unchanged by this work.
    expect(readFileSync(logPath, "utf8")).toMatch(
      /^\[WARN\] \d{4}\/\d{2}\/\d{2} - \d{2}:\d{2}:\d{2} \| cap refusal$/m,
    );
  });
});

describe("Logger — size-based rotation", () => {
  let dir: string;
  let logPath: string;
  let errorPath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "logger-rot-"));
    logPath = join(dir, "app.log");
    errorPath = join(dir, "error.log");
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  function makeLogger(maxSizeBytes: number): Logger {
    return new Logger({
      logFilePath: logPath,
      errorFilePath: errorPath,
      shouldConsoleLog: "none", // isolate rotation from console mirroring
      maxSizeBytes,
    });
  }

  it("rotates to <name>.1 once the file exceeds the threshold", async () => {
    const logger = makeLogger(200);
    logger.info("A".repeat(300)); // single write crosses the 200-byte cap

    await waitFor(() => existsSync(`${logPath}.1`));
    // The oversized content moved to .1; the live file was reopened fresh.
    await waitFor(() => fileSize(`${logPath}.1`) > 200);
    expect(readFileSync(`${logPath}.1`, "utf8")).toContain("A".repeat(300));

    logger.close();
  });

  it("replaces .1 on the next rotation (single generation, not accumulating)", async () => {
    const logger = makeLogger(200);

    logger.info(`ALPHA-${"x".repeat(300)}`);
    await waitFor(
      () =>
        existsSync(`${logPath}.1`) &&
        readFileSync(`${logPath}.1`, "utf8").includes("ALPHA"),
    );

    logger.info(`BRAVO-${"y".repeat(300)}`);
    await waitFor(() => readFileSync(`${logPath}.1`, "utf8").includes("BRAVO"));

    // Single generation: the older generation is gone, only the newest .1 kept.
    const rotated = readFileSync(`${logPath}.1`, "utf8");
    expect(rotated).toContain("BRAVO");
    expect(rotated).not.toContain("ALPHA");

    logger.close();
  });

  it("keeps logging (never throws) after a rotation failure and emits one console line", async () => {
    const consoleErr = vi.spyOn(console, "error").mockImplementation(() => {});
    // Force renameSync to fail: pre-occupy the .1 destination with a NON-EMPTY
    // directory so rename(2) refuses to overwrite it. This drives the
    // crash-safe swallow path without mocking the fs module.
    mkdirSync(`${logPath}.1`);
    mkdirSync(join(`${logPath}.1`, "blocker"));

    const logger = makeLogger(200);
    // The rotation attempt fails internally and must NOT throw here.
    expect(() => logger.info("Z".repeat(300))).not.toThrow();
    // Logging continues afterwards.
    expect(() => logger.info("after-failure")).not.toThrow();

    logger.close();
    await waitFor(() => fileSize(logPath) > 0);
    // The live file still received the writes (rotation failed, logging didn't).
    expect(readFileSync(logPath, "utf8")).toContain("after-failure");
    // Exactly the swallow-and-report console line was emitted.
    expect(
      consoleErr.mock.calls.some((c) =>
        String(c[0]).includes("log rotation failed"),
      ),
    ).toBe(true);
  });

  it("seeds the byte counter from the on-disk size (append across process restart)", async () => {
    // First logger writes some bytes and closes (simulating a prior process).
    const first = makeLogger(10_000);
    first.info("preexisting-line");
    first.close();
    await waitFor(() => fileSize(logPath) > 0);
    const preSize = fileSize(logPath);
    expect(preSize).toBeGreaterThan(0);

    // A fresh logger with a threshold JUST above the existing size must rotate
    // on the very next write, because the counter is seeded from disk — not 0.
    const second = new Logger({
      logFilePath: logPath,
      errorFilePath: errorPath,
      shouldConsoleLog: "none",
      maxSizeBytes: preSize + 10,
    });
    second.info("Q".repeat(100));
    await waitFor(() => existsSync(`${logPath}.1`));
    expect(readFileSync(`${logPath}.1`, "utf8")).toContain("preexisting-line");

    second.close();
  });
});

describe("Logger — boot-safe file open (missing/read-only log dir)", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "logger-openfail-"));
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("never throws at construction, and falls back to console-only for the broken stream(s)", () => {
    const consoleErr = vi.spyOn(console, "error").mockImplementation(() => {});
    const consoleInfo = vi.spyOn(console, "info").mockImplementation(() => {});

    // Opening a DIRECTORY for append-write fails with EISDIR — portable,
    // and unlike a chmod-based test, doesn't depend on running as
    // non-root (a permission test would silently pass through under root,
    // which CI sometimes runs as).
    const brokenLogPath = dir; // the directory itself, not a file in it
    // A path whose PARENT directory doesn't exist fails with ENOENT —
    // covers the "missing log dir" half of the audit finding, distinct
    // from the "read-only dir" (EISDIR) half above.
    const brokenErrorPath = join(dir, "nonexistent-subdir", "error.log");

    let logger: Logger | undefined;
    expect(() => {
      logger = new Logger({
        logFilePath: brokenLogPath,
        errorFilePath: brokenErrorPath,
        // Explicit "none" is the adversarial case: the fallback must
        // override even an operator's explicit request for console
        // silence, because the alternative is losing every log line with
        // zero signal that logging is broken at all.
        shouldConsoleLog: "none",
      });
    }).not.toThrow();

    // One diagnostic line per broken stream, naming the path and reason.
    const openFailLines = consoleErr.mock.calls.filter((c) =>
      String(c[0]).includes("file logging disabled"),
    );
    expect(openFailLines.length).toBe(2);
    expect(
      openFailLines.some((c) => String(c[0]).includes(brokenLogPath)),
    ).toBe(true);
    expect(
      openFailLines.some((c) => String(c[0]).includes(brokenErrorPath)),
    ).toBe(true);

    // Logging still reaches the console despite shouldConsoleLog: "none" —
    // P6, no swallowed errors just because the file sink is down.
    logger?.info("still visible despite mode=none");
    expect(consoleInfo).toHaveBeenCalled();
    expect(
      consoleInfo.mock.calls.some((c) =>
        String(c[0]).includes("still visible despite mode=none"),
      ),
    ).toBe(true);

    logger?.close(); // must not throw on a null stream either
  });
});
