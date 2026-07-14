/**
 * Isolated regression test for `Logger.rotate()`'s reopen-failure recovery
 * (Track C2 fix-round item A3 — coordinator audit follow-up, 2026-07-14).
 *
 * Forcing "renameSync succeeds, then the reopen of `<name>` fails" needs
 * `fs.openSync` to fail on exactly the SECOND call of a rotation (the
 * reopen), while the first call (initial construction) and every other fs
 * operation behave normally. That needs a module-level mock of `fs`, which
 * is why this lives in its own file — `logger.test.ts`'s suites are real-
 * filesystem tests and Vitest gives each test file its own module registry,
 * so this mock never leaks there.
 */

import { existsSync, mkdtempSync, readFileSync, statSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// vi.mock factories are hoisted above all imports; a plain `const` declared
// above wouldn't survive that hoist (TDZ), so the mutable control flag has
// to go through vi.hoisted() to be visible inside the factory below.
const openSyncControl = vi.hoisted(() => ({ failNext: false }));

vi.mock("fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs")>();
  return {
    ...actual,
    // Delegates to the real openSync for everything except one
    // caller-armed failure — logger.ts's OTHER fs calls (createWriteStream,
    // renameSync, statSync) are untouched, spread straight from `actual`.
    openSync: ((...args: unknown[]) => {
      if (openSyncControl.failNext) {
        openSyncControl.failNext = false;
        const err = new Error("EACCES: simulated reopen failure");
        (err as NodeJS.ErrnoException).code = "EACCES";
        throw err;
      }
      return (actual.openSync as (...a: unknown[]) => number)(...args);
    }) as typeof actual.openSync,
  };
});

import { Logger } from "./logger";

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

describe("Logger — rotation reopen-failure recovery", () => {
  let dir: string;
  let logPath: string;
  let errorPath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "logger-reopen-"));
    logPath = join(dir, "app.log");
    errorPath = join(dir, "error.log");
    vi.spyOn(console, "error").mockImplementation(() => {});
    openSyncControl.failNext = false;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("restores <name> when the post-rename reopen fails, and keeps logging uninterrupted", async () => {
    const logger = new Logger({
      logFilePath: logPath,
      errorFilePath: errorPath,
      shouldConsoleLog: "none",
      maxSizeBytes: 200,
    });

    openSyncControl.failNext = true; // fails the NEXT openSync — rotate()'s reopen
    logger.info("A".repeat(300)); // crosses the threshold, triggers rotate()

    // Rename succeeded, reopen failed, rotate() restored the original
    // filename: <name> exists again and <name>.1 does NOT (the pre-fix bug
    // left <name> permanently missing here, ENOENT-ing every later rotate).
    // The rename dance is synchronous, but the WriteStream's buffered write
    // flushes to the fd asynchronously — wait on CONTENT, not just the
    // filename settling, or this reads the file before the flush lands.
    await waitFor(() => {
      if (!existsSync(logPath) || existsSync(`${logPath}.1`)) return false;
      try {
        return readFileSync(logPath, "utf8").includes("A".repeat(300));
      } catch {
        return false;
      }
    });

    // The pre-rotation content survived the rename-then-restore round trip.
    expect(readFileSync(logPath, "utf8")).toContain("A".repeat(300));

    // Logging keeps working — `old`'s fd is still bound to the same inode,
    // now (again) named <name> on disk, so this write lands in the same file.
    logger.info("after-reopen-failure");
    logger.close();
    await waitFor(
      () =>
        fileSize(logPath) > 0 &&
        readFileSync(logPath, "utf8").includes("after-reopen-failure"),
    );
    expect(existsSync(`${logPath}.1`)).toBe(false);

    // One diagnostic line was emitted for the reopen failure — from
    // openStream()'s own catch, since it's openStream (not rotate) that
    // caught the openSync throw (P6 — no swallowed errors).
    const errSpy = vi.mocked(console.error);
    expect(
      errSpy.mock.calls.some((c) => String(c[0]).includes("failed to open")),
    ).toBe(true);
  });
});
