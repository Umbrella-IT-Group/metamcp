/**
 * The recorder seam wins over a lazy import that was already in flight (#242).
 *
 * `resolveRecorder()` imports the repository after the first audited call and
 * assigns the real recorder when the import settles. A test that pinned its
 * own recorder (or `null`) during that import had the pin overwritten, which
 * is the sink swap behind #237. The generation counter makes a seam write that
 * lands mid-import win. These cases hold the import open with an async mock
 * factory, so the race is deterministic rather than a load flake.
 *
 * Each case resets the middleware and registers a fresh repository mock.
 * Vitest's module reset preserves the mock cache.
 */
import { CallToolRequest } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { MetaMCPHandlerContext } from "./functional-middleware";

const realRecord = vi.fn();

const context: MetaMCPHandlerContext = {
  namespaceUuid: "ns-123",
  sessionId: "sess-456",
  requestId: "req-aaaa",
};

const request = {
  method: "tools/call",
  params: { name: "autotask__search", arguments: { q: 1 } },
} as CallToolRequest;

let releaseImport: (() => void) | undefined;

async function freshAuditing() {
  vi.resetModules();
  let markImportStarted: () => void;
  const importStarted = new Promise<void>((resolve) => {
    markImportStarted = resolve;
  });
  const importReleased = new Promise<void>((resolve) => {
    releaseImport = resolve;
  });
  vi.doMock("../../../db/repositories/tool-call-audit.repo", async () => {
    markImportStarted();
    await importReleased;
    return { toolCallAuditRepository: { record: realRecord } };
  });
  return { ...(await import("./auditing.functional")), importStarted };
}

beforeEach(() => {
  realRecord.mockReset().mockResolvedValue(undefined);
});

afterEach(async () => {
  releaseImport?.();
  await vi.dynamicImportSettled();
});

describe("setAuditRecorderForTesting during the lazy repository import", () => {
  it("keeps the recorder a test installed while the import was pending", async () => {
    const {
      createAuditingMiddleware,
      setAuditRecorderForTesting,
      importStarted,
    } = await freshAuditing();
    const wrapped = createAuditingMiddleware()(
      vi.fn().mockResolvedValue({ content: [] }),
    );

    // Starts resolveRecorder(), which now waits on the held import.
    await wrapped(request, context);
    await importStarted;
    const mine = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(mine);
    releaseImport?.();
    await vi.dynamicImportSettled();

    expect(mine).toHaveBeenCalledTimes(1);
    expect(realRecord).not.toHaveBeenCalled();

    // The pin also holds for the NEXT call: the late import did not replace it.
    await wrapped(request, context);
    await vi.dynamicImportSettled();
    expect(mine).toHaveBeenCalledTimes(2);
    expect(realRecord).not.toHaveBeenCalled();
  });

  it("keeps a pinned null (no sink) while the import was pending", async () => {
    const {
      createAuditingMiddleware,
      setAuditRecorderForTesting,
      importStarted,
    } = await freshAuditing();
    const wrapped = createAuditingMiddleware()(
      vi.fn().mockResolvedValue({ content: [] }),
    );

    await wrapped(request, context);
    await importStarted;
    setAuditRecorderForTesting(null);
    releaseImport?.();
    await vi.dynamicImportSettled();
    await wrapped(request, context);
    await vi.dynamicImportSettled();

    expect(realRecord).not.toHaveBeenCalled();
  });

  it("resolves afresh when the seam is reset to undefined mid-import", async () => {
    const {
      createAuditingMiddleware,
      setAuditRecorderForTesting,
      importStarted,
    } = await freshAuditing();
    const wrapped = createAuditingMiddleware()(
      vi.fn().mockResolvedValue({ content: [] }),
    );

    await wrapped(request, context);
    await importStarted;
    setAuditRecorderForTesting(undefined);
    releaseImport?.();
    await vi.dynamicImportSettled();

    // `undefined` means "resolve again", so the row reaches the repository.
    expect(realRecord).toHaveBeenCalledTimes(1);
  });

  it("still installs the repository recorder when nothing touched the seam", async () => {
    const { createAuditingMiddleware, importStarted } = await freshAuditing();
    const wrapped = createAuditingMiddleware()(
      vi.fn().mockResolvedValue({ content: [] }),
    );

    await wrapped(request, context);
    await importStarted;
    releaseImport?.();
    await vi.dynamicImportSettled();
    await wrapped(request, context);
    await vi.dynamicImportSettled();

    expect(realRecord).toHaveBeenCalledTimes(2);
  });
});
