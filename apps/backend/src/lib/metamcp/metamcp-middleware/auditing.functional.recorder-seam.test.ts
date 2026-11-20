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
 * Each case imports a fresh copy of the middleware (`vi.resetModules()`), so
 * every case gets its own first, still-pending import.
 */
import { CallToolRequest } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { MetaMCPHandlerContext } from "./functional-middleware";

const gate = vi.hoisted(() => ({
  // Resolved by the case when the import may settle.
  open: null as Promise<void> | null,
  realRecord: vi.fn(),
}));

vi.mock("../../../db/repositories/tool-call-audit.repo", async () => {
  await gate.open;
  return { toolCallAuditRepository: { record: gate.realRecord } };
});

const context: MetaMCPHandlerContext = {
  namespaceUuid: "ns-123",
  sessionId: "sess-456",
  requestId: "req-aaaa",
};

const request = {
  method: "tools/call",
  params: { name: "autotask__search", arguments: { q: 1 } },
} as CallToolRequest;

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

let releaseImport: () => void;

async function freshAuditing() {
  vi.resetModules();
  gate.open = new Promise<void>((resolve) => {
    releaseImport = resolve;
  });
  return import("./auditing.functional");
}

beforeEach(() => {
  gate.realRecord.mockReset().mockResolvedValue(undefined);
});

afterEach(() => {
  releaseImport?.();
});

describe("setAuditRecorderForTesting during the lazy repository import", () => {
  it("keeps the recorder a test installed while the import was pending", async () => {
    const { createAuditingMiddleware, setAuditRecorderForTesting } =
      await freshAuditing();
    const wrapped = createAuditingMiddleware()(
      vi.fn().mockResolvedValue({ content: [] }),
    );

    // Starts resolveRecorder(), which now waits on the held import.
    await wrapped(request, context);
    const mine = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(mine);
    releaseImport();
    await flush();

    expect(mine).toHaveBeenCalledTimes(1);
    expect(gate.realRecord).not.toHaveBeenCalled();

    // The pin also holds for the NEXT call: the late import did not replace it.
    await wrapped(request, context);
    await flush();
    expect(mine).toHaveBeenCalledTimes(2);
    expect(gate.realRecord).not.toHaveBeenCalled();
  });

  it("keeps a pinned null (no sink) while the import was pending", async () => {
    const { createAuditingMiddleware, setAuditRecorderForTesting } =
      await freshAuditing();
    const wrapped = createAuditingMiddleware()(
      vi.fn().mockResolvedValue({ content: [] }),
    );

    await wrapped(request, context);
    setAuditRecorderForTesting(null);
    releaseImport();
    await flush();
    await wrapped(request, context);
    await flush();

    expect(gate.realRecord).not.toHaveBeenCalled();
  });

  it("resolves afresh when the seam is reset to undefined mid-import", async () => {
    const { createAuditingMiddleware, setAuditRecorderForTesting } =
      await freshAuditing();
    const wrapped = createAuditingMiddleware()(
      vi.fn().mockResolvedValue({ content: [] }),
    );

    await wrapped(request, context);
    setAuditRecorderForTesting(undefined);
    releaseImport();
    await flush();

    // `undefined` means "resolve again", so the row reaches the repository.
    expect(gate.realRecord).toHaveBeenCalledTimes(1);
  });

  it("still installs the repository recorder when nothing touched the seam", async () => {
    const { createAuditingMiddleware } = await freshAuditing();
    const wrapped = createAuditingMiddleware()(
      vi.fn().mockResolvedValue({ content: [] }),
    );

    await wrapped(request, context);
    releaseImport();
    await flush();
    await wrapped(request, context);
    await flush();

    expect(gate.realRecord).toHaveBeenCalledTimes(2);
  });
});
