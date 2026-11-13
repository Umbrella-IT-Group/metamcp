/**
 * Per-call plumbing helpers. Oracle for the cancel link: the SDK's
 * shared/protocol.js, where `_onclose` aborts every handler signal and then
 * clears the transport in one synchronous run, while `_oncancel` aborts and
 * leaves the transport set (so a close and a cancel differ only by transport
 * state, read one promise turn later). Oracle for the cap helper: the SDK's
 * `_resetTimeout` rejection shape (McpError -32001 with data.maxTotalTimeout).
 */
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";

import { ToolCallCancelledError } from "./tool-call-cancelled";
import {
  cancelAfterTotalTimeout,
  cancelPassthroughEnabled,
  getToolCallExtra,
  linkCallerSignal,
  progressPassthroughEnabled,
  runWithToolCallExtra,
} from "./tool-call-extra";

const turn = async () => {
  for (let i = 0; i < 5; i += 1) await Promise.resolve();
};

describe("linkCallerSignal", () => {
  it("aborts with the typed error when the signal is already aborted and the transport is open", () => {
    const caller = new AbortController();
    caller.abort();
    const controller = new AbortController();

    linkCallerSignal(caller.signal, controller, () => false);

    expect(controller.signal.aborted).toBe(true);
    expect(controller.signal.reason).toBeInstanceOf(ToolCallCancelledError);
  });

  it("does not abort when the signal is already aborted and the transport is closed", () => {
    const caller = new AbortController();
    caller.abort();
    const controller = new AbortController();

    linkCallerSignal(caller.signal, controller, () => true);

    expect(controller.signal.aborted).toBe(false);
  });

  it("aborts one turn after a later abort when the transport is still open", async () => {
    const caller = new AbortController();
    const controller = new AbortController();
    linkCallerSignal(caller.signal, controller, () => false);

    caller.abort();
    expect(controller.signal.aborted).toBe(false); // deferred by one turn
    await turn();

    expect(controller.signal.reason).toBeInstanceOf(ToolCallCancelledError);
  });

  it("does not abort when the transport has closed by the time the turn runs", async () => {
    const caller = new AbortController();
    const controller = new AbortController();
    let closed = false;
    linkCallerSignal(caller.signal, controller, () => closed);

    // The SDK aborts first and clears the transport in the same synchronous
    // run, so the close is visible by the time the deferred check reads it.
    caller.abort();
    closed = true;
    await turn();

    expect(controller.signal.aborted).toBe(false);
  });

  it("does nothing after unlink, for a pending deferred abort or a later abort", async () => {
    const caller = new AbortController();
    const controller = new AbortController();
    const unlink = linkCallerSignal(caller.signal, controller, () => false);

    caller.abort();
    unlink(); // the call settled before the deferred decision ran
    await turn();
    expect(controller.signal.aborted).toBe(false);

    const later = new AbortController();
    const second = new AbortController();
    const unlinkLater = linkCallerSignal(later.signal, second, () => false);
    unlinkLater();
    later.abort();
    await turn();
    expect(second.signal.aborted).toBe(false);
  });
});

describe("cancelAfterTotalTimeout", () => {
  const capError = () =>
    McpError.fromError(-32001, "Maximum total timeout exceeded", {
      maxTotalTimeout: 1000,
      totalElapsed: 1100,
    });

  it("aborts the controller with the SDK's own error for the cap shape", () => {
    const controller = new AbortController();
    const error = capError();

    cancelAfterTotalTimeout(error, controller);

    expect(controller.signal.aborted).toBe(true);
    expect(controller.signal.reason).toBe(error);
  });

  it("leaves the controller alone for a plain timeout and for other errors", () => {
    const plainTimeout = McpError.fromError(-32001, "Request timed out", {
      timeout: 500,
    });
    for (const error of [
      plainTimeout,
      new McpError(-32603, "Internal error"),
      new Error("Maximum total timeout exceeded"),
      "Maximum total timeout exceeded",
      undefined,
    ]) {
      const controller = new AbortController();
      cancelAfterTotalTimeout(error, controller);
      expect(controller.signal.aborted).toBe(false);
    }
  });
});

describe("runWithToolCallExtra", () => {
  it("scopes the store to the run, across awaits, and keeps parallel runs apart", async () => {
    const make = (label: string) => ({
      signal: new AbortController().signal,
      transportClosed: () => label === "closed",
    });
    expect(getToolCallExtra()).toBeUndefined();

    const seen = await Promise.all(
      ["a", "closed"].map((label) =>
        runWithToolCallExtra(make(label), async () => {
          await turn();
          return getToolCallExtra()?.transportClosed();
        }),
      ),
    );

    expect(seen).toEqual([false, true]);
    expect(getToolCallExtra()).toBeUndefined();
  });
});

describe("feature flags", () => {
  const table: Array<[string | undefined, boolean]> = [
    [undefined, true],
    ["true", true],
    ["1", true],
    ["", true],
    ["off", false],
    ["OFF", false],
    ["false", false],
    ["0", false],
    [" off ", false],
  ];

  it.each(table)("MCP_TOOL_CALL_PROGRESS=%s -> %s", (value, expected) => {
    const env = value === undefined ? {} : { MCP_TOOL_CALL_PROGRESS: value };
    expect(progressPassthroughEnabled(env)).toBe(expected);
  });

  it.each(table)("MCP_TOOL_CALL_CANCEL=%s -> %s", (value, expected) => {
    const env = value === undefined ? {} : { MCP_TOOL_CALL_CANCEL: value };
    expect(cancelPassthroughEnabled(env)).toBe(expected);
  });

  it("the two flags are independent", () => {
    expect(progressPassthroughEnabled({ MCP_TOOL_CALL_CANCEL: "off" })).toBe(
      true,
    );
    expect(cancelPassthroughEnabled({ MCP_TOOL_CALL_PROGRESS: "off" })).toBe(
      true,
    );
  });
});
