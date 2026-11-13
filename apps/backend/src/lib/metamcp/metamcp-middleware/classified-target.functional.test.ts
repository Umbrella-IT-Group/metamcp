/**
 * The identity check of `call_tool`, alone: it compares the name the overrides
 * middleware resolved with the tool the read-only verdict was given for, and
 * only for a call that carries a verdict.
 */
import type {
  CallToolRequest,
  CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it, vi } from "vitest";

import {
  type ClassifiedCallContext,
  classifiedTargetRefusal,
  createClassifiedTargetMiddleware,
  TARGET_CHANGED_ANSWER,
} from "./classified-target.functional";

const request = (name: string): CallToolRequest => ({
  method: "tools/call",
  params: { name, arguments: { id: "1" } },
});

const OK: CallToolResult = { content: [{ type: "text", text: "ran" }] };

function run(
  name: string,
  context: Partial<ClassifiedCallContext>,
  onRefused?: () => void,
) {
  const handler = vi.fn(async () => OK);
  const wrapped = createClassifiedTargetMiddleware({ onRefused })(handler);
  const full: ClassifiedCallContext = {
    namespaceUuid: "ns",
    sessionId: "s",
    classifiedServerUuid: "desk-id",
    classifiedTargetIsCurrent: () => true,
    ...context,
  };
  return { handler, result: wrapped(request(name), full), full };
}

describe("createClassifiedTargetMiddleware", () => {
  it("lets a call through whose resolved name is the tool the verdict was given for, with the request and context untouched", async () => {
    const { handler, result, full } = run("desk__legacy", {
      classifiedTarget: "desk__legacy",
    });
    expect(await result).toBe(OK);
    expect(handler).toHaveBeenCalledTimes(1);
    const [seenRequest, seenContext] = handler.mock.calls[0] as unknown as [
      CallToolRequest,
      unknown,
    ];
    expect(seenRequest.params.name).toBe("desk__legacy");
    expect(seenContext).toBe(full);
  });

  it("refuses a call whose resolved name is any other tool, runs nothing, and says the tool changed", async () => {
    const onRefused = vi.fn();
    for (const resolved of [
      "desk__write",
      "desk__legacy ",
      "DESK__LEGACY",
      "other__legacy",
      "desk__modern",
    ]) {
      const { handler, result } = run(
        resolved,
        { classifiedTarget: "desk__legacy" },
        onRefused,
      );
      expect(await result, resolved).toEqual({
        isError: true,
        content: [{ type: "text", text: TARGET_CHANGED_ANSWER }],
      });
      expect(handler, resolved).not.toHaveBeenCalled();
    }
    expect(onRefused).toHaveBeenCalledTimes(5);
  });

  it("refuses with constant text that names the two ways to look again and echoes nothing, and does not point at call_write_tool", () => {
    expect(TARGET_CHANGED_ANSWER).toContain("changed");
    expect(TARGET_CHANGED_ANSWER).toContain("search_tools");
    expect(TARGET_CHANGED_ANSWER).toContain("describe_tool");
    expect(TARGET_CHANGED_ANSWER).not.toContain("call_write_tool");
    expect(TARGET_CHANGED_ANSWER).not.toContain("__");
  });

  it("does nothing for a call that carries no verdict: call_write_tool and a direct call run whatever name resolved", async () => {
    const onRefused = vi.fn();
    for (const name of ["desk__legacy", "desk__write", "anything"]) {
      const { handler, result } = run(name, {}, onRefused);
      expect(await result).toBe(OK);
      expect(handler).toHaveBeenCalledTimes(1);
    }
    expect(onRefused).not.toHaveBeenCalled();
  });

  it("treats an empty-string target as a verdict, never as no verdict", async () => {
    const { handler, result } = run("desk__write", { classifiedTarget: "" });
    expect((await result).isError).toBe(true);
    expect(handler).not.toHaveBeenCalled();
  });

  it("refuses revoked or incomplete hints even when the resolved name is unchanged", async () => {
    for (const context of [
      { classifiedTargetIsCurrent: () => false },
      { classifiedTargetIsCurrent: undefined },
      { classifiedServerUuid: undefined },
    ]) {
      const { handler, result } = run("desk__legacy", {
        classifiedTarget: "desk__legacy",
        ...context,
      });
      expect((await result).isError).toBe(true);
      expect(handler).not.toHaveBeenCalled();
    }
  });

  it("checks the actual backend UUID at dispatch even if its prefix and tool name stayed the same", () => {
    const context = {
      namespaceUuid: "ns",
      sessionId: "s",
      classifiedTarget: "desk__legacy",
      classifiedServerUuid: "original-id",
      classifiedTargetIsCurrent: () => true,
    };
    expect(
      classifiedTargetRefusal(request("desk__legacy"), context, "original-id"),
    ).toBeUndefined();
    expect(
      classifiedTargetRefusal(
        request("desk__legacy"),
        context,
        "replacement-id",
      )?.isError,
    ).toBe(true);
  });

  it("keeps two calls' verdicts apart: each is judged against its own context", async () => {
    const first = run("desk__a", { classifiedTarget: "desk__a" });
    const second = run("desk__a", { classifiedTarget: "desk__b" });
    expect(await first.result).toBe(OK);
    expect((await second.result).isError).toBe(true);
  });
});
