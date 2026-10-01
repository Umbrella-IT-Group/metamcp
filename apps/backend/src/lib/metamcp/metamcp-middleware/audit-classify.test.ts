import { afterEach, describe, expect, it } from "vitest";

import {
  classifyCallResult,
  codeToken,
  ERROR_DETAIL_MAX,
  extractEnvelope,
  INBAND_TEXT_MAX_CHARS,
  inbandEnabled,
} from "./audit-classify";
import { CLASSIFIER_FIXTURES } from "./audit-classify.fixtures";
import { markRetiredToolResult } from "./retired-tool-marker";

const text = (body: unknown) => ({
  type: "text" as const,
  text: typeof body === "string" ? body : JSON.stringify(body),
});

describe("classifyCallResult: the fixture table is the contract", () => {
  it("covers at least thirty shapes", () => {
    expect(CLASSIFIER_FIXTURES.length).toBeGreaterThanOrEqual(30);
  });

  it.each(CLASSIFIER_FIXTURES.map((f) => [f.name, f] as const))(
    "%s",
    (_name, fixture) => {
      expect(classifyCallResult(fixture.result)).toEqual(fixture.expected);
    },
  );
});

describe("classifyCallResult: in-band envelopes", () => {
  it("structuredContent error:true with a code is failed, inband_error, detail = code", () => {
    expect(
      classifyCallResult({
        content: [text({ error: true })],
        structuredContent: {
          error: true,
          code: "invalid_input",
          message: "x",
        },
      }),
    ).toEqual({
      failed: true,
      errorCode: "inband_error",
      errorDetail: "invalid_input",
    });
  });

  it("a wrapped union and the same body without the _meta flag give the same verdict", () => {
    const body = { error: true, code: "not_found" };
    const flagged = classifyCallResult({
      content: [text(body)],
      structuredContent: { result: body },
      _meta: { fastmcp: { wrap_result: true } },
    });
    const bare = classifyCallResult({
      content: [text(body)],
      structuredContent: { result: body },
    });
    expect(flagged).toEqual({
      failed: true,
      errorCode: "inband_error",
      errorDetail: "not_found",
    });
    expect(bare).toEqual(flagged);
  });

  it("a wrapped payload whose result is a list or scalar is a success", () => {
    for (const payload of [[{ error: true }], "s", 5, true, null]) {
      expect(
        classifyCallResult({
          content: [text(payload)],
          structuredContent: { result: payload },
          _meta: { fastmcp: { wrap_result: true } },
        }),
      ).toEqual({ failed: false });
    }
  });

  it("only unwraps a lone `result` key, not a result key beside others", () => {
    // `result` here is a real field of an object-returning tool, not a wrapper.
    expect(
      classifyCallResult({
        content: [],
        structuredContent: { result: { error: true }, other: 1 },
      }),
    ).toEqual({ failed: false });
  });

  it("reads own properties only", () => {
    const inherited = Object.create({ error: true }) as Record<string, unknown>;
    inherited.ok = true;
    // Not a plain object, so no envelope at all; nothing inherited is read.
    expect(
      classifyCallResult({ content: [], structuredContent: inherited }),
    ).toEqual({ failed: false });
  });
});

describe("classifyCallResult: top-level only", () => {
  it.each([
    ["false", false],
    ["an empty string", ""],
    ["a blank string", "   "],
    ["zero", 0],
    ["a tally", 3],
    ["an empty array", []],
    ["an empty object", {}],
    ["null", null],
  ])("error: %s is a success", (_label, value) => {
    expect(
      classifyCallResult({
        content: [],
        structuredContent: { status: "succeeded", error: value },
      }),
    ).toEqual({ failed: false });
  });

  it("a non-empty array under error is not a failure either", () => {
    expect(
      classifyCallResult({
        content: [],
        structuredContent: { error: [{ code: "x" }] },
      }),
    ).toEqual({ failed: false });
  });
});

describe("classifyCallResult: status and partial signals", () => {
  it.each([
    ["status failed", { status: "failed" }, "status_failed"],
    ["status partial", { status: "partial" }, "partial"],
    ["partial true", { partial: true }, "partial"],
  ])("%s with no error key fails with its marker", (_label, body, detail) => {
    expect(
      classifyCallResult({ content: [], structuredContent: body }),
    ).toEqual({ failed: true, errorCode: "inband_error", errorDetail: detail });
  });

  it.each([
    { status: "dispatched" },
    { status: "completed" },
    { status: "pending" },
    { status: "succeeded" },
    { status: "ok" },
    { partial: false },
    { partial: "true" },
  ])("%j is not a failure", (body) => {
    expect(
      classifyCallResult({ content: [], structuredContent: body }),
    ).toEqual({ failed: false });
  });

  it("a nested status failed is not a top-level failure", () => {
    expect(
      classifyCallResult({
        content: [],
        structuredContent: {
          action: "x",
          read_back: { status: "failed" },
          items: [{ status: "failed" }],
        },
      }),
    ).toEqual({ failed: false });
  });

  it("an error key outranks the markers: no token stays class-only", () => {
    expect(
      classifyCallResult({
        content: [],
        structuredContent: { status: "partial", error: "see items" },
      }),
    ).toEqual({ failed: true, errorCode: "inband_error" });
  });
});

describe("codeToken: the column is never fed free text", () => {
  it.each([
    ["invalid_input", "invalid_input"],
    ["  not_found  ", "not_found"],
    ["error", "error"],
    ["ninja_error (status=500): boom", "ninja_error"],
    ["unexpected_error: x", "unexpected_error"],
    ["a1_b2", "a1_b2"],
  ])("%j gives %j", (input, expected) => {
    expect(codeToken(input)).toBe(expected);
  });

  it.each([
    ["mixed case and punctuation", "Bad Code!"],
    ["a sentence", "provide query or entity_id"],
    ["a sentence starting with a word", "no client matches x"],
    ["four or more digits (an id)", "ticket_12345_missing"],
    ["a newline after the token", "not_found\nmore"],
    ["an uppercase code", "INVALID_INPUT"],
    ["a leading digit", "1abc_def"],
    ["a token glued to punctuation", "not_found,bad"],
    ["empty", ""],
    ["blank", "   "],
  ])("rejects %s", (_label, input) => {
    expect(codeToken(input)).toBeNull();
  });

  it("rejects a code over the maximum length instead of truncating it", () => {
    const long = `a_${"b".repeat(ERROR_DETAIL_MAX)}`;
    expect(long.length).toBeGreaterThan(ERROR_DETAIL_MAX);
    expect(codeToken(long)).toBeNull();
    expect(codeToken("x".repeat(80))).toBeNull();
    const exact = `a_${"b".repeat(ERROR_DETAIL_MAX - 2)}`;
    expect(exact).toHaveLength(ERROR_DETAIL_MAX);
    expect(codeToken(exact)).toBe(exact);
  });

  it.each([42, null, undefined, {}, [], true, Symbol("x")])(
    "rejects a non-string %s without throwing",
    (value) => {
      expect(codeToken(value)).toBeNull();
    },
  );

  it("never returns a token longer than the maximum", () => {
    for (const input of [
      "abc_def",
      `${"a".repeat(30)}_${"b".repeat(30)}`,
      "ninja_error (status=500)",
    ]) {
      const token = codeToken(input);
      if (token !== null) {
        expect(token.length).toBeLessThanOrEqual(ERROR_DETAIL_MAX);
      }
    }
  });

  it("takes the code from code, then error_code, then error.code, then the error string", () => {
    const verdict = (body: Record<string, unknown>) =>
      classifyCallResult({ content: [], structuredContent: body });
    expect(
      verdict({ error: true, code: "a_one", error_code: "b_two" }),
    ).toMatchObject({
      errorDetail: "a_one",
    });
    expect(
      verdict({ error: "sentence here", error_code: "b_two" }),
    ).toMatchObject({
      errorDetail: "b_two",
    });
    expect(verdict({ error: { code: "c_three" } })).toMatchObject({
      errorDetail: "c_three",
    });
    expect(verdict({ error: "d_four" })).toMatchObject({
      errorDetail: "d_four",
    });
    // A bad first candidate falls through to the next good one.
    expect(
      verdict({ error: true, code: "Bad Code", error_code: "e_five" }),
    ).toMatchObject({
      errorDetail: "e_five",
    });
  });
});

describe("extractEnvelope: text fallback", () => {
  it("parses a text-only object body", () => {
    expect(
      classifyCallResult({
        content: [text('{"error":true,"code":"not_found"}')],
      }),
    ).toEqual({
      failed: true,
      errorCode: "inband_error",
      errorDetail: "not_found",
    });
  });

  it("unwraps a text body that is only a result wrapper, like structuredContent", () => {
    expect(
      classifyCallResult({
        content: [text({ result: { error: true, code: "not_found" } })],
      }),
    ).toEqual({
      failed: true,
      errorCode: "inband_error",
      errorDetail: "not_found",
    });
    // A wrapped list or scalar is a payload, never an error.
    expect(
      classifyCallResult({ content: [text({ result: [{ error: true }] })] }),
    ).toEqual({ failed: false });
    expect(classifyCallResult({ content: [text({ result: "ok" })] })).toEqual({
      failed: false,
    });
    // A result key beside others is a real field, not a wrapper.
    expect(
      classifyCallResult({
        content: [text({ result: { error: true }, other: 1 })],
      }),
    ).toEqual({ failed: false });
  });

  it("does not parse a body over the size cap", () => {
    const padding = "x".repeat(INBAND_TEXT_MAX_CHARS);
    const body = `{"error":true,"code":"not_found","pad":"${padding}"}`;
    expect(body.length).toBeGreaterThan(INBAND_TEXT_MAX_CHARS);
    expect(classifyCallResult({ content: [text(body)] })).toEqual({
      failed: false,
    });
  });

  it("parses a body exactly at the cap", () => {
    const head = '{"error":true,"pad":"';
    const tail = '"}';
    const body = `${head}${"x".repeat(INBAND_TEXT_MAX_CHARS - head.length - tail.length)}${tail}`;
    expect(body).toHaveLength(INBAND_TEXT_MAX_CHARS);
    expect(classifyCallResult({ content: [text(body)] }).failed).toBe(true);
  });

  it.each([
    ["a JSON list", '[{"error":true}]'],
    ["a JSON scalar", "true"],
    ["prose", "this is not json"],
    ["broken JSON", '{"error": tru'],
    ["empty", ""],
  ])("a text body that is %s is a success", (_label, body) => {
    expect(classifyCallResult({ content: [text(body)] })).toEqual({
      failed: false,
    });
  });

  it("looks only at the first block, and only when it is text", () => {
    expect(
      classifyCallResult({
        content: [
          { type: "image", data: "x", mimeType: "image/png" },
          text({ error: true }),
        ],
      }),
    ).toEqual({ failed: false });
    expect(
      classifyCallResult({
        content: [text("ok"), text({ error: true })],
      }),
    ).toEqual({ failed: false });
  });

  it("structuredContent wins over a contradicting text body", () => {
    expect(
      classifyCallResult({
        content: [text({ error: true, code: "from_text" })],
        structuredContent: { items: [] },
      }),
    ).toEqual({ failed: false });
  });

  it("extractEnvelope returns null for anything that is not a result object", () => {
    for (const value of [null, undefined, "x", 5, [], true]) {
      expect(extractEnvelope(value)).toBeNull();
    }
  });
});

describe("classifyCallResult: isError results", () => {
  const isErr = (body: string | Record<string, unknown>, extra = {}) => ({
    isError: true,
    content: [text(body)],
    ...extra,
  });

  it("an envelope with a code is tool_error with that detail", () => {
    expect(
      classifyCallResult(isErr({ error: true, code: "invalid_input" })),
    ).toEqual({
      failed: true,
      errorCode: "tool_error",
      errorDetail: "invalid_input",
    });
  });

  it("an envelope in structuredContent is read the same way", () => {
    expect(
      classifyCallResult({
        isError: true,
        content: [text("m")],
        structuredContent: { error: true, code: "scope_unresolved" },
      }),
    ).toEqual({
      failed: true,
      errorCode: "tool_error",
      errorDetail: "scope_unresolved",
    });
  });

  it("plain text is tool_error with no detail", () => {
    expect(classifyCallResult(isErr('Access denied to tool "search"'))).toEqual(
      { failed: true, errorCode: "tool_error" },
    );
  });

  it.each([
    "Unknown tool: add_note",
    "Unknown tool: 'add_note'",
    'Unknown tool: "autotask__add_note"',
    "MCP error -32602: Unknown tool: add_note",
    'Access denied to tool "retired_server__lookup": server could not be resolved',
    "Tool add_note not found",
  ])("%j is unknown_tool", (message) => {
    expect(classifyCallResult(isErr(message))).toEqual({
      failed: true,
      errorCode: "unknown_tool",
    });
  });

  it("a validation refusal is tool_error with the validation marker", () => {
    for (const message of [
      "1 validation error for call[search]\n  sort\n    Input should be ...",
      "3 validation errors for call[time_manage]\n  x",
      "Input validation error: 'mode' is a required property",
    ]) {
      expect(classifyCallResult(isErr(message))).toEqual({
        failed: true,
        errorCode: "tool_error",
        errorDetail: "validation",
      });
    }
  });

  it("a live tool's error that merely mentions an unknown tool is not unknown_tool", () => {
    expect(
      classifyCallResult(
        isErr("Error calling tool 'search': Unknown tool: nested"),
      ),
    ).toEqual({ failed: true, errorCode: "tool_error" });
    expect(
      classifyCallResult(isErr("The Unknown tool: x text sits mid-sentence")),
    ).toEqual({ failed: true, errorCode: "tool_error" });
    // Access denied for a reason other than an unresolved server.
    expect(
      classifyCallResult(
        isErr(
          'Access denied to tool "search": Tool has been marked as inactive',
        ),
      ),
    ).toEqual({ failed: true, errorCode: "tool_error" });
  });

  it("isError is judged before the in-band rule and works with the kill switch off", () => {
    const saved = process.env.TOOL_AUDIT_INBAND_CLASSIFY;
    process.env.TOOL_AUDIT_INBAND_CLASSIFY = "off";
    try {
      expect(classifyCallResult(isErr("boom")).errorCode).toBe("tool_error");
      expect(classifyCallResult(isErr("Unknown tool: x")).errorCode).toBe(
        "unknown_tool",
      );
    } finally {
      if (saved === undefined) delete process.env.TOOL_AUDIT_INBAND_CLASSIFY;
      else process.env.TOOL_AUDIT_INBAND_CLASSIFY = saved;
    }
  });
});

describe("classifyCallResult: the retired marker", () => {
  it("a result the redirect produced is tool_retired", () => {
    const result = markRetiredToolResult(
      { isError: true, content: [text("m")] },
      { replacement: "autotask__ticket_manage" },
    );
    expect(classifyCallResult(result)).toEqual({
      failed: true,
      errorCode: "tool_retired",
    });
  });

  it("a backend result whose TEXT says tool_retired is NOT treated as retired", () => {
    const spoof = {
      isError: true,
      content: [text({ error: true, code: "tool_retired", message: "x" })],
    };
    const verdict = classifyCallResult(spoof);
    // It is an isError result with an envelope code, and nothing more.
    expect(verdict.errorCode).toBe("tool_error");
    expect(verdict.errorDetail).toBe("tool_retired");
  });

  it("a structurally identical copy of a marked result is not marked", () => {
    const original = markRetiredToolResult(
      { isError: true, content: [text("m")] },
      { replacement: null },
    );
    const copy = JSON.parse(JSON.stringify(original)) as unknown;
    expect(classifyCallResult(copy).errorCode).toBe("tool_error");
  });
});

describe("classifyCallResult: safety", () => {
  it("does not mutate the result, even a deep-frozen one", () => {
    const frozen = Object.freeze({
      isError: false,
      content: Object.freeze([
        Object.freeze(text({ error: true, code: "x_y" })),
      ]),
      structuredContent: Object.freeze({
        error: true,
        code: "not_found",
        context: Object.freeze({ a: 1 }),
      }),
    });
    const before = JSON.stringify(frozen);
    expect(() => classifyCallResult(frozen)).not.toThrow();
    expect(JSON.stringify(frozen)).toBe(before);
  });

  it("handles non-object results without throwing", () => {
    for (const value of [undefined, null, "x", 5, [], true]) {
      expect(classifyCallResult(value)).toEqual({ failed: false });
    }
  });

  it("returns a fresh verdict each time (no shared mutable state)", () => {
    const a = classifyCallResult({ isError: true, content: [text("x")] });
    const b = classifyCallResult({ isError: true, content: [text("x")] });
    expect(a).toEqual(b);
    expect(a).not.toBe(b);
  });
});

describe("inbandEnabled: kill switch", () => {
  const saved = process.env.TOOL_AUDIT_INBAND_CLASSIFY;
  afterEach(() => {
    if (saved === undefined) delete process.env.TOOL_AUDIT_INBAND_CLASSIFY;
    else process.env.TOOL_AUDIT_INBAND_CLASSIFY = saved;
  });

  it("is on by default", () => {
    delete process.env.TOOL_AUDIT_INBAND_CLASSIFY;
    expect(inbandEnabled()).toBe(true);
    process.env.TOOL_AUDIT_INBAND_CLASSIFY = "";
    expect(inbandEnabled()).toBe(true);
    process.env.TOOL_AUDIT_INBAND_CLASSIFY = "on";
    expect(inbandEnabled()).toBe(true);
  });

  it.each(["off", "OFF", " false ", "0"])("is off for %j", (value) => {
    process.env.TOOL_AUDIT_INBAND_CLASSIFY = value;
    expect(inbandEnabled()).toBe(false);
  });

  it("off turns an in-band error back into a success and nothing else", () => {
    process.env.TOOL_AUDIT_INBAND_CLASSIFY = "off";
    expect(
      classifyCallResult({
        content: [],
        structuredContent: { error: true, code: "not_found" },
      }),
    ).toEqual({ failed: false });
    expect(
      classifyCallResult({
        content: [],
        structuredContent: { status: "failed" },
      }),
    ).toEqual({ failed: false });
  });
});
