import { describe, expect, it, vi } from "vitest";

import {
  hasProblems,
  instructionsLength,
  isDirty,
  type PresentationFormState,
  type StoredPresentation,
  swallowEnter,
  toFormState,
  toRequest,
  validate,
} from "./endpoint-presentation-form";

/**
 * The rules behind the endpoint presentation panel: what may be saved, what
 * counts as a change, and what is sent. The bounds and the character rules are
 * the backend's (title 80 characters on one line, instructions 1500 with TAB
 * and LF allowed, no control, bidi or zero-width characters, in UTF-16 code
 * units, judged on the normalized text), so this file pins that the panel
 * refuses what the server would, at the same boundaries.
 */

const UUID = "11111111-1111-4111-8111-111111111111";
const EMPTY: PresentationFormState = {
  title: "",
  instructions: "",
  omitOutputSchemas: false,
};
const STORED: StoredPresentation = {
  title: "Desk",
  instructions: "Be brief.",
  omit_output_schemas: true,
  tool_listing: "full",
};

describe("toFormState", () => {
  it("is empty for an endpoint with nothing stored", () => {
    expect(toFormState(undefined)).toEqual(EMPTY);
    expect(
      toFormState({
        title: null,
        instructions: null,
        omit_output_schemas: false,
        tool_listing: "full",
      }),
    ).toEqual(EMPTY);
  });

  it("copies the stored values", () => {
    expect(toFormState(STORED)).toEqual({
      title: "Desk",
      instructions: "Be brief.",
      omitOutputSchemas: true,
    });
  });
});

describe("validate", () => {
  it("accepts an empty form", () => {
    expect(validate(EMPTY)).toEqual({});
  });

  it("accepts a title of 80 characters and refuses 81", () => {
    expect(validate({ ...EMPTY, title: "t".repeat(80) })).toEqual({});
    expect(validate({ ...EMPTY, title: "t".repeat(81) })).toEqual({
      title: "too_long",
    });
  });

  it("accepts instructions of 1500 characters and refuses 1501", () => {
    expect(validate({ ...EMPTY, instructions: "i".repeat(1500) })).toEqual({});
    expect(validate({ ...EMPTY, instructions: "i".repeat(1501) })).toEqual({
      instructions: "too_long",
    });
  });

  it("counts UTF-16 code units: 40 astral characters fit in a title, 41 do not", () => {
    expect(validate({ ...EMPTY, title: "\u{1F600}".repeat(40) })).toEqual({});
    expect(validate({ ...EMPTY, title: "\u{1F600}".repeat(41) })).toEqual({
      title: "too_long",
    });
  });

  it("judges the normalized text: padding and CRLF do not count against the limit", () => {
    expect(validate({ ...EMPTY, title: ` ${"t".repeat(80)} ` })).toEqual({});
    const withCrlf = `${"i".repeat(749)}\r\n${"i".repeat(750)}`;
    expect(withCrlf.length).toBe(1501);
    expect(validate({ ...EMPTY, instructions: withCrlf })).toEqual({});
  });

  it("refuses a newline in the title and allows TAB and LF in the instructions", () => {
    expect(validate({ ...EMPTY, title: "a\nb" })).toEqual({ title: "newline" });
    expect(validate({ ...EMPTY, instructions: "a\n\tb" })).toEqual({});
  });

  it.each([
    ["a control character", "\u0007", "control"],
    ["DEL", "\u007F", "control"],
    ["a C1 control", "\u0085", "control"],
    ["a bidi override", "‮", "format"],
    ["a zero-width space", "​", "format"],
  ] as const)("refuses %s in either text", (_label, char, problem) => {
    expect(validate({ ...EMPTY, title: `a${char}b` })).toEqual({
      title: problem,
    });
    expect(validate({ ...EMPTY, instructions: `a${char}b` })).toEqual({
      instructions: problem,
    });
  });

  it("reports both fields when both are wrong", () => {
    const problems = validate({
      ...EMPTY,
      title: "t".repeat(81),
      instructions: "a\u0007",
    });
    expect(problems).toEqual({ title: "too_long", instructions: "control" });
    expect(hasProblems(problems)).toBe(true);
    expect(hasProblems({})).toBe(false);
  });
});

describe("isDirty", () => {
  it("is false for the stored state, with or without text", () => {
    expect(isDirty(toFormState(STORED), STORED)).toBe(false);
    const nothing: StoredPresentation = {
      title: null,
      instructions: null,
      omit_output_schemas: false,
      tool_listing: "full",
    };
    expect(isDirty(EMPTY, nothing)).toBe(false);
    expect(isDirty(EMPTY, undefined)).toBe(false);
  });

  it("is false when only padding or line endings differ, since they normalize away", () => {
    expect(
      isDirty(
        {
          title: "  Desk ",
          instructions: "Be brief.\r\n",
          omitOutputSchemas: true,
        },
        STORED,
      ),
    ).toBe(false);
    expect(
      isDirty(
        { ...toFormState(STORED), instructions: "a\r\nb" },
        { ...STORED, instructions: "a\nb" },
      ),
    ).toBe(false);
  });

  it("is true when any one field differs", () => {
    const base = toFormState(STORED);
    expect(isDirty({ ...base, title: "Other" }, STORED)).toBe(true);
    expect(isDirty({ ...base, instructions: "Other." }, STORED)).toBe(true);
    expect(isDirty({ ...base, omitOutputSchemas: false }, STORED)).toBe(true);
    expect(isDirty({ ...base, title: "" }, STORED)).toBe(true);
  });

  it("is true for a stored lean mode even when the fields match, so it can be cleared", () => {
    expect(
      isDirty(EMPTY, {
        title: null,
        instructions: null,
        omit_output_schemas: false,
        tool_listing: "lean",
      }),
    ).toBe(true);
  });
});

describe("toRequest", () => {
  it("sends normalized text, the trim flag and the full listing", () => {
    expect(
      toRequest(UUID, {
        title: "  Helpdesk desk ",
        instructions: "one\r\ntwo\r\n",
        omitOutputSchemas: true,
      }),
    ).toEqual({
      endpoint_uuid: UUID,
      title: "Helpdesk desk",
      instructions: "one\ntwo",
      tool_listing: "full",
      omit_output_schemas: true,
    });
  });

  it("sends null for an empty field, which clears it", () => {
    expect(toRequest(UUID, EMPTY)).toEqual({
      endpoint_uuid: UUID,
      title: null,
      instructions: null,
      tool_listing: "full",
      omit_output_schemas: false,
    });
  });
});

describe("instructionsLength", () => {
  it("counts the normalized text, which is what the limit applies to", () => {
    expect(instructionsLength(EMPTY)).toBe(0);
    expect(instructionsLength({ ...EMPTY, instructions: " ab\r\ncd \n" })).toBe(
      5,
    );
  });
});

describe("swallowEnter", () => {
  it("stops Enter, so a title field cannot submit the endpoint form around it", () => {
    const preventDefault = vi.fn();
    swallowEnter({ key: "Enter", preventDefault });
    expect(preventDefault).toHaveBeenCalledTimes(1);
  });

  it("leaves every other key alone", () => {
    const preventDefault = vi.fn();
    for (const key of ["a", "Tab", " ", "Escape", "Backspace"]) {
      swallowEnter({ key, preventDefault });
    }
    expect(preventDefault).not.toHaveBeenCalled();
  });
});
