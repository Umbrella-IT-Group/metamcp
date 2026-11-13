/**
 * The pure half of per-endpoint presentation: the text rules the request
 * schemas enforce, what `createServer` is handed for the SDK constructor, how
 * the kill switch resolves, and the `init_params` pin lazy recovery reads.
 *
 * Oracles: the bounds and character rules are the design's (title 80 characters
 * on one line, instructions 1500 with TAB and LF allowed, no control, bidi or
 * zero-width characters; UTF-16 code units, the unit of `String.length` and of
 * zod's `.max()`); the Unicode category Cf and the C0/C1 control ranges are
 * the Unicode standard's; the `serverInfo` literal for a session with no
 * presentation is the object `createServer` passed to the SDK before this
 * change existed.
 */
import {
  ENDPOINT_INSTRUCTIONS_MAX,
  ENDPOINT_TITLE_MAX,
  normalizePresentationText,
  SetEndpointPresentationRequestSchema,
} from "@repo/zod-types";
import { describe, expect, it } from "vitest";

import {
  buildServerMetadata,
  effectivePresentation,
  presentationEnabled,
  presentationFromInitParams,
  presentationToInitParams,
  type SessionPresentation,
  withoutOutputSchema,
} from "./endpoint-presentation";

const UUID = "11111111-1111-4111-8111-111111111111";

/** Parse a set request with just these two texts, everything else valid. */
function parse(title: string | null, instructions: string | null) {
  return SetEndpointPresentationRequestSchema.safeParse({
    endpoint_uuid: UUID,
    title,
    instructions,
    tool_listing: "full",
    omit_output_schemas: false,
  });
}

function messageOf(result: ReturnType<typeof parse>): string | undefined {
  return result.success ? undefined : result.error.issues[0]?.message;
}

describe("normalizePresentationText", () => {
  it.each([
    ["CRLF becomes LF", "a\r\nb", "a\nb"],
    ["a lone CR becomes LF", "a\rb", "a\nb"],
    ["surrounding whitespace is trimmed", "  hi \n", "hi"],
    ["inner whitespace is kept", "a  b\tc", "a  b\tc"],
  ])("%s", (_label, input, expected) => {
    expect(normalizePresentationText(input)).toBe(expected);
  });

  it.each(["", "   ", "\n\n", "\r\n \t"])(
    "empty after trimming (%j) means no text",
    (input) => {
      expect(normalizePresentationText(input)).toBeNull();
    },
  );

  it("treats null and undefined as no text", () => {
    expect(normalizePresentationText(null)).toBeNull();
    expect(normalizePresentationText(undefined)).toBeNull();
  });
});

describe("title rules", () => {
  it("accepts 80 characters and refuses 81", () => {
    expect(parse("t".repeat(ENDPOINT_TITLE_MAX), null).success).toBe(true);
    const refused = parse("t".repeat(ENDPOINT_TITLE_MAX + 1), null);
    expect(refused.success).toBe(false);
    expect(messageOf(refused)).toBe("Must be 80 characters or fewer.");
  });

  it("counts UTF-16 code units: 40 astral characters fit, 41 do not", () => {
    // U+1F600 is one code point and two UTF-16 units; zod's .max() and the
    // limit are in units, and Postgres counts fewer, so the app is the
    // stricter layer.
    expect(parse("\u{1F600}".repeat(40), null).success).toBe(true);
    expect(parse("\u{1F600}".repeat(41), null).success).toBe(false);
  });

  it("judges the normalized value: padding does not count against the bound", () => {
    expect(parse(`  ${"t".repeat(80)}  `, null).success).toBe(true);
  });

  it("is one line: LF, CR and CRLF are refused", () => {
    for (const title of ["a\nb", "a\rb", "a\r\nb"]) {
      const refused = parse(title, null);
      expect(refused.success).toBe(false);
      expect(messageOf(refused)).toBe("Must be a single line.");
    }
  });

  it.each(["\u2028", "\u2029"])(
    "refuses Unicode line and paragraph separators (%j) in a title",
    (separator) => {
      const refused = parse(`a${separator}b`, null);
      expect(refused.success).toBe(false);
      expect(messageOf(refused)).toBe("Must be a single line.");
      // Multi-line guidance may still contain these ordinary separators.
      expect(parse(null, `a${separator}b`).success).toBe(true);
    },
  );

  it("refuses TAB, which a single line does not allow", () => {
    const refused = parse("a\tb", null);
    expect(refused.success).toBe(false);
    expect(messageOf(refused)).toBe("Must not contain control characters.");
  });

  it("accepts ordinary text in other scripts and accents", () => {
    for (const title of ["Zürich desk", "デスク", "Café 😀"]) {
      expect(parse(title, null).success).toBe(true);
    }
  });

  it("stores empty as null", () => {
    const parsed = parse("   ", null);
    expect(parsed.success && parsed.data.title).toBeNull();
  });
});

describe("instructions rules", () => {
  it("accepts 1500 characters and refuses 1501", () => {
    expect(parse(null, "i".repeat(ENDPOINT_INSTRUCTIONS_MAX)).success).toBe(
      true,
    );
    const refused = parse(null, "i".repeat(ENDPOINT_INSTRUCTIONS_MAX + 1));
    expect(refused.success).toBe(false);
    expect(messageOf(refused)).toBe("Must be 1500 characters or fewer.");
  });

  it("counts UTF-16 code units: 750 astral characters fit, 751 do not", () => {
    expect(parse(null, "\u{1F600}".repeat(750)).success).toBe(true);
    expect(parse(null, "\u{1F600}".repeat(751)).success).toBe(false);
  });

  it("judges the normalized value: CRLF and trailing newlines do not count against the bound", () => {
    // 749 + CRLF + 750 is 1501 raw units, 1500 once CRLF is one LF.
    const withCrlf = `${"i".repeat(749)}\r\n${"i".repeat(750)}`;
    expect(withCrlf.length).toBe(1501);
    const parsed = parse(null, withCrlf);
    expect(parsed.success).toBe(true);
    expect(parsed.success && parsed.data.instructions?.length).toBe(1500);
    expect(parse(null, `${"i".repeat(1500)}\n\n`).success).toBe(true);
  });

  it("keeps TAB and LF and stores CRLF as LF", () => {
    const parsed = parse(null, "step one\r\n\tstep two");
    expect(parsed.success && parsed.data.instructions).toBe(
      "step one\n\tstep two",
    );
  });

  it("stores empty as null", () => {
    const parsed = parse(null, "\r\n\t ");
    expect(parsed.success && parsed.data.instructions).toBeNull();
  });
});

describe("characters refused in both texts", () => {
  const CONTROLS = [
    ["NUL", "\u0000"],
    ["BEL", "\u0007"],
    ["VT", "\u000B"],
    ["ESC", "\u001B"],
    ["DEL", "\u007F"],
    ["C1 NEL", "\u0085"],
    ["C1 APC", "\u009F"],
  ] as const;

  const FORMAT = [
    ["right-to-left override", "‮"],
    ["left-to-right isolate", "⁦"],
    ["zero-width space", "​"],
    ["zero-width joiner", "‍"],
    ["byte-order mark inside the text", "﻿"],
    ["soft hyphen", "­"],
    ["tag character", "\u{E0041}"],
  ] as const;

  it.each(CONTROLS)("refuses the control character %s", (_name, char) => {
    for (const refused of [
      parse(`ab${char}cd`, null),
      parse(null, `ab${char}cd`),
    ]) {
      expect(refused.success).toBe(false);
      expect(messageOf(refused)).toBe("Must not contain control characters.");
    }
  });

  it.each(FORMAT)("refuses the format character: %s", (_name, char) => {
    for (const refused of [
      parse(`ab${char}cd`, null),
      parse(null, `ab${char}cd`),
    ]) {
      expect(refused.success).toBe(false);
      expect(messageOf(refused)).toBe(
        "Must not contain invisible or text-direction characters.",
      );
    }
  });

  it("never echoes the submitted text in a refusal", () => {
    const secret = "do-not-echo-this";
    const refused = parse(null, `${secret}\u0007`);
    expect(refused.success).toBe(false);
    expect(JSON.stringify(refused.error)).not.toContain(secret);
  });
});

describe("the set request", () => {
  it("only accepts the full listing in this release", () => {
    const refused = SetEndpointPresentationRequestSchema.safeParse({
      endpoint_uuid: UUID,
      title: null,
      instructions: null,
      tool_listing: "lean",
      omit_output_schemas: false,
    });
    expect(refused.success).toBe(false);
  });

  it("requires an endpoint uuid", () => {
    const refused = SetEndpointPresentationRequestSchema.safeParse({
      endpoint_uuid: "not-a-uuid",
      title: null,
      instructions: null,
      tool_listing: "full",
      omit_output_schemas: false,
    });
    expect(refused.success).toBe(false);
  });
});

describe("buildServerMetadata", () => {
  it("is exactly today's { name, version } for a session with no presentation", () => {
    const metadata = buildServerMetadata("ns-1", undefined);
    // The literal createServer always passed to the SDK, and nothing more:
    // no `title` key and no `instructions` key at all.
    expect(metadata).toEqual({
      serverInfo: { name: "metamcp-unified-ns-1", version: "1.0.0" },
    });
    expect(Object.keys(metadata.serverInfo)).toEqual(["name", "version"]);
    expect("instructions" in metadata).toBe(false);
  });

  it("adds only the title when there is a title", () => {
    const metadata = buildServerMetadata("ns-1", {
      title: "Helpdesk tools",
      toolListing: "full",
      omitOutputSchemas: false,
    });
    expect(metadata).toEqual({
      serverInfo: {
        name: "metamcp-unified-ns-1",
        version: "1.0.0",
        title: "Helpdesk tools",
      },
    });
  });

  it("carries the instructions, and no title key, when there are only instructions", () => {
    const metadata = buildServerMetadata("ns-1", {
      instructions: "Prefer read-only tools.",
      toolListing: "full",
      omitOutputSchemas: false,
    });
    expect(metadata.instructions).toBe("Prefer read-only tools.");
    expect("title" in metadata.serverInfo).toBe(false);
  });

  it("never lets the title change the server name", () => {
    const metadata = buildServerMetadata("ns-2", {
      title: "metamcp-unified-other",
      toolListing: "full",
      omitOutputSchemas: true,
    });
    expect(metadata.serverInfo.name).toBe("metamcp-unified-ns-2");
  });
});

describe("MCP_ENDPOINT_PRESENTATION", () => {
  it.each(["off", "false", "0", "OFF", "False", "  off  "])(
    "%j turns presentation off",
    (value) => {
      expect(presentationEnabled({ MCP_ENDPOINT_PRESENTATION: value })).toBe(
        false,
      );
    },
  );

  it.each([undefined, "", "on", "true", "1", "enabled"])(
    "%j leaves presentation on",
    (value) => {
      expect(presentationEnabled({ MCP_ENDPOINT_PRESENTATION: value })).toBe(
        true,
      );
    },
  );
});

describe("effectivePresentation", () => {
  const full: SessionPresentation = {
    title: "Desk",
    instructions: "Be brief.",
    toolListing: "full",
    omitOutputSchemas: true,
  };

  it("is undefined for no input and for an all-default input", () => {
    expect(effectivePresentation(undefined, {})).toBeUndefined();
    expect(
      effectivePresentation(
        { toolListing: "full", omitOutputSchemas: false },
        {},
      ),
    ).toBeUndefined();
  });

  it("treats empty strings as no text", () => {
    expect(
      effectivePresentation(
        {
          title: "",
          instructions: "",
          toolListing: "full",
          omitOutputSchemas: false,
        },
        {},
      ),
    ).toBeUndefined();
  });

  it("passes a real presentation through, and applying it twice changes nothing", () => {
    const once = effectivePresentation(full, {});
    expect(once).toEqual(full);
    expect(effectivePresentation(once, {})).toEqual(once);
  });

  it("serves a stored lean listing as the full listing in this release, and a lean-only input as none", () => {
    expect(
      effectivePresentation(
        { toolListing: "lean", omitOutputSchemas: false },
        {},
      ),
    ).toBeUndefined();
    expect(
      effectivePresentation(
        { title: "Desk", toolListing: "lean", omitOutputSchemas: false },
        {},
      ),
    ).toEqual({ title: "Desk", toolListing: "full", omitOutputSchemas: false });
  });

  it("is undefined whatever the content when the kill switch is off", () => {
    expect(
      effectivePresentation(full, { MCP_ENDPOINT_PRESENTATION: "off" }),
    ).toBeUndefined();
  });
});

describe("the init_params pin", () => {
  const trimmed: SessionPresentation = {
    title: "Desk",
    instructions: "Be brief.",
    toolListing: "full",
    omitOutputSchemas: true,
  };

  it("writes {} for a default session, exactly what was always persisted", () => {
    expect(presentationToInitParams(undefined)).toEqual({});
  });

  it("writes only the behavioural bits, never the title or the instructions", () => {
    const pin = presentationToInitParams(trimmed);
    expect(pin).toEqual({ presentation: { v: 1, lean: false, omit: true } });
    expect(JSON.stringify(pin)).not.toContain("Desk");
    expect(JSON.stringify(pin)).not.toContain("Be brief.");
  });

  it("round-trips the trim", () => {
    expect(
      presentationFromInitParams(presentationToInitParams(trimmed), {}),
    ).toEqual({ toolListing: "full", omitOutputSchemas: true });
  });

  it("reads a pin that only records a title as no presentation", () => {
    expect(
      presentationFromInitParams(
        presentationToInitParams({
          title: "Desk",
          toolListing: "full",
          omitOutputSchemas: false,
        }),
        {},
      ),
    ).toBeUndefined();
  });

  it("reads a lean pin as the full listing in this release", () => {
    expect(
      presentationFromInitParams(
        { presentation: { v: 1, lean: true, omit: false } },
        {},
      ),
    ).toBeUndefined();
  });

  it.each([
    ["an empty object, the row of every pre-existing session", {}],
    ["null", null],
    ["undefined", undefined],
    ["a string", "presentation"],
    ["a number", 7],
    ["an array", [{ presentation: { v: 1, lean: false, omit: true } }]],
    ["a null pin", { presentation: null }],
    ["an unknown version", { presentation: { v: 2, lean: false, omit: true } }],
    ["a missing version", { presentation: { lean: false, omit: true } }],
    ["wrong types", { presentation: { v: 1, lean: "false", omit: "true" } }],
    [
      "an extra key in the pin",
      { presentation: { v: 1, lean: false, omit: true, extra: 1 } },
    ],
    ["a missing field", { presentation: { v: 1, omit: true } }],
  ])("reads %s as no pin", (_label, raw) => {
    expect(presentationFromInitParams(raw, {})).toBeUndefined();
  });

  it("reads a __proto__ key in the pin as no pin", () => {
    const raw = JSON.parse(
      '{"presentation":{"v":1,"lean":false,"omit":true,"__proto__":{"omit":false}}}',
    );
    expect(presentationFromInitParams(raw, {})).toBeUndefined();
  });

  it("does not read the pin off a prototype", () => {
    const inherited = Object.create({
      presentation: { v: 1, lean: false, omit: true },
    });
    expect(presentationFromInitParams(inherited, {})).toBeUndefined();
  });

  it("lets the kill switch win over a pin", () => {
    expect(
      presentationFromInitParams(
        { presentation: { v: 1, lean: false, omit: true } },
        { MCP_ENDPOINT_PRESENTATION: "off" },
      ),
    ).toBeUndefined();
  });
});

describe("withoutOutputSchema", () => {
  it("copies the tool without its outputSchema and leaves the original alone", () => {
    const tool = {
      name: "alpha__list",
      description: "List things",
      inputSchema: { type: "object" as const },
      outputSchema: { type: "object" as const },
      annotations: { readOnlyHint: true },
      _meta: { source: "test" },
    };
    const trimmed = withoutOutputSchema(tool);
    expect(trimmed).toEqual({
      name: "alpha__list",
      description: "List things",
      inputSchema: { type: "object" },
      annotations: { readOnlyHint: true },
      _meta: { source: "test" },
    });
    expect("outputSchema" in trimmed).toBe(false);
    expect(tool.outputSchema).toEqual({ type: "object" });
  });
});
