import { describe, expect, it } from "vitest";

import fixture from "./fixtures/optional-parameters-tool.json";
import {
  coerceExecutionArgByType,
  coerceTextInputValueByType,
  extractEnumOptions,
  getToolPropertyType,
  parseObjectFromPaste,
  resolveRef,
  resolveToolPropertySchema,
} from "./schema-utils";

const root = fixture.tool.inputSchema as Record<string, unknown>;
const prunedRoot = fixture.prunedVariant.inputSchema as Record<string, unknown>;
const properties = root.properties as Record<string, Record<string, unknown>>;

// The document RFC 6901 section 5 uses for its examples, with every value
// turned into a small object so a resolved reference can be told apart by its
// title. Section 6 gives the URI fragment form of each pointer.
const rfcDocument = {
  foo: [{ title: "bar" }, { title: "baz" }],
  "": { title: "empty" },
  "a/b": { title: "slash" },
  "c%d": { title: "percent" },
  "e^f": { title: "caret" },
  "g|h": { title: "pipe" },
  "i\\j": { title: "backslash" },
  'k"l': { title: "quote" },
  " ": { title: "space" },
  "m~n": { title: "tilde" },
};

const titleOf = (ref: string, document: Record<string, unknown>) =>
  resolveRef({ $ref: ref }, document).title;

describe("resolveRef: JSON Pointer in a URI fragment (RFC 6901 sections 4 and 6)", () => {
  it.each([
    ["#/foo/0", "bar"],
    ["#/foo/1", "baz"],
    ["#/", "empty"],
    ["#/a~1b", "slash"],
    ["#/c%25d", "percent"],
    ["#/e%5Ef", "caret"],
    ["#/g%7Ch", "pipe"],
    ["#/i%5Cj", "backslash"],
    ["#/k%22l", "quote"],
    ["#/%20", "space"],
    ["#/m~0n", "tilde"],
  ])("resolves the RFC example %s", (ref, title) => {
    expect(titleOf(ref, rfcDocument)).toBe(title);
  });

  it("decodes the fragment once, so an encoded separator is a path step", () => {
    const document = {
      $defs: {
        A: { B: { title: "nested A then B" } },
        "A/B": { title: "one property named A/B" },
        "A%2FB": { title: "one property named A%2FB" },
      },
    };
    // %2F decodes to "/" before the pointer is split.
    expect(titleOf("#/$defs/A%2FB", document)).toBe("nested A then B");
    // ~1 is the in-pointer escape for a literal "/" inside one name.
    expect(titleOf("#/$defs/A~1B", document)).toBe("one property named A/B");
    // %25 decodes to "%", and the decoded text is not decoded a second time.
    expect(titleOf("#/$defs/A%252FB", document)).toBe(
      "one property named A%2FB",
    );
  });

  it("accepts an escaped leading separator", () => {
    const document = { $defs: { A: { title: "found" } } };
    expect(titleOf("#%2F$defs%2FA", document)).toBe("found");
  });

  it("unescapes ~1 before ~0, so ~01 is the two characters ~1", () => {
    const document = { "~1": { title: "literal tilde one" } };
    expect(titleOf("#/~01", document)).toBe("literal tilde one");
  });

  it.each(["#/$defs/A%", "#/$defs/%E0%A4%A", "#/$defs/%zz"])(
    "leaves %s unresolved without throwing",
    (ref) => {
      const schema = { $ref: ref };
      const document = { $defs: { A: { type: "string" } } };
      expect(() => resolveRef(schema, document)).not.toThrow();
      expect(resolveRef(schema, document)).toBe(schema);
    },
  );

  it.each(["#/$defs/A~", "#/$defs/A~2B", "#$defs/A", "#foo"])(
    "leaves the malformed pointer %s unresolved",
    (ref) => {
      const schema = { $ref: ref };
      const document = { $defs: { A: { type: "string" }, "A~2B": {} } };
      expect(resolveRef(schema, document)).toBe(schema);
    },
  );

  it.each([
    "https://example.com/schema.json",
    "other.json#/$defs/A",
    "/$defs/A",
  ])("never follows the external reference %s", (ref) => {
    const schema = { $ref: ref };
    expect(resolveRef(schema, { $defs: { A: { type: "string" } } })).toBe(
      schema,
    );
  });

  it("does not walk the prototype chain", () => {
    for (const ref of [
      "#/constructor",
      "#/__proto__",
      "#/toString",
      "#/$defs/constructor",
      "#/$defs/__proto__",
    ]) {
      const schema = { $ref: ref };
      expect(resolveRef(schema, { $defs: {} })).toBe(schema);
    }
  });

  it("reads an own __proto__ property that came from JSON", () => {
    const parsed = JSON.parse('{"$defs":{"__proto__":{"title":"own"}}}');
    expect(titleOf("#/$defs/__proto__", parsed)).toBe("own");
  });

  it("does not read an array's length or a non-index step", () => {
    const document = { anyOf: [{ title: "first" }] };
    expect(titleOf("#/anyOf/0", document)).toBe("first");
    const schema = { $ref: "#/anyOf/length" };
    expect(resolveRef(schema, document)).toBe(schema);
    const leading = { $ref: "#/anyOf/00" };
    expect(resolveRef(leading, document)).toBe(leading);
  });

  it("does not return a value that is not a schema object", () => {
    const schema = { $ref: "#/note" };
    expect(resolveRef(schema, { note: "text" })).toBe(schema);
  });

  it("follows a chain of references to the schema at the end", () => {
    const document = {
      $defs: {
        B: { $ref: "#/$defs/C" },
        C: { type: "integer" },
      },
    };
    expect(resolveRef({ $ref: "#/$defs/B" }, document).type).toBe("integer");
  });

  it("terminates on a reference to itself and on a two-step cycle", () => {
    const self = { $defs: { A: { $ref: "#/$defs/A" } } };
    expect(resolveRef({ $ref: "#/$defs/A" }, self)).toEqual({
      $ref: "#/$defs/A",
    });
    const loop = {
      $defs: { A: { $ref: "#/$defs/B" }, B: { $ref: "#/$defs/A" } },
    };
    const resolved = resolveRef({ $ref: "#/$defs/A" }, loop);
    expect(typeof resolved.$ref).toBe("string");
  });

  it("keeps the description a $ref sits beside", () => {
    const document = { $defs: { A: { type: "string", title: "A" } } };
    const resolved = resolveRef(
      { $ref: "#/$defs/A", description: "Outer words" },
      document,
    );
    expect(resolved.type).toBe("string");
    expect(resolved.description).toBe("Outer words");
  });
});

describe("resolveToolPropertySchema on real pydantic output", () => {
  it("reads Optional[str] as a nullable string and keeps the outer metadata", () => {
    const resolved = resolveToolPropertySchema(properties.query, root);
    expect(resolved).toMatchObject({
      type: "string",
      nullable: true,
      description: "Search text",
      title: "Query",
      default: null,
    });
  });

  it("reads Optional[int] and Optional[list[str]]", () => {
    expect(getToolPropertyType(properties.page, root)).toBe("integer");
    expect(resolveToolPropertySchema(properties.page, root).nullable).toBe(
      true,
    );
    const tags = resolveToolPropertySchema(properties.tags, root);
    expect(tags.type).toBe("array");
    expect(tags.nullable).toBe(true);
  });

  it("resolves a $ref inside an optional to the object schema", () => {
    const filt = resolveToolPropertySchema(properties.filt, root);
    expect(filt.type).toBe("object");
    expect(filt.nullable).toBe(true);
    expect(filt.description).toBe("Optional filter");
    expect(filt.default).toBeNull();
  });

  it("leaves a plain default alone", () => {
    const resolved = resolveToolPropertySchema(properties.include_closed, root);
    expect(resolved).toMatchObject({ type: "boolean", default: false });
    expect(resolved.nullable).toBeUndefined();
  });

  it("reads the pruned variant the same way", () => {
    const pruned = prunedRoot.properties as Record<
      string,
      Record<string, unknown>
    >;
    expect(resolveToolPropertySchema(pruned.query, prunedRoot)).toMatchObject({
      type: "string",
      nullable: true,
    });
    expect(resolveToolPropertySchema(pruned.filt, prunedRoot).type).toBe(
      "object",
    );
  });

  it("reads oneOf with a null branch", () => {
    const resolved = resolveToolPropertySchema(
      {
        oneOf: [{ type: "string" }, { type: "null" }],
        description: "One of",
      },
      {},
    );
    expect(resolved).toMatchObject({
      type: "string",
      nullable: true,
      description: "One of",
    });
  });

  it("reads the older allOf-with-one-$ref shape next to a description", () => {
    const resolved = resolveToolPropertySchema(
      { allOf: [{ $ref: "#/$defs/Filt" }], description: "A filter" },
      root,
    );
    expect(resolved.type).toBe("object");
    expect(resolved.description).toBe("A filter");
  });

  it("reads a type array that includes null", () => {
    expect(getToolPropertyType({ type: ["integer", "null"] }, {})).toBe(
      "integer",
    );
    expect(getToolPropertyType({ type: ["null"] }, {})).toBeUndefined();
  });

  it("does not guess between non-null types in a type array", () => {
    for (const type of [
      ["string", "integer"],
      ["null", "integer", "string"],
    ]) {
      expect(getToolPropertyType({ type }, {})).toBeUndefined();
      expect(
        getToolPropertyType({ anyOf: [{ type }, { type: "string" }] }, {}),
      ).toBeUndefined();
    }
  });

  it("keeps nullability from a type array inside a same-type union", () => {
    expect(
      resolveToolPropertySchema(
        {
          anyOf: [
            { type: ["string", "null"] },
            { type: "string", format: "date" },
          ],
        },
        {},
      ),
    ).toMatchObject({ type: "string", nullable: true });
  });

  it("does not guess between two different non-null types", () => {
    const resolved = resolveToolPropertySchema(
      { anyOf: [{ type: "string" }, { type: "integer" }, { type: "null" }] },
      {},
    );
    expect(resolved.ambiguousUnion).toBe(true);
    expect(resolved.type).toBeUndefined();
    expect(resolved.nullable).toBe(true);
    expect(
      getToolPropertyType(
        { anyOf: [{ type: "string" }, { type: "integer" }] },
        {},
      ),
    ).toBeUndefined();
  });

  it("treats a missing or non-object schema as an empty schema", () => {
    expect(getToolPropertyType(undefined, {})).toBeUndefined();
    expect(getToolPropertyType("nope", {})).toBeUndefined();
    expect(getToolPropertyType(true, {})).toBeUndefined();
  });
});

describe("extractEnumOptions", () => {
  it("returns labelled options for string, number and boolean enums", () => {
    expect(extractEnumOptions({ enum: ["open", "closed"] })).toEqual([
      { label: "open", value: "open" },
      { label: "closed", value: "closed" },
    ]);
    expect(extractEnumOptions({ enum: [1, 2.5] })).toEqual([
      { label: "1", value: 1 },
      { label: "2.5", value: 2.5 },
    ]);
    expect(extractEnumOptions({ enum: [true, false] })).toEqual([
      { label: "true", value: true },
      { label: "false", value: false },
    ]);
  });

  it("treats const as a one-option enum", () => {
    expect(extractEnumOptions({ const: "fixed" })).toEqual([
      { label: "fixed", value: "fixed" },
    ]);
  });

  it("refuses an enum it cannot show as a list", () => {
    expect(extractEnumOptions({ enum: ["a", null] })).toBeNull();
    expect(extractEnumOptions({ enum: ["a", { b: 1 }] })).toBeNull();
    expect(extractEnumOptions({ enum: [] })).toBeNull();
    expect(extractEnumOptions({ type: "string" })).toBeNull();
    expect(extractEnumOptions(undefined)).toBeNull();
    const many = Array.from({ length: 201 }, (_, i) => `v${i}`);
    expect(extractEnumOptions({ enum: many })).toBeNull();
    expect(extractEnumOptions({ enum: many.slice(0, 200) })).toHaveLength(200);
  });
});

// ECMAScript Number() semantics decide these; they are pinned because the
// form's number handling is built on them.
describe("coercion", () => {
  it.each([
    ["  7 ", 7],
    ["1e3", 1000],
    ["-0.5", -0.5],
    ["abc", "abc"],
    ["Infinity", "Infinity"],
    ["", ""],
    ["   ", "   "],
  ])("coerces the text %j for a number", (text, expected) => {
    expect(coerceTextInputValueByType(text, "number")).toBe(expected);
    expect(coerceTextInputValueByType(text, "integer")).toBe(expected);
  });

  it.each([
    ["true", true],
    ["yes", true],
    ["on", true],
    ["1", true],
    ["false", false],
    ["no", false],
    ["off", false],
    ["0", false],
    ["maybe", "maybe"],
  ])("coerces the text %j for a boolean", (text, expected) => {
    expect(coerceTextInputValueByType(text, "boolean")).toBe(expected);
    expect(coerceExecutionArgByType(text, "boolean")).toBe(expected);
  });

  it("leaves other types as typed", () => {
    expect(coerceTextInputValueByType("12", "string")).toBe("12");
    expect(coerceTextInputValueByType("12", undefined)).toBe("12");
    expect(coerceExecutionArgByType(undefined, "number")).toBeUndefined();
    expect(coerceExecutionArgByType('{"a":1}', "object")).toEqual({ a: 1 });
    expect(coerceExecutionArgByType("{broken", "object")).toBe("{broken");
    expect(coerceExecutionArgByType(" 4 ", "integer")).toBe(4);
  });
});

describe("parseObjectFromPaste", () => {
  it("parses a JSON object", () => {
    expect(parseObjectFromPaste('  {"a": 1, "b": [2]} ')).toEqual({
      a: 1,
      b: [2],
    });
  });

  it("refuses arrays, scalars, empty input and garbage", () => {
    expect(parseObjectFromPaste("[1, 2]")).toBeNull();
    expect(parseObjectFromPaste("5")).toBeNull();
    expect(parseObjectFromPaste("")).toBeNull();
    expect(parseObjectFromPaste("{not json")).toBeNull();
    expect(parseObjectFromPaste(undefined as unknown as string)).toBeNull();
  });

  it("accepts the backtick strings a JavaScript object literal uses", () => {
    expect(parseObjectFromPaste('{"a": `say "hi"`}')).toEqual({
      a: 'say "hi"',
    });
  });

  it("does not pollute Object.prototype through a __proto__ key", () => {
    const parsed = parseObjectFromPaste('{"__proto__": {"polluted": "yes"}}');
    expect(parsed).not.toBeNull();
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.keys(parsed as object)).toEqual(["__proto__"]);
  });
});
