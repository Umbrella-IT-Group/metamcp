import { describe, expect, it } from "vitest";

import fixture from "./fixtures/optional-parameters-tool.json";
import { parseObjectFromPaste } from "./schema-utils";
import {
  applyPastedObject,
  buildArguments,
  describeFields,
  type FieldSpec,
  type FormState,
  initialFormState,
  payloadText,
  selectedEnumIndex,
  setBoolean,
  setEmptyString,
  setEnumIndex,
  setNull,
  setText,
} from "./tool-form";

type Properties = Record<string, unknown>;

// Builds the form for a small synthetic input schema. `required` is the
// schema's own required array.
function formFor(properties: Properties, required: string[] = []) {
  const specs = describeFields({
    inputSchema: { type: "object", properties, required },
  });
  return { specs, state: initialFormState(specs) };
}

const specOf = (specs: FieldSpec[], key: string): FieldSpec => {
  const found = specs.find((spec) => spec.key === key);
  if (!found) throw new Error(`no spec for ${key}`);
  return found;
};

const typeInto = (
  specs: FieldSpec[],
  state: FormState,
  key: string,
  text: string,
) => setText(state, specOf(specs, key), text);

describe("describeFields", () => {
  it("reads kinds, nullability and metadata from real pydantic output", () => {
    const specs = describeFields(fixture.tool);
    expect(specs.map((spec) => [spec.key, spec.kind, spec.nullable])).toEqual([
      ["query", "text", true],
      ["include_closed", "boolean", false],
      ["page", "integer", true],
      ["filt", "json", true],
      ["tags", "json", true],
    ]);
    const query = specOf(specs, "query");
    expect(query.description).toBe("Search text");
    expect(query.title).toBe("Query");
    expect(specs.every((spec) => !spec.required)).toBe(true);
  });

  it("reads the pruned variant the same way", () => {
    const specs = describeFields(fixture.prunedVariant);
    expect(specs.map((spec) => [spec.key, spec.kind, spec.nullable])).toEqual(
      describeFields(fixture.tool).map((spec) => [
        spec.key,
        spec.kind,
        spec.nullable,
      ]),
    );
  });

  it("does not treat a null default as a default", () => {
    const specs = describeFields(fixture.tool);
    expect(specOf(specs, "query").defaultValue).toBeUndefined();
    expect(specOf(specs, "filt").defaultValue).toBeUndefined();
    expect(specOf(specs, "include_closed").defaultValue).toBe(false);
  });

  it("maps every schema shape to a control kind", () => {
    const { specs } = formFor(
      {
        s: { type: "string" },
        n: { type: "number" },
        i: { type: "integer" },
        b: { type: "boolean" },
        e: { enum: ["a", "b"] },
        c: { const: "fixed" },
        o: { type: "object" },
        a: { type: "array", items: { type: "string" } },
        amb: { anyOf: [{ type: "string" }, { type: "integer" }] },
        unknown: {},
        eOpt: {
          anyOf: [
            { enum: ["open", "closed"], type: "string" },
            { type: "null" },
          ],
        },
        intNull: { type: ["integer", "null"] },
      },
      ["s", "i"],
    );
    expect(specs.map((spec) => [spec.key, spec.kind, spec.required])).toEqual([
      ["s", "text", true],
      ["n", "number", false],
      ["i", "integer", true],
      ["b", "boolean", false],
      ["e", "enum", false],
      ["c", "enum", false],
      ["o", "json", false],
      ["a", "json", false],
      ["amb", "json", false],
      ["unknown", "json", false],
      ["eOpt", "enum", false],
      ["intNull", "integer", false],
    ]);
    expect(specOf(specs, "eOpt").nullable).toBe(true);
    expect(specOf(specs, "intNull").nullable).toBe(true);
    expect(specOf(specs, "e").enumOptions?.map((o) => o.value)).toEqual([
      "a",
      "b",
    ]);
  });

  it("lists the schema's own constraints as hint text", () => {
    const { specs } = formFor({
      d: {
        type: "string",
        format: "date",
        minLength: 2,
        maxLength: 5,
        pattern: "^a",
      },
      n: { type: "number", minimum: 1, maximum: 9 },
    });
    expect(specOf(specs, "d").constraints).toEqual([
      "format: date",
      "minLength: 2",
      "maxLength: 5",
      "pattern: ^a",
    ]);
    expect(specOf(specs, "n").constraints).toEqual([
      "minimum: 1",
      "maximum: 9",
    ]);
  });

  it("lets a type-array union send each permitted JSON type", () => {
    const { specs, state } = formFor({
      choice: { type: ["string", "integer", "null"] },
    });
    expect(specOf(specs, "choice")).toMatchObject({
      kind: "json",
      nullable: true,
    });
    expect(
      buildArguments(specs, typeInto(specs, state, "choice", "42")).args,
    ).toEqual({ choice: 42 });
    expect(
      buildArguments(specs, typeInto(specs, state, "choice", '"42"')).args,
    ).toEqual({ choice: "42" });
    expect(buildArguments(specs, setNull(state, "choice", true)).args).toEqual({
      choice: null,
    });
  });

  it("returns no fields for a schema without properties", () => {
    expect(describeFields({ inputSchema: { type: "object" } })).toEqual([]);
    expect(describeFields({})).toEqual([]);
    expect(describeFields({ inputSchema: "nope" })).toEqual([]);
  });
});

// JSON Schema 2020-12 section 9.2: "default" is an annotation. A client may
// prefill it, and a null default says the parameter is optional, so it is
// not a value to send.
describe("what the form starts with", () => {
  it("starts only the non-null default as set, for the pydantic fixture", () => {
    const specs = describeFields(fixture.tool);
    const state = initialFormState(specs);
    expect(Object.fromEntries(state)).toEqual({
      query: { mode: "unset" },
      include_closed: { mode: "value", text: "false" },
      page: { mode: "unset" },
      filt: { mode: "unset" },
      tags: { mode: "unset" },
    });
    const built = buildArguments(specs, state);
    expect(built.args).toEqual({ include_closed: false });
    expect(built.sentKeys).toEqual(["include_closed"]);
    expect(built.missingRequired).toEqual([]);
    expect(built.errors).toEqual([]);
  });

  it("sends the same for the pruned variant", () => {
    const specs = describeFields(fixture.prunedVariant);
    expect(buildArguments(specs, initialFormState(specs)).args).toEqual({
      include_closed: false,
    });
  });

  it("prefills a non-null default of every kind and skips an empty-string default", () => {
    const { specs, state } = formFor({
      limit: { type: "integer", default: 25 },
      ratio: { type: "number", default: 0.5 },
      mode: { type: "string", default: "fast" },
      label: { type: "string", default: "" },
      flag: { type: "boolean", default: true },
      tags: { type: "array", default: ["a"] },
      kind: { enum: ["x", "y"], default: "y" },
      stray: { enum: ["x", "y"], default: "zzz" },
    });
    expect(buildArguments(specs, state).args).toEqual({
      limit: 25,
      ratio: 0.5,
      mode: "fast",
      flag: true,
      tags: ["a"],
      kind: "y",
    });
  });

  it("does not turn an unset boolean into false", () => {
    const { specs, state } = formFor({ b: { type: "boolean" } });
    expect(buildArguments(specs, state).args).toEqual({});
    expect(buildArguments(specs, setBoolean(state, "b", "false")).args).toEqual(
      { b: false },
    );
    expect(buildArguments(specs, setBoolean(state, "b", "true")).args).toEqual({
      b: true,
    });
    expect(
      buildArguments(
        specs,
        setBoolean(setBoolean(state, "b", "true"), "b", null),
      ).args,
    ).toEqual({});
  });
});

describe("buildArguments: strings", () => {
  const { specs, state } = formFor({ s: { type: "string" } });

  it("sends the exact text, including text that is only spaces", () => {
    expect(
      buildArguments(specs, typeInto(specs, state, "s", "abc")).args,
    ).toEqual({ s: "abc" });
    expect(
      buildArguments(specs, typeInto(specs, state, "s", "  ")).args,
    ).toEqual({ s: "  " });
  });

  it("treats exactly empty text as not set", () => {
    const typed = typeInto(specs, state, "s", "abc");
    expect(buildArguments(specs, typeInto(specs, typed, "s", "")).args).toEqual(
      {},
    );
  });

  it("sends an empty string only when asked to", () => {
    expect(
      buildArguments(specs, setEmptyString(state, "s", true)).args,
    ).toEqual({ s: "" });
    const off = setEmptyString(setEmptyString(state, "s", true), "s", false);
    expect(buildArguments(specs, off).args).toEqual({});
  });

  it("sends null only when asked to", () => {
    expect(buildArguments(specs, setNull(state, "s", true)).args).toEqual({
      s: null,
    });
    const off = setNull(setNull(state, "s", true), "s", false);
    expect(buildArguments(specs, off).args).toEqual({});
  });

  it("moves from null to a typed value", () => {
    const next = typeInto(specs, setNull(state, "s", true), "s", "x");
    expect(buildArguments(specs, next).args).toEqual({ s: "x" });
  });
});

// ECMAScript Number() and Number.isSafeInteger decide what a typed number is.
describe("buildArguments: numbers", () => {
  const { specs, state } = formFor({
    n: { type: "number" },
    i: { type: "integer" },
  });
  const build = (key: string, text: string) =>
    buildArguments(specs, typeInto(specs, state, key, text));

  it("sends a typed integer as a number", () => {
    expect(build("i", "50").args).toEqual({ i: 50 });
    expect(build("i", " 7 ").args).toEqual({ i: 7 });
    expect(build("i", "1e3").args).toEqual({ i: 1000 });
    expect(build("i", "50").warnings).toEqual([]);
  });

  it("sends a fraction for an integer field, with a warning", () => {
    const built = build("i", "1.5");
    expect(built.args).toEqual({ i: 1.5 });
    expect(built.warnings).toEqual([{ key: "i", reason: "notInteger" }]);
  });

  // SPEC edit (the foreman's decision that no silently changed number is sent):
  // a typed integer beyond Number.MAX_SAFE_INTEGER (9007199254740991) used to
  // go out as its typed digits in a string, with a warning; it now blocks the
  // call with a field error, because a string is not what a number field
  // asked for and the person decides whether to quote it.
  it("refuses an integer beyond the safe range and sends the boundary", () => {
    const built = build("i", "9007199254740993");
    expect(built.args).toEqual({});
    expect(built.errors).toEqual([{ key: "i", reason: "unsafeNumber" }]);
    expect(built.warnings).toEqual([]);
    expect(build("i", "9007199254740991").args).toEqual({
      i: 9007199254740991,
    });
  });

  it("sends text that is not a number as typed text, with a warning", () => {
    for (const key of ["n", "i"]) {
      const built = build(key, "abc");
      expect(built.args).toEqual({ [key]: "abc" });
      expect(built.warnings).toEqual([{ key, reason: "notNumber" }]);
    }
    expect(build("n", "Infinity").args).toEqual({ n: "Infinity" });
  });

  it("sends a float for a number field and nothing for blank text", () => {
    expect(build("n", "2.5").args).toEqual({ n: 2.5 });
    expect(build("n", "  ").args).toEqual({});
    expect(build("n", "").args).toEqual({});
  });
});

describe("buildArguments: arrays, objects, enums", () => {
  it("parses JSON fields and reports only the field that is not valid JSON", () => {
    const { specs, state } = formFor({
      list: { type: "array" },
      obj: { type: "object" },
      broken: { type: "object" },
      fine: { type: "string" },
    });
    let next = typeInto(specs, state, "list", "[1, 2]");
    next = typeInto(specs, next, "obj", '{"a": {"b": null}}');
    next = typeInto(specs, next, "broken", "{nope");
    next = typeInto(specs, next, "fine", "ok");
    const built = buildArguments(specs, next);
    expect(built.args).toEqual({
      list: [1, 2],
      obj: { a: { b: null } },
      fine: "ok",
    });
    expect(built.errors).toEqual([{ key: "broken", reason: "invalidJson" }]);
    expect(built.sentKeys).toEqual(["list", "obj", "fine"]);
  });

  it("sends the typed value of the chosen enum option", () => {
    const { specs, state } = formFor({
      word: { enum: ["a", "b"] },
      num: { enum: [10, 20] },
      flag: { enum: [true, false] },
    });
    let next = setEnumIndex(state, specOf(specs, "word"), 1);
    next = setEnumIndex(next, specOf(specs, "num"), 0);
    next = setEnumIndex(next, specOf(specs, "flag"), 1);
    expect(buildArguments(specs, next).args).toEqual({
      word: "b",
      num: 10,
      flag: false,
    });
    expect(selectedEnumIndex(specOf(specs, "word"), next.get("word"))).toBe(1);
    const cleared = setEnumIndex(next, specOf(specs, "word"), null);
    expect(buildArguments(specs, cleared).args).not.toHaveProperty("word");
    expect(selectedEnumIndex(specOf(specs, "word"), cleared.get("word"))).toBe(
      null,
    );
  });

  it("ignores an enum index that points at no option", () => {
    const { specs, state } = formFor({ word: { enum: ["a", "b"] } });
    const next = setEnumIndex(state, specOf(specs, "word"), 5);
    expect(buildArguments(specs, next).args).toEqual({});
  });
});

describe("buildArguments: required fields", () => {
  it("lists required fields that are unset and still builds the rest", () => {
    const { specs, state } = formFor(
      { q: { type: "string" }, r: { type: "string" }, o: { type: "string" } },
      ["q", "r"],
    );
    const next = typeInto(specs, state, "r", "here");
    const built = buildArguments(specs, next);
    expect(built.missingRequired).toEqual(["q"]);
    expect(built.args).toEqual({ r: "here" });
    expect(built.errors).toEqual([]);
  });

  it("counts an explicit null as set", () => {
    const { specs, state } = formFor({ q: { type: "string" } }, ["q"]);
    expect(
      buildArguments(specs, setNull(state, "q", true)).missingRequired,
    ).toEqual([]);
  });
});

// ECMAScript Object.fromEntries uses CreateDataProperty, so a key named
// __proto__ becomes an ordinary own property instead of being swallowed by
// the prototype setter.
describe("a parameter named __proto__", () => {
  it("is sent as an own property and does not change the argument prototype", () => {
    const properties = JSON.parse(
      '{"__proto__": {"type": "string"}, "ok": {"type": "string"}}',
    ) as Properties;
    const { specs, state } = formFor(properties);
    const next = typeInto(specs, state, "__proto__", "value");
    const { args } = buildArguments(specs, next);
    expect(Object.keys(args)).toEqual(["__proto__"]);
    expect(Object.getPrototypeOf(args)).toBe(Object.prototype);
    expect(JSON.parse(payloadText(args))).toEqual(
      JSON.parse('{"__proto__": "value"}'),
    );
  });
});

describe("applyPastedObject", () => {
  const properties: Properties = {
    s: { type: "string" },
    n: { type: "integer" },
    b: { type: "boolean" },
    e: { enum: ["x", "y"] },
    j: { type: "object" },
    ns: { anyOf: [{ type: "string" }, { type: "null" }] },
    keep: { type: "string", default: "kept" },
  };

  it("fills known fields by kind, reports unknown keys and leaves the rest", () => {
    const { specs, state } = formFor(properties);
    const result = applyPastedObject(specs, state, {
      s: 5,
      n: 7,
      b: true,
      e: "y",
      j: { a: [1] },
      ns: null,
      zzz: 1,
    });
    expect(result.filled).toEqual(["s", "n", "b", "e", "j", "ns"]);
    expect(result.ignored).toEqual(["zzz"]);
    expect(buildArguments(specs, result.state).args).toEqual({
      s: "5",
      n: 7,
      b: true,
      e: "y",
      j: { a: [1] },
      ns: null,
      keep: "kept",
    });
  });

  it("does not change the state it was given", () => {
    const { specs, state } = formFor(properties);
    const before = JSON.stringify([...state]);
    applyPastedObject(specs, state, { s: "changed" });
    expect(JSON.stringify([...state])).toBe(before);
  });

  it("keeps an enum value that matches no option, so the server answers", () => {
    const { specs, state } = formFor(properties);
    const result = applyPastedObject(specs, state, { e: "zzz" });
    expect(buildArguments(specs, result.state).args.e).toBe("zzz");
    expect(
      selectedEnumIndex(specOf(specs, "e"), result.state.get("e")),
    ).toBeNull();
  });

  it("keeps a string for a text field and stringifies other values", () => {
    const { specs, state } = formFor(properties);
    const result = applyPastedObject(specs, state, { s: { nested: true } });
    expect(buildArguments(specs, result.state).args.s).toBe('{"nested":true}');
  });

  it("sends a pasted value that does not fit a boolean field as typed text", () => {
    const { specs, state } = formFor(properties);
    const result = applyPastedObject(specs, state, { b: "yes" });
    const built = buildArguments(specs, result.state);
    expect(built.args.b).toBe("yes");
    expect(built.warnings).toEqual([{ key: "b", reason: "notBoolean" }]);
  });

  it("treats a pasted __proto__ key as an unknown key", () => {
    const { specs, state } = formFor(properties);
    const pasted = parseObjectFromPaste('{"__proto__": {"x": 1}, "s": "a"}');
    expect(pasted).not.toBeNull();
    const result = applyPastedObject(specs, state, pasted ?? {});
    expect(result.ignored).toEqual(["__proto__"]);
    expect(result.filled).toEqual(["s"]);
    expect(({} as Record<string, unknown>).x).toBeUndefined();
  });
});

// Number.MAX_SAFE_INTEGER (ECMAScript) is 9007199254740991. A JSON number past
// it cannot be sent exactly, so the form refuses it instead of sending a
// rounded one: 9007199254740993 would go out as 9007199254740992.
describe("numbers that cannot be sent exactly", () => {
  const UNSAFE_TEXT = [
    "9007199254740992",
    "9007199254740993",
    "-9007199254740992",
    "-9007199254740993",
    "9.007199254740993e15",
    "90071992547409930e-1",
    "1e16",
    "1e400",
    "-1e400",
    "0x20000000000001",
    "9007199254740990.5",
    "9007199254740991.1",
    "1.0000000000000001",
    "0.10000000000000001",
    "1234567890123456.7",
    "4e-324",
  ];

  describe("in number and integer fields", () => {
    const { specs, state } = formFor({
      n: { type: "number" },
      i: { type: "integer" },
      s: { type: "string" },
    });

    it.each(UNSAFE_TEXT)("refuses %s as a field error", (text) => {
      for (const key of ["n", "i"]) {
        const built = buildArguments(specs, typeInto(specs, state, key, text));
        expect(built.errors).toEqual([{ key, reason: "unsafeNumber" }]);
        expect(built.args).toEqual({});
        expect(built.sentKeys).toEqual([]);
        expect(built.warnings).toEqual([]);
      }
    });

    it("sends the safe boundary in both directions and ordinary floats", () => {
      for (const key of ["n", "i"]) {
        expect(
          buildArguments(specs, typeInto(specs, state, key, "9007199254740991"))
            .args,
        ).toEqual({ [key]: 9007199254740991 });
        expect(
          buildArguments(
            specs,
            typeInto(specs, state, key, "-9007199254740991"),
          ).args,
        ).toEqual({ [key]: -9007199254740991 });
      }
      for (const text of [
        "1.5",
        "0.1",
        "2.5e3",
        "1.2300",
        "0.30000000000000004",
        "4503599627370495.5",
        "5e-324",
      ]) {
        const built = buildArguments(specs, typeInto(specs, state, "n", text));
        expect(built.args).toEqual({ n: Number(text) });
        expect(built.errors).toEqual([]);
      }
    });

    it("blocks only the field it names and still builds the others", () => {
      let next = typeInto(specs, state, "s", "kept");
      next = typeInto(specs, next, "i", "9007199254740993");
      const built = buildArguments(specs, next);
      expect(built.errors).toEqual([{ key: "i", reason: "unsafeNumber" }]);
      expect(built.args).toEqual({ s: "kept" });
    });

    it("still tells text that is not a number from a number that is too big", () => {
      const built = buildArguments(specs, typeInto(specs, state, "n", "abc"));
      expect(built.errors).toEqual([]);
      expect(built.warnings).toEqual([{ key: "n", reason: "notNumber" }]);
    });
  });

  describe("in JSON and enum fields", () => {
    const { specs, state } = formFor({
      j: { type: "object" },
      list: { type: "array" },
      e: { enum: ["a", "b"] },
    });

    it("refuses an unsafe number anywhere in the JSON", () => {
      const texts = [
        '{"id": 9007199254740993}',
        '{"a": {"b": [1, [9007199254740992]]}}',
        '{"id": 1e400}',
        '{"id": -9007199254740993}',
        '{"id": 9.007199254740993e15}',
        '{"id": 9007199254740990.5}',
        '{"id": 1.0000000000000001}',
        '{"id": 0.10000000000000001}',
      ];
      for (const text of texts) {
        const built = buildArguments(specs, typeInto(specs, state, "j", text));
        expect(built.errors).toEqual([{ key: "j", reason: "unsafeNumber" }]);
        expect(built.args).toEqual({});
      }
      const array = buildArguments(
        specs,
        typeInto(specs, state, "list", "[1, 9007199254740993]"),
      );
      expect(array.errors).toEqual([{ key: "list", reason: "unsafeNumber" }]);
    });

    it("refuses an unsafe number typed into an enum field's custom value", () => {
      const built = buildArguments(
        specs,
        typeInto(specs, state, "e", "9007199254740993"),
      );
      expect(built.errors).toEqual([{ key: "e", reason: "unsafeNumber" }]);
      expect(built.args).toEqual({});
    });

    it("refuses a decimal rounded within the safe range in an enum field", () => {
      const built = buildArguments(
        specs,
        typeInto(specs, state, "e", "9007199254740990.5"),
      );
      expect(built.errors).toEqual([{ key: "e", reason: "unsafeNumber" }]);
      expect(built.args).toEqual({});
    });

    it("sends exact numbers, and numbers inside strings untouched", () => {
      const text =
        '{"id": 9007199254740991, "low": -9007199254740991, "f": 1.5, "g": 0.1, "s": "9007199254740993", "k": "1e400"}';
      const built = buildArguments(specs, typeInto(specs, state, "j", text));
      expect(built.errors).toEqual([]);
      expect(built.args).toEqual({
        j: {
          id: 9007199254740991,
          low: -9007199254740991,
          f: 1.5,
          g: 0.1,
          s: "9007199254740993",
          k: "1e400",
        },
      });
    });

    it("keeps reporting text that is not JSON as invalid JSON", () => {
      const built = buildArguments(
        specs,
        typeInto(specs, state, "j", '{"id": 9007199254740993'),
      );
      expect(built.errors).toEqual([{ key: "j", reason: "invalidJson" }]);
    });
  });

  describe("after a paste", () => {
    const { specs, state } = formFor({
      i: { type: "integer" },
      j: { type: "object" },
      s: { type: "string" },
    });

    it("sends pasted numbers on the safe boundary exactly", () => {
      const pasted = parseObjectFromPaste(
        '{"i": 9007199254740991, "j": {"a": [-9007199254740991, 1.5]}}',
      );
      expect(pasted).not.toBeNull();
      const result = applyPastedObject(specs, state, pasted ?? {});
      const built = buildArguments(specs, result.state);
      expect(built.errors).toEqual([]);
      expect(built.args).toEqual({
        i: 9007199254740991,
        j: { a: [-9007199254740991, 1.5] },
      });
      expect(payloadText(built.args)).toContain("9007199254740991");
    });

    it("refuses a value that was already rounded before it got here", () => {
      // 2 ** 53 is what 9007199254740992 and 9007199254740993 both parse to.
      const result = applyPastedObject(specs, state, {
        i: 2 ** 53,
        j: { a: [2 ** 53] },
      });
      const built = buildArguments(specs, result.state);
      expect(built.errors).toEqual([
        { key: "i", reason: "unsafeNumber" },
        { key: "j", reason: "unsafeNumber" },
      ]);
      expect(built.args).toEqual({});
    });
  });
});

describe("payloadText", () => {
  it("is the exact JSON the call sends", () => {
    const specs = describeFields(fixture.tool);
    const { args } = buildArguments(specs, initialFormState(specs));
    expect(payloadText(args)).toBe(JSON.stringify(args, null, 2));
    expect(payloadText(args)).toBe('{\n  "include_closed": false\n}');
    expect(payloadText({})).toBe("{}");
  });
});
