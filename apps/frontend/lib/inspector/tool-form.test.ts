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

  it("sends an integer beyond the safe range as typed text, with a warning", () => {
    const built = build("i", "9007199254740993");
    expect(built.args).toEqual({ i: "9007199254740993" });
    expect(built.warnings).toEqual([{ key: "i", reason: "unsafeInteger" }]);
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

describe("payloadText", () => {
  it("is the exact JSON the call sends", () => {
    const specs = describeFields(fixture.tool);
    const { args } = buildArguments(specs, initialFormState(specs));
    expect(payloadText(args)).toBe(JSON.stringify(args, null, 2));
    expect(payloadText(args)).toBe('{\n  "include_closed": false\n}');
    expect(payloadText({})).toBe("{}");
  });
});
