import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { ToolArgSchema } from "../tool-arg-keys";
import {
  MAX_ENUM_VALUES,
  MAX_SCHEMA_KEYS,
  MAX_TOOLS,
  schemaFromInputSchema,
  ToolArgSchemaRegistry,
} from "../tool-arg-keys";
import {
  argsShapeEnabled,
  buildArgsShape,
  KEY_MAX_LEN,
  MAX_KEYS,
  SELECTOR_KEYS,
  SELECTOR_UNENUMERATED_MARKER,
  SELECTOR_VALUE_MAX,
} from "./audit-args-shape";

// The syntax rules below are exercised with a schema that declares every key the
// call sends, so only the key and value policies decide. The schema allowlist
// itself is tested at the end of the file.
function allowAll(args: unknown): ToolArgSchema | undefined {
  if (args === null || typeof args !== "object" || Array.isArray(args))
    return undefined;
  // Each selector the call sends is declared as an enum holding the value sent
  // (an empty enum for a non-string), so membership passes and the length and
  // character rules alone decide. Values are stored only from a closed set.
  const enums = new Map<string, ReadonlySet<string>>();
  for (const key of SELECTOR_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(args, key)) continue;
    const v = (args as Record<string, unknown>)[key];
    enums.set(key, new Set(typeof v === "string" ? [v] : []));
  }
  return { keys: new Set(Object.keys(args)), enums };
}
const shapeAllowAll = (args: unknown) => buildArgsShape(args, allowAll(args));

describe("buildArgsShape: what is stored", () => {
  it("records key names and the mode selector, and nothing else about the values", () => {
    const shape = shapeAllowAll({
      mode: "note_add",
      ticket: 123,
      note: { description: "secret text" },
      author: "x",
    });

    expect(shape).toEqual({
      sel: { mode: "note_add" },
      keys: ["author", "mode", "note", "ticket"],
    });
    const serialized = JSON.stringify(shape);
    expect(serialized).not.toContain("secret text");
    expect(serialized).not.toContain("123");
    // "x" is the value of `author`; it must not appear as a value anywhere.
    expect(serialized).not.toContain('"x"');
  });

  it("records every allowlisted selector together", () => {
    const shape = shapeAllowAll({
      mode: "create",
      profile: "alert",
      action: "run_script",
      operation: "listSites",
      entity: "resources",
      method: "POST",
    });

    expect(shape.sel).toEqual({
      mode: "create",
      profile: "alert",
      action: "run_script",
      operation: "listSites",
      entity: "resources",
      method: "POST",
    });
    expect(shape.keys).toEqual([
      "action",
      "entity",
      "method",
      "mode",
      "operation",
      "profile",
    ]);
  });

  it("allowlist is exactly the six reviewed selector keys", () => {
    // Widening this list is a privacy decision (selector VALUES are the only
    // argument values ever stored), so it is pinned and must be edited on
    // purpose.
    expect([...SELECTOR_KEYS]).toEqual([
      "mode",
      "action",
      "profile",
      "operation",
      "entity",
      "method",
    ]);
  });

  it("never records a value for a key that is not an allowlisted selector", () => {
    const shape = shapeAllowAll({
      query: "printer",
      company: "Example Co",
      ticket_id: 4242,
    });
    expect(shape.sel).toBeUndefined();
    expect(JSON.stringify(shape)).not.toMatch(/printer|Example Co|4242/);
  });
});

describe("buildArgsShape: selector value policy", () => {
  const misuse = [
    ["a 33 character string", "a".repeat(SELECTOR_VALUE_MAX + 1)],
    ["an empty string", ""],
    ["a number", 5],
    ["a boolean", true],
    ["an object", { x: 1 }],
    ["an array", ["a"]],
    ["an email address", "john.smith@client.example"],
    ["a string with a space", "has space"],
    ["a string with a leading digit", "1leading"],
    ["a path", "/users/me"],
    ["null", null],
  ] as const;

  it.each(misuse)("stores the misuse marker for %s", (_label, value) => {
    const shape = shapeAllowAll({ mode: value });
    expect(shape.sel).toEqual({ mode: "?" });
    // The offending value is never echoed.
    expect(JSON.stringify(shape)).not.toContain("client.example");
    expect(JSON.stringify(shape)).not.toContain("has space");
  });

  it.each(["note_add", "task_note_add", "GET", "v1.2:beta", "a-b"])(
    "stores %s verbatim",
    (value) => {
      expect(shapeAllowAll({ mode: value }).sel).toEqual({ mode: value });
    },
  );

  it("accepts a selector value of exactly the maximum length", () => {
    const value = `a${"b".repeat(SELECTOR_VALUE_MAX - 1)}`;
    expect(value).toHaveLength(SELECTOR_VALUE_MAX);
    expect(shapeAllowAll({ action: value }).sel).toEqual({ action: value });
  });

  it("omits a selector that is absent and records one that is present", () => {
    expect(shapeAllowAll({ mode: "list" }).sel).toEqual({ mode: "list" });
    expect(shapeAllowAll({ other: 1 }).sel).toBeUndefined();
  });

  it("ignores a selector that exists only on the prototype", () => {
    const args = Object.create({ mode: "inherited" }) as Record<
      string,
      unknown
    >;
    args.other = 1;
    // Object.create({...}) has a non-Object prototype, so it is not a plain
    // object at all; the point is that nothing inherited is ever read.
    const shape = shapeAllowAll(args);
    expect(JSON.stringify(shape)).not.toContain("inherited");
  });
});

describe("buildArgsShape: key hygiene", () => {
  it("counts keys that are not identifier-shaped and never echoes them", () => {
    const shape = shapeAllowAll({
      "bad key": 1,
      "a@b": 2,
      [`x${"y".repeat(KEY_MAX_LEN)}`]: 3,
      "": 4,
      good: 5,
    });

    expect(shape.keys).toEqual(["good"]);
    expect(shape.invalid_keys).toBe(4);
    const serialized = JSON.stringify(shape);
    expect(serialized).not.toContain("bad key");
    expect(serialized).not.toContain("a@b");
    expect(serialized).not.toContain("yyyy");
  });

  it("accepts a key of exactly the maximum length and rejects one more", () => {
    const ok = `k${"z".repeat(KEY_MAX_LEN - 1)}`;
    const tooLong = `${ok}z`;
    expect(ok).toHaveLength(KEY_MAX_LEN);
    const shape = shapeAllowAll({ [ok]: 1, [tooLong]: 2 });
    expect(shape.keys).toEqual([ok]);
    expect(shape.invalid_keys).toBe(1);
  });

  it("handles an own __proto__ key from JSON.parse without touching the prototype", () => {
    const args = JSON.parse('{"__proto__": {"polluted": true}, "mode": "x1"}');
    const shape = shapeAllowAll(args);

    expect(shape.keys).toEqual(["__proto__", "mode"]);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.getPrototypeOf(shape)).toBe(Object.prototype);
    expect(JSON.stringify(shape)).not.toContain("polluted");
  });

  it("truncates beyond the maximum and says so", () => {
    const args: Record<string, unknown> = {};
    for (let i = 0; i < 40; i += 1) {
      args[`key_${String(i).padStart(2, "0")}`] = i;
    }
    const shape = shapeAllowAll(args);

    expect(shape.keys).toHaveLength(MAX_KEYS);
    expect(shape.truncated).toBe(true);
    // Sorted first, then cut: the first 32 in UTF-16 order.
    expect(shape.keys[0]).toBe("key_00");
    expect(shape.keys[MAX_KEYS - 1]).toBe("key_31");
  });

  it("sorts deterministically regardless of insertion order", () => {
    const a = shapeAllowAll({ b: 1, a: 2, C: 3 });
    const b = shapeAllowAll({ C: 3, a: 2, b: 1 });
    expect(a.keys).toEqual(["C", "a", "b"]);
    expect(b).toEqual(a);
  });

  it("does not list nested key names", () => {
    const shape = shapeAllowAll({ note: { description: "d", title: "t" } });
    expect(shape.keys).toEqual(["note"]);
    expect(JSON.stringify(shape)).not.toContain("description");
  });
});

describe("buildArgsShape: input kinds", () => {
  it("treats undefined and null as no arguments", () => {
    expect(shapeAllowAll(undefined)).toEqual({ keys: [] });
    expect(shapeAllowAll(null)).toEqual({ keys: [] });
  });

  it("flags a non-object argument value", () => {
    expect(shapeAllowAll([])).toEqual({ keys: [], non_object: true });
    expect(shapeAllowAll("x")).toEqual({ keys: [], non_object: true });
    expect(shapeAllowAll(5)).toEqual({ keys: [], non_object: true });
    expect(shapeAllowAll(true)).toEqual({ keys: [], non_object: true });
  });

  it("an empty object is an empty key list, not a flagged input", () => {
    expect(shapeAllowAll({})).toEqual({ keys: [] });
  });

  it("stays small: the worst case is bounded", () => {
    const args: Record<string, unknown> = {};
    for (let i = 0; i < 200; i += 1) args[`k${i}`] = i;
    for (const selector of SELECTOR_KEYS) args[selector] = "v".repeat(40);
    const size = JSON.stringify(shapeAllowAll(args)).length;
    // Design budget is about 1.7 KB in the worst case.
    expect(size).toBeLessThan(2048);
  });
});

describe("argsShapeEnabled: kill switch", () => {
  const saved = process.env.TOOL_AUDIT_ARGS_SHAPE;

  afterEach(() => {
    if (saved === undefined) {
      delete process.env.TOOL_AUDIT_ARGS_SHAPE;
    } else {
      process.env.TOOL_AUDIT_ARGS_SHAPE = saved;
    }
  });

  it("is on by default", () => {
    delete process.env.TOOL_AUDIT_ARGS_SHAPE;
    expect(argsShapeEnabled()).toBe(true);
    process.env.TOOL_AUDIT_ARGS_SHAPE = "";
    expect(argsShapeEnabled()).toBe(true);
    process.env.TOOL_AUDIT_ARGS_SHAPE = "on";
    expect(argsShapeEnabled()).toBe(true);
  });

  it.each(["off", "OFF", " false ", "0", "False"])("is off for %j", (value) => {
    process.env.TOOL_AUDIT_ARGS_SHAPE = value;
    expect(argsShapeEnabled()).toBe(false);
  });
});

describe("buildArgsShape: the tool schema decides which names are stored (Sol review 2026-10-02)", () => {
  const schema = (props: Record<string, unknown>) =>
    schemaFromInputSchema({
      type: "object",
      properties: props,
    }) as ToolArgSchema;

  it("a caller-chosen key the schema does not declare is counted, never stored", () => {
    const shape = buildArgsShape(
      { mode: "list", ticket: 1, Alice_Smith: 1, client_secret_SAMPLE: "x" },
      schema({ mode: { enum: ["list"] }, ticket: {} }),
    );
    expect(shape).toEqual({
      keys: ["mode", "ticket"],
      sel: { mode: "list" },
      unknown_keys: 2,
    });
    expect(JSON.stringify(shape)).not.toMatch(/Alice|secret/);
  });

  it("an unknown tool stores counts only: no names, no selector values", () => {
    const shape = buildArgsShape({ mode: "list", Alice_Smith: 1 }, undefined);
    expect(shape).toEqual({ keys: [], unverified_keys: 2 });
  });

  it("an enum selector stores only a declared value; anything else is the marker", () => {
    const s = schema({ mode: { type: "string", enum: ["list", "get"] } });
    expect(buildArgsShape({ mode: "get" }, s).sel).toEqual({ mode: "get" });
    expect(buildArgsShape({ mode: "Alice_Smith" }, s).sel).toEqual({
      mode: "?",
    });
  });

  it("an enum on an anyOf branch (FastMCP Literal | None) is read too", () => {
    const s = schema({
      mode: { anyOf: [{ type: "string", enum: ["a", "b"] }, { type: "null" }] },
    });
    expect(buildArgsShape({ mode: "b" }, s).sel).toEqual({ mode: "b" });
    expect(buildArgsShape({ mode: "zzz" }, s).sel).toEqual({ mode: "?" });
  });

  it.each([
    "a".repeat(SELECTOR_VALUE_MAX + 1),
    "person@client.example",
    "has space",
  ])(
    "an enum member still obeys the selector size and character limits: %s",
    (value) => {
      const s = schema({ mode: { enum: [value] } });
      expect(buildArgsShape({ mode: value }, s).sel).toEqual({ mode: "?" });
    },
  );

  it.each([
    { values: [] },
    { values: [1, 2] },
    { values: [null] },
    { values: [false] },
  ])(
    "an enum without string members cannot allow a caller-chosen string: $values",
    ({ values }) => {
      const s = schema({ mode: { enum: values } });
      expect(buildArgsShape({ mode: "Alice_Smith" }, s).sel).toEqual({
        mode: "?",
      });
    },
  );

  it("a constant selector stores only its declared identifier", () => {
    const s = schema({ mode: { const: "list" } });
    expect(buildArgsShape({ mode: "list" }, s).sel).toEqual({ mode: "list" });
    expect(buildArgsShape({ mode: "get" }, s).sel).toEqual({ mode: "?" });
  });

  it.each([
    { const: "list" },
    { $ref: "#/$defs/Mode" },
    { oneOf: [{ enum: ["list"] }, { type: "null" }] },
    { allOf: [{ enum: ["list"] }] },
    { anyOf: [{ anyOf: [{ enum: ["list"] }] }, { type: "null" }] },
  ])(
    "a composed or referenced selector never falls back to an arbitrary identifier: %j",
    (def) => {
      const s = schema({ mode: def });
      expect(buildArgsShape({ mode: "Alice_Smith" }, s).sel).toEqual({
        mode: "?",
      });
    },
  );

  it("a selector the schema does not declare is just an unknown key", () => {
    const shape = buildArgsShape({ action: "run", q: 1 }, schema({ q: {} }));
    expect(shape).toEqual({ keys: ["q"], unknown_keys: 1 });
  });
});

describe("tool-arg-keys: a routing instance's schema snapshot", () => {
  let registry: ToolArgSchemaRegistry;
  beforeEach(() => {
    registry = new ToolArgSchemaRegistry();
  });

  it("records and looks up by the exposed name", () => {
    registry.record("autotask__search", {
      type: "object",
      properties: { query: {}, mode: { enum: ["recency"] } },
    });
    const s = registry.get("autotask__search");
    expect(s && [...s.keys].sort()).toEqual(["mode", "query"]);
    expect(s?.enums.get("mode")).toEqual(new Set(["recency"]));
    expect(registry.get("autotask__other")).toBeUndefined();
  });

  it("a schema with no properties object leaves the tool unknown, and clears a stale entry", () => {
    registry.record("x__t", { type: "object", properties: { a: {} } });
    registry.record("x__t", { type: "object" });
    expect(registry.get("x__t")).toBeUndefined();
  });

  it("never throws on hostile input and stays bounded", () => {
    expect(() => registry.record("x__t", null)).not.toThrow();
    expect(() => registry.record("x__t", "nope")).not.toThrow();
    for (let i = 0; i < MAX_TOOLS + 10; i++) {
      registry.record(`s__t${i}`, { properties: { a: {} } });
    }
    expect(registry.get("s__t0")).toBeUndefined();
    expect(registry.get(`s__t${MAX_TOOLS + 9}`)).toBeDefined();
  });

  it("different routing instances cannot teach each other a key or enum", () => {
    const other = new ToolArgSchemaRegistry();
    registry.record("shared__search", {
      properties: { ticket: {}, mode: { enum: ["get"] } },
    });
    other.record("shared__search", {
      properties: { Alice_Smith: {}, mode: { enum: ["Alice_Smith"] } },
    });
    expect(
      buildArgsShape(
        { Alice_Smith: 1, mode: "Alice_Smith" },
        registry.get("shared__search"),
      ),
    ).toEqual({ keys: ["mode"], sel: { mode: "?" }, unknown_keys: 1 });
  });

  it("a replacement snapshot clears renamed and removed tools", () => {
    registry.record("s__old", { properties: { mode: {} } });
    registry.replace([
      { name: "s__new", inputSchema: { properties: { query: {} } } },
    ]);
    expect(
      buildArgsShape({ mode: "Alice_Smith" }, registry.get("s__old")),
    ).toEqual({ keys: [], unverified_keys: 1 });
    expect(registry.get("s__new")?.keys).toEqual(new Set(["query"]));
    registry.replace([]);
    expect(registry.get("s__new")).toBeUndefined();
  });

  it("duplicate final exposed names are unknown, including a third duplicate", () => {
    registry.replace(
      ["a", "b", "c"].map((key) => ({
        name: "s__alias",
        inputSchema: { properties: { [key]: {} } },
      })),
    );
    expect(registry.get("s__alias")).toBeUndefined();
  });

  it("additionalProperties never declares caller-chosen names", () => {
    registry.record("s__t", {
      properties: { query: {} },
      additionalProperties: true,
    });
    expect(
      buildArgsShape({ query: "x", Alice_Smith: 1 }, registry.get("s__t")),
    ).toEqual({ keys: ["query"], unknown_keys: 1 });
  });

  it("a faulting schema clears a stale entry without throwing", () => {
    registry.record("s__t", { properties: { mode: {} } });
    expect(() =>
      registry.record("s__t", {
        get properties() {
          throw new Error("fault");
        },
      }),
    ).not.toThrow();
    expect(registry.get("s__t")).toBeUndefined();
  });

  it("a faulting snapshot becomes entirely unknown without throwing", () => {
    registry.record("s__old", { properties: { mode: {} } });
    expect(() =>
      registry.replace([
        {
          name: "s__new",
          get inputSchema() {
            throw new Error("fault");
          },
        },
      ]),
    ).not.toThrow();
    expect(registry.get("s__old")).toBeUndefined();
    expect(registry.get("s__new")).toBeUndefined();
  });

  it("oversized property and enum collections cannot grow retained data", () => {
    registry.record("s__t", {
      properties: Object.fromEntries(
        Array.from({ length: MAX_SCHEMA_KEYS + 1 }, (_, i) => [`key${i}`, {}]),
      ),
    });
    expect(registry.get("s__t")).toBeUndefined();
    registry.record("s__t", {
      properties: {
        mode: {
          enum: Array.from(
            { length: MAX_ENUM_VALUES + 1 },
            (_, i) => `mode${i}`,
          ),
        },
      },
    });
    expect(buildArgsShape({ mode: "mode0" }, registry.get("s__t")).sel).toEqual(
      { mode: "?" },
    );
  });
});

describe("buildArgsShape: a selector with no enum stores only that it was sent (Sol review, second pass)", () => {
  it("a plain-string mode stores the marker, never the caller's value", () => {
    const schema = { keys: new Set(["mode", "q"]), enums: new Map() };
    const shape = buildArgsShape(
      { mode: "client_secret_SAMPLE", q: 1 },
      schema,
    );
    expect(shape.sel).toEqual({ mode: SELECTOR_UNENUMERATED_MARKER });
    expect(JSON.stringify(shape)).not.toMatch(/secret/);
  });

  it("an enum member is stored; a non-member is the misuse marker", () => {
    const schema = {
      keys: new Set(["mode"]),
      enums: new Map([["mode", new Set(["list"])]]),
    };
    expect(buildArgsShape({ mode: "list" }, schema).sel).toEqual({
      mode: "list",
    });
    expect(buildArgsShape({ mode: "lst" }, schema).sel).toEqual({ mode: "?" });
  });
});
