import { afterEach, describe, expect, it } from "vitest";

import {
  argsShapeEnabled,
  buildArgsShape,
  KEY_MAX_LEN,
  MAX_KEYS,
  SELECTOR_KEYS,
  SELECTOR_VALUE_MAX,
} from "./audit-args-shape";

describe("buildArgsShape: what is stored", () => {
  it("records key names and the mode selector, and nothing else about the values", () => {
    const shape = buildArgsShape({
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
    const shape = buildArgsShape({
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
    const shape = buildArgsShape({
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
    const shape = buildArgsShape({ mode: value });
    expect(shape.sel).toEqual({ mode: "?" });
    // The offending value is never echoed.
    expect(JSON.stringify(shape)).not.toContain("client.example");
    expect(JSON.stringify(shape)).not.toContain("has space");
  });

  it.each(["note_add", "task_note_add", "GET", "v1.2:beta", "a-b"])(
    "stores %s verbatim",
    (value) => {
      expect(buildArgsShape({ mode: value }).sel).toEqual({ mode: value });
    },
  );

  it("accepts a selector value of exactly the maximum length", () => {
    const value = `a${"b".repeat(SELECTOR_VALUE_MAX - 1)}`;
    expect(value).toHaveLength(SELECTOR_VALUE_MAX);
    expect(buildArgsShape({ action: value }).sel).toEqual({ action: value });
  });

  it("omits a selector that is absent and records one that is present", () => {
    expect(buildArgsShape({ mode: "list" }).sel).toEqual({ mode: "list" });
    expect(buildArgsShape({ other: 1 }).sel).toBeUndefined();
  });

  it("ignores a selector that exists only on the prototype", () => {
    const args = Object.create({ mode: "inherited" }) as Record<
      string,
      unknown
    >;
    args.other = 1;
    // Object.create({...}) has a non-Object prototype, so it is not a plain
    // object at all; the point is that nothing inherited is ever read.
    const shape = buildArgsShape(args);
    expect(JSON.stringify(shape)).not.toContain("inherited");
  });
});

describe("buildArgsShape: key hygiene", () => {
  it("counts keys that are not identifier-shaped and never echoes them", () => {
    const shape = buildArgsShape({
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
    const shape = buildArgsShape({ [ok]: 1, [tooLong]: 2 });
    expect(shape.keys).toEqual([ok]);
    expect(shape.invalid_keys).toBe(1);
  });

  it("handles an own __proto__ key from JSON.parse without touching the prototype", () => {
    const args = JSON.parse('{"__proto__": {"polluted": true}, "mode": "x1"}');
    const shape = buildArgsShape(args);

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
    const shape = buildArgsShape(args);

    expect(shape.keys).toHaveLength(MAX_KEYS);
    expect(shape.truncated).toBe(true);
    // Sorted first, then cut: the first 32 in UTF-16 order.
    expect(shape.keys[0]).toBe("key_00");
    expect(shape.keys[MAX_KEYS - 1]).toBe("key_31");
  });

  it("sorts deterministically regardless of insertion order", () => {
    const a = buildArgsShape({ b: 1, a: 2, C: 3 });
    const b = buildArgsShape({ C: 3, a: 2, b: 1 });
    expect(a.keys).toEqual(["C", "a", "b"]);
    expect(b).toEqual(a);
  });

  it("does not list nested key names", () => {
    const shape = buildArgsShape({ note: { description: "d", title: "t" } });
    expect(shape.keys).toEqual(["note"]);
    expect(JSON.stringify(shape)).not.toContain("description");
  });
});

describe("buildArgsShape: input kinds", () => {
  it("treats undefined and null as no arguments", () => {
    expect(buildArgsShape(undefined)).toEqual({ keys: [] });
    expect(buildArgsShape(null)).toEqual({ keys: [] });
  });

  it("flags a non-object argument value", () => {
    expect(buildArgsShape([])).toEqual({ keys: [], non_object: true });
    expect(buildArgsShape("x")).toEqual({ keys: [], non_object: true });
    expect(buildArgsShape(5)).toEqual({ keys: [], non_object: true });
    expect(buildArgsShape(true)).toEqual({ keys: [], non_object: true });
  });

  it("an empty object is an empty key list, not a flagged input", () => {
    expect(buildArgsShape({})).toEqual({ keys: [] });
  });

  it("stays small: the worst case is bounded", () => {
    const args: Record<string, unknown> = {};
    for (let i = 0; i < 200; i += 1) args[`k${i}`] = i;
    for (const selector of SELECTOR_KEYS) args[selector] = "v".repeat(40);
    const size = JSON.stringify(buildArgsShape(args)).length;
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
