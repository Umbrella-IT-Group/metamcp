import { describe, expect, it } from "vitest";

import { findUnsafeNumber, isUnsafeNumberText } from "./json-numbers";

// The oracle is ECMAScript Number.MAX_SAFE_INTEGER (2^53 - 1), which is
// 9007199254740991: every integer up to it is exactly a double, and the next
// one up (9007199254740992) is also what 9007199254740993 rounds to. The
// literals below are written out, not computed, so a wrong constant in the
// code cannot agree with itself.
describe("findUnsafeNumber", () => {
  it("accepts the safe boundary in both directions and ordinary numbers", () => {
    expect(findUnsafeNumber('{"a": 9007199254740991}')).toBeNull();
    expect(findUnsafeNumber('{"a": -9007199254740991}')).toBeNull();
    expect(findUnsafeNumber("9007199254740991")).toBeNull();
    expect(findUnsafeNumber("[0, -0, 1, -1, 42, 1000000]")).toBeNull();
    expect(findUnsafeNumber("[9007199254740991.0, 9.007199254740991e15]")).toBe(
      null,
    );
  });

  it("is not triggered by fractions or small exponents", () => {
    expect(
      findUnsafeNumber("[1.5, 0.1, -2.5e3, 1e5, 1E+2, 1.25e-7]"),
    ).toBeNull();
    expect(findUnsafeNumber("[0e5, 0.0, 0e-400, -0.000]")).toBeNull();
  });

  it.each([
    ["9007199254740992", "9007199254740992"],
    ["-9007199254740992", "-9007199254740992"],
    ["9007199254740993", "9007199254740993"],
    ["18014398509481984", "18014398509481984"],
    ["123456789012345678901234567890", "123456789012345678901234567890"],
    ["1e400", "1e400"],
    ["-1e400", "-1e400"],
    ["1E+400", "1E+400"],
    ["9.007199254740993e15", "9.007199254740993e15"],
    ["90071992547409930e-1", "90071992547409930e-1"],
    ["1e16", "1e16"],
    ["1e21", "1e21"],
    ["1.5e300", "1.5e300"],
    ["1e-400", "1e-400"],
  ])("refuses %s", (text, token) => {
    expect(findUnsafeNumber(text)).toBe(token);
    expect(findUnsafeNumber(`{"a": ${text}}`)).toBe(token);
    expect(findUnsafeNumber(`[1, [2, {"deep": [${text}]}]]`)).toBe(token);
  });

  it("reports the first unsafe number in the text", () => {
    expect(findUnsafeNumber("[1, 9007199254740993, 1e400]")).toBe(
      "9007199254740993",
    );
  });

  it.each([
    "9007199254740990.5",
    "9007199254740991.1",
    "-9007199254740990.5",
    "1.0000000000000001",
    "0.10000000000000001",
    "1234567890123456.7",
    "9.0071992547409905e15",
    "4e-324",
  ])("refuses a decimal that serializes to a different value: %s", (text) => {
    expect(isUnsafeNumberText(text)).toBe(true);
    expect(findUnsafeNumber(`{"n":${text}}`)).toBe(text);
  });

  it.each([
    "1.2300",
    "12300e-4",
    "1.0000000000000000",
    "0.10000000000000000",
    "1.2345678901234567",
    "0.30000000000000004",
    "4503599627370495.5",
    "5e-324",
    "50e-325",
    "2.2250738585072014e-308",
    "9007199254740991000e-3",
  ])("accepts equivalent decimal spellings: %s", (text) => {
    expect(isUnsafeNumberText(text)).toBe(false);
    expect(findUnsafeNumber(`{"n":${text}}`)).toBeNull();
  });

  it("retains significant digits after long zero runs", () => {
    const zeros = "0".repeat(20000);
    expect(isUnsafeNumberText(`0.1${zeros}`)).toBe(false);
    expect(isUnsafeNumberText(`0.1${zeros}1`)).toBe(true);
    expect(isUnsafeNumberText(`0.1${zeros}10`)).toBe(true);
  });

  it("ignores numbers inside strings, keys included", () => {
    expect(findUnsafeNumber('{"a": "9007199254740993"}')).toBeNull();
    expect(findUnsafeNumber('"9007199254740993"')).toBeNull();
    expect(findUnsafeNumber('{"9007199254740993": 1}')).toBeNull();
    expect(findUnsafeNumber('{"a": "1e400", "b": "-1e999"}')).toBeNull();
    expect(
      findUnsafeNumber('{"a": "she said \\"9007199254740993\\" twice"}'),
    ).toBeNull();
  });

  it("finds a number that follows a string ending in an escaped backslash", () => {
    // The JSON text is ["a\\", 9007199254740993]: the string is a, backslash,
    // and the quote after the two backslashes closes it.
    expect(findUnsafeNumber('["a\\\\", 9007199254740993]')).toBe(
      "9007199254740993",
    );
    expect(findUnsafeNumber('{"a":"x","b":9007199254740993}')).toBe(
      "9007199254740993",
    );
  });

  it("does not read digits of true, false or null, and never throws", () => {
    expect(findUnsafeNumber("[true, false, null]")).toBeNull();
    expect(findUnsafeNumber("")).toBeNull();
    expect(findUnsafeNumber("-")).toBeNull();
    expect(() => findUnsafeNumber('{"a": "unterminated')).not.toThrow();
    expect(() => findUnsafeNumber("{{{ ]]] -- 1e")).not.toThrow();
  });
});

describe("isUnsafeNumberText", () => {
  it.each([
    "9007199254740992",
    " 9007199254740993 ",
    "-9007199254740993",
    "+9007199254740993",
    "1e400",
    "-1e400",
    ".5e400",
    "9.007199254740993e15",
    "1e16",
    "1e-400",
    "5e-400",
    "0x20000000000000",
    "0X20000000000001",
    "0b100000000000000000000000000000000000000000000000000000",
    "0o1000000000000000000000",
  ])("refuses %j", (text) => {
    expect(isUnsafeNumberText(text)).toBe(true);
  });

  it.each([
    "9007199254740991",
    "-9007199254740991",
    "+9007199254740991",
    "9007199254740991.0",
    "50",
    "1.5",
    "0.1",
    ".5",
    "5.",
    "1e3",
    "0",
    "-0",
    "0e999",
    "0.000",
    "0x1FFFFFFFFFFFFF",
    "0b11111111111111111111111111111111111111111111111111111",
  ])("accepts %j", (text) => {
    expect(isUnsafeNumberText(text)).toBe(false);
  });

  it.each([
    "",
    "   ",
    "abc",
    "Infinity",
    "-Infinity",
    "NaN",
    "1,5",
    "12abc",
    "0x",
    "0b12",
    '"9007199254740993"',
  ])("leaves text that is not a number to the caller: %j", (text) => {
    expect(isUnsafeNumberText(text)).toBe(false);
  });
});
