/**
 * Finds the numbers the Inspector cannot send exactly.
 *
 * Why this exists: a tool call carries its arguments as JSON, and every
 * browser reads a JSON number as an IEEE 754 double. A whole number past
 * Number.MAX_SAFE_INTEGER (ECMAScript, 2^53 - 1, which is 9007199254740991)
 * is no longer one-to-one with the digits that were typed: 9007199254740993
 * and 9007199254740992 are the same double, so a record id, a ticket number
 * or a device id typed or pasted into the form would reach the tool as a
 * different number, with nothing on screen saying so. On a tool that changes
 * a client's record that is the wrong record. So the form refuses, and the
 * person decides: the tool may take the value as a string.
 *
 * A number is refused when its value, as the browser would read it, is
 *   - a whole number whose magnitude is above Number.MAX_SAFE_INTEGER, in
 *     any spelling that gets there: 9007199254740993, 9.007199254740993e15,
 *     90071992547409930e-1, 1e16;
 *   - not finite: 1e400 reads as Infinity, which JSON cannot carry (and
 *     JSON.stringify would turn into null);
 *   - zero although the digits are not: 1e-400 reads as 0.
 * Fractions that fit (1.5, 0.1) are unaffected. A fraction such as 0.1 is not
 * exact in binary either, but it is the same number to every reader, which is
 * not true of a whole number past the boundary.
 *
 * The scan reads the raw text, never a parsed value, because the parse is
 * what loses the digits. Numbers inside string literals are text, not
 * numbers, and are skipped. JSON.parse's reviver can see the source text of a
 * number in newer engines only, and browsers differ, so this is a small
 * tokenizer instead.
 */

// What Number() reads as a decimal literal: an optional sign, digits with an
// optional point (5. and .5 are accepted), and an optional exponent. Every
// JSON number is one; "Infinity", "NaN" and words are not.
const DECIMAL_LITERAL =
  /^[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$/;

// Number() also reads unsigned hex, octal and binary integers (0x1F). Each
// pattern checks its own digits, so the value can be read without a parse
// that may fail.
const RADIX_LITERAL = /^0(?:[xX][0-9a-fA-F]+|[oO][0-7]+|[bB][01]+)$/;

// The number grammar of RFC 8259 section 6 (no leading plus, no leading zero,
// digits on both sides of a point, a signed exponent). Sticky, so a match
// starts exactly at lastIndex.
const JSON_NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

/**
 * True when `text`, read the way a number field reads typed text (Number()),
 * is a number that cannot be sent exactly. Text that is not a number at all
 * ("abc", "Infinity", "") is false: the caller already has a path for it.
 */
export function isUnsafeNumberText(text: string): boolean {
  const literal = text.trim();
  if (RADIX_LITERAL.test(literal)) {
    // Number() rounds to the nearest double, which is monotonic, so a value
    // above 2^53 - 1 reads above it and a value at or below it is exact.
    return Number(literal) > Number.MAX_SAFE_INTEGER;
  }
  if (!DECIMAL_LITERAL.test(literal)) return false;

  const value = Number(literal);
  if (!Number.isFinite(value) || Math.abs(value) > Number.MAX_SAFE_INTEGER) {
    return true;
  }
  // Underflow: the digits name a number that is not zero, the double is.
  const mantissa = literal.split(/[eE]/, 1)[0] ?? "";
  return value === 0 && /[1-9]/.test(mantissa);
}

// The index just after the string literal that starts at `start` (an opening
// quote). A backslash takes the next character with it, so \" does not close
// the string and \\ does not escape the closing quote. An unterminated string
// runs to the end of the text.
function endOfString(text: string, start: number): number {
  let index = start + 1;
  while (index < text.length) {
    const char = text.charAt(index);
    if (char === "\\") {
      index += 2;
    } else if (char === '"') {
      return index + 1;
    } else {
      index += 1;
    }
  }
  return text.length;
}

/**
 * The first number in `jsonText`, outside string literals, that cannot be
 * sent exactly, as it was written; null when there is none. Meant for text
 * that already parses as JSON, and total on any other text (it never throws).
 */
export function findUnsafeNumber(jsonText: string): string | null {
  let index = 0;
  while (index < jsonText.length) {
    const char = jsonText.charAt(index);
    if (char === '"') {
      index = endOfString(jsonText, index);
      continue;
    }
    if (char === "-" || (char >= "0" && char <= "9")) {
      JSON_NUMBER.lastIndex = index;
      const match = JSON_NUMBER.exec(jsonText);
      if (match) {
        if (isUnsafeNumberText(match[0])) return match[0];
        index += match[0].length;
        continue;
      }
    }
    index += 1;
  }
  return null;
}
