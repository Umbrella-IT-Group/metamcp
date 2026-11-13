/**
 * JSON Schema helpers for the Inspector's tool form.
 *
 * Adapted from mcp-use, libraries/typescript/packages/inspector/
 * src/client/components/tools/schema-utils.ts at commit 546081e
 * (https://github.com/mcp-use/mcp-use), which is distributed under the MIT
 * License below.
 *
 * MIT License
 *
 * Copyright (c) 2025 pietrozullo
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Changes from the original:
 *   - Every `any` is a typed record, so lint is clean.
 *   - `$ref` is a JSON Pointer in a URI fragment (RFC 6901 sections 4 and 6):
 *     the fragment is percent-decoded once, then split on "/", then each step
 *     has ~1 and ~0 unescaped. A malformed escape leaves the reference
 *     unresolved instead of throwing. Own properties only (the original
 *     followed the prototype chain), and a chain of references is followed up
 *     to a fixed number of hops, so a cycle ends.
 *   - Optionals are read from `anyOf`, `oneOf` and a one-element `allOf`. The
 *     outer description, title, default, examples and deprecated flag are kept
 *     (pydantic puts them on the outer schema), and a union of two different
 *     non-null types is reported as ambiguous instead of picking the first.
 *   - `extractEnumOptions` lists string, number and boolean enums and `const`.
 *   - `parsePastedObject` refuses a paste holding a number that cannot be
 *     sent exactly (past Number.MAX_SAFE_INTEGER, nonfinite, or a decimal
 *     whose value changes during JSON serialization), because JSON.parse
 *     rounds it before any field sees it. It also says why a paste failed;
 *     `parseObjectFromPaste` keeps its null.
 */

import { findUnsafeNumber } from "./json-numbers";

export type JsonSchema = Record<string, unknown>;

// Enough for any real chain ($ref -> $ref -> schema); a cycle stops here.
const MAX_REF_HOPS = 16;
// A union nested inside a union is read this deep and no further.
const MAX_UNION_DEPTH = 4;
const MAX_ENUM_OPTIONS = 200;

// The annotations pydantic and other generators put on the OUTER schema of an
// optional or referenced property, next to anyOf or $ref.
const OUTER_METADATA_KEYS = [
  "description",
  "title",
  "default",
  "examples",
  "deprecated",
] as const;

const hasOwn = (target: object, key: string) =>
  Object.prototype.hasOwnProperty.call(target, key);

const isRecord = (value: unknown): value is JsonSchema =>
  typeof value === "object" && value !== null && !Array.isArray(value);

// RFC 6901 section 4: an array index is "0" or a digit string with no leading
// zero.
const ARRAY_INDEX = /^(?:0|[1-9][0-9]*)$/;

function overlayMetadata(inner: JsonSchema, outer: JsonSchema): JsonSchema {
  const merged: JsonSchema = { ...inner };
  for (const key of OUTER_METADATA_KEYS) {
    if (hasOwn(outer, key)) merged[key] = outer[key];
  }
  return merged;
}

/**
 * Evaluates a "#/..." reference against the root schema. Returns null when the
 * reference is external, malformed, or points at nothing that is a schema
 * object.
 *
 * RFC 6901 section 6: a pointer in a URI fragment is percent-encoded UTF-8, so
 * the fragment is decoded first, as a whole, and only then is the pointer
 * split on "/". Splitting first would read %2F as part of a name instead of as
 * a separator. A literal "/" inside a name is written ~1 and a literal "~" is
 * written ~0 (section 3); section 4 unescapes ~1 first and then ~0, so "~01"
 * is the two characters "~1".
 */
function evaluatePointer(
  ref: string,
  rootSchema: JsonSchema,
): JsonSchema | null {
  // External references are never fetched or followed.
  if (!ref.startsWith("#")) return null;

  let pointer: string;
  try {
    pointer = decodeURIComponent(ref.slice(1));
  } catch {
    return null;
  }
  // "" is the whole document, which is never a useful reference target here;
  // anything else must start with "/" (RFC 6901 section 3).
  if (!pointer.startsWith("/")) return null;

  const steps = pointer.slice(1).split("/");
  let current: unknown = rootSchema;
  for (const step of steps) {
    // "~" must be followed by 0 or 1 (RFC 6901 section 3).
    if (/~(?![01])/.test(step)) return null;
    const name = step.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(current)) {
      if (!ARRAY_INDEX.test(name)) return null;
      const index = Number(name);
      if (index >= current.length) return null;
      current = current[index];
    } else if (isRecord(current) && hasOwn(current, name)) {
      current = current[name];
    } else {
      return null;
    }
  }
  return isRecord(current) ? current : null;
}

/**
 * Follows `$ref` (a chain of them, up to MAX_REF_HOPS) to the schema at the
 * end. An unresolvable reference, an external one, and a cycle all leave the
 * schema as it is, never an error. A reference that sits beside a description
 * or default keeps that outer metadata.
 */
export function resolveRef(
  schema: JsonSchema,
  rootSchema: JsonSchema,
): JsonSchema {
  let current = schema;
  for (let hop = 0; hop < MAX_REF_HOPS; hop += 1) {
    if (!isRecord(current) || typeof current.$ref !== "string") return current;
    const target = evaluatePointer(current.$ref, rootSchema);
    if (!target) return current;
    current = overlayMetadata(target, current);
  }
  return current;
}

function isNullSchema(schema: JsonSchema): boolean {
  const type = schema.type;
  if (type === "null") return true;
  return Array.isArray(type) && type.length === 1 && type[0] === "null";
}

/** The schema's single non-null type, or undefined for an ambiguous type array. */
export function firstNonNullType(schema: JsonSchema): string | undefined {
  const type = schema.type;
  if (typeof type === "string") return type;
  if (Array.isArray(type)) {
    // A type array is a union too. Picking its first member would prevent the
    // JSON field from carrying the other permitted types.
    const types = [...new Set(type.filter((entry) => entry !== "null"))];
    return types.length === 1 && typeof types[0] === "string"
      ? types[0]
      : undefined;
  }
  return undefined;
}

// The options of an optional or union: anyOf, oneOf, or an allOf of exactly one
// (older pydantic wrote allOf: [{$ref}] to attach a description to a $ref).
function unionOptions(schema: JsonSchema): unknown[] | null {
  if (Array.isArray(schema.anyOf)) return schema.anyOf;
  if (Array.isArray(schema.oneOf)) return schema.oneOf;
  if (Array.isArray(schema.allOf) && schema.allOf.length === 1) {
    return schema.allOf;
  }
  return null;
}

function normalizeUnionType(
  schema: JsonSchema,
  rootSchema: JsonSchema,
  depth: number,
): JsonSchema {
  const options = unionOptions(schema);
  if (!options) return schema;

  let sawNull = false;
  const nonNull: JsonSchema[] = [];
  for (const option of options) {
    const resolved = resolveRef(isRecord(option) ? option : {}, rootSchema);
    if (isNullSchema(resolved)) {
      sawNull = true;
      continue;
    }
    nonNull.push(
      depth < MAX_UNION_DEPTH
        ? normalizeUnionType(resolved, rootSchema, depth + 1)
        : resolved,
    );
  }

  // Only null options: nothing to read a type from.
  if (nonNull.length === 0) return schema;

  if (nonNull.length === 1) {
    const inner = nonNull[0] as JsonSchema;
    return overlayMetadata(
      {
        ...inner,
        nullable:
          sawNull ||
          inner.nullable === true ||
          (Array.isArray(inner.type) && inner.type.includes("null")),
      },
      schema,
    );
  }

  // Two or more non-null options. When they all name one type, that type is
  // still a fair control (two string formats are still a text box); otherwise
  // guessing the first would send the wrong kind of value.
  const types = new Set(
    nonNull.map((option) =>
      option.ambiguousUnion === true ? undefined : firstNonNullType(option),
    ),
  );
  const only = types.size === 1 ? [...types][0] : undefined;
  const merged: JsonSchema =
    only !== undefined ? { type: only } : { ambiguousUnion: true };
  merged.nullable =
    sawNull ||
    nonNull.some(
      (option) =>
        option.nullable === true ||
        (Array.isArray(option.type) && option.type.includes("null")),
    );
  return overlayMetadata(merged, schema);
}

export function resolveToolPropertySchema(
  propertySchema: unknown,
  rootSchema: JsonSchema,
): JsonSchema {
  const start = isRecord(propertySchema) ? propertySchema : {};
  let resolved = resolveRef(start, rootSchema);
  resolved = normalizeUnionType(resolved, rootSchema, 0);
  return resolveRef(resolved, rootSchema);
}

export function getToolPropertyType(
  propertySchema: unknown,
  rootSchema: JsonSchema,
): string | undefined {
  return firstNonNullType(
    resolveToolPropertySchema(propertySchema, rootSchema),
  );
}

/**
 * The choices of an enum or const whose members are all strings, numbers or
 * booleans, as labelled options. Null when the schema has no such list, a
 * member is anything else (a null or an object cannot be a menu item), or the
 * list is too long to be a menu.
 */
export function extractEnumOptions(
  propertySchema: unknown,
): { label: string; value: unknown }[] | null {
  if (!isRecord(propertySchema)) return null;
  const members = Array.isArray(propertySchema.enum)
    ? propertySchema.enum
    : hasOwn(propertySchema, "const")
      ? [propertySchema.const]
      : null;
  if (!members || members.length === 0 || members.length > MAX_ENUM_OPTIONS) {
    return null;
  }
  const primitive = members.every(
    (member) =>
      typeof member === "string" ||
      typeof member === "number" ||
      typeof member === "boolean",
  );
  if (!primitive) return null;
  return members.map((member) => ({ label: String(member), value: member }));
}

export function extractEnumValues(propertySchema: unknown): string[] | null {
  const enumValues = isRecord(propertySchema) ? propertySchema.enum : undefined;
  if (!Array.isArray(enumValues)) return null;
  if (enumValues.every((value) => typeof value === "string")) {
    return enumValues as string[];
  }
  return null;
}

function parseBoolean(value: string): boolean | string {
  const normalized = value.trim().toLowerCase();
  if (["true", "1", "yes", "on"].includes(normalized)) return true;
  if (["false", "0", "no", "off"].includes(normalized)) return false;
  return value;
}

export function coerceTextInputValueByType(
  rawValue: string,
  expectedType?: string,
): unknown {
  if (expectedType === "number" || expectedType === "integer") {
    const trimmed = rawValue.trim();
    if (!trimmed) return rawValue;
    const parsed = Number(trimmed);
    return Number.isFinite(parsed) ? parsed : rawValue;
  }

  if (expectedType === "boolean") {
    return parseBoolean(rawValue);
  }

  return rawValue;
}

export function coerceExecutionArgByType(
  value: unknown,
  expectedType?: string,
): unknown {
  if (value === undefined) return value;

  if (expectedType === "object" || expectedType === "array") {
    if (typeof value === "string") {
      try {
        return JSON.parse(value);
      } catch {
        return value;
      }
    }
    return value;
  }

  if (expectedType === "number" || expectedType === "integer") {
    if (typeof value === "number") return value;
    if (typeof value === "string") {
      const trimmed = value.trim();
      if (!trimmed) return value;
      const parsed = Number(trimmed);
      return Number.isFinite(parsed) ? parsed : value;
    }
    return value;
  }

  if (expectedType === "boolean") {
    if (typeof value === "boolean") return value;
    if (typeof value === "string") return parseBoolean(value);
    return value;
  }

  return value;
}

/**
 * Converts JavaScript object syntax with template literals to valid JSON
 * Handles backtick strings and special characters in keys
 */
function convertJSObjectToJSON(text: string): string {
  // State machine to track if we're inside a template literal
  let result = "";
  let i = 0;
  let inBacktick = false;
  let escaped = false;

  while (i < text.length) {
    const char = text[i];

    if (escaped) {
      result += char;
      escaped = false;
      i++;
      continue;
    }

    if (char === "\\") {
      escaped = true;
      result += char;
      i++;
      continue;
    }

    // Handle backtick transitions
    if (char === "`") {
      if (!inBacktick) {
        // Start of template literal - replace with double quote
        result += '"';
        inBacktick = true;
      } else {
        // End of template literal - replace with double quote
        result += '"';
        inBacktick = false;
      }
      i++;
      continue;
    }

    // Inside template literal - escape double quotes
    if (inBacktick && char === '"') {
      result += '\\"';
      i++;
      continue;
    }

    // Pass through all other characters
    result += char;
    i++;
  }

  return result;
}

export type PasteParse =
  | { ok: true; value: Record<string, unknown> }
  | { ok: false; reason: "notAnObject" }
  | { ok: false; reason: "unsafeNumber"; token: string };

/**
 * Reads pasted text as a JSON or JavaScript object, and says why when it
 * cannot. A paste holding a number the browser cannot carry exactly (past
 * Number.MAX_SAFE_INTEGER, nonfinite, or a decimal whose value changes during
 * JSON serialization; see json-numbers.ts) is refused whole: JSON.parse would
 * round it before any field saw it, so the value pasted would not be sent.
 * The text that was actually parsed is the one scanned, so the backtick
 * fallback is covered, and numbers inside strings are never read as numbers.
 */
export function parsePastedObject(text: string): PasteParse {
  const notAnObject: PasteParse = { ok: false, reason: "notAnObject" };
  if (!text || typeof text !== "string") {
    return notAnObject;
  }

  const trimmed = text.trim();

  // Must start with { to be an object
  if (!trimmed.startsWith("{")) {
    return notAnObject;
  }

  let jsonText = trimmed;
  let parsed: unknown;
  try {
    // First try standard JSON.parse
    parsed = JSON.parse(jsonText);
  } catch {
    // If JSON.parse fails, try converting JS syntax to JSON
    jsonText = convertJSObjectToJSON(trimmed);
    try {
      parsed = JSON.parse(jsonText);
    } catch {
      // Both attempts failed
      return notAnObject;
    }
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return notAnObject;
  }

  const token = findUnsafeNumber(jsonText);
  if (token !== null) return { ok: false, reason: "unsafeNumber", token };
  return { ok: true, value: parsed as Record<string, unknown> };
}

/**
 * Attempts to parse pasted text as a JSON or JavaScript object
 * Returns the parsed object, or null when the text is not an object or holds
 * a number that cannot be sent exactly (parsePastedObject says which).
 */
export function parseObjectFromPaste(
  text: string,
): Record<string, unknown> | null {
  const result = parsePastedObject(text);
  return result.ok ? result.value : null;
}
