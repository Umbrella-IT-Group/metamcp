import { findUnsafeNumber, isUnsafeNumberText } from "./json-numbers";
import {
  coerceTextInputValueByType,
  extractEnumOptions,
  firstNonNullType,
  type JsonSchema,
  resolveToolPropertySchema,
} from "./schema-utils";

/**
 * The Inspector tool form, as plain data.
 *
 * The rule the whole module serves: what is sent to a tool is exactly what the
 * person at the form set. A field they did not touch is not in the call. The
 * old form started every field at a filler value ("", 0, false, [], {}, null)
 * and sent all of them, which on a write tool means writing zeros and nulls
 * the caller never chose, and on a tool that validates its input means errors
 * about fields nobody typed.
 *
 * State is a Map keyed by parameter name so that a parameter called
 * "__proto__" is an ordinary key, and the arguments are built with
 * Object.fromEntries, which defines own properties (CreateDataProperty)
 * instead of assigning, for the same reason.
 */

export type FieldKind =
  | "text"
  | "number"
  | "integer"
  | "boolean"
  | "enum"
  | "json";

export interface EnumOption {
  label: string;
  value: unknown;
}

export interface FieldSpec {
  key: string;
  kind: FieldKind;
  required: boolean;
  nullable: boolean;
  description?: string;
  title?: string;
  format?: string;
  enumOptions?: EnumOption[];
  /**
   * The schema's default, or undefined when there is none OR it is null.
   * Pydantic writes `"default": null` for every `X | None = None`, which says
   * "optional", not "send null"; one value (undefined) for both keeps the
   * prefill test from disagreeing with the data.
   */
  defaultValue?: unknown;
  /** Short schema-keyword hints for the label, e.g. "minLength: 2". */
  constraints: string[];
}

export type FieldInput =
  | { mode: "unset" }
  | { mode: "null" }
  | { mode: "value"; text: string };

export type FormState = Map<string, FieldInput>;

export interface FieldError {
  key: string;
  /**
   * invalidJson: the text does not parse. unsafeNumber: it holds a number the
   * browser cannot carry exactly (see json-numbers.ts), and sending the
   * rounded one would send a value nobody typed.
   */
  reason: "invalidJson" | "unsafeNumber";
}

export interface FieldWarning {
  key: string;
  reason: "notNumber" | "notInteger" | "notBoolean";
}

export interface BuildResult {
  args: Record<string, unknown>;
  /** A field whose value cannot be formed at all. These block the call. */
  errors: FieldError[];
  /** Typed text that does not fit its type; sent anyway, as the server decides. */
  warnings: FieldWarning[];
  /** Required fields nothing was entered for. Advisory: the call still goes. */
  missingRequired: string[];
  sentKeys: string[];
}

const hasOwn = (target: object, key: string) =>
  Object.prototype.hasOwnProperty.call(target, key);

const isRecord = (value: unknown): value is JsonSchema =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const asString = (value: unknown): string | undefined =>
  typeof value === "string" ? value : undefined;

const CONSTRAINT_KEYS = [
  ["format", "format"],
  ["minimum", "minimum"],
  ["maximum", "maximum"],
  ["minLength", "minLength"],
  ["maxLength", "maxLength"],
  ["pattern", "pattern"],
] as const;

function constraintHints(resolved: JsonSchema): string[] {
  const hints: string[] = [];
  for (const [label, key] of CONSTRAINT_KEYS) {
    const value = resolved[key];
    if (typeof value === "string" || typeof value === "number") {
      hints.push(`${label}: ${value}`);
    }
  }
  return hints;
}

function kindOf(resolved: JsonSchema, options: EnumOption[] | null): FieldKind {
  if (options) return "enum";
  switch (firstNonNullType(resolved)) {
    case "string":
      return "text";
    case "number":
      return "number";
    case "integer":
      return "integer";
    case "boolean":
      return "boolean";
    default:
      // object, array, an ambiguous union, or no type at all
      return "json";
  }
}

function isNullable(resolved: JsonSchema): boolean {
  if (resolved.nullable === true) return true;
  return Array.isArray(resolved.type) && resolved.type.includes("null");
}

export function describeFields(tool: { inputSchema?: unknown }): FieldSpec[] {
  const root = tool.inputSchema;
  if (!isRecord(root) || !isRecord(root.properties)) return [];
  const required = Array.isArray(root.required) ? root.required : [];
  const properties = root.properties;

  return Object.keys(properties).map((key) => {
    const resolved = resolveToolPropertySchema(properties[key], root);
    const enumOptions = extractEnumOptions(resolved);
    const rawDefault = hasOwn(resolved, "default") ? resolved.default : null;
    const spec: FieldSpec = {
      key,
      kind: kindOf(resolved, enumOptions),
      required: required.includes(key),
      nullable: isNullable(resolved),
      constraints: constraintHints(resolved),
    };
    const description = asString(resolved.description);
    if (description !== undefined) spec.description = description;
    const title = asString(resolved.title);
    if (title !== undefined) spec.title = title;
    const format = asString(resolved.format);
    if (format !== undefined) spec.format = format;
    if (enumOptions) spec.enumOptions = enumOptions;
    if (rawDefault !== null && rawDefault !== undefined) {
      spec.defaultValue = rawDefault;
    }
    return spec;
  });
}

// The text a value takes in its field. An enum's text is the JSON of its value
// (so a pasted value that matches no option can still be held and sent, and an
// option is found by comparing JSON text).
function textFor(spec: FieldSpec, value: unknown): string | null {
  switch (spec.kind) {
    case "text":
      return typeof value === "string" ? value : JSON.stringify(value);
    case "number":
    case "integer":
    case "boolean":
      return String(value);
    case "json":
      return JSON.stringify(value, null, 2) ?? null;
    case "enum":
      return JSON.stringify(value) ?? null;
  }
}

function optionIndex(spec: FieldSpec, text: string): number {
  return (spec.enumOptions ?? []).findIndex(
    (option) => JSON.stringify(option.value) === text,
  );
}

/**
 * A field starts as a value only when the schema gives a non-null default
 * (JSON Schema 2020-12 section 9.2: "default" is an annotation a client may
 * prefill). A default of "" is left unset: omitting it is the same by
 * definition. An enum default that is not one of the options is left unset
 * rather than shown as something the menu cannot display.
 */
export function initialFormState(specs: FieldSpec[]): FormState {
  const state: FormState = new Map();
  for (const spec of specs) {
    let input: FieldInput = { mode: "unset" };
    const value = spec.defaultValue;
    if (value !== undefined && !(spec.kind === "text" && value === "")) {
      const text = textFor(spec, value);
      if (
        text !== null &&
        (spec.kind !== "enum" || optionIndex(spec, text) >= 0)
      ) {
        input = { mode: "value", text };
      }
    }
    state.set(spec.key, input);
  }
  return state;
}

function withInput(state: FormState, key: string, input: FieldInput) {
  const next: FormState = new Map(state);
  next.set(key, input);
  return next;
}

/**
 * Typing into a field. Empty text is "not set": exactly "" for a text field
 * (spaces are a value), blank for the other kinds. A person who wants the
 * empty string sends it on purpose with setEmptyString.
 */
export function setText(
  state: FormState,
  spec: FieldSpec,
  text: string,
): FormState {
  const blank = spec.kind === "text" ? text === "" : text.trim() === "";
  return withInput(
    state,
    spec.key,
    blank ? { mode: "unset" } : { mode: "value", text },
  );
}

export function setEmptyString(
  state: FormState,
  key: string,
  on: boolean,
): FormState {
  return withInput(
    state,
    key,
    on ? { mode: "value", text: "" } : { mode: "unset" },
  );
}

export function setNull(state: FormState, key: string, on: boolean): FormState {
  return withInput(state, key, on ? { mode: "null" } : { mode: "unset" });
}

export function setEnumIndex(
  state: FormState,
  spec: FieldSpec,
  index: number | null,
): FormState {
  const option = index === null ? undefined : spec.enumOptions?.[index];
  if (option === undefined)
    return withInput(state, spec.key, { mode: "unset" });
  return withInput(state, spec.key, {
    mode: "value",
    text: JSON.stringify(option.value),
  });
}

/** The option an enum field currently shows, or null for none or a custom value. */
export function selectedEnumIndex(
  spec: FieldSpec,
  input: FieldInput | undefined,
): number | null {
  if (input?.mode !== "value") return null;
  const index = optionIndex(spec, input.text);
  return index === -1 ? null : index;
}

export function setBoolean(
  state: FormState,
  key: string,
  value: "true" | "false" | null,
): FormState {
  return withInput(
    state,
    key,
    value === null ? { mode: "unset" } : { mode: "value", text: value },
  );
}

/**
 * What the form sends, in schema order. See the module comment for the rule.
 * Text that does not fit a number or boolean field is sent as typed, as a
 * string, with a warning, because the tester's job is often to see the server
 * refuse it. Two things block: a JSON field that does not parse (no value can
 * be formed from it), and a number the browser cannot carry exactly (a whole
 * number past Number.MAX_SAFE_INTEGER, or one that overflows). The second is
 * the same rule as the first: a rounded number is a value nobody typed, and
 * sending it as a string would be a change nobody chose, so the call waits
 * for the person to quote it themselves if the tool takes a string.
 */
export function buildArguments(
  specs: FieldSpec[],
  state: FormState,
): BuildResult {
  const entries: [string, unknown][] = [];
  const errors: FieldError[] = [];
  const warnings: FieldWarning[] = [];
  const missingRequired: string[] = [];

  for (const spec of specs) {
    const input = state.get(spec.key) ?? { mode: "unset" };
    if (input.mode === "unset") {
      if (spec.required) missingRequired.push(spec.key);
      continue;
    }
    if (input.mode === "null") {
      entries.push([spec.key, null]);
      continue;
    }

    const { text } = input;
    switch (spec.kind) {
      case "text":
        entries.push([spec.key, text]);
        break;
      case "number":
      case "integer": {
        // Before anything is converted: Number() would round the typed digits.
        if (isUnsafeNumberText(text)) {
          errors.push({ key: spec.key, reason: "unsafeNumber" });
          break;
        }
        const coerced = coerceTextInputValueByType(text, spec.kind);
        if (typeof coerced !== "number") {
          entries.push([spec.key, text]);
          warnings.push({ key: spec.key, reason: "notNumber" });
        } else if (spec.kind === "integer" && !Number.isInteger(coerced)) {
          entries.push([spec.key, coerced]);
          warnings.push({ key: spec.key, reason: "notInteger" });
        } else {
          entries.push([spec.key, coerced]);
        }
        break;
      }
      case "boolean":
        if (text === "true" || text === "false") {
          entries.push([spec.key, text === "true"]);
        } else {
          entries.push([spec.key, text]);
          warnings.push({ key: spec.key, reason: "notBoolean" });
        }
        break;
      case "enum":
      case "json": {
        let parsed: unknown;
        try {
          parsed = JSON.parse(text);
        } catch {
          errors.push({ key: spec.key, reason: "invalidJson" });
          break;
        }
        // JSON.parse has already rounded such a number, so the text is read.
        if (findUnsafeNumber(text) !== null) {
          errors.push({ key: spec.key, reason: "unsafeNumber" });
          break;
        }
        entries.push([spec.key, parsed]);
        break;
      }
    }
  }

  return {
    args: Object.fromEntries(entries),
    errors,
    warnings,
    missingRequired,
    sentKeys: entries.map(([key]) => key),
  };
}

/**
 * Fills the form from a pasted JSON object. Keys the schema does not have are
 * reported, not added. A pasted value is converted to the field's text form;
 * one that does not fit (a number for a boolean, a value that is no enum
 * option) is kept as is so the server's validation is what answers.
 */
export function applyPastedObject(
  specs: FieldSpec[],
  state: FormState,
  pasted: Record<string, unknown>,
): { state: FormState; filled: string[]; ignored: string[] } {
  const bySpec = new Map(specs.map((spec) => [spec.key, spec]));
  let next: FormState = state;
  const filled: string[] = [];
  const ignored: string[] = [];

  for (const key of Object.keys(pasted)) {
    const spec = bySpec.get(key);
    if (!spec) {
      ignored.push(key);
      continue;
    }
    const value = pasted[key];
    if (value === null) {
      next = withInput(next, key, { mode: "null" });
    } else {
      const text = textFor(spec, value);
      if (text === null) {
        ignored.push(key);
        continue;
      }
      next = withInput(next, key, { mode: "value", text });
    }
    filled.push(key);
  }

  return { state: next, filled, ignored };
}

/** The exact JSON the call sends; the preview and the copy button show this. */
export function payloadText(args: Record<string, unknown>): string {
  return JSON.stringify(args, null, 2);
}
