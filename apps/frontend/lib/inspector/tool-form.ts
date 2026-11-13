// Skeleton: the final exported API with bodies that reproduce the form's
// behaviour before this change (every field starts set to a filler value and
// every field is sent). It exists so the tests can be run red first.

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
  defaultValue?: unknown;
  constraints: string[];
}

export type FieldInput =
  | { mode: "unset" }
  | { mode: "null" }
  | { mode: "value"; text: string };

export type FormState = Map<string, FieldInput>;

export interface FieldError {
  key: string;
  reason: "invalidJson";
}

export interface FieldWarning {
  key: string;
  reason: "notNumber" | "notInteger" | "unsafeInteger" | "notBoolean";
}

export interface BuildResult {
  args: Record<string, unknown>;
  errors: FieldError[];
  warnings: FieldWarning[];
  missingRequired: string[];
  sentKeys: string[];
}

export function describeFields(tool: { inputSchema?: unknown }): FieldSpec[] {
  const schema = (tool.inputSchema ?? {}) as Record<string, unknown>;
  const properties = (schema.properties ?? {}) as Record<
    string,
    Record<string, unknown>
  >;
  const required = (schema.required ?? []) as string[];
  return Object.keys(properties).map((key) => {
    const property = properties[key] ?? {};
    const type = property.type;
    const kind: FieldKind =
      type === "string"
        ? "text"
        : type === "number" || type === "integer"
          ? "number"
          : type === "boolean"
            ? "boolean"
            : "json";
    return {
      key,
      kind,
      required: required.includes(key),
      nullable: false,
      description: property.description as string | undefined,
      defaultValue: property.default,
      constraints: [],
    };
  });
}

function fillerText(spec: FieldSpec): string {
  const fallback = spec.defaultValue;
  switch (spec.kind) {
    case "text":
      return typeof fallback === "string" ? fallback : "";
    case "number":
    case "integer":
      return fallback === undefined ? "0" : String(fallback);
    case "boolean":
      return fallback === undefined ? "false" : String(fallback);
    default:
      return JSON.stringify(fallback ?? null, null, 2);
  }
}

export function initialFormState(specs: FieldSpec[]): FormState {
  return new Map(
    specs.map((spec) => [
      spec.key,
      { mode: "value", text: fillerText(spec) } as FieldInput,
    ]),
  );
}

function withInput(state: FormState, key: string, input: FieldInput) {
  const next = new Map(state);
  next.set(key, input);
  return next;
}

export function setText(
  state: FormState,
  spec: FieldSpec,
  text: string,
): FormState {
  return withInput(state, spec.key, { mode: "value", text });
}

export function setEmptyString(
  state: FormState,
  key: string,
  on: boolean,
): FormState {
  return withInput(state, key, { mode: "value", text: on ? "" : "" });
}

export function setNull(state: FormState, key: string, on: boolean): FormState {
  return withInput(
    state,
    key,
    on ? { mode: "null" } : { mode: "value", text: "" },
  );
}

export function setEnumIndex(
  state: FormState,
  spec: FieldSpec,
  index: number | null,
): FormState {
  const option = index === null ? undefined : spec.enumOptions?.[index];
  return withInput(state, spec.key, {
    mode: "value",
    text: option === undefined ? "" : JSON.stringify(option.value),
  });
}

export function selectedEnumIndex(
  spec: FieldSpec,
  input: FieldInput | undefined,
): number | null {
  if (input?.mode !== "value") return null;
  const index = (spec.enumOptions ?? []).findIndex(
    (option) => JSON.stringify(option.value) === input.text,
  );
  return index === -1 ? null : index;
}

export function setBoolean(
  state: FormState,
  key: string,
  value: "true" | "false" | null,
): FormState {
  return withInput(state, key, { mode: "value", text: value ?? "false" });
}

export function buildArguments(
  specs: FieldSpec[],
  state: FormState,
): BuildResult {
  const entries: [string, unknown][] = [];
  const errors: FieldError[] = [];
  for (const spec of specs) {
    const input = state.get(spec.key) ?? { mode: "unset" };
    const text = input.mode === "value" ? input.text : "";
    try {
      if (spec.kind === "number" || spec.kind === "integer") {
        entries.push([spec.key, text ? parseFloat(text) : 0]);
      } else if (spec.kind === "boolean") {
        entries.push([spec.key, text === "true"]);
      } else if (spec.kind === "json") {
        entries.push([spec.key, text ? JSON.parse(text) : null]);
      } else {
        entries.push([spec.key, text]);
      }
    } catch {
      errors.push({ key: spec.key, reason: "invalidJson" });
    }
  }
  // Assignment onto a plain object, as the form did before.
  const args: Record<string, unknown> = {};
  for (const [key, value] of entries) args[key] = value;
  return {
    args,
    errors,
    warnings: [],
    missingRequired: [],
    sentKeys: entries.map(([key]) => key),
  };
}

export function applyPastedObject(
  _specs: FieldSpec[],
  state: FormState,
  _pasted: Record<string, unknown>,
): { state: FormState; filled: string[]; ignored: string[] } {
  return { state, filled: [], ignored: [] };
}

export function payloadText(args: Record<string, unknown>): string {
  return JSON.stringify(args, null, 2);
}
