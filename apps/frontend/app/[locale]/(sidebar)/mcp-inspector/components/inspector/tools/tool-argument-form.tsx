"use client";

import { Copy } from "lucide-react";
import { type ReactNode, useId, useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { CodeBlock } from "@/components/ui/code-block";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { copyToClipboard } from "@/lib/inspector/clipboard";
import { parseObjectFromPaste } from "@/lib/inspector/schema-utils";
import {
  applyPastedObject,
  type BuildResult,
  type FieldInput,
  type FieldSpec,
  type FormState,
  payloadText,
  selectedEnumIndex,
  setBoolean,
  setEmptyString,
  setEnumIndex,
  setNull,
  setText,
} from "@/lib/inspector/tool-form";
import type { Translate } from "@/lib/inspector/translate";

// Radix Select refuses an empty-string item value, so "not set" has its own.
const UNSET = "__unset__";
// The item a Select shows for a value that matches none of its options (a
// value pasted from JSON that the schema does not list).
const CUSTOM = "__custom__";

const WARNING_KEY = {
  notNumber: "inspector:inspectorForm.warnNotNumber",
  notInteger: "inspector:inspectorForm.warnNotInteger",
  unsafeInteger: "inspector:inspectorForm.warnUnsafeInteger",
  notBoolean: "inspector:inspectorForm.warnNotBoolean",
} as const;

interface ToolArgumentFormProps {
  specs: FieldSpec[];
  state: FormState;
  build: BuildResult;
  onStateChange: (next: FormState) => void;
  t: Translate;
}

function valueText(input: FieldInput | undefined): string {
  return input?.mode === "value" ? input.text : "";
}

function ChoiceSelect({
  id,
  value,
  items,
  customText,
  unsetLabel,
  onChange,
}: {
  id: string;
  value: string;
  items: { value: string; label: string }[];
  customText: string | null;
  unsetLabel: string | null;
  onChange: (value: string) => void;
}) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger id={id} className="w-full" size="sm">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {unsetLabel !== null && (
          <SelectItem value={UNSET}>{unsetLabel}</SelectItem>
        )}
        {items.map((item) => (
          <SelectItem key={item.value} value={item.value}>
            {item.label}
          </SelectItem>
        ))}
        {customText !== null && (
          <SelectItem value={CUSTOM}>{customText}</SelectItem>
        )}
      </SelectContent>
    </Select>
  );
}

function FieldRow({
  spec,
  state,
  build,
  onStateChange,
  t,
}: {
  spec: FieldSpec;
  state: FormState;
  build: BuildResult;
  onStateChange: (next: FormState) => void;
  t: Translate;
}) {
  const id = useId();
  const input = state.get(spec.key);
  const mode = input?.mode ?? "unset";
  const text = valueText(input);
  const warning = build.warnings.find((entry) => entry.key === spec.key);
  const error = build.errors.find((entry) => entry.key === spec.key);
  const hint = [spec.kind, ...spec.constraints].join(" · ");

  let control: ReactNode;
  switch (spec.kind) {
    case "text":
      control = (
        <div className="space-y-1">
          <Textarea
            id={id}
            value={text}
            rows={1}
            className="min-h-9 font-mono text-xs"
            onChange={(event) =>
              onStateChange(setText(state, spec, event.target.value))
            }
          />
          <label className="flex items-center gap-2 text-xs text-muted-foreground">
            <Switch
              checked={mode === "value" && text === ""}
              onCheckedChange={(on) =>
                onStateChange(setEmptyString(state, spec.key, on))
              }
            />
            {t("inspector:inspectorForm.sendEmptyString")}
          </label>
        </div>
      );
      break;
    case "number":
    case "integer":
      control = (
        <Input
          id={id}
          value={text}
          inputMode="decimal"
          className="font-mono text-xs"
          onChange={(event) =>
            onStateChange(setText(state, spec, event.target.value))
          }
        />
      );
      break;
    case "boolean": {
      const known = text === "true" || text === "false";
      control = (
        <ChoiceSelect
          id={id}
          value={mode !== "value" ? UNSET : known ? text : CUSTOM}
          items={[
            { value: "true", label: "true" },
            { value: "false", label: "false" },
          ]}
          customText={
            mode === "value" && !known
              ? t("inspector:inspectorForm.customValue", { value: text })
              : null
          }
          unsetLabel={t("inspector:inspectorForm.unset")}
          onChange={(choice) => {
            if (choice === CUSTOM) return;
            onStateChange(
              setBoolean(
                state,
                spec.key,
                choice === "true" || choice === "false" ? choice : null,
              ),
            );
          }}
        />
      );
      break;
    }
    case "enum": {
      const index = selectedEnumIndex(spec, input);
      const custom = mode === "value" && index === null;
      control = (
        <ChoiceSelect
          id={id}
          value={custom ? CUSTOM : index === null ? UNSET : String(index)}
          items={(spec.enumOptions ?? []).map((option, position) => ({
            value: String(position),
            label: option.label,
          }))}
          customText={
            custom
              ? t("inspector:inspectorForm.customValue", { value: text })
              : null
          }
          unsetLabel={t("inspector:inspectorForm.unset")}
          onChange={(choice) => {
            if (choice === CUSTOM) return;
            onStateChange(
              setEnumIndex(
                state,
                spec,
                choice === UNSET ? null : Number(choice),
              ),
            );
          }}
        />
      );
      break;
    }
    case "json":
      control = (
        <Textarea
          id={id}
          value={text}
          rows={3}
          className="font-mono text-xs"
          onChange={(event) =>
            onStateChange(setText(state, spec, event.target.value))
          }
        />
      );
      break;
  }

  return (
    <div className="space-y-1" data-field={spec.key}>
      <div className="flex flex-wrap items-baseline gap-x-2">
        <label
          htmlFor={id}
          className="block text-xs font-medium text-muted-foreground"
        >
          {spec.key}
          {spec.required && (
            <span className="ml-1 text-red-500">
              * {t("inspector:inspectorForm.required")}
            </span>
          )}
        </label>
        <span className="text-xs text-muted-foreground/70">{hint}</span>
        {mode === "unset" && (
          <span className="text-xs italic text-muted-foreground/70">
            {t("inspector:inspectorForm.notSent")}
          </span>
        )}
      </div>
      {spec.description !== undefined && (
        <p className="text-xs text-muted-foreground">{spec.description}</p>
      )}
      {control}
      {spec.nullable && (
        <label className="flex items-center gap-2 text-xs text-muted-foreground">
          <Switch
            checked={mode === "null"}
            onCheckedChange={(on) =>
              onStateChange(setNull(state, spec.key, on))
            }
          />
          {t("inspector:inspectorForm.sendNull")}
        </label>
      )}
      {warning !== undefined && (
        <p className="text-xs text-yellow-700 dark:text-yellow-400">
          {t(WARNING_KEY[warning.reason])}
        </p>
      )}
      {error !== undefined && (
        <p className="text-xs text-red-600 dark:text-red-400">
          {t("inspector:inspectorForm.errInvalidJson")}
        </p>
      )}
    </div>
  );
}

/**
 * The arguments form. Every field starts "not sent" unless the schema gives a
 * non-null default, and the payload preview shows exactly what the call will
 * carry, so there is no gap between what the person set and what is sent.
 */
export function ToolArgumentForm({
  specs,
  state,
  build,
  onStateChange,
  t,
}: ToolArgumentFormProps) {
  const [fillOpen, setFillOpen] = useState(false);
  const [fillText, setFillText] = useState("");
  const [fillError, setFillError] = useState<string | null>(null);
  const preview = payloadText(build.args);

  const applyFill = () => {
    const pasted = parseObjectFromPaste(fillText);
    if (pasted === null) {
      setFillError(t("inspector:inspectorForm.notAnObject"));
      return;
    }
    const result = applyPastedObject(specs, state, pasted);
    onStateChange(result.state);
    setFillError(null);
    setFillOpen(false);
    setFillText("");
    toast.success(
      t("inspector:inspectorForm.filled", { count: result.filled.length }),
      result.ignored.length > 0
        ? {
            description: t("inspector:inspectorForm.ignoredKeys", {
              keys: result.ignored.join(", "),
            }),
          }
        : undefined,
    );
  };

  const copyPayload = async () => {
    const copied = await copyToClipboard(preview);
    if (copied) toast.success(t("inspector:inspectorForm.payloadCopied"));
    else toast.error(t("inspector:inspectorResult.copyFailed"));
  };

  return (
    <div className="space-y-3">
      {specs.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          {t("inspector:inspectorForm.noParameters")}
        </p>
      ) : (
        <>
          <div className="space-y-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setFillOpen((open) => !open)}
            >
              {t("inspector:inspectorForm.fillFromJson")}
            </Button>
            {fillOpen && (
              <div className="space-y-2">
                <p className="text-xs text-muted-foreground">
                  {t("inspector:inspectorForm.fillHelp")}
                </p>
                <Textarea
                  value={fillText}
                  rows={4}
                  className="font-mono text-xs"
                  onChange={(event) => setFillText(event.target.value)}
                />
                {fillError !== null && (
                  <p className="text-xs text-red-600 dark:text-red-400">
                    {fillError}
                  </p>
                )}
                <Button size="sm" onClick={applyFill}>
                  {t("inspector:inspectorForm.apply")}
                </Button>
              </div>
            )}
          </div>
          <div className="space-y-3">
            {specs.map((spec) => (
              <FieldRow
                key={spec.key}
                spec={spec}
                state={state}
                build={build}
                onStateChange={onStateChange}
                t={t}
              />
            ))}
          </div>
        </>
      )}

      <div className="space-y-1">
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-muted-foreground">
            {t("inspector:inspectorForm.payload")}
          </span>
          <Button
            variant="ghost"
            size="sm"
            className="h-6 gap-1 px-2 text-xs"
            onClick={copyPayload}
          >
            <Copy className="h-3 w-3" />
            {t("inspector:inspectorForm.copyPayload")}
          </Button>
        </div>
        {build.sentKeys.length === 0 ? (
          <p className="text-xs text-muted-foreground">
            {t("inspector:inspectorForm.payloadEmpty")}
          </p>
        ) : (
          <CodeBlock language="json" maxHeight="200px" className="text-xs">
            {preview}
          </CodeBlock>
        )}
        {build.missingRequired.length > 0 && (
          <p className="text-xs text-yellow-700 dark:text-yellow-400">
            {t("inspector:inspectorForm.missingRequired", {
              fields: build.missingRequired.join(", "),
            })}
          </p>
        )}
        {build.errors.length > 0 && (
          <p className="text-xs text-red-600 dark:text-red-400">
            {t("inspector:inspectorForm.errBlocked", {
              fields: build.errors.map((entry) => entry.key).join(", "),
            })}
          </p>
        )}
      </div>
    </div>
  );
}
