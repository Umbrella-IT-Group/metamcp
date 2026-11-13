import { readFileSync } from "node:fs";
import path from "node:path";

import * as React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ToolArgumentForm } from "@/app/[locale]/(sidebar)/mcp-inspector/components/inspector/tools/tool-argument-form";
import { getTranslation, type Translations } from "@/lib/i18n";

import {
  buildArguments,
  describeFields,
  initialFormState,
  setText,
} from "./tool-form";

const FRONTEND = path.join(__dirname, "..", "..");

const dictionary = {
  inspector: JSON.parse(
    readFileSync(
      path.join(FRONTEND, "public", "locales", "en", "inspector.json"),
      "utf8",
    ),
  ),
} as unknown as Translations;
const t = (key: string, params?: Record<string, string | number>) =>
  getTranslation(dictionary, key, params);

beforeEach(() => {
  // Next supplies the automatic JSX runtime; this Vitest config emits classic
  // JSX. Supply its React binding without changing the app's build config.
  vi.stubGlobal("React", React);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const specs = describeFields({
  inputSchema: {
    type: "object",
    properties: {
      count: { type: "integer" },
      filter: { type: "object" },
    },
  },
});

function renderWith(typed: Record<string, string>) {
  let state = initialFormState(specs);
  for (const spec of specs) {
    const text = typed[spec.key];
    if (text !== undefined) state = setText(state, spec, text);
  }
  const build = buildArguments(specs, state);
  const html = renderToStaticMarkup(
    React.createElement(ToolArgumentForm, {
      specs,
      state,
      build,
      onStateChange: () => undefined,
      t,
    }),
  );
  return { html, build };
}

describe("ToolArgumentForm and numbers that cannot be sent exactly", () => {
  it("says an unsafe number cannot be sent exactly and to quote it as a string", () => {
    const { html, build } = renderWith({
      count: "9007199254740993",
      filter: '{"id": 9007199254740993}',
    });
    expect(build.errors.map((entry) => entry.reason)).toEqual([
      "unsafeNumber",
      "unsafeNumber",
    ]);
    const message =
      "Cannot be sent exactly as a JSON number. If the tool accepts a string, quote it as a string.";
    expect(html.split(message)).toHaveLength(3);
    expect(html).not.toContain("Not valid JSON");
  });

  it("still says text that is not JSON is not valid JSON", () => {
    const { html } = renderWith({ filter: '{"id": ' });
    expect(html).toContain("Not valid JSON");
    expect(html).not.toContain("cannot be sent exactly");
  });
});
