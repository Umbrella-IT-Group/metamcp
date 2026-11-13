import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { getTranslation, loadTranslations } from "@/lib/i18n";

const FRONTEND = path.join(__dirname, "..", "..");
const INSPECTOR_DIR = "app/[locale]/(sidebar)/mcp-inspector/components";

// The files this change owns that look up translation keys.
const FILES = [
  `${INSPECTOR_DIR}/inspector/inspector-tools.tsx`,
  `${INSPECTOR_DIR}/inspector/tools/tool-list.tsx`,
  `${INSPECTOR_DIR}/inspector/tools/tool-argument-form.tsx`,
  `${INSPECTOR_DIR}/inspector/tools/tool-result-view.tsx`,
  "app/[locale]/(sidebar)/mcp-servers/[uuid]/components/tool-management.tsx",
];

// The new strings live in new top-level objects of the English file only. The
// loader merges one level deep (lib/i18n.ts: `{ ...english.inspector,
// ...korean.inspector }`), so a top-level object the other locales do not have
// falls back to English whole, while a new key added inside an object they DO
// have would render as its raw key there. These tests pin both halves.
const NEW_OBJECTS = [
  ["inspector", "inspectorFilter"],
  ["inspector", "inspectorForm"],
  ["inspector", "inspectorResult"],
  ["mcp-servers", "toolListTruncated"],
] as const;

const KEY_LITERAL =
  /["'`]((?:inspector|mcp-servers|settings):[A-Za-z0-9_.-]+)["'`]/g;

const keysUsed = FILES.flatMap((file) => {
  const source = readFileSync(path.join(FRONTEND, file), "utf8");
  return [...source.matchAll(KEY_LITERAL)].map((match) => match[1] as string);
});

// Keys that existed before this change and are missing from the ko and zh
// files, so those locales show the raw key. Not touched here (they are
// human-translation work); named so the check below can say "every key this
// change adds or relies on resolves" without hiding the gap.
const MISSING_IN_KO_ZH_BEFORE_THIS_CHANGE = /^mcp-servers:tools\.reconnect/;

describe("translation keys used by the inspector tools", () => {
  it("finds the keys it is meant to check", () => {
    expect(keysUsed.length).toBeGreaterThan(40);
    expect(keysUsed).toContain("inspector:inspectorResult.stopWaiting");
    expect(keysUsed).toContain("mcp-servers:toolListTruncated.pageCap");
  });

  it.each(["en", "ko", "zh"])(
    "every key resolves to text in %s",
    async (locale) => {
      const dictionary = await loadTranslations(locale);
      const unresolved = [...new Set(keysUsed)]
        .filter(
          (key) =>
            locale === "en" || !MISSING_IN_KO_ZH_BEFORE_THIS_CHANGE.test(key),
        )
        .filter((key) => getTranslation(dictionary, key) === key);
      expect(unresolved).toEqual([]);
    },
  );

  it.each(["ko", "zh"])(
    "gives %s the English text for every new top-level object",
    async (locale) => {
      const english = await loadTranslations("en");
      const other = await loadTranslations(locale);
      const read = (
        dictionary: typeof english,
        namespace: string,
        name: string,
      ) =>
        (dictionary as unknown as Record<string, Record<string, unknown>>)[
          namespace
        ]?.[name];
      for (const [namespace, name] of NEW_OBJECTS) {
        expect(read(english, namespace, name)).toBeTypeOf("object");
        expect(read(other, namespace, name)).toEqual(
          read(english, namespace, name),
        );
      }
    },
  );
});

// The reset-on-progress setting works (the SDK resets its timer on progress),
// so its label no longer says it is under development.
describe("the reset-on-progress label", () => {
  it.each(["en", "ko", "zh"])(
    "is not marked under development in %s",
    (locale) => {
      const settings = JSON.parse(
        readFileSync(
          path.join(FRONTEND, "public", "locales", locale, "settings.json"),
          "utf8",
        ),
      ) as Record<string, string>;
      expect(settings.mcpResetTimeoutOnProgress).toBeTypeOf("string");
      expect(settings.mcpResetTimeoutOnProgress).not.toMatch(
        /development|개발|开发/i,
      );
    },
  );
});
