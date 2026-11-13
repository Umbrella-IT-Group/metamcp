import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { getTranslation, loadTranslations } from "@/lib/i18n";

const FRONTEND = path.join(__dirname, "..", "..");
const INSPECTOR_DIR = "app/[locale]/(sidebar)/mcp-inspector";

// The files this change owns that look up translation keys.
const FILES = [
  `${INSPECTOR_DIR}/page.tsx`,
  `${INSPECTOR_DIR}/components/inspector.tsx`,
  `${INSPECTOR_DIR}/components/inspector-server-info.tsx`,
  `${INSPECTOR_DIR}/components/inspector-target-notice.tsx`,
  `${INSPECTOR_DIR}/components/rpc-traffic-panel.tsx`,
  "lib/inspector/inspector-target.ts",
];

// The new strings live in new top-level objects of the English file only. The
// loader merges one level deep (lib/i18n.ts: `{ ...english.inspector,
// ...korean.inspector }`), so a top-level object the other locales do not have
// falls back to English whole, while a new key added inside an object they DO
// have would render as its raw key there. These tests pin both halves.
const NEW_OBJECTS = [
  "inspectorTarget",
  "inspectorServerInfo",
  "inspectorTraffic",
] as const;

const KEY_LITERAL = /["'`]((?:inspector|mcp-servers):[A-Za-z0-9_.-]+)["'`]/g;

const keysUsed = FILES.flatMap((file) => {
  const source = readFileSync(path.join(FRONTEND, file), "utf8");
  return [...source.matchAll(KEY_LITERAL)].map((match) => match[1] as string);
});

describe("translation keys used by the inspector targets and traffic log", () => {
  it("finds the keys it is meant to check", () => {
    expect(keysUsed.length).toBeGreaterThan(40);
    expect(keysUsed).toContain("inspector:inspectorTarget.endpointLabel");
    expect(keysUsed).toContain("inspector:inspectorTraffic.privacyNote");
    expect(keysUsed).toContain("inspector:inspectorServerInfo.gatewayNote");
  });

  it.each(["en", "ko", "zh"] as const)(
    "every key resolves to text in %s",
    async (locale) => {
      const dictionary = await loadTranslations(locale);
      const unresolved = [...new Set(keysUsed)].filter(
        (key) => getTranslation(dictionary, key) === key,
      );
      expect(unresolved).toEqual([]);
    },
  );

  it.each(["ko", "zh"] as const)(
    "gives %s the English text for every new top-level object",
    async (locale) => {
      const english = await loadTranslations("en");
      const other = await loadTranslations(locale);
      const read = (dictionary: typeof english, name: string) =>
        (dictionary as unknown as Record<string, Record<string, unknown>>)
          .inspector?.[name];
      for (const name of NEW_OBJECTS) {
        expect(read(english, name)).toBeTypeOf("object");
        expect(read(other, name)).toEqual(read(english, name));
      }
    },
  );
});
