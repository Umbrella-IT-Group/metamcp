/**
 * The install dialog's strings live in a new top-level `installClient` object
 * in the English inspector file only. That works because the loader merges
 * each locale over English one level down (`{ ...en.inspector, ...ko.inspector }`):
 * a top-level key the other locales lack falls back to English as a whole.
 * Two ways to break it, both of which would show operators raw key names:
 * a code path that names a key English does not have, and a locale that
 * defines `installClient` itself, partially, which replaces the English object.
 */
import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { getTranslation, loadTranslations } from "./i18n";

const FRONTEND = path.join(__dirname, "..");

// The files that name install-dialog strings.
const SOURCES = [
  "components/install-snippet-panel.tsx",
  "components/install-client-dialog.tsx",
  "app/[locale]/(sidebar)/endpoints/endpoints-list.tsx",
];

const USED_KEYS = [
  ...new Set(
    SOURCES.flatMap((file) =>
      [
        ...readFileSync(path.join(FRONTEND, file), "utf8").matchAll(
          /inspector:installClient\.([A-Za-z0-9]+)/g,
        ),
      ].map((m) => m[1]!),
    ),
  ),
];

const english = JSON.parse(
  readFileSync(
    path.join(FRONTEND, "public", "locales", "en", "inspector.json"),
    "utf8",
  ),
) as { installClient?: Record<string, unknown> };

describe("install dialog strings", () => {
  it("finds the keys the code uses", () => {
    // A guard on the scan itself: an empty list would make the cases below
    // pass without checking anything.
    expect(USED_KEYS.length).toBeGreaterThan(20);
  });

  it.each(["en", "ko", "zh"] as const)(
    "resolves every key the code uses to text in %s",
    async (locale) => {
      const dictionary = await loadTranslations(locale);
      for (const key of USED_KEYS) {
        const full = `inspector:installClient.${key}`;
        const text = getTranslation(dictionary, full);
        expect(text, full).not.toBe(full);
        expect(text.length, full).toBeGreaterThan(0);
      }
    },
  );

  it.each(["ko", "zh"] as const)(
    "gives %s the English text for every installClient key",
    async (locale) => {
      const dictionary = await loadTranslations(locale);
      // Equal-to-English alone would pass with the object missing everywhere.
      expect(Object.keys(english.installClient ?? {}).length).toBeGreaterThan(
        20,
      );
      expect(dictionary.inspector.installClient).toEqual(english.installClient);
    },
  );
});
