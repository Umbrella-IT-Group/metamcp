/**
 * The namespace forms offer only the ownership the backend actually applies
 * (TASKLIST METAMCP-NO-PRIVATE-NAMESPACES). The create form used to offer
 * "For myself", which sent no owner; the backend stores that as public, so the
 * option promised a private namespace and silently made a public one.
 *
 * The forms render client-side React this suite cannot mount (node
 * environment, no DOM), so the decision lives in a pure helper tested here,
 * and the create page's source is pinned so the option cannot quietly return.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { namespaceOwnershipChoices } from "./namespace-ownership";

const FRONTEND = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

describe("namespaceOwnershipChoices", () => {
  it("offers only 'everyone' for a public namespace", () => {
    expect(namespaceOwnershipChoices(null)).toEqual(["everyone"]);
  });

  it("offers only 'everyone' when there is no stored owner at all", () => {
    expect(namespaceOwnershipChoices(undefined)).toEqual(["everyone"]);
    expect(namespaceOwnershipChoices("")).toEqual(["everyone"]);
  });

  it("keeps both choices for an owned namespace, so its owner can publish it", () => {
    expect(namespaceOwnershipChoices("user-1")).toEqual([
      "forMyself",
      "everyone",
    ]);
  });
});

describe("the create form", () => {
  const page = readFileSync(
    path.join(FRONTEND, "app/[locale]/(sidebar)/namespaces/page.tsx"),
    "utf8",
  );

  it("no longer offers 'For myself'", () => {
    expect(page).not.toContain("namespaces:forMyself");
    expect(page).not.toContain('setValue("user_id", undefined)');
  });

  it("states the ownership it applies", () => {
    expect(page).toContain('t("namespaces:everyone")');
    expect(page).toContain('t("namespaces:ownershipPublicNote")');
  });
});

describe("ownershipPublicNote is translated in every shipped locale", () => {
  it.each(["en", "ko", "zh"])("%s", (locale) => {
    const strings = JSON.parse(
      readFileSync(
        path.join(FRONTEND, "public/locales", locale, "namespaces.json"),
        "utf8",
      ),
    ) as Record<string, unknown>;

    expect(typeof strings.ownershipPublicNote).toBe("string");
    expect((strings.ownershipPublicNote as string).length).toBeGreaterThan(0);
  });
});
