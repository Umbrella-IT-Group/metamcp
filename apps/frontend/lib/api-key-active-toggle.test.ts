/**
 * The API Keys page offers the re-activate action only to an administrator.
 * The backend refuses a member's re-activation with FORBIDDEN whatever the
 * page shows; this keeps the page from offering a button that can only fail.
 *
 * The page is client-side React this suite cannot mount (node environment, no
 * DOM), so the decision lives in a pure helper tested here, and the page's
 * source is pinned so both key tables keep using it.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { canToggleApiKeyActive } from "./api-key-active-toggle";

const FRONTEND = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

describe("canToggleApiKeyActive", () => {
  it("offers deactivation of an active key to every viewer", () => {
    expect(canToggleApiKeyActive({ isActive: true, isAdmin: false })).toBe(
      true,
    );
    expect(canToggleApiKeyActive({ isActive: true, isAdmin: true })).toBe(true);
  });

  it("offers re-activation of an inactive key to an administrator only", () => {
    expect(canToggleApiKeyActive({ isActive: false, isAdmin: true })).toBe(
      true,
    );
    expect(canToggleApiKeyActive({ isActive: false, isAdmin: false })).toBe(
      false,
    );
  });
});

describe("the API Keys page", () => {
  const source = readFileSync(
    path.join(FRONTEND, "app/[locale]/(sidebar)/api-keys/page.tsx"),
    "utf8",
  );

  it("gates the active-state toggle in both key tables on the helper", () => {
    const gates = source.match(/canToggleApiKeyActive\(\{/g) ?? [];
    const toggles = source.match(/handleToggleActive\(\{/g) ?? [];
    expect(toggles).toHaveLength(2);
    expect(gates).toHaveLength(toggles.length);
  });
});
