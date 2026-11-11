/**
 * The server edit form's bearer-token payload (bearerFieldsForUpdate) and its
 * use by the edit dialog. The dialog is client-side React this suite cannot
 * mount (node environment, no DOM), so the decision lives in the helper and
 * the dialog's source is pinned to use it.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { bearerFieldsForUpdate } from "./server-bearer-update";

const FRONTEND = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);

describe("bearerFieldsForUpdate", () => {
  it("sends a typed token as the replacement and no clear flag", () => {
    expect(bearerFieldsForUpdate({ bearerToken: "new-token" })).toEqual({
      bearerToken: "new-token",
    });
  });

  it("sends a blank token (keep the stored one) and no clear flag", () => {
    expect(bearerFieldsForUpdate({ bearerToken: "" })).toEqual({
      bearerToken: "",
    });
    expect(
      bearerFieldsForUpdate({ bearerToken: "", clearBearerToken: false }),
    ).toEqual({ bearerToken: "" });
  });

  it("sends the clear flag with a blank token when ticked, whatever the field holds", () => {
    expect(
      bearerFieldsForUpdate({
        bearerToken: "left-over",
        clearBearerToken: true,
      }),
    ).toEqual({ bearerToken: "", clearBearerToken: true });
  });
});

describe("the edit dialog", () => {
  const source = readFileSync(
    path.join(FRONTEND, "components/edit-mcp-server.tsx"),
    "utf8",
  );

  it("builds its bearer fields with the helper", () => {
    expect(source).toContain("...bearerFieldsForUpdate(data)");
    expect(source).not.toMatch(/bearerToken: data\.bearerToken,/);
  });

  it("offers the clear control", () => {
    expect(source).toContain('id="edit-clearBearerToken"');
    expect(source).toContain('t("mcp-servers:clearBearerToken")');
  });
});
