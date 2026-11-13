/**
 * What the "Add to client" panel puts on screen. The builder's own tests pin
 * the snippets; these pin the two things the panel adds: which tabs an endpoint
 * is offered (a key-only endpoint has no hosted-connector path), and that
 * snippet text is rendered as text, never as markup, since part of it comes
 * from the operator-configured gateway URL.
 */
import { readFileSync } from "node:fs";
import path from "node:path";

import * as React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getTranslation, type Translations } from "@/lib/i18n";
import {
  buildInstallSnippets,
  type InstallInput,
  type InstallSnippets,
} from "@/lib/install-snippets";

import { InstallSnippetPanel } from "./install-snippet-panel";

const inspector = JSON.parse(
  readFileSync(
    path.join(__dirname, "..", "public", "locales", "en", "inspector.json"),
    "utf8",
  ),
);
const dictionary = { inspector } as unknown as Translations;
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

function snippets(overrides: Partial<InstallInput>): InstallSnippets {
  const result = buildInstallSnippets({
    appUrl: "https://gw.example.com",
    endpointName: "ops-tools",
    enableApiKeyAuth: false,
    enableOauth: false,
    requireScopedApiKey: false,
    ...overrides,
  });
  if (!result.ok) throw new Error(`expected snippets, got ${result.reason}`);
  return result;
}

const render = (s: InstallSnippets) =>
  renderToStaticMarkup(
    React.createElement(InstallSnippetPanel, {
      snippets: s,
      t,
      onCopy: () => {},
    }),
  );

describe("InstallSnippetPanel", () => {
  it.each([
    { apiKey: true, oauth: false, claude: false },
    { apiKey: false, oauth: true, claude: true },
    { apiKey: true, oauth: true, claude: true },
    { apiKey: false, oauth: false, claude: false },
  ])(
    "offers the Claude web and desktop tab only with OAuth (api key $apiKey, oauth $oauth)",
    ({ apiKey, oauth, claude }) => {
      const html = render(
        snippets({ enableApiKeyAuth: apiKey, enableOauth: oauth }),
      );
      expect(html.includes("Claude (web and desktop)")).toBe(claude);
      // The four command-line and editor clients are always offered.
      for (const tab of ["Claude Code", "Codex", "Cursor", "VS Code"]) {
        expect(html).toContain(`>${tab}</button>`);
      }
    },
  );

  it("renders snippet text as text, whatever the gateway URL holds", () => {
    const html = render(
      snippets({
        appUrl: "https://gw.example.com/<script>alert(1)</script>",
        enableApiKeyAuth: true,
      }),
    );
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("<script>");
  });

  it("shows the key placeholder and variable name, and no query-parameter key", () => {
    const html = render(snippets({ enableApiKeyAuth: true }));
    expect(html).toContain("Bearer YOUR_API_KEY");
    expect(html).toContain("MCP_OPS_TOOLS_API_KEY");
    expect(html).not.toContain("api_key=");
  });
});
