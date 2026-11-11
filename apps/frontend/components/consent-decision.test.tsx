import { readFileSync } from "node:fs";
import path from "node:path";

import * as React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getTranslation, type Translations } from "@/lib/i18n";

import { ConsentDecision } from "./consent-decision";

const LOCALES = ["en", "ko", "zh"] as const;

function translatorFor(locale: (typeof LOCALES)[number]) {
  const auth = JSON.parse(
    readFileSync(
      path.join(__dirname, "..", "public", "locales", locale, "auth.json"),
      "utf8",
    ),
  );
  const dictionary = { auth } as unknown as Translations;
  return (key: string, params?: Record<string, string | number>) =>
    getTranslation(dictionary, key, params);
}

const INFO = {
  client_id: "mcp_client_example",
  client_name: "Claude Code",
  redirect_uri: "http://localhost:53682/callback",
  scope: "mcp",
};

function render(
  overrides: Partial<typeof INFO> = {},
  locale: (typeof LOCALES)[number] = "en",
) {
  return renderToStaticMarkup(
    React.createElement(ConsentDecision, {
      info: { ...INFO, ...overrides },
      areq: "signed-request",
      orgName: "Umbrella IT",
      t: translatorFor(locale),
    }),
  );
}

beforeEach(() => {
  // Next supplies the automatic JSX runtime; this Vitest config emits classic
  // JSX. Supply its React binding without changing the app's build config.
  vi.stubGlobal("React", React);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("consent screen warning", () => {
  it("states who supplied the name and callback, what approving grants, and who never asks", () => {
    const html = render();

    expect(html).toContain(
      "The application name and the callback address above were supplied by whoever started this request. The gateway has not verified either of them.",
    );
    expect(html).toContain(
      "Approving lets that application act as you on this gateway until the access is revoked.",
    );
    expect(html).toContain(
      "Umbrella IT never asks anyone to approve a connection for them, or to send or paste an authorization code for them. If someone asked you to, choose Deny.",
    );
  });

  it("sits after the request details and directly before the Approve button", () => {
    const html = render();

    const redirectAt = html.indexOf(INFO.redirect_uri);
    const warningAt = html.indexOf('id="consent-warning"');
    const formAt = html.indexOf("<form");
    const approveAt = html.indexOf('value="approve"');

    expect(redirectAt).toBeGreaterThan(-1);
    expect(warningAt).toBeGreaterThan(redirectAt);
    expect(formAt).toBeGreaterThan(warningAt);
    expect(approveAt).toBeGreaterThan(formAt);
    // Nothing else is rendered between the warning and the form: the slice
    // starts inside the warning's own opening tag, so any further <div> would
    // be another block in between.
    expect(html.slice(warningAt, formAt)).not.toMatch(/<div/);
  });

  it("renders a hostile application name and callback as text, never as markup", () => {
    const html = render({
      client_name: `Claude Code"><img src=x onerror=alert(1)>`,
      redirect_uri: `http://localhost:1/cb?x=<script>alert(1)</script>`,
    });

    expect(html).not.toContain("<img src=x");
    expect(html).not.toContain("<script>");
    expect(html).toContain(
      "Claude Code&quot;&gt;&lt;img src=x onerror=alert(1)&gt;",
    );
  });

  it("posts the decision as a plain form with the signed request", () => {
    const html = render();

    expect(html).toContain('action="/oauth/authorize/decision"');
    expect(html).toContain('method="POST"');
    expect(html).toContain('name="areq" value="signed-request"');
  });

  it.each(LOCALES)(
    "has every warning sentence translated in %s, with no em dash",
    (locale) => {
      const t = translatorFor(locale);
      for (const key of [
        "auth:consentWarning",
        "auth:consentSuppliedBy",
        "auth:consentActsAsYou",
        "auth:consentNoSharing",
      ]) {
        const text = t(key, { orgName: "Umbrella IT" });
        expect(text).not.toBe(key);
        expect(text).not.toContain("—");
      }
      expect(t("auth:consentNoSharing", { orgName: "Umbrella IT" })).toContain(
        "Umbrella IT",
      );
    },
  );
});
