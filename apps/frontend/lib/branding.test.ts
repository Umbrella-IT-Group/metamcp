import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  Branding,
  DEFAULT_DESCRIPTION,
  DEFAULT_LOGO_PATH,
  DEFAULT_ORG_NAME,
  DEFAULT_PRODUCT_NAME,
  getBranding,
  resolveBrandText,
  resolveLogoPath,
} from "./branding";

// getBranding() reads through next-runtime-env's isomorphic `env()`. Mocking
// that one accessor exercises the real composition against a controlled env
// source, without dragging a Next request scope into a unit test.
const envValues: Record<string, string | undefined> = {};
vi.mock("next-runtime-env", () => ({
  env: (key: string) => envValues[key],
}));

describe("branding defaults", () => {
  // The zero-config parity contract: a deployment that sets no branding vars
  // must render exactly what it rendered before this feature existed. These
  // literals are what the Umbrella prod instance shows today, so editing a
  // default is a silent rebrand of every existing deployment — this test is
  // the tripwire, not a tautology.
  it("are the shipped Umbrella strings", () => {
    expect(DEFAULT_PRODUCT_NAME).toBe("Umbrella MCP Gateway");
    expect(DEFAULT_ORG_NAME).toBe("Umbrella IT");
    expect(DEFAULT_LOGO_PATH).toBe("/umbrella-bug.png");
    expect(DEFAULT_DESCRIPTION).toBe(
      "Umbrella IT Group's MCP gateway — aggregates Autotask, IT Glue, CIPP, registry and more into curated namespaces for AI tooling.",
    );
  });
});

describe("resolveBrandText", () => {
  it("falls back when the var is unset", () => {
    expect(resolveBrandText(undefined, "fallback")).toBe("fallback");
    expect(resolveBrandText(null, "fallback")).toBe("fallback");
  });

  it("treats an empty or whitespace-only value as unset", () => {
    expect(resolveBrandText("", "fallback")).toBe("fallback");
    expect(resolveBrandText("   ", "fallback")).toBe("fallback");
  });

  it("uses and trims a real value", () => {
    expect(resolveBrandText("Ivantsov", "fallback")).toBe("Ivantsov");
    expect(resolveBrandText("  Personal MCP Gateway  ", "fallback")).toBe(
      "Personal MCP Gateway",
    );
  });
});

describe("resolveLogoPath", () => {
  let warn: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    warn = vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    warn.mockRestore();
  });

  it("falls back to the bundled asset when unset or empty", () => {
    expect(resolveLogoPath(undefined)).toBe(DEFAULT_LOGO_PATH);
    expect(resolveLogoPath("")).toBe(DEFAULT_LOGO_PATH);
    expect(resolveLogoPath("  ")).toBe(DEFAULT_LOGO_PATH);
    expect(warn).not.toHaveBeenCalled();
  });

  it("accepts an app-served absolute path", () => {
    expect(resolveLogoPath("/branding/logo.png")).toBe("/branding/logo.png");
    expect(resolveLogoPath("  /branding/logo.svg  ")).toBe(
      "/branding/logo.svg",
    );
    expect(warn).not.toHaveBeenCalled();
  });

  // next/image throws on a src whose host is not in images.remotePatterns, and
  // this renders in the layout wrapping every authenticated page — so a bad
  // value must degrade to the default LOUDLY rather than 500 the whole UI.
  it.each([
    ["https://cdn.example.com/logo.png", "absolute URL"],
    ["//cdn.example.com/logo.png", "protocol-relative URL"],
    ["branding/logo.png", "relative path"],
    ["data:image/png;base64,AAAA", "data URI"],
  ])("rejects %s (%s) and warns", (value) => {
    expect(resolveLogoPath(value)).toBe(DEFAULT_LOGO_PATH);
    expect(warn).toHaveBeenCalledTimes(1);
  });
});

describe("getBranding", () => {
  beforeEach(() => {
    for (const key of Object.keys(envValues)) delete envValues[key];
  });

  it("returns the Umbrella defaults with nothing configured", () => {
    expect(getBranding()).toEqual<Branding>({
      productName: DEFAULT_PRODUCT_NAME,
      orgName: DEFAULT_ORG_NAME,
      logoPath: DEFAULT_LOGO_PATH,
      description: DEFAULT_DESCRIPTION,
    });
  });

  it("applies a full override", () => {
    envValues.NEXT_PUBLIC_BRANDING_PRODUCT_NAME = "Personal MCP Gateway";
    envValues.NEXT_PUBLIC_BRANDING_ORG_NAME = "Ivantsov";
    envValues.NEXT_PUBLIC_BRANDING_LOGO_PATH = "/branding/logo.png";
    envValues.NEXT_PUBLIC_BRANDING_DESCRIPTION = "A personal MCP gateway.";

    expect(getBranding()).toEqual<Branding>({
      productName: "Personal MCP Gateway",
      orgName: "Ivantsov",
      logoPath: "/branding/logo.png",
      description: "A personal MCP gateway.",
    });
  });

  it("overrides each field independently", () => {
    envValues.NEXT_PUBLIC_BRANDING_ORG_NAME = "Ivantsov";

    expect(getBranding()).toEqual<Branding>({
      productName: DEFAULT_PRODUCT_NAME,
      orgName: "Ivantsov",
      logoPath: DEFAULT_LOGO_PATH,
      description: DEFAULT_DESCRIPTION,
    });
  });
});
