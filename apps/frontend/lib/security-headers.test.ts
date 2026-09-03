/**
 * The document CSP holds the script side strict: an inline-script injection is
 * how the transiently-stored downstream MCP OAuth tokens would be read out of
 * sessionStorage, so `script-src` must never carry 'unsafe-inline', and it must
 * not carry 'unsafe-eval' in production, only 'self' plus the per-request
 * nonce. These pin that shape so a later "just add 'unsafe-inline' to fix a
 * script" reintroduces the hole loudly. The one env-dependent relaxation
 * ('unsafe-eval' for `next dev`) is pinned to production-off / development-on.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { buildContentSecurityPolicy, NONCE_HEADER } from "./security-headers";

function cspForEnv(env: string): string {
  vi.stubEnv("NODE_ENV", env);
  try {
    return buildContentSecurityPolicy("TESTNONCE==");
  } finally {
    vi.unstubAllEnvs();
  }
}

function directive(csp: string, name: string): string | undefined {
  return csp
    .split(";")
    .map((d) => d.trim())
    .find((d) => d.startsWith(name));
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("buildContentSecurityPolicy (production)", () => {
  const csp = cspForEnv("production");

  it("carries the nonce in script-src and nothing looser", () => {
    expect(csp).toContain("script-src 'self' 'nonce-TESTNONCE=='");
  });

  it("never allows unsafe-inline or unsafe-eval for scripts", () => {
    const scriptSrc = directive(csp, "script-src");
    expect(scriptSrc).toBeDefined();
    expect(scriptSrc).not.toContain("unsafe-inline");
    expect(scriptSrc).not.toContain("unsafe-eval");
  });

  it("keeps default-src, object-src and base-uri locked down", () => {
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("base-uri 'self'");
  });

  it("denies framing in both directions and pins form-action", () => {
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("frame-src 'none'");
    expect(csp).toContain("form-action 'self'");
  });

  it("keeps connect-src same-origin", () => {
    expect(csp).toContain("connect-src 'self'");
  });

  it("allows unsafe-inline for styles only, not scripts", () => {
    const styleSrc = directive(csp, "style-src");
    // Radix/toast/theme set inline style ATTRIBUTES a nonce cannot cover, so
    // style-src must keep 'unsafe-inline'. It must not also carry a nonce, or
    // browsers ignore 'unsafe-inline' next to it.
    expect(styleSrc).toContain("'unsafe-inline'");
    expect(styleSrc).not.toContain("nonce-");
  });

  it("exposes the nonce request-header name", () => {
    expect(NONCE_HEADER).toBe("x-nonce");
  });
});

describe("buildContentSecurityPolicy (development)", () => {
  const csp = cspForEnv("development");

  it("adds 'unsafe-eval' so `next dev` can run, but never 'unsafe-inline'", () => {
    const scriptSrc = directive(csp, "script-src");
    expect(scriptSrc).toContain("'unsafe-eval'");
    expect(scriptSrc).not.toContain("unsafe-inline");
    expect(scriptSrc).toContain("'nonce-TESTNONCE=='");
  });
});
