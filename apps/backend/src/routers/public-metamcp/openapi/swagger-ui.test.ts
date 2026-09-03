/**
 * The Swagger UI page interpolates the endpoint name from the request URL and
 * loads swagger-ui from a CDN. These pin the three hardenings: the name is
 * escaped in both the HTML title and the inline script, the CDN assets carry
 * Subresource Integrity, and the inline bootstrap runs under a nonce the
 * response CSP authorises with no 'unsafe-inline' for scripts.
 */

import { describe, expect, it } from "vitest";

import {
  renderSwaggerUiHtml,
  SWAGGER_UI_CDN_ORIGIN,
  swaggerUiCsp,
  swaggerUiNonce,
} from "./swagger-ui";

describe("renderSwaggerUiHtml escaping", () => {
  // Endpoint names are charset-restricted upstream; this hostile value proves
  // the escaping holds if that rule is ever loosened.
  const hostile = 'a"><script>alert(1)</script>';
  const html = renderSwaggerUiHtml(hostile, "NONCE123");

  it("does not emit the raw injection payload anywhere", () => {
    expect(html).not.toContain("<script>alert(1)</script>");
  });

  it("HTML-escapes the name in the title", () => {
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });

  it("neutralises a script-closing sequence inside the inline bootstrap", () => {
    // The openapi.json URL is JSON-encoded with `<` escaped, so a `</script>`
    // in the name cannot close the element.
    expect(html).toContain("\\u003c/script>");
  });
});

describe("renderSwaggerUiHtml integrity and nonce", () => {
  const html = renderSwaggerUiHtml("weather", "NONCE123");

  it("pins Subresource Integrity on all three CDN assets", () => {
    const integrityCount = (html.match(/integrity="sha384-/g) || []).length;
    expect(integrityCount).toBe(3);
    expect(html).toContain('crossorigin="anonymous"');
  });

  it("only loads swagger-ui from the pinned CDN origin", () => {
    const cdnRefs = html.match(/https:\/\/unpkg\.com/g) || [];
    expect(cdnRefs.length).toBeGreaterThan(0);
    expect(html).toContain(`${SWAGGER_UI_CDN_ORIGIN}/swagger-ui-dist@`);
  });

  it("puts the nonce on the inline script only", () => {
    expect(html).toContain('<script nonce="NONCE123">');
  });

  it("mints a fresh, non-empty nonce each call", () => {
    expect(swaggerUiNonce()).not.toBe(swaggerUiNonce());
    expect(swaggerUiNonce().length).toBeGreaterThan(0);
  });
});

describe("swaggerUiCsp", () => {
  const csp = swaggerUiCsp("NONCE123");

  it("authorises the inline script by nonce, never by unsafe-inline", () => {
    const scriptSrc = csp
      .split(";")
      .map((d) => d.trim())
      .find((d) => d.startsWith("script-src"));
    expect(scriptSrc).toContain("'nonce-NONCE123'");
    expect(scriptSrc).toContain(SWAGGER_UI_CDN_ORIGIN);
    expect(scriptSrc).not.toContain("unsafe-inline");
  });

  it("denies framing", () => {
    expect(csp).toContain("frame-ancestors 'none'");
  });
});
