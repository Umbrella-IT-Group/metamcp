/**
 * The consent document's form-action widening: the ONLY origin it may add is the
 * scheme+host of the redirect_uri carried by the request's own areq, and only on
 * the consent path. These pin that a genuine claude.ai / loopback areq widens to
 * exactly one host-source, that every malformed or out-of-shape input widens to
 * nothing (never a partial or CSP-breaking source), and that the signature is
 * NOT consulted (the backend verifies it at decision time; see the module doc).
 */

import { describe, expect, it } from "vitest";

import {
  consentFormActionSources,
  consentRedirectOrigin,
  isConsentDocumentPath,
} from "./consent-form-action";

function areqFor(payload: unknown, signature = "deadbeef"): string {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${encoded}.${signature}`;
}

const CLAUDE = areqFor({
  client_id: "mcp_client_x",
  redirect_uri: "https://claude.ai/api/mcp/auth_callback",
  cid: "abc",
  csrf: "nonce",
  exp: 1,
});

describe("isConsentDocumentPath", () => {
  it("matches the consent document with or without a locale segment", () => {
    expect(isConsentDocumentPath("/consent")).toBe(true);
    expect(isConsentDocumentPath("/en/consent")).toBe(true);
    expect(isConsentDocumentPath("/zh/consent")).toBe(true);
  });

  it("does not match anything else", () => {
    for (const p of [
      "/en/login",
      "/en/consent/x",
      "/consent-x",
      "/oauth/consent/info",
      "/",
    ]) {
      expect(isConsentDocumentPath(p)).toBe(false);
    }
  });
});

describe("consentRedirectOrigin", () => {
  it("returns the scheme+host of a claude.ai redirect", () => {
    expect(consentRedirectOrigin(CLAUDE)).toBe("https://claude.ai");
    expect(
      consentRedirectOrigin(
        areqFor({ redirect_uri: "https://claude.com/api/mcp/auth_callback" }),
      ),
    ).toBe("https://claude.com");
  });

  it("keeps the port for loopback redirects (Claude Code, OpenCode)", () => {
    expect(
      consentRedirectOrigin(
        areqFor({ redirect_uri: "http://localhost:3118/callback" }),
      ),
    ).toBe("http://localhost:3118");
    expect(
      consentRedirectOrigin(
        areqFor({ redirect_uri: "http://127.0.0.1:19876/mcp/oauth/callback" }),
      ),
    ).toBe("http://127.0.0.1:19876");
    expect(
      consentRedirectOrigin(
        areqFor({ redirect_uri: "http://[::1]:3118/callback" }),
      ),
    ).toBe("http://[::1]:3118");
  });

  it("drops a default port the way the browser's origin does", () => {
    expect(
      consentRedirectOrigin(
        areqFor({ redirect_uri: "https://claude.ai:443/cb" }),
      ),
    ).toBe("https://claude.ai");
  });

  it("does not consult the signature", () => {
    expect(
      consentRedirectOrigin(
        areqFor({ redirect_uri: "https://claude.ai/cb" }, ""),
      ),
    ).toBe("https://claude.ai");
    const noDot = areqFor({ redirect_uri: "https://claude.ai/cb" }).split(
      ".",
    )[0];
    expect(consentRedirectOrigin(noDot)).toBe("https://claude.ai");
  });

  it("widens to nothing for anything missing or malformed", () => {
    expect(consentRedirectOrigin(null)).toBeNull();
    expect(consentRedirectOrigin(undefined)).toBeNull();
    expect(consentRedirectOrigin("")).toBeNull();
    expect(consentRedirectOrigin("x")).toBeNull();
    expect(consentRedirectOrigin("not base64url!.sig")).toBeNull();
    expect(
      consentRedirectOrigin(Buffer.from("not json").toString("base64url")),
    ).toBeNull();
    expect(consentRedirectOrigin(areqFor("a string payload"))).toBeNull();
    expect(consentRedirectOrigin(areqFor({ client_id: "x" }))).toBeNull();
    expect(consentRedirectOrigin(areqFor({ redirect_uri: 42 }))).toBeNull();
    expect(
      consentRedirectOrigin(areqFor({ redirect_uri: "not a url" })),
    ).toBeNull();
    expect(consentRedirectOrigin("a".repeat(9000))).toBeNull();
  });

  it("refuses redirect shapes the backend never registers", () => {
    expect(
      consentRedirectOrigin(areqFor({ redirect_uri: "myapp://callback" })),
    ).toBeNull();
    expect(
      consentRedirectOrigin(areqFor({ redirect_uri: "javascript:alert(1)" })),
    ).toBeNull();
    expect(
      consentRedirectOrigin(
        areqFor({ redirect_uri: "https://user:pw@evil.example/cb" }),
      ),
    ).toBeNull();
    expect(
      consentRedirectOrigin(areqFor({ redirect_uri: "file:///etc/passwd" })),
    ).toBeNull();
  });

  it("never emits a source that could break out of the directive", () => {
    for (const bad of [
      "https://evil.example;script-src 'unsafe-inline'/cb",
      "https://evil.example 'unsafe-inline'/cb",
      "https://evil.example%20https://x/cb",
    ]) {
      const out = consentRedirectOrigin(areqFor({ redirect_uri: bad }));
      // Either refused outright, or normalised by URL parsing to a clean host.
      expect(out === null || /^https:\/\/[A-Za-z0-9.-]+$/.test(out)).toBe(true);
      expect(out ?? "").not.toMatch(/[;' ]/);
    }
  });
});

describe("consentFormActionSources", () => {
  it("adds exactly the redirect origin on the consent document", () => {
    expect(consentFormActionSources("/en/consent", CLAUDE)).toEqual([
      "https://claude.ai",
    ]);
    expect(consentFormActionSources("/consent", CLAUDE)).toEqual([
      "https://claude.ai",
    ]);
  });

  it("adds nothing off the consent path, even with a valid areq", () => {
    expect(consentFormActionSources("/en/login", CLAUDE)).toEqual([]);
    expect(consentFormActionSources("/en/namespaces", CLAUDE)).toEqual([]);
  });

  it("adds nothing on the consent path without a usable areq", () => {
    expect(consentFormActionSources("/en/consent", null)).toEqual([]);
    expect(consentFormActionSources("/en/consent", "garbage")).toEqual([]);
  });
});
