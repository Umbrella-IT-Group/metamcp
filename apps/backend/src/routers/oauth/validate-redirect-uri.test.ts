/**
 * Tests for `validateRedirectUri`, the production-only half of the
 * `/oauth/authorize` redirect_uri gate.
 *
 * WHY THIS FILE EXISTS. The function's rules are all conditioned on
 * `NODE_ENV`, and nothing pinned them — the sibling suite
 * (`redirect-uri-allowlist.test.ts`) drives `isAllowedRedirectUri`, which
 * deliberately has no NODE_ENV branch at all. So the one checker whose
 * behaviour CHANGES between a dev run and a production deploy was the one
 * with no coverage, and the difference was only ever observable by deploying.
 *
 * The case that bites is `accepts a loopback callback under production`.
 * RFC 8252 §7.3 has a native app receive its authorization code on
 * `http://127.0.0.1:<ephemeral>` — plain http, on a port the OS hands out at
 * runtime — because there is no other loopback shape an installed client can
 * use. Refusing that shape does not harden anything reachable from the
 * network; it removes the only redirect an installed client has, so every
 * such client breaks the moment NODE_ENV is set to `production`.
 *
 * The other half is asserted just as explicitly: RFC 1918 hosts and plain
 * http on a routable host stay refused under production. Loopback is exempt
 * because the loopback interface is not reachable from off-box, which is not
 * true of `192.168.1.5`.
 *
 * `NODE_ENV` is stubbed per test rather than set once at module scope so both
 * the production and the non-production expectations can live in one file.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { validateRedirectUri } from "./utils";

/**
 * The loopback shapes RFC 8252 §7.3 names: `localhost`, the IPv4 literal, and
 * the IPv6 literal. All three over plain http, on ports an installed client
 * did not choose — including the reserved-but-parseable `:9` — because
 * "whatever the OS handed us" is the only port an installed client can offer.
 */
const LOOPBACK_URIS: readonly string[] = [
  "http://localhost:54321/callback",
  "http://127.0.0.1:8080/cb",
  "http://[::1]:9/cb",
];

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("validateRedirectUri — loopback under NODE_ENV=production", () => {
  it.each(LOOPBACK_URIS)("accepts %s", (uri) => {
    vi.stubEnv("NODE_ENV", "production");
    expect(validateRedirectUri(uri)).toBe(true);
  });

  it("accepts loopback on any port, not a fixed one", () => {
    // An installed client binds an ephemeral port it does not get to choose,
    // so a port-restricted rule would break clients at random.
    vi.stubEnv("NODE_ENV", "production");
    for (const port of [1024, 3000, 8080, 49152, 65535]) {
      expect(validateRedirectUri(`http://127.0.0.1:${port}/callback`)).toBe(
        true,
      );
    }
  });

  it("accepts loopback in development too", () => {
    // The exemption is unconditional; nothing about it is environment-shaped.
    vi.stubEnv("NODE_ENV", "development");
    for (const uri of LOOPBACK_URIS) {
      expect(validateRedirectUri(uri)).toBe(true);
    }
  });
});

describe("validateRedirectUri — what production still refuses", () => {
  it("refuses an RFC 1918 host", () => {
    // A private-range address is reachable by anything else on the LAN, so it
    // gets none of the loopback exemption's reasoning.
    vi.stubEnv("NODE_ENV", "production");
    for (const uri of [
      "http://192.168.1.5/cb",
      "http://10.0.0.7/cb",
      "http://172.16.0.3/cb",
    ]) {
      expect(validateRedirectUri(uri)).toBe(false);
    }
  });

  it("refuses an RFC 1918 host over https as well", () => {
    // The private-range rule is about the host, not the scheme — https to a
    // LAN address is still a callback this server cannot reason about.
    vi.stubEnv("NODE_ENV", "production");
    expect(validateRedirectUri("https://192.168.1.5/cb")).toBe(false);
  });

  it("refuses plain http on a routable host", () => {
    vi.stubEnv("NODE_ENV", "production");
    expect(validateRedirectUri("http://example.com/cb")).toBe(false);
  });

  it("accepts https on a routable host", () => {
    vi.stubEnv("NODE_ENV", "production");
    expect(validateRedirectUri("https://example.com/cb")).toBe(true);
  });

  it("refuses every non-http(s) scheme", () => {
    vi.stubEnv("NODE_ENV", "production");
    for (const uri of [
      "javascript:alert(1)",
      "data:text/html,<script>1</script>",
      "myapp://callback",
      "file:///etc/passwd",
    ]) {
      expect(validateRedirectUri(uri)).toBe(false);
    }
  });

  it("refuses unparseable input", () => {
    vi.stubEnv("NODE_ENV", "production");
    expect(validateRedirectUri("not a url")).toBe(false);
    expect(validateRedirectUri("")).toBe(false);
  });

  it("still applies an explicit allowedHosts argument to a loopback URI", () => {
    // The loopback exemption is from the NODE_ENV rules only. A caller that
    // passes an explicit host list is stating the whole set of acceptable
    // hosts, and loopback is not silently added to it.
    vi.stubEnv("NODE_ENV", "production");
    expect(
      validateRedirectUri("http://localhost:54321/cb", ["example.com"]),
    ).toBe(false);
    expect(
      validateRedirectUri("http://localhost:54321/cb", ["localhost"]),
    ).toBe(true);
  });

  it("does not treat a loopback label as loopback when it is a prefix or suffix", () => {
    // `localhost.evil.com` starts with a loopback label and `evil.localhost`
    // ends with one; neither is the loopback interface, so neither may inherit
    // the plain-http exemption.
    vi.stubEnv("NODE_ENV", "production");
    for (const host of [
      "localhost.evil.com",
      "127.0.0.1.evil.com",
      "evil.localhost",
      "notlocalhost",
    ]) {
      expect(validateRedirectUri(`http://${host}/cb`)).toBe(false);
    }
  });
});
