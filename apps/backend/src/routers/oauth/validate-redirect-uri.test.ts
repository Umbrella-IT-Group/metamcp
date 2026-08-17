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
 * The last block drives the PAIR. `/oauth/authorize` runs this checker and
 * then `isAllowedRedirectUri`, and only a URI both accept reaches a minted
 * code — so "loopback is accepted here" is a claim about one gate, not about
 * the endpoint, and the composed cases are what say which.
 *
 * `NODE_ENV` is stubbed per test rather than set once at module scope so both
 * the production and the non-production expectations can live in one file.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  GATEWAY_INTERNAL_PORT,
  isAllowedRedirectUri,
  validateRedirectUri,
} from "./utils";

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

describe("validateRedirectUri — the optional allowedHosts narrowing", () => {
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

  it("matches an IPv6 entry in either spelling", () => {
    // The parser reports IPv6 hosts bracketed, so a raw comparison made the
    // unbracketed `::1` — the spelling an operator would write, and the one
    // LOOPBACK_HOSTNAMES uses — silently never match.
    vi.stubEnv("NODE_ENV", "production");
    for (const entry of ["::1", "[::1]"]) {
      expect(validateRedirectUri("http://[::1]:9/cb", [entry])).toBe(true);
    }
    expect(validateRedirectUri("http://[::1]:9/cb", ["127.0.0.1"])).toBe(false);
  });

  it("normalises entry case and surrounding whitespace", () => {
    // A raw comparison meant an uppercase entry matched nothing at all, since
    // the parser lowercases the host it reports.
    vi.stubEnv("NODE_ENV", "production");
    for (const entry of ["EXAMPLE.COM", "  example.com  ", "Example.Com"]) {
      expect(validateRedirectUri("https://example.com/cb", [entry])).toBe(true);
    }
  });

  it("treats an EMPTY array as no restriction, unlike resolveDcrAllowedHosts", () => {
    // Deliberate, and deliberately different from the sibling: an empty value
    // for DCR_REDIRECT_URI_ALLOWED_HOSTS is documented as a configured
    // "loopback only", whereas this parameter is an optional narrowing a
    // caller opts into and an empty array is nothing opted into. The two are
    // reached differently — the env is operator configuration, this is an
    // argument — and no caller passes this one today. Pinned so the divergence
    // is a decision on the record rather than something to be discovered.
    vi.stubEnv("NODE_ENV", "production");
    expect(validateRedirectUri("https://example.com/cb", [])).toBe(true);
    expect(validateRedirectUri("http://127.0.0.1:8080/cb", [])).toBe(true);
  });
});

describe("the composed authorize gate — both checkers in sequence", () => {
  // `/oauth/authorize` runs validateRedirectUri and THEN isAllowedRedirectUri,
  // so a URI reaches a minted code only if both accept it. Asserting the pair
  // is what stops this change from being read as "loopback is now accepted at
  // authorize" when the second gate still has the final say.

  it("accepts a loopback callback through BOTH gates under production", () => {
    vi.stubEnv("NODE_ENV", "production");
    for (const uri of LOOPBACK_URIS) {
      expect(validateRedirectUri(uri)).toBe(true);
      expect(isAllowedRedirectUri(uri)).toEqual({ ok: true });
    }
  });

  it("lets the second gate refuse what the first one does not", () => {
    // Both shapes pass validateRedirectUri — https, non-loopback, not a
    // private range — and both are refused before a code is minted. This is
    // the half of the pair that the loopback change must not weaken.
    vi.stubEnv("NODE_ENV", "production");

    const userinfo = "https://claude.ai@evil.example.com/cb";
    expect(validateRedirectUri(userinfo)).toBe(true);
    const userinfoCheck = isAllowedRedirectUri(userinfo);
    expect(userinfoCheck.ok).toBe(false);
    if (!userinfoCheck.ok) {
      expect(userinfoCheck.reason).toBe("userinfo_present");
    }

    const offAllowlist = "https://evil.example.com/cb";
    expect(validateRedirectUri(offAllowlist)).toBe(true);
    const hostCheck = isAllowedRedirectUri(offAllowlist);
    expect(hostCheck.ok).toBe(false);
    if (!hostCheck.ok) {
      expect(hostCheck.reason).toBe("host_not_allowed");
    }
  });

  it("refuses the gateway's own loopback port at the second gate", () => {
    // The one loopback shape the first gate now accepts and the second must
    // not: nothing external listens on the gateway's internal port, so a
    // redirect there is only ever the server being pointed at itself.
    vi.stubEnv("NODE_ENV", "production");

    const uri = `http://127.0.0.1:${GATEWAY_INTERNAL_PORT}/cb`;
    expect(validateRedirectUri(uri)).toBe(true);
    const check = isAllowedRedirectUri(uri);
    expect(check.ok).toBe(false);
    if (!check.ok) expect(check.reason).toBe("gateway_internal_port");
  });
});
