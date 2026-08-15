/**
 * Tests for the registration-time redirect_uri gate — a HIGH-severity
 * security review finding: redirect_uri was validated by scheme only.
 *
 * The review registered all of the URIs in REJECTED_URI_CASES below and got a
 * 201 for every one of them; only `javascript:` and `data:` were refused.
 * Because `POST /oauth/register` takes no credential, each of those 201s is a
 * client a signed-in human can be phished into approving on the consent
 * screen, with the authorization code landing on the attacker's host. So
 * every case here is a URI that WAS accepted and must not be again.
 *
 * The other half matters just as much and is asserted just as explicitly: the
 * allowlist is default-on, so LEGIT_CASES pins the shapes the 65 already-
 * registered clients actually use — loopback on any port, plus the two
 * Anthropic connector callbacks. A change that broke one of those would take
 * the live Claude connectors down.
 *
 * Both the pure function and the registration core it gates are driven, the
 * second so the RFC 7591 error contract is pinned alongside the rule.
 */

import { readFileSync } from "node:fs";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { buildClientRegistration } from "./client-registration";
import {
  DCR_REDIRECT_URI_ALLOWED_HOSTS_ENV,
  DEFAULT_DCR_REDIRECT_URI_ALLOWED_HOSTS,
  GATEWAY_INTERNAL_PORT,
  isAllowedRedirectUri,
  RedirectUriRejectionReason,
  resolveDcrAllowedHosts,
} from "./utils";

/**
 * Every URI the security review got a 201 for, paired with the rule
 * that now refuses it. Pinning the REASON and not just the boolean is what
 * stops a future edit from passing this suite for the wrong reason (e.g. a
 * scheme bug that happens to reject the userinfo case).
 */
const REJECTED_URI_CASES: ReadonlyArray<[string, RedirectUriRejectionReason]> =
  [
    ["https://evil.com/callback", "host_not_allowed"],
    ["https://your-gateway.example.com.evil.com/callback", "host_not_allowed"],
    // Real host is evil.com; the part that reads as ours is userinfo.
    ["https://your-gateway.example.com@evil.com/callback", "userinfo_present"],
    ["http://localhost:12009/callback", "gateway_internal_port"],
    ["https://claude.ai/api/mcp/auth_callback#stolen", "fragment_present"],
    ["http://evil.com/callback", "insecure_scheme_non_loopback"],
    // A loopback label as a PREFIX — what a `startsWith` test would let through.
    ["http://localhost.evil.com/callback", "insecure_scheme_non_loopback"],
    ["https://localhost.evil.com/callback", "host_not_allowed"],
    ["https://127.0.0.1.evil.com/callback", "host_not_allowed"],
    // A loopback label as a SUFFIX — what an `endsWith` test would let through.
    // `evil.localhost` and `notlocalhost` both end in the string "localhost"
    // and neither is the loopback interface.
    ["http://evil.localhost/callback", "insecure_scheme_non_loopback"],
    ["https://evil.localhost/callback", "host_not_allowed"],
    ["https://notlocalhost/callback", "host_not_allowed"],
    ["https://x.127.0.0.1.example/callback", "host_not_allowed"],
  ];

/**
 * The shapes the live client rows actually use. Loopback covers the installed
 * clients (MCP Inspector, Claude Code) which bind an ephemeral port; the two
 * https entries are the Anthropic connector callbacks.
 */
const LEGIT_CASES: readonly string[] = [
  "http://localhost/callback",
  "http://localhost:3118/callback",
  "http://127.0.0.1:49372/callback",
  "http://[::1]:49372/callback",
  "https://claude.ai/api/mcp/auth_callback",
  "https://claude.com/api/mcp/auth_callback",
];

const ENV_BEFORE = process.env[DCR_REDIRECT_URI_ALLOWED_HOSTS_ENV];

afterEach(() => {
  if (ENV_BEFORE === undefined) {
    delete process.env[DCR_REDIRECT_URI_ALLOWED_HOSTS_ENV];
  } else {
    process.env[DCR_REDIRECT_URI_ALLOWED_HOSTS_ENV] = ENV_BEFORE;
  }
});

describe("isAllowedRedirectUri — the security review cases", () => {
  it.each(REJECTED_URI_CASES)("rejects %s (%s)", (uri, reason) => {
    const result = isAllowedRedirectUri(uri);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe(reason);
  });

  it("rejects every non-http(s) scheme, not just javascript:/data:", () => {
    for (const uri of [
      "javascript:alert(1)",
      "data:text/html,<script>1</script>",
      "myapp://callback",
      "file:///etc/passwd",
      "ftp://evil.com/cb",
    ]) {
      const result = isAllowedRedirectUri(uri);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toBe("unsupported_scheme");
    }
  });

  it("rejects unparseable input and non-strings", () => {
    expect(isAllowedRedirectUri("not a url")).toEqual({
      ok: false,
      reason: "unparseable",
    });
    expect(isAllowedRedirectUri("")).toEqual({
      ok: false,
      reason: "unparseable",
    });
    for (const value of [12345, null, undefined, {}, ["https://claude.ai"]]) {
      expect(isAllowedRedirectUri(value)).toEqual({
        ok: false,
        reason: "not_a_string",
      });
    }
  });

  it("rejects userinfo even when the host itself IS allowlisted", () => {
    // The mirror of the lookalike-host trick: here the readable part is the evil
    // host and the real one is ours. Still refused — a URI whose authority a
    // human and a parser disagree about has no business in a client record.
    const result = isAllowedRedirectUri("https://evil.com@claude.ai/callback");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("userinfo_present");
  });

  it("rejects a password-only userinfo", () => {
    const result = isAllowedRedirectUri("https://:secret@claude.ai/callback");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("userinfo_present");
  });

  it("rejects a fragment on a loopback URI too", () => {
    const result = isAllowedRedirectUri("http://127.0.0.1:8080/cb#x");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("fragment_present");
  });

  it("rejects the gateway's internal port on every loopback spelling", () => {
    for (const host of ["localhost", "127.0.0.1", "[::1]"]) {
      const result = isAllowedRedirectUri(
        `http://${host}:${GATEWAY_INTERNAL_PORT}/callback`,
      );
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toBe("gateway_internal_port");
    }
  });

  it("treats loopback membership as EXACT in both directions", () => {
    // Pinned as its own case because a prefix test and a suffix test fail
    // differently and only one of them is the obvious bug. `localhost.evil.com`
    // starts with a loopback label; `evil.localhost` ends with one. Neither is
    // the loopback interface, and treating either as loopback would hand an
    // attacker's host the "any port, plain http, no allowlist" exemption.
    for (const hostname of [
      "localhost.evil.com",
      "127.0.0.1.evil.com",
      "evil.localhost",
      "notlocalhost",
      "x.127.0.0.1.example",
      "localhost.",
    ]) {
      const result = isAllowedRedirectUri(`https://${hostname}:8080/cb`);
      expect(result.ok, `${hostname} must not be treated as loopback`).toBe(
        false,
      );
      if (!result.ok) expect(result.reason).toBe("host_not_allowed");
    }
  });

  it("does not accept an allowlisted host as a SUFFIX", () => {
    // `evil-claude.ai` and `claude.ai.evil.com` both contain the allowlisted
    // string. Exact match is the only thing that separates them from the
    // real host.
    for (const uri of [
      "https://evil-claude.ai/cb",
      "https://claude.ai.evil.com/cb",
      "https://notclaude.com/cb",
    ]) {
      const result = isAllowedRedirectUri(uri);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toBe("host_not_allowed");
    }
  });

  it("does not accept arbitrary subdomains of an allowlisted host", () => {
    // Deliberate: user-controlled content has lived on vendor subdomains
    // before, and an allowlist that grants `*.claude.ai` grants those too.
    const result = isAllowedRedirectUri("https://evil.claude.ai/cb");
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("host_not_allowed");
  });
});

describe("isAllowedRedirectUri — the clients that actually exist", () => {
  it.each(LEGIT_CASES)("accepts %s", (uri) => {
    expect(isAllowedRedirectUri(uri)).toEqual({ ok: true });
  });

  it("accepts every default-allowlisted host", () => {
    for (const host of DEFAULT_DCR_REDIRECT_URI_ALLOWED_HOSTS) {
      expect(isAllowedRedirectUri(`https://${host}/callback`)).toEqual({
        ok: true,
      });
    }
  });

  it("accepts a loopback callback on an arbitrary ephemeral port", () => {
    // An installed client does not get to choose its port, so anything but
    // "any port except the gateway's own" would break them at random.
    for (const port of [1024, 3000, 8080, 49152, 65535]) {
      expect(isAllowedRedirectUri(`http://127.0.0.1:${port}/callback`)).toEqual(
        { ok: true },
      );
    }
  });

  it("normalises host case rather than refusing it", () => {
    expect(isAllowedRedirectUri("https://CLAUDE.AI/callback")).toEqual({
      ok: true,
    });
  });
});

describe("resolveDcrAllowedHosts — operator override", () => {
  it("uses the built-in default when the env is absent", () => {
    delete process.env[DCR_REDIRECT_URI_ALLOWED_HOSTS_ENV];
    expect(resolveDcrAllowedHosts()).toEqual([
      ...DEFAULT_DCR_REDIRECT_URI_ALLOWED_HOSTS,
    ]);
  });

  it("REPLACES the default rather than extending it", () => {
    process.env[DCR_REDIRECT_URI_ALLOWED_HOSTS_ENV] =
      " Partner.Example.com , other.example.net ";

    expect(resolveDcrAllowedHosts()).toEqual([
      "partner.example.com",
      "other.example.net",
    ]);

    expect(isAllowedRedirectUri("https://partner.example.com/cb")).toEqual({
      ok: true,
    });
    // The default hosts are gone, because "replaces" is what the operator
    // needs in order to remove one of ours.
    const claude = isAllowedRedirectUri("https://claude.ai/cb");
    expect(claude.ok).toBe(false);
    if (!claude.ok) expect(claude.reason).toBe("host_not_allowed");
  });

  it("treats an empty env value as 'loopback only', not as unset", () => {
    process.env[DCR_REDIRECT_URI_ALLOWED_HOSTS_ENV] = "";
    expect(resolveDcrAllowedHosts()).toEqual([]);

    const claude = isAllowedRedirectUri("https://claude.ai/cb");
    expect(claude.ok).toBe(false);
    if (!claude.ok) expect(claude.reason).toBe("host_not_allowed");

    // Loopback is allowed regardless of the allowlist — it is not a host
    // decision, it is the installed-client case.
    expect(isAllowedRedirectUri("http://127.0.0.1:5000/cb")).toEqual({
      ok: true,
    });
  });

  it("honours an explicit allowedHosts argument over the env", () => {
    process.env[DCR_REDIRECT_URI_ALLOWED_HOSTS_ENV] = "env.example.com";
    expect(
      isAllowedRedirectUri("https://arg.example.com/cb", {
        allowedHosts: ["arg.example.com"],
      }),
    ).toEqual({ ok: true });
  });
});

describe("buildClientRegistration — the redirect_uri gate at the registration surface", () => {
  it("refuses every security review URI with the RFC 7591 error contract intact", () => {
    for (const [uri] of REJECTED_URI_CASES) {
      const result = buildClientRegistration({ redirect_uris: [uri] });
      expect(result.ok).toBe(false);
      if (result.ok) continue;
      // The 400 body shape `/oauth/register` has always emitted.
      expect(result.error).toBe("invalid_redirect_uri");
      expect(result.error_description).toContain(
        `Invalid redirect URI: ${uri}`,
      );
      expect(result.error_description).toContain(
        "Must use secure scheme and valid format.",
      );
    }
  });

  it("still registers every client shape that exists today", () => {
    // The load-bearing half of the fix: locking DCR to Claude + loopback
    // must not take the live connectors down.
    const result = buildClientRegistration({
      redirect_uris: [...LEGIT_CASES],
      client_name: "Claude",
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.client.redirect_uris).toEqual([...LEGIT_CASES]);
    }
  });

  it("refuses the whole registration when only ONE uri is evil", () => {
    // A client is only as safe as its loosest redirect_uri: the authorize
    // endpoint accepts any entry in the array.
    const result = buildClientRegistration({
      redirect_uris: [
        "https://claude.ai/api/mcp/auth_callback",
        "https://evil.com/callback",
      ],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("invalid_redirect_uri");
      expect(result.error_description).toContain("https://evil.com/callback");
    }
  });
});

describe("GATEWAY_INTERNAL_PORT stays in step with the listener", () => {
  it("matches the port apps/backend/src/index.ts listens on", () => {
    // The constant is a second copy of a number that lives in index.ts. This
    // reads the original back rather than trusting the comment next to it —
    // if the listener ever moves, the loopback port ban would otherwise go on
    // guarding a port nothing serves.
    const indexPath = path.resolve(__dirname, "../../index.ts");
    const source = readFileSync(indexPath, "utf8");
    const match = source.match(/app\.listen\(\s*(\d+)/);

    expect(match).not.toBeNull();
    expect(Number(match?.[1])).toBe(GATEWAY_INTERNAL_PORT);
  });
});
