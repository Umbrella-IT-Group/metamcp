/**
 * Tests for `isLoopbackRedirectUri`, the predicate that decides whether the
 * consent success branch renders the copy-the-code page (loopback client) or
 * keeps the bare 302 (claude.ai, Claude Desktop).
 *
 * WHY THIS FILE EXISTS. Getting the boundary wrong is not cosmetic. A false
 * positive on a routable host would render an authorization code into an HTML
 * body for a redirect that was supposed to be a server-to-browser 302, and a
 * false negative on a real loopback client would leave the headless flow with
 * the dead-port 302 this change exists to fix. So the suffix look-alikes get
 * their own explicit refusals: `localhost.evil.com` and `127.0.0.1.evil.com`
 * both carry a loopback label and neither is the loopback interface. The
 * helper matches host membership EXACTLY, the same way the two redirect_uri
 * validators alongside it do, which is what keeps the three in agreement.
 */

import { describe, expect, it } from "vitest";

import { isLoopbackRedirectUri } from "./utils";

describe("isLoopbackRedirectUri — loopback hosts", () => {
  it.each([
    ["http://localhost/callback", "localhost, no port"],
    ["http://localhost:49213/callback", "localhost with an ephemeral port"],
    ["http://127.0.0.1/callback", "127.0.0.1, no port"],
    ["http://127.0.0.1:8976/callback", "127.0.0.1 with a port"],
    ["http://[::1]/callback", "bracketed IPv6 ::1, no port"],
    ["http://[::1]:3000/callback", "bracketed IPv6 ::1 with a port"],
    ["http://LocalHost:3000/cb", "case-insensitive host"],
  ])("accepts %s (%s)", (uri) => {
    expect(isLoopbackRedirectUri(uri)).toBe(true);
  });
});

describe("isLoopbackRedirectUri — non-loopback and malformed", () => {
  it.each([
    ["https://claude.ai/api/mcp/auth_callback", "the real remote redirect"],
    ["https://claude.ai/", "a routable https host"],
    // The two that make a suffix rule dangerous: both end in a loopback label.
    ["http://127.0.0.1.evil.com/callback", "127.0.0.1 as a subdomain label"],
    ["http://localhost.evil.com/callback", "localhost as a subdomain label"],
    ["http://evil.localhost.com/callback", "localhost as an inner label"],
    ["http://10.0.0.5/callback", "a private LAN host, not loopback"],
    ["", "empty string"],
    ["not-a-url", "an unparseable value"],
    ["///nonsense", "a value with no host"],
  ])("refuses %s (%s)", (uri) => {
    expect(isLoopbackRedirectUri(uri)).toBe(false);
  });
});
