/**
 * The client metadata document (CIMD) id grammar, the allowlist and the
 * kill-switch predicate.
 *
 * Oracles. The id rules are the OAuth Client ID Metadata Document draft's
 * "Client Identifier URL" requirements (draft-ietf-oauth-client-id-metadata-
 * document, section 3), read from the published text on 2026-11-12:
 *   "MUST use the `https` URL scheme"
 *   "MUST contain a path component other than `/`"
 *   "MUST NOT contain single-dot or double-dot path components"
 *   "MUST NOT contain a fragment component"
 *   "MUST NOT contain a userinfo component"
 *   "SHOULD NOT contain a query component"
 * and the MCP authorization spec's client test, mirrored by the SDK client's
 * `isHttpsUrl` (https with a non-root path). Beyond the draft, this gateway
 * refuses a query, requires the one canonical spelling, and refuses an
 * IP-literal host: those rows are marked "design decision". Allowlist
 * admission follows mcp-use `clients.ts` (an exact URL, or an https origin).
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const loggerMock = vi.hoisted(() => ({
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
}));
vi.mock("@/utils/logger", () => ({ default: loggerMock }));

const config = await import("./cimd-config");
const {
  checkCimdClientId,
  cimdClientIdHost,
  getCimdAllowlist,
  isCimdClientAdmitted,
  isCimdEnabled,
  isCimdRowBlocked,
  looksLikeCimdClientId,
  OAUTH_CIMD_ALLOWED_CLIENTS_ENV,
  parseCimdAllowlist,
  resetCimdConfigForTesting,
} = config;

beforeEach(() => {
  delete process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV];
  resetCimdConfigForTesting();
  vi.clearAllMocks();
});

describe("checkCimdClientId", () => {
  const long = (length: number) =>
    `https://example.com/${"a".repeat(length - "https://example.com/".length)}`;

  it.each([
    ["a plain https path", "https://example.com/oauth/client-metadata.json"],
    ["a port", "https://example.com:8443/client.json"],
    ["a sub-domain host", "https://app.example.com/c"],
    [
      "percent-encoded characters already in canonical form",
      "https://example.com/a%20b",
    ],
    ["exactly 512 characters", long(512)],
  ])("accepts %s", (_name, id) => {
    expect(checkCimdClientId(id).ok).toBe(true);
  });

  it.each([
    ["http scheme", "http://example.com/client.json", "not_https"],
    [
      "the root path (draft: path other than /)",
      "https://example.com/",
      "root_path",
    ],
    ["no path at all", "https://example.com", "root_path"],
    [
      "a fragment (draft: MUST NOT)",
      "https://example.com/c#frag",
      "query_or_fragment",
    ],
    ["an empty fragment mark", "https://example.com/c#", "query_or_fragment"],
    ["userinfo (draft: MUST NOT)", "https://user@example.com/c", "userinfo"],
    ["userinfo with a password", "https://user:pw@example.com/c", "userinfo"],
    ["an empty userinfo", "https://@example.com/c", "not_canonical"],
    [
      "a dot segment (draft: MUST NOT)",
      "https://example.com/a/./c",
      "not_canonical",
    ],
    [
      "a double-dot segment (draft: MUST NOT)",
      "https://example.com/a/../c",
      "not_canonical",
    ],
    [
      "a query (design decision)",
      "https://example.com/c?x=1",
      "query_or_fragment",
    ],
    [
      "an empty query mark (design decision)",
      "https://example.com/c?",
      "query_or_fragment",
    ],
    [
      "an uppercase host (design decision)",
      "https://Example.com/c",
      "not_canonical",
    ],
    [
      "the default port (design decision)",
      "https://example.com:443/c",
      "not_canonical",
    ],
    [
      "an unencoded space (design decision)",
      "https://example.com/a b",
      "not_canonical",
    ],
    [
      "a backslash (design decision)",
      "https://example.com/a\\b",
      "not_canonical",
    ],
    [
      "a Unicode host, not punycode (design decision)",
      "https://bücher.example/c",
      "not_canonical",
    ],
    [
      "an IPv4 literal (design decision)",
      "https://203.0.113.9/c",
      "ip_literal",
    ],
    [
      "an IPv6 literal (design decision)",
      "https://[2001:db8::1]/c",
      "ip_literal",
    ],
    ["513 characters", long(513), "length"],
    ["an empty string", "", "length"],
    ["not a URL", "not a url", "unparsable"],
  ])("refuses %s", (_name, id, reason) => {
    expect(checkCimdClientId(id)).toEqual({ ok: false, reason });
  });

  it.each([undefined, null, 5, {}, ["https://example.com/c"]])(
    "refuses a non-string (%j)",
    (value) => {
      expect(checkCimdClientId(value)).toEqual({
        ok: false,
        reason: "not_a_string",
      });
    },
  );

  it("returns the host and origin of an accepted id", () => {
    expect(checkCimdClientId("https://example.com:8443/c")).toEqual({
      ok: true,
      host: "example.com:8443",
      origin: "https://example.com:8443",
    });
    expect(cimdClientIdHost("https://example.com:8443/c")).toBe(
      "example.com:8443",
    );
  });
});

describe("looksLikeCimdClientId", () => {
  // The SDK client's own test: https with a non-root path (client/auth.js
  // `isHttpsUrl`). Broad on purpose: it only decides whether the authorize
  // handler considers resolving, and it must never throw on a query value.
  it.each([
    ["https://example.com/c", true],
    ["https://example.com/c?x=1", true],
    ["https://example.com/", false],
    ["http://example.com/c", false],
    ["mcp_client_abc123", false],
    ["", false],
    [undefined, false],
    [["https://example.com/c"], false],
    [{ href: "https://example.com/c" }, false],
  ])("%j -> %s", (value, expected) => {
    expect(looksLikeCimdClientId(value)).toBe(expected);
  });
});

describe("parseCimdAllowlist", () => {
  it("separates exact URLs from origins, with or without a trailing slash", () => {
    const list = parseCimdAllowlist(
      "https://a.example/oauth/client.json, https://b.example , https://c.example/",
    );
    expect([...list.urls]).toEqual(["https://a.example/oauth/client.json"]);
    expect([...list.origins]).toEqual([
      "https://b.example",
      "https://c.example",
    ]);
    expect(list.dropped).toEqual([]);
  });

  // An entry that is not understood admits nothing: it is dropped, never
  // widened into something it might have meant.
  it.each([
    "claude.ai",
    "http://a.example/c",
    "https://a.example/c?x=1",
    "https://a.example/c#f",
    "https://user@a.example/c",
    "https://A.example/c",
    "https://A.example",
    "https://a.example:443/c",
    "https://a.example/a/../c",
    "https://203.0.113.9/c",
    "https://203.0.113.9",
    `https://a.example/${"x".repeat(520)}`,
    "ftp://a.example/c",
  ])("drops %s", (entry) => {
    const list = parseCimdAllowlist(entry);
    expect(list.urls.size + list.origins.size).toBe(0);
    expect(list.dropped).toEqual([entry]);
  });

  it("is empty for undefined, empty and whitespace-only input", () => {
    for (const raw of [undefined, "", " , ,"]) {
      const list = parseCimdAllowlist(raw);
      expect(list.urls.size + list.origins.size).toBe(0);
      expect(list.dropped).toEqual([]);
    }
  });
});

describe("getCimdAllowlist and isCimdEnabled", () => {
  it("is disabled when the variable is unset or empty", () => {
    expect(isCimdEnabled()).toBe(false);
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = "   ";
    expect(isCimdEnabled()).toBe(false);
  });

  it("is disabled when every entry is dropped, and warns once per entry with a JSON-quoted, clamped value", () => {
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = `claude.ai,http://x`;
    expect(isCimdEnabled()).toBe(false);
    expect(isCimdEnabled()).toBe(false);
    const warnings = loggerMock.warn.mock.calls.map((call) => String(call[0]));
    // Memoized on the raw string: parsed, and warned about, once.
    expect(warnings).toHaveLength(2);
    expect(warnings[0]).toContain(JSON.stringify("claude.ai"));
    expect(warnings[1]).toContain(JSON.stringify("http://x"));
  });

  it("clamps and escapes a hostile dropped entry in the log line", () => {
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] =
      `x\nforged line ${"y".repeat(400)}`;
    getCimdAllowlist();
    const line = String(loggerMock.warn.mock.calls[0][0]);
    expect(line).not.toContain("\n");
    expect(line.length).toBeLessThan(400);
  });

  it("reads the variable per call, so a changed value takes effect", () => {
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = "https://a.example/c";
    expect(isCimdEnabled()).toBe(true);
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = "";
    expect(isCimdEnabled()).toBe(false);
  });
});

describe("isCimdClientAdmitted", () => {
  it("admits an exact URL and nothing else under its origin", () => {
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] =
      "https://app.example/oauth/client.json";
    expect(isCimdClientAdmitted("https://app.example/oauth/client.json")).toBe(
      true,
    );
    expect(isCimdClientAdmitted("https://app.example/oauth/other.json")).toBe(
      false,
    );
  });

  it("admits every canonical id under an origin entry", () => {
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = "https://app.example";
    expect(isCimdClientAdmitted("https://app.example/a")).toBe(true);
    expect(isCimdClientAdmitted("https://app.example/b/c.json")).toBe(true);
  });

  // mcp-use compares origins exactly (`allow.origins.has(new URL(id).origin)`),
  // so a longer host that merely starts with the allowed one, a sub-domain, a
  // different port and a different scheme are all different origins.
  it.each([
    "https://app.example.evil.example/a",
    "https://evil.example/https://app.example/a",
    "https://sub.app.example/a",
    "https://app.example:8443/a",
    "http://app.example/a",
  ])("does not admit %s under the origin entry https://app.example", (id) => {
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = "https://app.example";
    expect(isCimdClientAdmitted(id)).toBe(false);
  });

  it("never admits a non-canonical id, even under a listed origin", () => {
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = "https://app.example";
    for (const id of [
      "https://app.example/a?x=random",
      "https://APP.example/a",
      "https://app.example/a/../b",
      "https://app.example/",
      "https://app.example/a#f",
    ]) {
      expect(isCimdClientAdmitted(id)).toBe(false);
    }
  });

  it("admits nothing while the list is empty, and for a non-string", () => {
    expect(isCimdClientAdmitted("https://app.example/a")).toBe(false);
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = "https://app.example";
    expect(isCimdClientAdmitted(undefined)).toBe(false);
  });
});

describe("isCimdRowBlocked", () => {
  const listed = "https://app.example/client.json";
  const unlisted = "https://gone.example/client.json";

  it("blocks only a cimd row the allowlist no longer admits", () => {
    process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] = listed;
    const table: Array<[string, unknown, boolean]> = [
      [
        "cimd, listed",
        { client_id: listed, registration_source: "cimd" },
        false,
      ],
      [
        "cimd, delisted",
        { client_id: unlisted, registration_source: "cimd" },
        true,
      ],
      [
        "dcr with a URL-shaped id",
        { client_id: unlisted, registration_source: "dcr" },
        false,
      ],
      [
        "admin with a URL-shaped id",
        { client_id: unlisted, registration_source: "admin" },
        false,
      ],
      [
        "legacy null source",
        { client_id: unlisted, registration_source: null },
        false,
      ],
      ["source absent", { client_id: unlisted }, false],
      ["no row", null, false],
    ];
    for (const [name, row, expected] of table) {
      expect([name, isCimdRowBlocked(row as never)]).toEqual([name, expected]);
    }
  });

  it("blocks every cimd row once the list is cleared", () => {
    expect(
      isCimdRowBlocked({ client_id: listed, registration_source: "cimd" }),
    ).toBe(true);
  });
});
