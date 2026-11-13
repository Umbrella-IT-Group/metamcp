/**
 * Validation of a fetched client metadata document into a client row.
 *
 * Oracles, read from the published texts on 2026-11-12:
 *  - draft-ietf-oauth-client-id-metadata-document, section 4: "The Client ID
 *    Metadata Document MUST contain a `client_id` property whose value MUST
 *    match the Client Identifier URL", compared by simple string comparison;
 *    sections 4.1 and 5: "the `client_secret` and `client_secret_expires_at`
 *    properties MUST NOT be used" and the `token_endpoint_auth_method` and
 *    `token_endpoint_auth_methods_supported` properties MUST NOT include
 *    "`client_secret_post`, `client_secret_basic`, `client_secret_jwt`, or any
 *    other method based around a shared symmetric secret"; an absent method
 *    means "the authorization server MUST assume ... `none`".
 *  - The MCP authorization spec (2025-11-25), "Example Metadata Document",
 *    reproduced below verbatim.
 *  - mcp-use `clients.ts` (the public-client rule: a methods list decides when
 *    present, otherwise the singular value must be absent or `none`).
 * Rows marked "design decision" have no outside oracle: hosted callbacks only
 * (a loopback or private-use callback is refused), and the shared registration
 * core's rules (10 URIs of at most 512 characters, the host allowlist).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

const { decodeCimdBody, parseCimdDocument } = await import("./cimd-document");
const { DCR_REDIRECT_URI_ALLOWED_HOSTS_ENV: HOSTS_ENV } = await import(
  "./utils"
);

const CLIENT_ID = "https://app.example.com/oauth/client-metadata.json";
const HOSTED_CALLBACK = "https://claude.ai/api/mcp/auth_callback";

/** The MCP 2025-11-25 authorization spec's example document, verbatim. */
const SPEC_EXAMPLE = {
  client_id: "https://app.example.com/oauth/client-metadata.json",
  client_name: "Example MCP Client",
  client_uri: "https://app.example.com",
  logo_uri: "https://app.example.com/logo.png",
  redirect_uris: [
    "http://127.0.0.1:3000/callback",
    "http://localhost:3000/callback",
  ],
  grant_types: ["authorization_code"],
  response_types: ["code"],
  token_endpoint_auth_method: "none",
};

const doc = (overrides: Record<string, unknown> = {}) =>
  JSON.stringify({
    client_id: CLIENT_ID,
    client_name: "Example",
    redirect_uris: [HOSTED_CALLBACK],
    ...overrides,
  });

const ORIGINAL_HOSTS = process.env[HOSTS_ENV];
beforeEach(() => {
  delete process.env[HOSTS_ENV];
});
afterEach(() => {
  if (ORIGINAL_HOSTS === undefined) {
    delete process.env[HOSTS_ENV];
  } else {
    process.env[HOSTS_ENV] = ORIGINAL_HOSTS;
  }
});

describe("the MCP spec's own example document", () => {
  // The spec example lists loopback callbacks. This gateway takes hosted
  // callbacks only (design decision), so the example is refused for exactly
  // that and for nothing else: with a hosted callback in its place, the rest
  // of the document validates unchanged.
  it("is refused only because of its loopback callbacks", () => {
    expect(parseCimdDocument(JSON.stringify(SPEC_EXAMPLE), CLIENT_ID)).toEqual({
      ok: false,
      reason: "non_hosted_redirect_uri",
      detail: "scheme",
    });
  });

  it("validates once its callbacks are hosted", () => {
    const result = parseCimdDocument(
      JSON.stringify({ ...SPEC_EXAMPLE, redirect_uris: [HOSTED_CALLBACK] }),
      CLIENT_ID,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.client).toMatchObject({
      client_id: CLIENT_ID,
      client_secret: null,
      client_name: "Example MCP Client",
      redirect_uris: [HOSTED_CALLBACK],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      scope: "mcp",
      client_uri: "https://app.example.com",
      logo_uri: "https://app.example.com/logo.png",
    });
  });
});

describe("the client_id match (draft section 4)", () => {
  it.each([
    ["a different URL", "https://app.example.com/other.json"],
    ["the same URL with a trailing difference", `${CLIENT_ID}/`],
    ["a different case", CLIENT_ID.toUpperCase()],
    ["a missing client_id", undefined],
    ["a non-string client_id", 5],
  ])("refuses %s", (_name, value) => {
    expect(parseCimdDocument(doc({ client_id: value }), CLIENT_ID)).toEqual({
      ok: false,
      reason: "client_id_mismatch",
    });
  });

  it("accepts the identical string", () => {
    expect(parseCimdDocument(doc(), CLIENT_ID).ok).toBe(true);
  });
});

describe("what is not JSON", () => {
  it.each([
    ["text", "not json"],
    ["an empty body", ""],
    ["truncated JSON", `{"client_id": "${CLIENT_ID}"`],
  ])("refuses %s as not_json", (_name, text) => {
    expect(parseCimdDocument(text, CLIENT_ID)).toEqual({
      ok: false,
      reason: "not_json",
    });
  });

  it.each([
    ["an array", "[]"],
    ["null", "null"],
    ["a string", '"x"'],
    ["a number", "5"],
  ])("refuses %s as an invalid document", (_name, text) => {
    expect(parseCimdDocument(text, CLIENT_ID)).toMatchObject({
      ok: false,
      reason: "invalid_document",
    });
  });

  it("decodes UTF-8 and refuses bytes that are not UTF-8", () => {
    expect(decodeCimdBody(new TextEncoder().encode('{"a":"é"}'))).toBe(
      '{"a":"é"}',
    );
    expect(decodeCimdBody(new Uint8Array([0x7b, 0xff, 0xfe, 0x7d]))).toBeNull();
  });
});

describe("public clients only (draft sections 4.1 and 5)", () => {
  it.each([
    ["client_secret", { client_secret: "s3cret" }],
    ["client_secret as null", { client_secret: null }],
    ["client_secret_expires_at", { client_secret_expires_at: 0 }],
    [
      "client_secret_basic",
      { token_endpoint_auth_method: "client_secret_basic" },
    ],
    [
      "client_secret_post",
      { token_endpoint_auth_method: "client_secret_post" },
    ],
    ["client_secret_jwt", { token_endpoint_auth_method: "client_secret_jwt" }],
    [
      "a shared-secret method inside the supported list",
      {
        token_endpoint_auth_methods_supported: ["none", "client_secret_basic"],
      },
    ],
    // mcp-use: the singular value alone must be absent or none.
    [
      "private_key_jwt alone",
      { token_endpoint_auth_method: "private_key_jwt" },
    ],
    [
      "a list that does not offer none",
      { token_endpoint_auth_methods_supported: ["private_key_jwt"] },
    ],
  ])("refuses %s", (_name, overrides) => {
    expect(parseCimdDocument(doc(overrides), CLIENT_ID)).toMatchObject({
      ok: false,
      reason: "not_public_client",
    });
  });

  it.each([
    ["no method at all (draft: assume none)", {}],
    ["method none", { token_endpoint_auth_method: "none" }],
    // mcp-use: when a list is present the list decides, so a client that
    // prefers private_key_jwt and also offers none is a public client.
    [
      "a list offering none and private_key_jwt",
      { token_endpoint_auth_methods_supported: ["none", "private_key_jwt"] },
    ],
  ])("accepts %s, and always stores none", (_name, overrides) => {
    const result = parseCimdDocument(doc(overrides), CLIENT_ID);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.client.token_endpoint_auth_method).toBe("none");
      expect(result.client.client_secret).toBeNull();
    }
  });

  it("refuses a method field of the wrong type", () => {
    expect(
      parseCimdDocument(doc({ token_endpoint_auth_method: 7 }), CLIENT_ID),
    ).toMatchObject({ ok: false, reason: "invalid_document" });
    expect(
      parseCimdDocument(
        doc({ token_endpoint_auth_methods_supported: "none" }),
        CLIENT_ID,
      ),
    ).toMatchObject({ ok: false, reason: "invalid_document" });
  });
});

describe("callbacks: hosted https only, through the shared rules", () => {
  it.each([
    [
      "a loopback IPv4 callback",
      ["http://127.0.0.1:3000/callback"],
      "non_hosted_redirect_uri",
    ],
    [
      "a localhost callback",
      ["http://localhost:3000/callback"],
      "non_hosted_redirect_uri",
    ],
    [
      "an IPv6 loopback callback",
      ["http://[::1]:3000/callback"],
      "non_hosted_redirect_uri",
    ],
    [
      "https on localhost",
      ["https://localhost/callback"],
      "non_hosted_redirect_uri",
    ],
    [
      "a private-use scheme callback",
      ["com.example.app:/callback"],
      "non_hosted_redirect_uri",
    ],
    [
      "a custom scheme callback",
      ["myapp://callback"],
      "non_hosted_redirect_uri",
    ],
    ["javascript:", ["javascript:alert(1)"], "non_hosted_redirect_uri"],
    [
      "plain http on a hosted name",
      ["http://example.com/cb"],
      "non_hosted_redirect_uri",
    ],
    [
      "one loopback callback among hosted ones",
      [HOSTED_CALLBACK, "http://127.0.0.1:3000/callback"],
      "non_hosted_redirect_uri",
    ],
    [
      "a host outside the allowlist",
      ["https://evil.example/cb"],
      "invalid_redirect_uri",
    ],
    ["userinfo", ["https://claude.ai@evil.example/cb"], "invalid_redirect_uri"],
    ["a fragment", [`${HOSTED_CALLBACK}#f`], "invalid_redirect_uri"],
    ["a string that is not a URL", ["not a url"], "invalid_redirect_uri"],
    ["a non-string entry", [5], "invalid_redirect_uri"],
    ["an empty list", [], "invalid_redirect_uri"],
  ])("refuses %s", (_name, redirect_uris, reason) => {
    expect(parseCimdDocument(doc({ redirect_uris }), CLIENT_ID)).toMatchObject({
      ok: false,
      reason,
    });
  });

  it("refuses missing, null and non-array redirect_uris", () => {
    for (const redirect_uris of [undefined, null, "https://claude.ai/cb"]) {
      expect(
        parseCimdDocument(doc({ redirect_uris }), CLIENT_ID),
      ).toMatchObject({ ok: false, reason: "invalid_redirect_uri" });
    }
  });

  it("names the rule that refused a host outside the allowlist", () => {
    expect(
      parseCimdDocument(
        doc({ redirect_uris: ["https://evil.example/cb"] }),
        CLIENT_ID,
      ),
    ).toEqual({
      ok: false,
      reason: "invalid_redirect_uri",
      detail: "host_not_allowed",
    });
  });

  it("applies the registration core's caps: 11 callbacks, or one over 512 characters", () => {
    const eleven = Array.from(
      { length: 11 },
      (_, i) => `https://claude.ai/cb/${i}`,
    );
    expect(
      parseCimdDocument(doc({ redirect_uris: eleven }), CLIENT_ID),
    ).toMatchObject({
      ok: false,
      reason: "invalid_redirect_uri",
    });
    const ten = eleven.slice(0, 10);
    expect(parseCimdDocument(doc({ redirect_uris: ten }), CLIENT_ID).ok).toBe(
      true,
    );
    const tooLong = `https://claude.ai/${"a".repeat(500)}`;
    expect(
      parseCimdDocument(doc({ redirect_uris: [tooLong] }), CLIENT_ID),
    ).toMatchObject({
      ok: false,
      reason: "invalid_redirect_uri",
    });
  });

  // The coupling, in both directions: a hosted callback outside claude.ai,
  // claude.com and anthropic.com is refused until DCR_REDIRECT_URI_ALLOWED_HOSTS
  // is widened, and widening it admits that host here as it does for
  // anonymous registration and the admin dialog (design decision).
  it("follows DCR_REDIRECT_URI_ALLOWED_HOSTS in both directions", () => {
    const hosted = doc({ redirect_uris: ["https://partner.example/cb"] });
    expect(parseCimdDocument(hosted, CLIENT_ID)).toMatchObject({
      ok: false,
      reason: "invalid_redirect_uri",
      detail: "host_not_allowed",
    });
    process.env[HOSTS_ENV] = "partner.example";
    expect(parseCimdDocument(hosted, CLIENT_ID).ok).toBe(true);
    // And the widened list replaces the default, as it does everywhere.
    expect(parseCimdDocument(doc(), CLIENT_ID)).toMatchObject({
      ok: false,
      detail: "host_not_allowed",
    });
  });
});

describe("grant and response types", () => {
  it("defaults the grants to authorization_code and refresh_token", () => {
    const result = parseCimdDocument(doc(), CLIENT_ID);
    expect(result.ok && result.client.grant_types).toEqual([
      "authorization_code",
      "refresh_token",
    ]);
    expect(result.ok && result.client.response_types).toEqual(["code"]);
  });

  it.each([
    [
      "client_credentials",
      { grant_types: ["authorization_code", "client_credentials"] },
    ],
    ["no authorization_code", { grant_types: ["refresh_token"] }],
    ["an empty list", { grant_types: [] }],
    ["a non-array", { grant_types: "authorization_code" }],
    [
      "an implicit-flow token response type",
      { response_types: ["code", "token"] },
    ],
    ["an empty response list", { response_types: [] }],
  ])("refuses %s", (_name, overrides) => {
    expect(parseCimdDocument(doc(overrides), CLIENT_ID)).toMatchObject({
      ok: false,
      reason: "invalid_document",
    });
  });

  it("collapses duplicates", () => {
    const result = parseCimdDocument(
      doc({ grant_types: ["authorization_code", "authorization_code"] }),
      CLIENT_ID,
    );
    expect(result.ok && result.client.grant_types).toEqual([
      "authorization_code",
    ]);
  });
});

describe("what the document is allowed to say about itself", () => {
  it("never carries contacts, software ids, jwks or unknown keys into the row", () => {
    const result = parseCimdDocument(
      doc({
        contacts: ["ops@example.invalid"],
        software_id: "sw",
        software_version: "1",
        jwks_uri: "https://app.example.com/jwks.json",
        jwks: { keys: [] },
        something_new: { nested: true },
      }),
      CLIENT_ID,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.client.contacts).toBeNull();
    expect(result.client.software_id).toBeNull();
    expect(result.client.software_version).toBeNull();
    expect(JSON.stringify(result.client)).not.toContain("jwks");
    expect(JSON.stringify(result.client)).not.toContain("something_new");
  });

  it("stores a metadata URI only if it is an https URL within the length budget", () => {
    const result = parseCimdDocument(
      doc({
        client_uri: "javascript:alert(1)",
        logo_uri: "http://app.example.com/logo.png",
        tos_uri: "https://app.example.com/tos",
        policy_uri: `https://app.example.com/${"p".repeat(520)}`,
      }),
      CLIENT_ID,
    );
    // The over-long one is refused by the shared core's cap; the others are
    // judged on their scheme.
    expect(result).toMatchObject({ ok: false, reason: "invalid_document" });

    const kept = parseCimdDocument(
      doc({
        client_uri: "javascript:alert(1)",
        logo_uri: "http://app.example.com/logo.png",
        tos_uri: "https://app.example.com/tos",
      }),
      CLIENT_ID,
    );
    expect(kept.ok && kept.client.client_uri).toBeNull();
    expect(kept.ok && kept.client.logo_uri).toBeNull();
    expect(kept.ok && kept.client.tos_uri).toBe("https://app.example.com/tos");
  });

  it("clamps the name to 255 characters and removes control and bidirectional characters", () => {
    // Built from code points so the source carries no invisible characters:
    // a right-to-left override, a NUL, a zero-width space and a newline.
    const unprintable = [0x202e, 0x0000, 0x200b, 0x000a].map((cp) =>
      String.fromCodePoint(cp),
    );
    const [override, nul, zeroWidth, newline] = unprintable;
    const hostile = `${override}Claude${nul}${zeroWidth} Code${newline}${"x".repeat(400)}`;
    const result = parseCimdDocument(doc({ client_name: hostile }), CLIENT_ID);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.client.client_name.length).toBeLessThanOrEqual(255);
    expect(result.client.client_name).toMatch(/^Claude Code/);
    for (const ch of unprintable) {
      expect(result.client.client_name.includes(ch)).toBe(false);
    }
  });

  it("falls back to the host for a missing or blank name, and refuses a non-string one", () => {
    const invisible = String.fromCodePoint(0x200b, 0x202e);
    for (const client_name of [undefined, "", "   ", invisible]) {
      const result = parseCimdDocument(doc({ client_name }), CLIENT_ID);
      expect(result.ok && result.client.client_name).toBe("app.example.com");
    }
    expect(
      parseCimdDocument(doc({ client_name: { a: 1 } }), CLIENT_ID),
    ).toMatchObject({ ok: false, reason: "invalid_document" });
  });
});
