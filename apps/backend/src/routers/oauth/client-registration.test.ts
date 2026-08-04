/**
 * Tests for the shared OAuth client-registration core — the validation +
 * credential-minting rules that BOTH the public RFC 7591 `POST /oauth/register`
 * endpoint and the admin UI's tRPC create path now run.
 *
 * That sharing is the reason these tests matter: before the extraction there
 * was one caller, so a rule could only be wrong in one place. Now a regression
 * here (a redirect URI that stops being validated, a secret minted for a PKCE
 * public client) is wrong on two surfaces at once, one of which is anonymous
 * and internet-facing.
 *
 * The core does no I/O, so it is driven directly — no express app, no DB.
 */

import { describe, expect, it } from "vitest";

import { buildClientRegistration } from "./client-registration";

// The two canonical Anthropic connector callbacks the create dialog's Claude
// preset fills in. Pinned here so a change to the preset has to be deliberate.
const CLAUDE_CALLBACKS = [
  "https://claude.ai/api/mcp/auth_callback",
  "https://claude.com/api/mcp/auth_callback",
];

describe("buildClientRegistration — redirect URIs", () => {
  it("rejects a missing, non-array, or empty redirect_uris", () => {
    for (const redirect_uris of [undefined, null, "https://a.example", []]) {
      const result = buildClientRegistration({ redirect_uris });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toBe("invalid_redirect_uri");
        expect(result.error_description).toContain("non-empty array");
      }
    }
  });

  it("rejects an unsafe scheme", () => {
    const result = buildClientRegistration({
      redirect_uris: ["myapp://callback"],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("invalid_redirect_uri");
      expect(result.error_description).toContain("myapp://callback");
    }
  });

  it("rejects a non-string entry rather than coercing it", () => {
    const result = buildClientRegistration({ redirect_uris: [12345] });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe("invalid_redirect_uri");
  });

  it("rejects when ANY uri in the list is invalid, not just the first", () => {
    const result = buildClientRegistration({
      redirect_uris: ["https://good.example/cb", "not a url"],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error_description).toContain("not a url");
  });

  it("accepts both Claude connector callbacks", () => {
    const result = buildClientRegistration({
      redirect_uris: CLAUDE_CALLBACKS,
      client_name: "Claude",
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.client.redirect_uris).toEqual(CLAUDE_CALLBACKS);
    }
  });
});

describe("buildClientRegistration — OAuth 2.1 defaults", () => {
  it("defaults to a PKCE public client with no secret", () => {
    const result = buildClientRegistration({
      redirect_uris: CLAUDE_CALLBACKS,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.client.token_endpoint_auth_method).toBe("none");
    // The security-relevant half: a public client must not be handed a
    // long-lived shared secret it has nowhere safe to keep.
    expect(result.client.client_secret).toBeNull();
    expect(result.client.grant_types).toEqual(["authorization_code"]);
    expect(result.client.response_types).toEqual(["code"]);
    expect(result.client.scope).toBe("admin");
    expect(result.client.client_name).toBe("Unnamed MCP Client");
  });

  it("mints a secret only for the confidential auth methods", () => {
    for (const method of ["client_secret_post", "client_secret_basic"]) {
      const result = buildClientRegistration({
        redirect_uris: CLAUDE_CALLBACKS,
        token_endpoint_auth_method: method,
      });
      expect(result.ok).toBe(true);
      if (!result.ok) continue;
      expect(result.client.token_endpoint_auth_method).toBe(method);
      expect(result.client.client_secret).toMatch(/^mcp_secret_/);
    }
  });

  it("issues a prefixed, unique client_id per call", () => {
    const first = buildClientRegistration({ redirect_uris: CLAUDE_CALLBACKS });
    const second = buildClientRegistration({ redirect_uris: CLAUDE_CALLBACKS });

    expect(first.ok && second.ok).toBe(true);
    if (!first.ok || !second.ok) return;

    expect(first.client.client_id).toMatch(/^mcp_client_/);
    // upsertClient is an INSERT ... ON CONFLICT, so a repeated id would
    // silently update an existing client instead of creating a new one.
    expect(first.client.client_id).not.toBe(second.client.client_id);
  });

  it("nulls unset optional metadata instead of leaving it undefined", () => {
    const result = buildClientRegistration({
      redirect_uris: CLAUDE_CALLBACKS,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.client.client_uri).toBeNull();
    expect(result.client.logo_uri).toBeNull();
    expect(result.client.contacts).toBeNull();
    expect(result.client.tos_uri).toBeNull();
    expect(result.client.policy_uri).toBeNull();
    expect(result.client.software_id).toBeNull();
    expect(result.client.software_version).toBeNull();
  });

  it("passes explicit values through", () => {
    const result = buildClientRegistration({
      redirect_uris: ["https://app.example.com/cb"],
      client_name: "My App",
      scope: "admin",
      grant_types: ["authorization_code", "refresh_token"],
      client_uri: "https://app.example.com",
      contacts: ["ops@example.com"],
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.client.client_name).toBe("My App");
    expect(result.client.grant_types).toEqual([
      "authorization_code",
      "refresh_token",
    ]);
    expect(result.client.client_uri).toBe("https://app.example.com");
    expect(result.client.contacts).toEqual(["ops@example.com"]);
  });
});

describe("buildClientRegistration — value-set validation", () => {
  it("rejects an unsupported grant type", () => {
    const result = buildClientRegistration({
      redirect_uris: CLAUDE_CALLBACKS,
      grant_types: ["implicit"],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("invalid_request");
      expect(result.error_description).toBe("Unsupported grant type: implicit");
    }
  });

  it("rejects an unsupported response type", () => {
    const result = buildClientRegistration({
      redirect_uris: CLAUDE_CALLBACKS,
      response_types: ["token"],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error_description).toBe("Unsupported response type: token");
    }
  });

  it("rejects an unsupported token endpoint auth method", () => {
    const result = buildClientRegistration({
      redirect_uris: CLAUDE_CALLBACKS,
      token_endpoint_auth_method: "private_key_jwt",
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error_description).toBe(
        "Unsupported token endpoint auth method: private_key_jwt",
      );
    }
  });

  it("validates redirect URIs before anything else", () => {
    // Both legs are invalid; the redirect-URI error must win so the response
    // matches what the DCR endpoint returned before the extraction.
    const result = buildClientRegistration({
      redirect_uris: [],
      grant_types: ["implicit"],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBe("invalid_redirect_uri");
  });
});
