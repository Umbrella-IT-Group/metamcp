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
      scope: "mcp:read",
      grant_types: ["authorization_code", "refresh_token"],
      client_uri: "https://app.example.com",
      contacts: ["ops@example.com"],
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.client.client_name).toBe("My App");
    expect(result.client.scope).toBe("mcp:read");
    expect(result.client.grant_types).toEqual([
      "authorization_code",
      "refresh_token",
    ]);
    expect(result.client.client_uri).toBe("https://app.example.com");
    expect(result.client.contacts).toEqual(["ops@example.com"]);
  });
});

// The registration core used to write `scope: scope || "admin"`, so a client
// that POSTed to the UNAUTHENTICATED /oauth/register endpoint and named no
// scope was stored as fully privileged, and one that asked for "admin" was
// handed it verbatim. Nothing reads oauth_clients.scope for authorization
// today, so neither granted access — but the stored row is what a future
// scope-based check would read, and it would inherit "anyone who can reach
// /oauth/register is an admin". These cases pin the default at "no scope" and
// the elevated request at "refused", for the self-registration path only.
describe("buildClientRegistration — scope is not granted by default", () => {
  it("records NO scope for a self-registered client that asks for none", () => {
    const result = buildClientRegistration({
      redirect_uris: CLAUDE_CALLBACKS,
      client_name: "Claude",
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.client.scope).toBeNull();
    expect(result.client.scope).not.toBe("admin");
  });

  it("refuses a self-registered client that asks for the admin scope", () => {
    const result = buildClientRegistration({
      redirect_uris: CLAUDE_CALLBACKS,
      scope: "admin",
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;

    expect(result.error).toBe("invalid_client_metadata");
    expect(result.error_description).toContain("admin");
  });

  it("refuses an elevated scope hidden among ordinary ones", () => {
    const result = buildClientRegistration({
      redirect_uris: CLAUDE_CALLBACKS,
      scope: "mcp:read admin mcp:write",
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBe("invalid_client_metadata");
  });

  it("does NOT refuse an ordinary scope that merely contains 'admin'", () => {
    // Space-delimited tokens per RFC 6749 §3.3 — a substring match here would
    // reject legitimate scopes and turn a hygiene fix into an outage.
    const result = buildClientRegistration({
      redirect_uris: CLAUDE_CALLBACKS,
      scope: "read:administration",
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.client.scope).toBe("read:administration");
  });

  it("treats a blank scope as absent rather than storing whitespace", () => {
    const result = buildClientRegistration({
      redirect_uris: CLAUDE_CALLBACKS,
      scope: "   ",
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.client.scope).toBeNull();
  });

  it("ignores a non-string scope instead of coercing it", () => {
    const result = buildClientRegistration({
      redirect_uris: CLAUDE_CALLBACKS,
      scope: { admin: true },
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.client.scope).toBeNull();
  });

  it("allows the admin scope for an entitled caller (the admin UI path)", () => {
    // The tRPC create is adminProcedure-gated, so an elevated scope there is a
    // deliberate act by someone who already holds the role.
    const result = buildClientRegistration(
      { redirect_uris: CLAUDE_CALLBACKS, scope: "admin" },
      { allowElevatedScope: true },
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.client.scope).toBe("admin");
  });

  it("still registers a Claude connector end to end", () => {
    // The connector pairing path must keep working: the DCR body Claude sends
    // carries no scope, and the whole registration has to succeed unchanged
    // apart from the scope column.
    const result = buildClientRegistration({
      client_name: "Claude",
      redirect_uris: CLAUDE_CALLBACKS,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.client.client_id).toMatch(/^mcp_client_/);
    expect(result.client.client_secret).toBeNull();
    expect(result.client.redirect_uris).toEqual(CLAUDE_CALLBACKS);
    expect(result.client.grant_types).toEqual([
      "authorization_code",
      "refresh_token",
    ]);
    expect(result.client.scope).toBeNull();
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
