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
import { GRANTED_OAUTH_SCOPE } from "./utils";

// The two canonical Anthropic connector callbacks the create dialog's Claude
// preset fills in. Pinned here so a change to the preset has to be deliberate.
const CLAUDE_AI_CALLBACK = "https://claude.ai/api/mcp/auth_callback";
const CLAUDE_CALLBACKS = [
  CLAUDE_AI_CALLBACK,
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
    // First entry deliberately VALID (it is an allowlisted Claude callback),
    // so the failure can only come from the second — the whole point of the
    // assertion.
    const result = buildClientRegistration({
      redirect_uris: [CLAUDE_AI_CALLBACK, "not a url"],
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
    expect(result.client.scope).toBe(GRANTED_OAUTH_SCOPE);
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
      // An allowlisted host: this test is about metadata pass-through, and
      // since the host allowlist an arbitrary vendor host would fail before any of the
      // fields below were reached.
      redirect_uris: [CLAUDE_AI_CALLBACK],
      client_name: "My App",
      // NOTE: `scope` is deliberately absent here — it is not a
      // passed-through field. See the scope-substitution block below.
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

describe("buildClientRegistration — granted scope is server-decided", () => {
  // `POST /oauth/register` is anonymous and rate-limited only. Before this
  // was pinned, the caller's `scope` was echoed straight into the stored
  // client row and into the 201 response, defaulting to the literal "admin"
  // when absent — so a stranger could self-register a client recorded as
  // administrative. RFC 7591 §3.2.1 puts that decision on the server.

  it("grants the fixed non-administrative scope by default", () => {
    const result = buildClientRegistration({
      redirect_uris: CLAUDE_CALLBACKS,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.client.scope).toBe(GRANTED_OAUTH_SCOPE);
  });

  it("does not honour a caller-supplied scope, including 'admin'", () => {
    for (const scope of ["admin", "admin openid", "", "  "]) {
      const result = buildClientRegistration({
        redirect_uris: CLAUDE_CALLBACKS,
        scope,
      });
      expect(result.ok).toBe(true);
      if (!result.ok) continue;
      expect(result.client.scope).toBe(GRANTED_OAUTH_SCOPE);
    }
  });

  it("never grants an administrative scope, whatever the input shape", () => {
    // Non-string inputs went through the same `(scope as string) || "admin"`
    // cast, so an object or array could not be relied on to be rejected.
    for (const scope of [undefined, null, 0, ["admin"], { scope: "admin" }]) {
      const result = buildClientRegistration({
        redirect_uris: CLAUDE_CALLBACKS,
        scope,
      });
      expect(result.ok).toBe(true);
      if (!result.ok) continue;
      expect(result.client.scope).toBe(GRANTED_OAUTH_SCOPE);
      expect(result.client.scope).not.toBe("admin");
    }
  });

  it("pins the granted scope constant itself to a non-admin value", () => {
    // The assertions above would all still pass if the constant were changed
    // to "admin". This is the one that would not.
    expect(GRANTED_OAUTH_SCOPE).toBe("mcp");
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

describe("buildClientRegistration — input caps", () => {
  // `POST /oauth/register` takes no credential and every field here is stored
  // verbatim in a table with cascade children. Before these caps a single
  // anonymous request could write a multi-megabyte row, and 45 junk clients
  // had accumulated. Each assertion below pins one cap AND the error pair it
  // uses, because reusing the RFC 7591 codes is what keeps registered clients
  // able to read the refusal.

  const uriOfLength = (length: number) =>
    // A real allowlisted host, padded in the PATH — so the only thing wrong
    // with this URI is its length. A padded HOST would be refused by the
    // allowlist first and the test would pass for the wrong reason.
    `https://claude.ai/${"a".repeat(length - "https://claude.ai/".length)}`;

  it("rejects more than 10 redirect_uris", () => {
    const result = buildClientRegistration({
      redirect_uris: Array.from({ length: 11 }, () => CLAUDE_AI_CALLBACK),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("invalid_redirect_uri");
      expect(result.error_description).toContain("at most 10");
    }
  });

  it("accepts exactly 10 redirect_uris", () => {
    const result = buildClientRegistration({
      redirect_uris: Array.from({ length: 10 }, () => CLAUDE_AI_CALLBACK),
    });
    expect(result.ok).toBe(true);
  });

  it("rejects a redirect_uri longer than 512 characters", () => {
    const result = buildClientRegistration({
      redirect_uris: [CLAUDE_AI_CALLBACK, uriOfLength(513)],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("invalid_redirect_uri");
      expect(result.error_description).toContain("at most 512");
    }
  });

  it("accepts a redirect_uri of exactly 512 characters", () => {
    // The boundary in the passing direction. Without it, an off-by-one that
    // rejected everything at the cap would still satisfy the test above.
    const result = buildClientRegistration({
      redirect_uris: [uriOfLength(512)],
    });
    expect(result.ok).toBe(true);
  });

  it("rejects a client_name longer than 255 characters", () => {
    // 255 is the same bound CreateOAuthClientRequestSchema puts on the admin
    // UI path, which is the point: one shared core, one rule.
    const result = buildClientRegistration({
      redirect_uris: CLAUDE_CALLBACKS,
      client_name: "n".repeat(256),
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBe("invalid_request");
      expect(result.error_description).toContain("client_name");
      expect(result.error_description).toContain("255");
    }
  });

  it("accepts a client_name of exactly 255 characters", () => {
    const result = buildClientRegistration({
      redirect_uris: CLAUDE_CALLBACKS,
      client_name: "n".repeat(255),
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.client.client_name).toHaveLength(255);
  });

  it("caps every optional metadata URI at 512", () => {
    for (const field of ["client_uri", "logo_uri", "tos_uri", "policy_uri"]) {
      const result = buildClientRegistration({
        redirect_uris: CLAUDE_CALLBACKS,
        [field]: `https://example.com/${"a".repeat(512)}`,
      });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toBe("invalid_request");
        expect(result.error_description).toContain(field);
      }
    }
  });

  it("caps software_id at 255 and software_version at 64", () => {
    const tooLongId = buildClientRegistration({
      redirect_uris: CLAUDE_CALLBACKS,
      software_id: "s".repeat(256),
    });
    expect(tooLongId.ok).toBe(false);
    if (!tooLongId.ok) {
      expect(tooLongId.error_description).toContain("software_id");
    }

    const tooLongVersion = buildClientRegistration({
      redirect_uris: CLAUDE_CALLBACKS,
      software_version: "v".repeat(65),
    });
    expect(tooLongVersion.ok).toBe(false);
    if (!tooLongVersion.ok) {
      expect(tooLongVersion.error_description).toContain("software_version");
    }
  });

  it("caps contacts by count and by element length", () => {
    const tooMany = buildClientRegistration({
      redirect_uris: CLAUDE_CALLBACKS,
      contacts: Array.from({ length: 11 }, () => "ops@example.com"),
    });
    expect(tooMany.ok).toBe(false);
    if (!tooMany.ok) {
      expect(tooMany.error).toBe("invalid_request");
      expect(tooMany.error_description).toContain("at most 10");
    }

    const tooLong = buildClientRegistration({
      redirect_uris: CLAUDE_CALLBACKS,
      contacts: ["ops@example.com", "c".repeat(256)],
    });
    expect(tooLong.ok).toBe(false);
    if (!tooLong.ok) {
      expect(tooLong.error_description).toContain("at most 255");
    }
  });

  it("rejects a non-string where a string is expected, rather than storing it", () => {
    // The `(x as string) || null` cast these fields go through does not
    // narrow anything at runtime, so an object used to reach the insert.
    for (const contacts of [{ ops: "ops@example.com" }, [null], [12345]]) {
      const result = buildClientRegistration({
        redirect_uris: CLAUDE_CALLBACKS,
        contacts,
      });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error).toBe("invalid_request");
    }

    const objectName = buildClientRegistration({
      redirect_uris: CLAUDE_CALLBACKS,
      client_name: { toString: () => "Claude" },
    });
    expect(objectName.ok).toBe(false);
  });

  it("leaves a normal Claude registration untouched", () => {
    // The regression guard for all of the above: the caps must be invisible to
    // the only registration shape that actually matters.
    const result = buildClientRegistration({
      redirect_uris: CLAUDE_CALLBACKS,
      client_name: "Claude",
      client_uri: "https://claude.ai",
      contacts: ["support@anthropic.com"],
      software_id: "claude-connector",
      software_version: "1.0.0",
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.client.redirect_uris).toEqual(CLAUDE_CALLBACKS);
      expect(result.client.client_name).toBe("Claude");
      expect(result.client.contacts).toEqual(["support@anthropic.com"]);
    }
  });
});
