import { describe, expect, it } from "vitest";

import {
  projectGatewayEventForAdminPlane,
  redactDiagnosticText,
} from "./diagnostic-redaction";

describe("redactDiagnosticText", () => {
  it.each([
    [
      "a URL's user info, query and fragment",
      "GET https://agent:hunter2@vendor.example/mcp/v1?api_key=s3cr3t&x=1#frag failed",
      "GET https://vendor.example/mcp/v1?[redacted] failed",
      ["hunter2", "s3cr3t", "frag"],
    ],
    [
      "a URL password containing an at sign",
      "GET https://reader:private@password@vendor.example/mcp failed",
      "GET https://vendor.example/mcp failed",
      ["private", "password"],
    ],
    [
      "a gateway key",
      "presented sk_mt_abcdefghijklmnopqrstuvwxyz0123456789ABCD and was refused",
      "presented sk_mt_[redacted] and was refused",
      ["abcdefghijklmnop"],
    ],
    [
      "an authorization scheme value",
      "header Authorization: Bearer eyJabc.def-ghi rejected; Basic dXNlcjpwYXNz",
      "header Authorization: Bearer [redacted] rejected; Basic [redacted]",
      ["eyJabc", "dXNlcjpwYXNz"],
    ],
    [
      "secret-named key=value and key: value pairs",
      'token=abc123 password: "letmein" client_secret=zzz api-key=k1',
      "token=[redacted] password=[redacted] client_secret=[redacted] api-key=[redacted]",
      ["abc123", "letmein", "zzz", "k1"],
    ],
    [
      "a JSON web token on its own",
      "id_token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl expired",
      "id_token [redacted] expired",
      ["eyJhbGciOiJIUzI1NiJ9"],
    ],
    [
      "a long opaque run",
      `upstream echoed ${"Ab9".repeat(20)} back`,
      "upstream echoed [redacted] back",
      ["Ab9Ab9Ab9"],
    ],
  ])("removes %s", (_label, input, expected, secrets) => {
    const output = redactDiagnosticText(input);
    expect(output).toBe(expected);
    for (const secret of secrets) expect(output).not.toContain(secret);
  });

  // The shapes upstream servers and proxies actually echo into error text:
  // a JSON error body, header lines, a digest, a cloud access key id, a key
  // file. Each case names the secrets that must not survive.
  it.each([
    ["a JSON-quoted password", '{"password":"hunter2zz"}', ["hunter2zz"]],
    [
      "a JSON OAuth error body with an access token and a client secret",
      '{"access_token":"abc123def456","token_type":"bearer","client_secret": "s3cr3tvalue-9z"}',
      ["abc123def456", "s3cr3tvalue-9z"],
    ],
    [
      "a JSON-quoted value holding spaces",
      '{"password":"my long pass phrase 9"}',
      ["pass phrase"],
    ],
    [
      "an Authorization header in capitals",
      "Authorization: BEARER abc123def456ghi",
      ["abc123def456ghi"],
    ],
    [
      "an Authorization header with the Token scheme",
      "authorization: Token abc123def456ghi",
      ["abc123def456ghi"],
    ],
    [
      "an Authorization header with no scheme",
      "Authorization: sk-live-abc123def456",
      ["sk-live-abc123def456"],
    ],
    [
      "a Proxy-Authorization header",
      "Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==",
      ["dXNlcjpwYXNzd29yZA"],
    ],
    [
      "a JSON-quoted Authorization header",
      '{"Authorization":"Bearer abc123def456"}',
      ["abc123def456"],
    ],
    [
      "a Cookie header",
      "Cookie: session=abc123def456; other=1",
      ["abc123def456", "other=1"],
    ],
    [
      "a Set-Cookie header",
      "set-cookie: __Secure-better-auth.session_token=abc.def; Path=/; HttpOnly",
      ["abc.def"],
    ],
    [
      "a 32-character hex secret",
      "key 5f4dcc3b5aa765d61d8327deb882cf99 rejected",
      ["5f4dcc3b5aa765d61d8327deb882cf99"],
    ],
    [
      "a 64-character hex digest",
      `digest ${"0123456789abcdef".repeat(4)} mismatch`,
      ["0123456789abcdef0123"],
    ],
    [
      "an AWS access key id",
      "AKIAIOSFODNN7EXAMPLE rejected",
      ["AKIAIOSFODNN7EXAMPLE"],
    ],
    [
      "a PEM private key",
      "bad key -----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0B\nAQEFAASC-----END PRIVATE KEY----- in config",
      ["MIIEvQ", "AQEFAASC"],
    ],
    [
      "a PEM block cut short before its end line",
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx9",
      ["MIIEowIBAAKCAQEAx9"],
    ],
    [
      "a single-quoted secret and a spaced assignment",
      "password='hunter2zz' api_key = abc123xyz",
      ["hunter2zz", "abc123xyz"],
    ],
    [
      "an escaped quote inside a JSON password",
      JSON.stringify({ password: 'prefix"private suffix', error: "refused" }),
      ["private suffix"],
    ],
    [
      "a multi-parameter Digest Authorization header",
      'Authorization: Digest username="reader", nonce="server-nonce", response="proof-value"',
      ["server-nonce", "proof-value"],
    ],
    [
      "a JSON-quoted Digest Authorization header",
      JSON.stringify({
        Authorization:
          'Digest username="reader", nonce="server-nonce", response="proof-value"',
        error: "refused",
      }),
      ["server-nonce", "proof-value"],
    ],
    [
      "an unrecognised Authorization scheme",
      "Authorization: Custom-Scheme short-proof",
      ["short-proof"],
    ],
    [
      "an unrecognised scheme with several credential parameters",
      'Authorization: Signature keyId="reader",signature="signed-proof",nonce="private-nonce"',
      ["signed-proof", "private-nonce"],
    ],
  ])("removes %s", (_label, input, secrets) => {
    const output = redactDiagnosticText(input);
    for (const secret of secrets) {
      expect({ secret, present: output.includes(secret) }).toEqual({
        secret,
        present: false,
      });
    }
    expect(output).toContain("[redacted]");
    // Redacting twice changes nothing: the marker is never read as a value.
    expect(redactDiagnosticText(output)).toBe(output);
  });

  it("keeps the readable part of a header, the scheme word and the key names", () => {
    expect(redactDiagnosticText("Authorization: BEARER abc123def456ghi")).toBe(
      "Authorization: BEARER [redacted]",
    );
    expect(redactDiagnosticText("authorization: Token abc123def456ghi")).toBe(
      "authorization: Token [redacted]",
    );
    expect(redactDiagnosticText("Cookie: session=abc123def456; other=1")).toBe(
      "Cookie: [redacted]",
    );
    expect(
      redactDiagnosticText('{"access_token":"abc123def456","expires_in":3600}'),
    ).toBe('{access_token=[redacted],"expires_in":3600}');
  });

  it("leaves printable text that holds no secret intact", () => {
    for (const text of [
      "Token refresh failed after 3 retries",
      "the session cookie jar is empty",
      "password policy requires 12 characters",
      "request 6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b took 4m12s",
      "listening on 10.0.0.12:8443, 32 workers, build 20261115",
      "Authorization failed for the request",
      "a hex value of 0123456789abcdef is short",
      "ECONNRESET at https://vendor.example/mcp/v1/tools",
    ]) {
      expect({ text, out: redactDiagnosticText(text) }).toEqual({
        text,
        out: text,
      });
    }
  });

  it("leaves ordinary diagnostic text alone", () => {
    const text =
      "Transport closed unexpectedly (backend drop, 4m12s) for server 6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b at http://backend.internal:8000/mcp";
    expect(redactDiagnosticText(text)).toBe(text);
  });
});

describe("projectGatewayEventForAdminPlane", () => {
  it("redacts the message and the error, keeps only the error in metadata and leaves the session out", () => {
    const projected = projectGatewayEventForAdminPlane({
      uuid: "e1",
      occurredAt: "2026-11-15T00:00:00.000Z",
      category: "connection",
      level: "error",
      serverUuid: null,
      serverName: "vendor",
      clientName: "poller",
      sessionId: "session-abc",
      message: "failed https://vendor.example/mcp?token=abc",
      metadata: { error: "password=letmein", extra: "dropped" },
    });
    expect(projected).toEqual({
      uuid: "e1",
      occurredAt: "2026-11-15T00:00:00.000Z",
      category: "connection",
      level: "error",
      serverUuid: null,
      serverName: "vendor",
      clientName: "poller",
      sessionId: null,
      message: "failed https://vendor.example/mcp?[redacted]",
      metadata: { error: "password=[redacted]" },
    });
  });

  it("drops metadata without a text error", () => {
    expect(
      projectGatewayEventForAdminPlane({
        uuid: "e2",
        occurredAt: "2026-11-15T00:00:00.000Z",
        category: "server",
        level: null,
        serverUuid: null,
        serverName: null,
        clientName: null,
        sessionId: null,
        message: "ok",
        metadata: { error: { nested: true } },
      }).metadata,
    ).toBeNull();
  });
});
