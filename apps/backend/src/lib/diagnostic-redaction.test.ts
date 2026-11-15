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
