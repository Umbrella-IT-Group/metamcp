/**
 * Tests for the lazy-recovery transport hydration shim.
 *
 * These exercise the REAL `@modelcontextprotocol/sdk` 1.29.0
 * `StreamableHTTPServerTransport` — NO mock — because the whole point of
 * the shim is to satisfy the SDK's internal `validateSession` gate that
 * a mocked transport would paper over. The original wedge
 * (PR #15 lazy-recovery returning -32600 on the first call after a
 * gateway restart) slipped through precisely because the existing
 * recovery tests mocked the transport and never hit `_initialized`.
 *
 * As of SDK 1.29 the Node transport is a thin wrapper whose session state
 * lives on an inner `_webStandardTransport`, and its `validateSession`
 * takes a Web Standard `Request` and returns a `Response` (invalid) or
 * `undefined` (valid) instead of the old boolean + Node `res` write. The
 * behavioural assertion drives that inner `validateSession`:
 *   - before hydration -> 400 {-32000 "Server not initialized"}
 *   - after  hydration -> undefined (session id matches, no error)
 */
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn() },
}));

import {
  assertRecoveryHydrationContract,
  hydrateRecoveredTransport,
} from "./transport-recovery-hydration";

const SESSION_ID = "11111111-2222-3333-4444-555555555555";

function freshTransport(): StreamableHTTPServerTransport {
  return new StreamableHTTPServerTransport({
    sessionIdGenerator: () => SESSION_ID,
  });
}

/**
 * SDK 1.29's `validateSession` lives on the inner `_webStandardTransport`,
 * takes a Web Standard `Request`, and returns a `Response` (invalid) or
 * `undefined` (valid). Reach it through a cast for the behavioural test.
 */
async function callValidateSession(
  transport: StreamableHTTPServerTransport,
  sessionId?: string,
): Promise<{ ok: boolean; status?: number; body?: string }> {
  const inner = (
    transport as unknown as {
      _webStandardTransport: {
        validateSession: (req: Request) => Response | undefined;
      };
    }
  )._webStandardTransport;

  const headers: Record<string, string> = {};
  if (sessionId) headers["mcp-session-id"] = sessionId;
  const req = new Request("http://localhost/mcp", { method: "POST", headers });

  const response = inner.validateSession(req);
  if (response === undefined) {
    return { ok: true };
  }
  return { ok: false, status: response.status, body: await response.text() };
}

describe("hydrateRecoveredTransport", () => {
  it("a fresh (un-hydrated) transport rejects a sessioned request — reproduces the wedge", async () => {
    const transport = freshTransport();
    const result = await callValidateSession(transport, SESSION_ID);

    expect(result.ok).toBe(false);
    expect(result.status).toBe(400);
    expect(result.body).toContain("Server not initialized");
    // -32000 is what the SDK writes; the Anthropic connector relays it
    // to the user as -32600 "Invalid content from server".
    expect(result.body).toContain("-32000");
  });

  it("after hydration the transport accepts the matching session id", async () => {
    const transport = freshTransport();

    const hydrated = hydrateRecoveredTransport(transport, SESSION_ID);
    expect(hydrated).toBe(true);

    const result = await callValidateSession(transport, SESSION_ID);
    expect(result.ok).toBe(true);
    expect(result.status).toBeUndefined(); // no error response = passed
  });

  it("sets the SDK internals the skipped handshake would have set", () => {
    const transport = freshTransport();
    const internals = (
      transport as unknown as {
        _webStandardTransport: { _initialized: boolean; sessionId?: string };
      }
    )._webStandardTransport;

    expect(internals._initialized).toBe(false);
    expect(internals.sessionId).toBeUndefined();

    hydrateRecoveredTransport(transport, SESSION_ID);

    expect(internals._initialized).toBe(true);
    expect(internals.sessionId).toBe(SESSION_ID);
  });

  it("a hydrated transport still rejects a DIFFERENT session id (404), not a blanket allow", async () => {
    const transport = freshTransport();
    hydrateRecoveredTransport(transport, SESSION_ID);

    const result = await callValidateSession(
      transport,
      "00000000-dead-beef-0000-000000000000",
    );
    expect(result.ok).toBe(false);
    expect(result.status).toBe(404); // -32001 "Session not found"
  });

  it("returns false (refuses) if the SDK internal field shape changed", () => {
    // Simulate an SDK upgrade that renamed `_initialized`: an inner
    // web-standard transport whose `_initialized` is not a boolean.
    const notATransport = {
      _webStandardTransport: {
        _initialized: "yes",
        sessionId: undefined,
      },
    } as unknown as StreamableHTTPServerTransport;

    expect(hydrateRecoveredTransport(notATransport, SESSION_ID)).toBe(false);
  });

  it("returns false (refuses) if the wrapper no longer exposes _webStandardTransport", () => {
    // Simulate an SDK that dropped the wrapper indirection entirely.
    const notATransport = {
      _initialized: false,
    } as unknown as StreamableHTTPServerTransport;

    expect(hydrateRecoveredTransport(notATransport, SESSION_ID)).toBe(false);
  });
});

describe("assertRecoveryHydrationContract", () => {
  it("passes against the pinned SDK (fresh transport exposes the expected internals)", () => {
    expect(assertRecoveryHydrationContract()).toBe(true);
  });
});
