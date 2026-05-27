/**
 * Tests for the lazy-recovery transport hydration shim.
 *
 * These exercise the REAL `@modelcontextprotocol/sdk` 1.16.0
 * `StreamableHTTPServerTransport` — NO mock — because the whole point of
 * the shim is to satisfy the SDK's internal `validateSession` gate that
 * a mocked transport would paper over. The original wedge
 * (PR #15 lazy-recovery returning -32600 on the first call after a
 * gateway restart) slipped through precisely because the existing
 * recovery tests mocked the transport and never hit `_initialized`.
 *
 * The behavioural assertion drives the transport's private
 * `validateSession(req, res)` with a minimal Node req/res pair:
 *   - before hydration -> false + 400 {-32000 "Server not initialized"}
 *   - after  hydration -> true (session id matches, no response written)
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
 * Minimal stand-ins for the Node req/res `validateSession` touches. The
 * res records the status it writes so we can assert the 400 path.
 */
function mockReq(sessionId?: string) {
  return {
    headers: sessionId ? { "mcp-session-id": sessionId } : {},
  } as unknown as Parameters<
    StreamableHTTPServerTransport["handleRequest"]
  >[0];
}

function mockRes() {
  const state: { status?: number; body?: string } = {};
  const res = {
    writeHead(status: number) {
      state.status = status;
      return res;
    },
    end(body?: string) {
      state.body = body;
      return res;
    },
  };
  return { res, state };
}

// `validateSession` is private in the SDK; reach it through a cast for
// the behavioural test.
function callValidateSession(
  transport: StreamableHTTPServerTransport,
  sessionId?: string,
): { ok: boolean; status?: number; body?: string } {
  const { res, state } = mockRes();
  const ok = (
    transport as unknown as {
      validateSession: (req: unknown, res: unknown) => boolean;
    }
  ).validateSession(mockReq(sessionId), res);
  return { ok, status: state.status, body: state.body };
}

describe("hydrateRecoveredTransport", () => {
  it("a fresh (un-hydrated) transport rejects a sessioned request — reproduces the wedge", () => {
    const transport = freshTransport();
    const result = callValidateSession(transport, SESSION_ID);

    expect(result.ok).toBe(false);
    expect(result.status).toBe(400);
    expect(result.body).toContain("Server not initialized");
    // -32000 is what the SDK writes; the Anthropic connector relays it
    // to the user as -32600 "Invalid content from server".
    expect(result.body).toContain("-32000");
  });

  it("after hydration the transport accepts the matching session id", () => {
    const transport = freshTransport();

    const hydrated = hydrateRecoveredTransport(transport, SESSION_ID);
    expect(hydrated).toBe(true);

    const result = callValidateSession(transport, SESSION_ID);
    expect(result.ok).toBe(true);
    expect(result.status).toBeUndefined(); // nothing written = passed
  });

  it("sets the SDK internals the skipped handshake would have set", () => {
    const transport = freshTransport();
    const internals = transport as unknown as {
      _initialized: boolean;
      sessionId?: string;
    };

    expect(internals._initialized).toBe(false);
    expect(internals.sessionId).toBeUndefined();

    hydrateRecoveredTransport(transport, SESSION_ID);

    expect(internals._initialized).toBe(true);
    expect(internals.sessionId).toBe(SESSION_ID);
  });

  it("a hydrated transport still rejects a DIFFERENT session id (404), not a blanket allow", () => {
    const transport = freshTransport();
    hydrateRecoveredTransport(transport, SESSION_ID);

    const result = callValidateSession(transport, "00000000-dead-beef-0000-000000000000");
    expect(result.ok).toBe(false);
    expect(result.status).toBe(404); // -32001 "Session not found"
  });

  it("returns false (refuses) if the SDK internal field shape changed", () => {
    // Simulate an SDK upgrade that renamed `_initialized`: a plain object
    // whose `_initialized` is not a boolean.
    const notATransport = {
      _initialized: "yes",
      sessionId: undefined,
    } as unknown as StreamableHTTPServerTransport;

    expect(hydrateRecoveredTransport(notATransport, SESSION_ID)).toBe(false);
  });
});

describe("assertRecoveryHydrationContract", () => {
  it("passes against the pinned SDK (fresh transport exposes the expected internals)", () => {
    expect(assertRecoveryHydrationContract()).toBe(true);
  });
});
