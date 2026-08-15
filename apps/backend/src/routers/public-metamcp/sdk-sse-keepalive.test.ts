/**
 * SDK contract tripwire: the default SSE keep-alive introduced in
 * `@modelcontextprotocol/sdk` 1.30.0.
 *
 * Why this file exists. `dispatchTracked` in `streamable-http.ts` documents
 * a sweeper blind spot — a half-open TCP peer leaves a standalone GET
 * stream's dispatch pending forever, so the session is never reaped. Before
 * 1.30.0 the transport wrote nothing on an idle SSE stream, so nothing ever
 * probed the dead peer. 1.30.0 arms an unref'd interval per SSE stream that
 * writes a `: keepalive` comment frame every `keepAliveMs`, and that option
 * DEFAULTS to 15000 — so the fork inherits heartbeats at all four
 * `new StreamableHTTPServerTransport(...)` sites with no code change and no
 * opt-in. The blind-spot comment now leans on that default being present.
 *
 * If a later SDK bump changes the default, or flips keep-alive back to
 * opt-in, that comment silently becomes a lie and the blind spot silently
 * re-opens. This test fails loudly instead. It mirrors the fail-loud posture
 * of `assertRecoveryHydrationContract` in
 * `lib/metamcp/transport-recovery-hydration.ts`.
 *
 * Scope note — this pins the CONFIG contract, not the wire behaviour. It
 * does NOT prove a frame reaches a socket or that a dead peer is detected;
 * that chain is reasoned from the SDK source and is deliberately described
 * as "narrowed, not proven closed" in `dispatchTracked`'s comment. Proving
 * it needs a real half-open connection, which is integration-test territory.
 */
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { describe, expect, it } from "vitest";

/**
 * `keepAliveMs` is public on `StreamableHTTPServerTransportOptions`, but the
 * RESOLVED value lands on the inner web-standard transport's private
 * `_keepAliveMs`. Reading a private is the point here: this is a tripwire on
 * SDK internals, exactly like the hydration contract check, and it is
 * test-only — no production code depends on this field.
 */
function resolvedKeepAliveMs(
  transport: StreamableHTTPServerTransport,
): unknown {
  return (
    transport as unknown as {
      _webStandardTransport?: { _keepAliveMs?: unknown };
    }
  )._webStandardTransport?._keepAliveMs;
}

/** How the fork actually builds these — no `keepAliveMs` passed anywhere. */
function forkStyleTransport(): StreamableHTTPServerTransport {
  return new StreamableHTTPServerTransport({
    sessionIdGenerator: () => "keepalive-contract-probe",
  });
}

describe("SDK SSE keep-alive contract", () => {
  it("is ON by default — the fork inherits 15s heartbeats without opting in", () => {
    expect(resolvedKeepAliveMs(forkStyleTransport())).toBe(15000);
  });

  it("stays a public option we can turn down or off if a consumer ever needs it", () => {
    // Not exercised in production today; asserted so the escape hatch is
    // known to exist before someone needs it under pressure. `< 1` is the
    // SDK's documented disable value.
    expect(
      resolvedKeepAliveMs(
        new StreamableHTTPServerTransport({
          sessionIdGenerator: () => "keepalive-contract-probe",
          keepAliveMs: 30000,
        }),
      ),
    ).toBe(30000);
    expect(
      resolvedKeepAliveMs(
        new StreamableHTTPServerTransport({
          sessionIdGenerator: () => "keepalive-contract-probe",
          keepAliveMs: 0,
        }),
      ),
    ).toBe(0);
  });
});
