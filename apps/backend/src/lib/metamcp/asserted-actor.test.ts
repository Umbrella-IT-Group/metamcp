/**
 * The caller-asserted `X-MCP-Actor` on the pooled data plane: how an inbound
 * value is normalized, and how the pool's fetch wrapper turns the
 * request-scoped binding into exactly one outgoing header.
 *
 * `client-actor-header.test.ts` proves both pooled transports are wired with
 * the wrapper and that a real SDK client's calls carry it; this file pins the
 * wrapper's own contract.
 */
import { describe, expect, it, vi } from "vitest";

import {
  ASSERTED_ACTOR_HEADER,
  ASSERTED_ACTOR_MAX_CHARS,
  normalizeAssertedActor,
  withAssertedActor,
} from "./asserted-actor";
import { runWithCallerContext } from "./caller-context-store";

const ok = () => new Response("ok", { status: 200 });

/** A base fetch that records the headers each request reached it with. */
function recordingFetch() {
  const seen: Headers[] = [];
  const fetchImpl = vi.fn(async (_url: string | URL, init?: RequestInit) => {
    seen.push(new Headers(init?.headers));
    return ok();
  });
  return { fetchImpl, seen };
}

describe("normalizeAssertedActor", () => {
  it("trims the value", () => {
    expect(normalizeAssertedActor("  tech.one@example.com ")).toBe(
      "tech.one@example.com",
    );
  });

  it("caps the value at the largest backend reader's limit", () => {
    const value = normalizeAssertedActor("a".repeat(1000));
    expect(value).toHaveLength(ASSERTED_ACTOR_MAX_CHARS);
    expect(ASSERTED_ACTOR_MAX_CHARS).toBe(256);
  });

  it("does not leave trailing whitespace where the cap cut the value", () => {
    const value = normalizeAssertedActor(
      `${"a".repeat(ASSERTED_ACTOR_MAX_CHARS - 1)} tail`,
    );
    expect(value).toBe("a".repeat(ASSERTED_ACTOR_MAX_CHARS - 1));
  });

  it.each([
    ["absent", undefined],
    ["empty", ""],
    ["blank", "   "],
    ["an array", ["a@example.com", "b@example.com"]],
    ["a number", 42],
  ])("forwards nothing for %s", (_label, raw) => {
    expect(normalizeAssertedActor(raw)).toBeUndefined();
  });
});

describe("withAssertedActor", () => {
  it("sets this request's asserted actor on the outgoing request", async () => {
    const { fetchImpl, seen } = recordingFetch();
    const wrapped = withAssertedActor(fetchImpl);

    await runWithCallerContext({ assertedActor: "tech.one@example.com" }, () =>
      wrapped("http://10.0.0.5:3000/mcp", {
        method: "POST",
        headers: { authorization: "Bearer row", "content-type": "x" },
      }),
    );

    expect(seen[0].get(ASSERTED_ACTOR_HEADER)).toBe("tech.one@example.com");
    // Everything else on the request is left as the transport built it.
    expect(seen[0].get("authorization")).toBe("Bearer row");
    expect(seen[0].get("content-type")).toBe("x");
  });

  it("sends no actor outside any request scope (idle warm-up, probes, sweeps)", async () => {
    const { fetchImpl, seen } = recordingFetch();
    await withAssertedActor(fetchImpl)("http://10.0.0.5:3000/mcp", {});
    expect(seen[0].has(ASSERTED_ACTOR_HEADER)).toBe(false);
  });

  it("sends no actor for a request whose caller asserted none", async () => {
    const { fetchImpl, seen } = recordingFetch();
    await runWithCallerContext({ apiKeyUuid: "k-1" }, () =>
      withAssertedActor(fetchImpl)("http://10.0.0.5:3000/mcp", {}),
    );
    expect(seen[0].has(ASSERTED_ACTOR_HEADER)).toBe(false);
  });

  it("drops a connection-level value (a stored server header) when the caller asserted none", async () => {
    // A stored value would label every caller of this server with one name.
    const { fetchImpl, seen } = recordingFetch();
    await runWithCallerContext({ apiKeyUuid: "k-1" }, () =>
      withAssertedActor(fetchImpl)("http://10.0.0.5:3000/mcp", {
        headers: { "X-MCP-Actor": "someone.else@example.com" },
      }),
    );
    expect(seen[0].has(ASSERTED_ACTOR_HEADER)).toBe(false);
  });

  it("replaces a connection-level value with this request's", async () => {
    const { fetchImpl, seen } = recordingFetch();
    await runWithCallerContext({ assertedActor: "tech.one@example.com" }, () =>
      withAssertedActor(fetchImpl)("http://10.0.0.5:3000/mcp", {
        headers: { "X-MCP-Actor": "someone.else@example.com" },
      }),
    );
    expect(seen[0].get(ASSERTED_ACTOR_HEADER)).toBe("tech.one@example.com");
  });

  it("gives each of two concurrent requests its own caller's actor", async () => {
    const { fetchImpl, seen } = recordingFetch();
    const wrapped = withAssertedActor(fetchImpl);
    await Promise.all(
      ["tech.one@example.com", "tech.two@example.com"].map((actor) =>
        runWithCallerContext({ assertedActor: actor }, async () => {
          // Yield first so the two requests interleave.
          await Promise.resolve();
          return wrapped("http://10.0.0.5:3000/mcp", {
            headers: { "x-test-caller": actor },
          });
        }),
      ),
    );
    expect(seen).toHaveLength(2);
    for (const headers of seen) {
      expect(headers.get(ASSERTED_ACTOR_HEADER)).toBe(
        headers.get("x-test-caller"),
      );
    }
  });
});
