/**
 * Rewrites route to the co-located backend.
 *
 * The frontend and backend run in one container, and every rewrite in
 * next.config.js exists to hand a backend-owned path (OAuth, auth, tRPC, the
 * MCP data plane, health) to the Express process on localhost:12009. A rewrite
 * whose destination is any other origin turns the frontend into a reverse proxy
 * for that origin, so these tests pin the destination origin and the set of
 * routes, and fail on anything else.
 *
 * The approved origin is fixed here rather than read from the config under
 * test, and destinations are compared by parsed origin, not by string prefix:
 * a prefix check accepts "http://localhost:12009@example.invalid/path", whose
 * origin is http://example.invalid.
 *
 * These tests only inspect configuration. They never contact a destination.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

const APPROVED_BACKEND_ORIGIN = "http://localhost:12009";

type Rewrite = { source: string; destination: string };

async function loadRewrites(nodeEnv: string): Promise<unknown> {
  vi.stubEnv("NODE_ENV", nodeEnv);
  vi.resetModules();
  const mod = await import("../next.config.js");
  const config = mod.default as { rewrites?: () => Promise<unknown> };
  expect(typeof config.rewrites).toBe("function");
  return config.rewrites!();
}

function assertFlatRewriteArray(result: unknown): Rewrite[] {
  // next.config.js returns a flat array today. If it ever returns the phased
  // object form ({ beforeFiles, afterFiles, fallback }), this fails until the
  // guard is taught to check every phase.
  expect(Array.isArray(result)).toBe(true);
  const rewrites = result as Rewrite[];
  expect(rewrites.length).toBeGreaterThan(0);
  return rewrites;
}

function destinationIsApprovedBackend(destination: string): boolean {
  let url: URL;
  try {
    url = new URL(destination);
  } catch {
    return false;
  }
  return (
    url.origin === APPROVED_BACKEND_ORIGIN &&
    url.username === "" &&
    url.password === ""
  );
}

// The backend routes the frontend forwards, source -> destination path.
const EXPECTED_ROUTES: ReadonlyArray<readonly [string, string]> = [
  ["/health", "/health"],
  ["/health/:path*", "/health/:path*"],
  ["/oauth/:path*", "/oauth/:path*"],
  ["/.well-known/:path*", "/.well-known/:path*"],
  ["/api/auth/:path*", "/api/auth/:path*"],
  ["/m365/:path*", "/m365/:path*"],
  ["/register", "/api/auth/register"],
  ["/trpc/:path*", "/trpc/frontend/:path*"],
  ["/mcp-proxy/:path*", "/mcp-proxy/:path*"],
  ["/metamcp/:path*", "/metamcp/:path*"],
];

afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetModules();
});

describe("destinationIsApprovedBackend", () => {
  it("accepts the co-located backend", () => {
    expect(destinationIsApprovedBackend("http://localhost:12009/health")).toBe(
      true,
    );
  });

  it("refuses a same-prefix destination on another origin", () => {
    expect(
      destinationIsApprovedBackend("http://localhost:12009@example.invalid/x"),
    ).toBe(false);
    expect(destinationIsApprovedBackend("http://localhost:120090/health")).toBe(
      false,
    );
    expect(destinationIsApprovedBackend("https://example.invalid/x")).toBe(
      false,
    );
    expect(destinationIsApprovedBackend("/relative/path")).toBe(false);
  });
});

describe.each(["production", "development"])(
  "next.config.js rewrites (NODE_ENV=%s)",
  (nodeEnv) => {
    it("route only to the co-located backend", async () => {
      const rewrites = assertFlatRewriteArray(await loadRewrites(nodeEnv));
      const offending = rewrites.filter(
        (r) => !destinationIsApprovedBackend(r.destination),
      );
      expect(offending).toEqual([]);
    });

    it("forward exactly the expected backend routes", async () => {
      const rewrites = assertFlatRewriteArray(await loadRewrites(nodeEnv));
      const actual = rewrites.map(
        (r) => [r.source, new URL(r.destination).pathname] as const,
      );
      expect(actual).toEqual(EXPECTED_ROUTES);
    });
  },
);
