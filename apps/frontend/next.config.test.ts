/**
 * The value-less security headers live in next.config's headers() so they cover
 * static assets too, while the nonce'd CSP is emitted from middleware. These
 * pin the static set on /:path* and the production-only HSTS gate.
 */

import { describe, expect, it, vi } from "vitest";

import nextConfig from "./next.config.js";

type HeaderEntry = { key: string; value: string };
type HeaderRule = { source: string; headers: HeaderEntry[] };

async function rulesForEnv(env: string): Promise<HeaderRule[]> {
  // headers() reads NODE_ENV at call time; stubEnv sets it without tripping the
  // read-only NODE_ENV type.
  vi.stubEnv("NODE_ENV", env);
  try {
    return await (
      nextConfig as { headers: () => Promise<HeaderRule[]> }
    ).headers();
  } finally {
    vi.unstubAllEnvs();
  }
}

describe("next.config headers()", () => {
  it("applies the static security headers to every path", async () => {
    const rules = await rulesForEnv("development");
    const global = rules.find((r) => r.source === "/:path*");
    expect(global).toBeDefined();
    const byKey = new Map(global!.headers.map((h) => [h.key, h.value]));
    expect(byKey.get("X-Frame-Options")).toBe("DENY");
    expect(byKey.get("X-Content-Type-Options")).toBe("nosniff");
    expect(byKey.get("Referrer-Policy")).toBe(
      "strict-origin-when-cross-origin",
    );
    expect(byKey.get("Permissions-Policy")).toContain("geolocation=()");
  });

  it("does not set a static CSP here (the nonce'd CSP is middleware's job)", async () => {
    const rules = await rulesForEnv("production");
    const global = rules.find((r) => r.source === "/:path*");
    const keys = global!.headers.map((h) => h.key);
    expect(keys).not.toContain("Content-Security-Policy");
  });

  it("sends HSTS only in production", async () => {
    const dev = await rulesForEnv("development");
    const devGlobal = dev.find((r) => r.source === "/:path*")!;
    expect(
      devGlobal.headers.some((h) => h.key === "Strict-Transport-Security"),
    ).toBe(false);

    const prod = await rulesForEnv("production");
    const prodGlobal = prod.find((r) => r.source === "/:path*")!;
    const hsts = prodGlobal.headers.find(
      (h) => h.key === "Strict-Transport-Security",
    );
    expect(hsts?.value).toContain("max-age=");
    expect(hsts?.value).toContain("includeSubDomains");
  });
});
