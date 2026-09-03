/**
 * The same-origin guard for post-auth redirects.
 *
 * `callbackUrl` is an attacker-controlled query parameter that both the login
 * page and the cors-error page navigate to. This proves the guard admits an
 * ordinary internal path and rejects every off-origin shape — the scheme, the
 * bare host, the protocol-relative and the backslash-smuggled forms — falling
 * back to "/" instead.
 *
 * The frontend harness is `environment: "node"` (see vitest.config.ts), so
 * getAppUrl() takes its server branch and reads process.env; NEXT_PUBLIC_APP_URL
 * is set below to give it a deterministic origin to validate against.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { toSafeInternalPath } from "./safe-redirect";

const APP_URL = "https://mcp.example.com";

let priorAppUrl: string | undefined;
let priorPublicAppUrl: string | undefined;

beforeAll(() => {
  priorAppUrl = process.env.APP_URL;
  priorPublicAppUrl = process.env.NEXT_PUBLIC_APP_URL;
  process.env.NEXT_PUBLIC_APP_URL = APP_URL;
});

afterAll(() => {
  if (priorAppUrl === undefined) delete process.env.APP_URL;
  else process.env.APP_URL = priorAppUrl;
  if (priorPublicAppUrl === undefined) delete process.env.NEXT_PUBLIC_APP_URL;
  else process.env.NEXT_PUBLIC_APP_URL = priorPublicAppUrl;
});

describe("toSafeInternalPath", () => {
  it("keeps an ordinary internal path", () => {
    expect(toSafeInternalPath("/x")).toBe("/x");
  });

  it("preserves the query and hash on a same-origin path", () => {
    expect(toSafeInternalPath("/mcp-servers?tab=tools#top")).toBe(
      "/mcp-servers?tab=tools#top",
    );
  });

  const REJECTED: Array<[string, string]> = [
    ["//evil", "protocol-relative URL -> another host"],
    ["/\\evil", "backslash the browser reads as a slash -> another host"],
    ["@evil.com", "userinfo host, no leading slash"],
    [".evil.com", "bare host, no leading slash"],
    ["https://evil", "absolute URL to another origin"],
    ["javascript:", "non-navigational scheme"],
  ];

  it.each(REJECTED)("rejects %s (%s) and falls back to /", (input) => {
    expect(toSafeInternalPath(input)).toBe("/");
  });

  it("falls back to / for empty, null and undefined", () => {
    expect(toSafeInternalPath("")).toBe("/");
    expect(toSafeInternalPath(null)).toBe("/");
    expect(toSafeInternalPath(undefined)).toBe("/");
  });

  it("honors an explicit fallback", () => {
    expect(toSafeInternalPath("https://evil", "/mcp-servers")).toBe(
      "/mcp-servers",
    );
  });
});
