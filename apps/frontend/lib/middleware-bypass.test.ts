/**
 * The middleware bypass set is expressed twice: once as the config.matcher
 * literal Next uses to decide whether to invoke the middleware at all, and once
 * as shouldBypassMiddleware, the in-body early return. They must agree, or a
 * path slips through one gate and is caught by the other. The bug these guard
 * against: bare-prefix matching (`startsWith("/oauth")`) swallowed the fork's
 * /oauth-clients admin page because its route shares the "/oauth" prefix of the
 * bypassed backend routes, so the locale redirect never ran and the page 404'd.
 * The second test compiles the ACTUAL matcher literal and asserts it and
 * shouldBypassMiddleware decide the same table, so the two can never drift.
 */

import { describe, expect, it } from "vitest";

import { config } from "../middleware";
import {
  MIDDLEWARE_BYPASS_PREFIXES,
  shouldBypassMiddleware,
} from "./middleware-bypass";

// [pathname, expected shouldBypassMiddleware result]. A bypassed path is one the
// middleware must NOT run on (framework internals, backend routes, static
// files); everything else is a localized page the middleware must process.
const TABLE: ReadonlyArray<readonly [string, boolean]> = [
  // The defect: a page whose route shares a prefix with a bypassed backend
  // route must still route through the middleware (locale redirect + auth).
  ["/oauth-clients", false],
  ["/en/oauth-clients", false],
  // The backend OAuth routes the prefix exists for: must stay bypassed.
  ["/oauth", true],
  ["/oauth/authorize", true],
  ["/oauth/token", true],
  // A distinct segment that happens to end in "oauth": bypassed on its own.
  ["/fe-oauth/callback", true],
  // Other real sidebar pages that must not be swallowed by a shared prefix.
  ["/api-keys", false],
  ["/en/api-keys", false],
  ["/mcp-servers", false],
  ["/access-groups", false],
  // Backend / framework / rewrite routes: bypassed.
  ["/api/auth/get-session", true],
  ["/trpc/frontend/example", true],
  ["/mcp-proxy/server", true],
  ["/metamcp/x/mcp", true],
  ["/service/anything", true],
  ["/.well-known/oauth-authorization-server", true],
  ["/m365/enroll", true],
  ["/health", true],
  ["/health/upstream", true],
  ["/_next/static/chunk", true],
  // Static files (a dot anywhere in the path).
  ["/favicon.ico", true],
  // The root is deliberately NOT bypassed: the middleware routes it to login or
  // the dashboard by session state, it is not a static/backend path.
  ["/", false],
];

describe("shouldBypassMiddleware", () => {
  it.each(TABLE)("%s -> bypass=%s", (pathname, expected) => {
    expect(shouldBypassMiddleware(pathname)).toBe(expected);
  });

  it("matches each bypass prefix on a segment boundary, not a bare prefix", () => {
    for (const prefix of MIDDLEWARE_BYPASS_PREFIXES) {
      // The prefix itself and any sub-path under it are bypassed.
      expect(shouldBypassMiddleware(prefix)).toBe(true);
      expect(shouldBypassMiddleware(prefix + "/sub")).toBe(true);
      // A DIFFERENT segment that merely starts with the prefix word is NOT
      // bypassed. (Skip prefixes carrying a dot: the static-file rule bypasses
      // anything with a dot regardless of the segment boundary.)
      if (!prefix.includes(".")) {
        expect(shouldBypassMiddleware(prefix + "-clients")).toBe(false);
      }
    }
  });
});

describe("config.matcher agrees with shouldBypassMiddleware", () => {
  // Next invokes the middleware only when the matcher MATCHES the path, so a
  // matched path is one that is NOT bypassed. Compile the literal Next actually
  // ships and hold it to the same table as the function.
  const matcher = config.matcher[0];
  const matcherRegex = new RegExp("^" + matcher + "$");

  it("is a single literal string (Next requires a static matcher)", () => {
    expect(Array.isArray(config.matcher)).toBe(true);
    expect(config.matcher).toHaveLength(1);
    expect(typeof matcher).toBe("string");
  });

  it.each(TABLE)(
    "%s: matcher match === not bypassed (%s)",
    (pathname, expectedBypass) => {
      const matcherRuns = matcherRegex.test(pathname);
      expect(matcherRuns).toBe(!expectedBypass);
      // And the function's own answer is consistent with the matcher's.
      expect(shouldBypassMiddleware(pathname)).toBe(!matcherRuns);
    },
  );
});
