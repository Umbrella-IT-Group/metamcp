/**
 * A tripwire wired to nothing is the failure this whole module exists to
 * prevent, and it is the one failure its own unit suite cannot catch: every
 * case in `tripwire.test.ts` calls `checkAuditStorage()` directly, so all of
 * them stay green after the call site is deleted from the sweep.
 *
 * The sweep itself is not unit-testable, because `routers/oauth/index.ts`
 * opens a pool and starts an interval at import, so this reads its source.
 * Same technique as the `cors()` call-site guard in
 * `routers/cors-policy.test.ts`.
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const OAUTH_ROUTER = readFileSync(
  path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "../../routers/oauth/index.ts",
  ),
  "utf8",
);

describe("the storage check is wired into the cleanup sweep", () => {
  it("is imported by the router that owns the interval", () => {
    expect(OAUTH_ROUTER).toContain(
      'import { checkAuditStorage } from "@/lib/audit-storage/tripwire";',
    );
  });

  it("is called inside the interval body, not merely imported", () => {
    // The interval callback runs from `setInterval(` to the closing `},` that
    // precedes the period. Scoping to it is what makes this assertion about
    // the sweep rather than about the file containing the string anywhere.
    const start = OAUTH_ROUTER.indexOf("setInterval(");
    const end = OAUTH_ROUTER.indexOf("5 * 60 * 1000", start);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);

    expect(OAUTH_ROUTER.slice(start, end)).toContain(
      "await checkAuditStorage()",
    );
  });

  it("runs AFTER the retention sweeps on the same tick", () => {
    // Measuring before the prunes would report the estate as it stood a moment
    // before the sweep that was about to shrink it, which is the one reading
    // guaranteed to be stale.
    const check = OAUTH_ROUTER.indexOf("await checkAuditStorage()");
    expect(check).toBeGreaterThan(OAUTH_ROUTER.indexOf("pruneOlderThan("));
    expect(check).toBeGreaterThan(
      OAUTH_ROUTER.indexOf("await pruneGatewayEvents()"),
    );
  });
});
