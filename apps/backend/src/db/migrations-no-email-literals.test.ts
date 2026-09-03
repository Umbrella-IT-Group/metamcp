/**
 * Committed migrations must not name email-address identities.
 *
 * Admin identity is a deployment concern, not a committed one: a deployment
 * names its own operator through configuration at boot (the platform overlay
 * supplies it via METAMCP_ADMIN_EMAIL; a self-hosted deploy provisions the
 * account with BOOTSTRAP_USERS and grants the role in its own seed), rather
 * than inheriting one baked into this public repository. Two early migrations
 * predate that policy and promote a specific address by literal in the SQL.
 * They are grandfathered here, not by choice but by fact: they have already
 * run in production and this repository's history is public, so rewriting them
 * would change nothing an attacker has not already read while breaking every
 * deployed migration checksum. The guard is therefore forward-looking -- it
 * fences off every migration written after the current head so a NEW one
 * cannot reintroduce the disclosure.
 *
 * This is a static assertion over the migration files, so it runs with no
 * database, the same way the immutability suites' layer 1 does.
 */

import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

// apps/backend/src/db -> apps/backend/drizzle
const DRIZZLE_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../drizzle",
);

// The two pre-policy migrations are 0020 and 0022. Everything numbered at or
// below the current head is left untouched (applied, immutable, public); the
// guard applies strictly ABOVE it. Bump this only when a reviewed migration
// legitimately becomes the new head, never to admit an email literal.
const GRANDFATHERED_THROUGH = 34;

// Matches a bare email address: a local part, an @, a domain, and a TLD. Kept
// deliberately permissive so an obfuscation-free literal in any position
// (comment or statement) is caught; a global instance is built per use because
// a shared /g/ RegExp carries lastIndex between calls.
const EMAIL_LITERAL = "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}";

function migrationsAfterHead(): string[] {
  return readdirSync(DRIZZLE_DIR)
    .filter((name) => name.endsWith(".sql"))
    .filter((name) => {
      const prefix = /^(\d{4})_/.exec(name);
      return prefix !== null && Number(prefix[1]) > GRANDFATHERED_THROUGH;
    })
    .sort();
}

describe("committed migrations name no email-address identities", () => {
  // Guards the guard: an empty set of newer migrations makes the scan below
  // pass vacuously, so this proves the detector actually fires on an address
  // rather than silently never matching.
  it("the email-literal detector matches a sample address", () => {
    expect(new RegExp(EMAIL_LITERAL).test("someone@example.com")).toBe(true);
  });

  it("no migration after the grandfathered head carries an email literal", () => {
    const offenders: string[] = [];
    for (const name of migrationsAfterHead()) {
      const sql = readFileSync(path.join(DRIZZLE_DIR, name), "utf-8");
      const matches = sql.match(new RegExp(EMAIL_LITERAL, "g"));
      if (matches) {
        offenders.push(`${name}: ${[...new Set(matches)].join(", ")}`);
      }
    }
    // Drive admin promotion through the bootstrap path (METAMCP_ADMIN_EMAIL /
    // BOOTSTRAP_USERS) instead of a literal in committed SQL.
    expect(offenders).toEqual([]);
  });
});
