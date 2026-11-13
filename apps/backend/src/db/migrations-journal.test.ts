/**
 * The drizzle migration journal must stay in an order the migrator will apply.
 *
 * WHY THIS IS A TEST. drizzle reads the newest `created_at` already applied
 * to the database ONCE, then runs only journal entries whose `when` is above
 * it. An entry whose `when` is not above its predecessor's is not an error:
 * on a database that already ran the predecessor it is silently skipped, so
 * the container starts, `drizzle-kit migrate` reports success, and the table or
 * constraint the code depends on does not exist. Two branches that each pick
 * "the next number" produce exactly that when they merge in the other order, and
 * a mechanical rename of a migration file (see UMBRELLA_FORK.md's
 * migration-ordering note) changes nothing about its `when`.
 *
 * What this guards is the journal as committed. It cannot see a migration that
 * is already applied in production, so the post-deploy read-back of the schema
 * (not only the journal) stays mandatory.
 *
 * The rules, and what they allow:
 *  - every journal tag has a `.sql` file and every `.sql` file has an entry;
 *  - tags are unique;
 *  - `idx` strictly increases, and each tag's numeric prefix equals its `idx`;
 *  - `when` strictly increases in array order.
 * Gaps in `idx` are allowed (the journal already has one, and a number reserved
 * by another branch that has not merged yet is a gap until it does), so this
 * passes with only some of the in-flight migrations present and with all of
 * them. Numbers are not required to be contiguous; their ORDER is what the
 * migrator uses, so that is what is checked.
 *
 * Static, no database: it runs in the default suite, unlike the integration
 * suites that read the same journal.
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

interface JournalEntry {
  idx: number;
  when: number;
  tag: string;
}

/**
 * Every way the journal can be out of order or out of step with the files,
 * one sentence each. Empty means the journal is sound. Pure, so the cases below
 * can feed it a journal that is wrong in exactly one way.
 */
function journalViolations(
  entries: JournalEntry[],
  sqlTags: string[],
): string[] {
  const violations: string[] = [];
  const seen = new Set<string>();
  entries.forEach((entry, position) => {
    if (seen.has(entry.tag)) {
      violations.push(`duplicate tag ${entry.tag}`);
    }
    seen.add(entry.tag);

    const prefix = /^(\d{4})_/.exec(entry.tag);
    if (!prefix || Number(prefix[1]) !== entry.idx) {
      violations.push(
        `tag ${entry.tag} does not start with its idx ${entry.idx}`,
      );
    }

    const previous = entries[position - 1];
    if (previous && entry.idx <= previous.idx) {
      violations.push(
        `idx ${entry.idx} (${entry.tag}) does not exceed the previous idx ${previous.idx}`,
      );
    }
    if (previous && entry.when <= previous.when) {
      violations.push(
        `when ${entry.when} (${entry.tag}) does not exceed the previous when ${previous.when}: drizzle silently skips it on a database that ran ${previous.tag}`,
      );
    }
  });
  for (const tag of sqlTags) {
    if (!seen.has(tag)) {
      violations.push(`${tag}.sql has no journal entry`);
    }
  }
  for (const entry of entries) {
    if (!sqlTags.includes(entry.tag)) {
      violations.push(`journal entry ${entry.tag} has no .sql file`);
    }
  }
  return violations;
}

const entry = (idx: number, when: number, name = "m"): JournalEntry => ({
  idx,
  when,
  tag: `${String(idx).padStart(4, "0")}_${name}`,
});

describe("journalViolations (the detector itself)", () => {
  // Guards the guard: a detector that never fires makes the real-journal test
  // below pass vacuously.
  const good = [entry(1, 100), entry(2, 200), entry(5, 300)];
  const goodTags = good.map((e) => e.tag);

  it("accepts an ordered journal, including a gap in idx", () => {
    expect(journalViolations(good, goodTags)).toEqual([]);
  });

  it("flags a `when` that does not exceed its predecessor's (the silent skip)", () => {
    const lowered = [entry(1, 100), entry(2, 200), entry(3, 150)];
    const violations = journalViolations(
      lowered,
      lowered.map((e) => e.tag),
    );
    expect(violations).toHaveLength(1);
    expect(violations[0]).toContain("silently skips");
  });

  it("flags an equal `when`", () => {
    const tied = [entry(1, 100), entry(2, 100)];
    expect(
      journalViolations(
        tied,
        tied.map((e) => e.tag),
      ),
    ).toHaveLength(1);
  });

  it("flags an idx that does not increase", () => {
    const backwards = [entry(2, 100), entry(1, 200)];
    expect(
      journalViolations(
        backwards,
        backwards.map((e) => e.tag),
      ).some((v) => v.includes("does not exceed the previous idx")),
    ).toBe(true);
  });

  it("flags a tag whose number is not its idx", () => {
    const renamed = [{ idx: 7, when: 100, tag: "0009_renamed" }];
    expect(journalViolations(renamed, ["0009_renamed"])).toEqual([
      "tag 0009_renamed does not start with its idx 7",
    ]);
  });

  it("flags a duplicate tag", () => {
    const dup = [entry(1, 100), { ...entry(1, 200) }];
    expect(
      journalViolations(
        dup,
        dup.map((e) => e.tag),
      ).some((v) => v.startsWith("duplicate tag")),
    ).toBe(true);
  });

  it("flags a .sql file with no entry and an entry with no .sql file", () => {
    expect(journalViolations(good, [...goodTags, "0006_orphan"])).toEqual([
      "0006_orphan.sql has no journal entry",
    ]);
    expect(journalViolations(good, goodTags.slice(1))).toEqual([
      `journal entry ${goodTags[0]} has no .sql file`,
    ]);
  });
});

describe("the committed drizzle journal", () => {
  const journal = JSON.parse(
    readFileSync(path.join(DRIZZLE_DIR, "meta", "_journal.json"), "utf8"),
  ) as { entries: JournalEntry[] };
  const sqlTags = readdirSync(DRIZZLE_DIR)
    .filter((name) => name.endsWith(".sql"))
    .map((name) => name.replace(/\.sql$/, ""));

  it("is ordered, numbered and matched to its files in a way the migrator applies", () => {
    expect(journalViolations(journal.entries, sqlTags)).toEqual([]);
  });

  it("has entries (a missing or empty journal must not pass vacuously)", () => {
    expect(journal.entries.length).toBeGreaterThan(40);
    expect(sqlTags.length).toBeGreaterThan(40);
  });
});
