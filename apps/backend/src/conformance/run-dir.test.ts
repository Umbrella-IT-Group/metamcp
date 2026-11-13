/**
 * The conformance run writes logs, a scrubbed results tree and, in the
 * trap, deletes its own output. `${OUT:?}` only rejects an empty string, so a
 * `CONFORMANCE_OUT` that names an existing directory (a developer's home, the
 * checkout, a shared folder) used to be wiped. These tests pin the rule that
 * replaced it: the run only ever creates a FRESH owned directory beneath the
 * caller's path, and only ever deletes a directory that is provably that one.
 *
 * Every case runs on a throwaway tree under the OS temp directory. The
 * "repository" is a temp directory holding a `.git` folder: nothing here ever
 * names the real checkout.
 *
 * Oracle: POSIX `lstat`/`realpath` semantics as documented for Node's `fs`
 * (a symlink is a distinct file type; `fs.rm` with `recursive` removes a link
 * itself and never follows it).
 */
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  allocateRunDir,
  assertOwnedRunDir,
  OWNER_MARKER,
  removeOwnedRunDir,
  RUN_DIR_PREFIX,
} from "./run-dir";

let sandbox: string;
let repoRoot: string;
let parent: string;
let outside: string;

function sentinel(dir: string, name = "sentinel.txt"): string {
  const file = path.join(dir, name);
  writeFileSync(file, "keep me");
  return file;
}

beforeEach(() => {
  sandbox = realpathSync(
    mkdtempSync(path.join(tmpdir(), "conformance-test-run-dir-")),
  );
  repoRoot = path.join(sandbox, "checkout");
  parent = path.join(sandbox, "caller-out");
  outside = path.join(sandbox, "elsewhere");
  for (const d of [repoRoot, parent, outside, path.join(repoRoot, ".git")]) {
    mkdirSync(d, { recursive: true });
  }
});

afterEach(() => {
  rmSync(sandbox, { recursive: true, force: true });
});

const ctx = () => ({ parent, repoRoot });

describe("allocateRunDir", () => {
  it("creates a fresh owned directory beneath an existing non-empty parent and leaves the parent alone", () => {
    const keep = sentinel(parent);
    const dir = allocateRunDir(ctx());

    expect(path.dirname(dir)).toBe(parent);
    expect(path.basename(dir).startsWith(RUN_DIR_PREFIX)).toBe(true);
    expect(readdirSync(dir)).toContain(OWNER_MARKER);
    expect(readFileSync(keep, "utf8")).toBe("keep me");
  });

  it("never reuses a directory: two runs get two directories", () => {
    expect(allocateRunDir(ctx())).not.toBe(allocateRunDir(ctx()));
  });

  it("creates a missing parent", () => {
    const missing = path.join(sandbox, "new", "parent");
    const dir = allocateRunDir({ parent: missing, repoRoot });
    expect(path.dirname(dir)).toBe(missing);
  });

  it("refuses a parent that is the repository root or inside it", () => {
    const logs = sentinel(repoRoot, "app.log");
    expect(() => allocateRunDir({ parent: repoRoot, repoRoot })).toThrow();
    expect(() =>
      allocateRunDir({ parent: path.join(repoRoot, "apps"), repoRoot }),
    ).toThrow();
    expect(readdirSync(repoRoot).sort()).toEqual([".git", "app.log"]);
    expect(readFileSync(logs, "utf8")).toBe("keep me");
  });

  it("refuses a parent that is a symlink into the repository", () => {
    const link = path.join(sandbox, "link-to-repo");
    symlinkSync(repoRoot, link);
    expect(() => allocateRunDir({ parent: link, repoRoot })).toThrow();
    expect(readdirSync(repoRoot)).toEqual([".git"]);
  });

  it("refuses checkout children whose names start with two dots", () => {
    for (const name of ["..cache", "..output/nested"]) {
      expect(() =>
        allocateRunDir({ parent: path.join(repoRoot, name), repoRoot }),
      ).toThrow();
    }
    expect(readdirSync(repoRoot)).toEqual([".git"]);
  });

  it("refuses a filesystem root or an empty parent", () => {
    expect(() => allocateRunDir({ parent: "/", repoRoot })).toThrow();
    expect(() => allocateRunDir({ parent: "", repoRoot })).toThrow();
  });
});

describe("removeOwnedRunDir", () => {
  it("removes the owned directory and nothing else", () => {
    const keep = sentinel(parent);
    const dir = allocateRunDir(ctx());
    writeFileSync(path.join(dir, "gateway.log"), "log");
    mkdirSync(path.join(dir, "results"));

    removeOwnedRunDir(dir, ctx());

    expect(existsSync(dir)).toBe(false);
    expect(existsSync(parent)).toBe(true);
    expect(readFileSync(keep, "utf8")).toBe("keep me");
  });

  it("refuses an existing non-empty directory that merely looks like a run directory", () => {
    const lookalike = path.join(parent, `${RUN_DIR_PREFIX}mine`);
    mkdirSync(lookalike);
    const keep = sentinel(lookalike);
    expect(() => removeOwnedRunDir(lookalike, ctx())).toThrow();
    expect(readFileSync(keep, "utf8")).toBe("keep me");
  });

  it("refuses the repository root, with or without a forged marker", () => {
    const keep = sentinel(repoRoot, "README.md");
    expect(() => removeOwnedRunDir(repoRoot, ctx())).toThrow();
    writeFileSync(path.join(repoRoot, OWNER_MARKER), "forged");
    expect(() => removeOwnedRunDir(repoRoot, ctx())).toThrow();
    expect(() =>
      removeOwnedRunDir(repoRoot, { parent: sandbox, repoRoot }),
    ).toThrow();
    expect(readFileSync(keep, "utf8")).toBe("keep me");
  });

  it("refuses a directory outside the allowed parent even when it is marked", () => {
    const dir = allocateRunDir({ parent: outside, repoRoot });
    const keep = sentinel(dir);
    expect(() => removeOwnedRunDir(dir, ctx())).toThrow();
    expect(readFileSync(keep, "utf8")).toBe("keep me");
  });

  it("refuses a directory whose name is not a run-directory name", () => {
    const odd = path.join(parent, "results");
    mkdirSync(odd);
    writeFileSync(path.join(odd, OWNER_MARKER), "x");
    const keep = sentinel(odd);
    expect(() => removeOwnedRunDir(odd, ctx())).toThrow();
    expect(readFileSync(keep, "utf8")).toBe("keep me");
  });

  it("refuses a run directory that has been swapped for a symlink to somewhere else", () => {
    const dir = allocateRunDir(ctx());
    rmSync(dir, { recursive: true });
    const keep = sentinel(outside);
    writeFileSync(path.join(outside, OWNER_MARKER), "x");
    symlinkSync(outside, dir);

    expect(() => removeOwnedRunDir(dir, ctx())).toThrow();
    expect(lstatSync(dir).isSymbolicLink()).toBe(true);
    expect(readFileSync(keep, "utf8")).toBe("keep me");
  });

  it("removes a symlink found INSIDE the run directory without following it", () => {
    const dir = allocateRunDir(ctx());
    const keep = sentinel(outside);
    symlinkSync(outside, path.join(dir, "escape"));
    symlinkSync(keep, path.join(dir, "escape-file"));

    removeOwnedRunDir(dir, ctx());

    expect(existsSync(dir)).toBe(false);
    expect(readFileSync(keep, "utf8")).toBe("keep me");
  });

  it("refuses a directory that belongs to another user", () => {
    const dir = allocateRunDir(ctx());
    const keep = sentinel(dir);
    const otherUid = (process.getuid?.() ?? 0) + 1;
    expect(() => removeOwnedRunDir(dir, { ...ctx(), uid: otherUid })).toThrow();
    expect(readFileSync(keep, "utf8")).toBe("keep me");
  });
});

describe("assertOwnedRunDir", () => {
  it("returns the canonical path of an owned directory and throws for a missing one", () => {
    const dir = allocateRunDir(ctx());
    expect(assertOwnedRunDir(dir, ctx())).toBe(realpathSync(dir));
    expect(() =>
      assertOwnedRunDir(path.join(parent, `${RUN_DIR_PREFIX}gone`), ctx()),
    ).toThrow();
  });

  it("throws for an empty path", () => {
    expect(() => assertOwnedRunDir("", ctx())).toThrow();
  });
});
