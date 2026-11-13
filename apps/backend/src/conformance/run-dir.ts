/**
 * The conformance run's owned output directory.
 *
 * The run writes process logs, the runner's results and, on exit, deletes its
 * own output. Treating a caller-supplied path as the thing to wipe is how a
 * stray `CONFORMANCE_OUT=$HOME` (or the checkout) loses real files, and
 * `${OUT:?}` only rejects an empty string. So the caller's path is only ever a
 * PARENT: the run creates a fresh, unpredictable child beneath it, marks it
 * with an ownership file, and deletes only a directory that is provably that
 * child (direct child of the parent, run-directory name, marker present,
 * same owner, not a symlink, not the checkout or an ancestor of it).
 */
import { randomBytes } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

export const RUN_DIR_PREFIX = "conformance-run-";
export const OWNER_MARKER = ".conformance-run-owner";
const MARKER_PREFIX = "conformance-run-owner v1 ";

export interface RunDirContext {
  /** The only place a run directory may live. Never itself deleted. */
  parent: string;
  /** The checkout: nothing in or around it is ever created or deleted here. */
  repoRoot: string;
  /** Test seam: the uid the directory must belong to. Defaults to the process uid. */
  uid?: number;
}

/** A refusal (as opposed to the tool failing): the CLI maps it to exit 1. */
export class RunDirRefusal extends Error {}

function contains(outer: string, inner: string): boolean {
  const rel = path.relative(outer, inner);
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

/** realpath of the deepest existing ancestor, plus the not-yet-created tail. */
function canonicalize(target: string): string {
  let head = path.resolve(target);
  const tail: string[] = [];
  for (;;) {
    try {
      return path.join(realpathSync(head), ...tail.reverse());
    } catch (error) {
      const up = path.dirname(head);
      if (up === head) throw error;
      tail.push(path.basename(head));
      head = up;
    }
  }
}

function checkParent(ctx: RunDirContext): { parent: string; repo: string } {
  if (!ctx.parent || !ctx.parent.trim()) {
    throw new RunDirRefusal("no output parent directory given");
  }
  const parent = canonicalize(ctx.parent);
  const repo = canonicalize(ctx.repoRoot);
  if (parent === path.parse(parent).root) {
    throw new RunDirRefusal("refusing the filesystem root as an output parent");
  }
  if (parent === repo || contains(repo, parent)) {
    throw new RunDirRefusal(
      `refusing an output parent inside the checkout: ${parent}`,
    );
  }
  return { parent, repo };
}

export function allocateRunDir(ctx: RunDirContext): string {
  const { parent } = checkParent(ctx);
  mkdirSync(parent, { recursive: true });
  const dir = mkdtempSync(path.join(parent, RUN_DIR_PREFIX));
  writeFileSync(
    path.join(dir, OWNER_MARKER),
    `${MARKER_PREFIX}${randomBytes(16).toString("hex")}\n`,
    { flag: "wx", mode: 0o600 },
  );
  return dir;
}

/** Returns the canonical path of an owned run directory, or throws. */
export function assertOwnedRunDir(dir: string, ctx: RunDirContext): string {
  if (!dir || !dir.trim()) throw new RunDirRefusal("no run directory given");
  const { parent, repo } = checkParent(ctx);

  const stat = lstatSync(path.resolve(dir));
  if (stat.isSymbolicLink()) {
    throw new RunDirRefusal(`run directory is a symlink: ${dir}`);
  }
  if (!stat.isDirectory()) {
    throw new RunDirRefusal(`run directory is not a directory: ${dir}`);
  }
  const canonical = realpathSync(dir);

  if (path.dirname(canonical) !== parent) {
    throw new RunDirRefusal(
      `not a direct child of the output parent: ${canonical}`,
    );
  }
  if (!path.basename(canonical).startsWith(RUN_DIR_PREFIX)) {
    throw new RunDirRefusal(`not a run directory name: ${canonical}`);
  }
  if (
    canonical === repo ||
    contains(repo, canonical) ||
    contains(canonical, repo)
  ) {
    throw new RunDirRefusal(`overlaps the checkout: ${canonical}`);
  }
  const expectedUid = ctx.uid ?? process.getuid?.();
  if (expectedUid !== undefined && stat.uid !== expectedUid) {
    throw new RunDirRefusal(
      `run directory belongs to another user: ${canonical}`,
    );
  }

  const markerPath = path.join(canonical, OWNER_MARKER);
  const markerStat = lstatSync(markerPath);
  if (markerStat.isSymbolicLink() || !markerStat.isFile()) {
    throw new RunDirRefusal(
      `ownership marker is not a regular file: ${markerPath}`,
    );
  }
  const marker = readFileSync(markerPath, "utf8");
  if (
    !marker.startsWith(MARKER_PREFIX) ||
    marker.length <= MARKER_PREFIX.length
  ) {
    throw new RunDirRefusal(`ownership marker is not ours: ${markerPath}`);
  }
  return canonical;
}

export function removeOwnedRunDir(dir: string, ctx: RunDirContext): void {
  const canonical = assertOwnedRunDir(dir, ctx);
  // `recursive` removes a symlink inside the tree as a link; it never follows it.
  rmSync(canonical, { recursive: true });
}
