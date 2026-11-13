// Stub: committed first so the tests fail on assertions rather than on a
// missing import. It is deliberately inert (creates and deletes nothing) so a
// red run can never touch a real directory. Replaced by the real implementation
// in the next commit.

export const RUN_DIR_PREFIX = "conformance-run-";
export const OWNER_MARKER = ".conformance-run-owner";

export interface RunDirContext {
  parent: string;
  repoRoot: string;
  /** Test seam: the uid the directory must belong to. Defaults to the process uid. */
  uid?: number;
}

export function allocateRunDir(ctx: RunDirContext): string {
  return ctx.parent;
}

export function assertOwnedRunDir(dir: string, _ctx: RunDirContext): string {
  return dir;
}

export function removeOwnedRunDir(_dir: string, _ctx: RunDirContext): void {}
