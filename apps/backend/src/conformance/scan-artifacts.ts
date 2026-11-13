/**
 * Secret scan over a run's results directory, run before anything is uploaded.
 *
 * Artifacts of a public repository are public, and the run handles a gateway
 * API key. Both credentials the harness generates carry a searchable prefix
 * (`sk_mt_`, `confsec_`) and a fixed shape (64 lowercase hex digits), so the
 * scan works without knowing the values and still works after a crash that
 * skipped every cleanup. It also catches a production-shaped key that ended up
 * in a log for any other reason.
 *
 * The scan fails CLOSED. A grep-style "no match" would read a permission error,
 * a symlink it skipped or a missing directory as a clean tree; here every one
 * of those throws, and the caller treats a throw as "could not look", never as
 * "nothing found".
 */
import fs from "node:fs";
import path from "node:path";

export const SECRET_PATTERN = /sk_mt_[0-9a-f]{64}|confsec_[0-9a-f]{64}/;

export interface ScanFs {
  readdirSync(dir: string): string[];
  lstatSync(file: string): {
    isFile(): boolean;
    isDirectory(): boolean;
    isSymbolicLink(): boolean;
  };
  readFileSync(file: string): Buffer;
}

export interface ScanResult {
  /** Paths relative to the scanned root; names only, never the matching text. */
  hits: string[];
  scanned: number;
}

const realFs: ScanFs = {
  readdirSync: (dir) => fs.readdirSync(dir),
  lstatSync: (file) => fs.lstatSync(file),
  readFileSync: (file) => fs.readFileSync(file),
};

export function scanDirectory(
  root: string,
  fsOps: ScanFs = realFs,
): ScanResult {
  const rootStat = fsOps.lstatSync(root);
  if (rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
    throw new Error(`scan root is not a directory: ${root}`);
  }

  const hits: string[] = [];
  let scanned = 0;

  const walk = (dir: string, relDir: string): void => {
    for (const name of fsOps.readdirSync(dir).sort()) {
      const full = path.join(dir, name);
      const rel = relDir ? path.join(relDir, name) : name;
      const stat = fsOps.lstatSync(full);
      if (stat.isSymbolicLink()) {
        throw new Error(`refusing a symlink in the results: ${rel}`);
      }
      if (stat.isDirectory()) {
        if (SECRET_PATTERN.test(name)) hits.push(rel);
        walk(full, rel);
        continue;
      }
      if (!stat.isFile()) {
        throw new Error(`refusing a non-regular file in the results: ${rel}`);
      }
      scanned += 1;
      // latin1 maps every byte to one character, so a binary file is searched
      // as faithfully as a text one and no byte sequence can fail to decode.
      const content = fsOps.readFileSync(full).toString("latin1");
      if (SECRET_PATTERN.test(name) || SECRET_PATTERN.test(content)) {
        hits.push(rel);
      }
    }
  };

  walk(root, "");
  return { hits, scanned };
}
