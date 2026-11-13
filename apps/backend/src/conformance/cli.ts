import { realpathSync } from "node:fs";
import { pathToFileURL } from "node:url";

/**
 * True when `metaUrl` (the caller's `import.meta.url`) is the script node was
 * started with, so an entry file can export its logic for tests and still run
 * when launched as `node --import tsx <file>`.
 */
export function isMainModule(metaUrl: string): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return metaUrl === pathToFileURL(realpathSync(entry)).href;
  } catch {
    return false;
  }
}
