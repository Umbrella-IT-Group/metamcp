/**
 * The conformance harness holds a proxy that injects a gateway key into every
 * request it forwards. It lives under `src/` so type-checking and lint cover it,
 * which is only safe while the production bundle cannot reach it: tsup bundles
 * exactly what `src/index.ts` imports. This test walks that import graph and
 * fails if any module in `src/conformance` becomes reachable, so the harness
 * can never be pulled into the image by an innocent-looking import. The job
 * also inspects the real built bundle (`ci-tools check-bundle`); this is the
 * cheap half that runs in the required unit job, which does not build the
 * backend.
 *
 * Oracle: `tsup.config.ts` declares `entry: ["src/index.ts"]` with
 * `bundle: true`; esbuild includes only modules reachable through static and
 * dynamic `import` specifiers from the entry.
 */
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

const SRC = path.resolve(import.meta.dirname, "..");

const SPECIFIER =
  /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+|\brequire\s*\(\s*)["']([^"']+)["']/g;

function resolveSpecifier(
  from: string,
  spec: string,
  srcRoot: string,
): string | undefined {
  let base: string;
  if (spec.startsWith("@/")) base = path.join(srcRoot, spec.slice(2));
  else if (spec.startsWith(".")) base = path.resolve(path.dirname(from), spec);
  else return undefined; // a package, bundled or external, never our source
  const stripped = base.replace(/\.(js|ts|tsx)$/, "");
  for (const candidate of [
    `${stripped}.ts`,
    `${stripped}.tsx`,
    path.join(base, "index.ts"),
    path.join(stripped, "index.ts"),
    base,
  ]) {
    if (existsSync(candidate) && /\.(ts|tsx)$/.test(candidate))
      return candidate;
  }
  return undefined;
}

export function reachableFrom(entry: string, srcRoot: string): Set<string> {
  const seen = new Set<string>();
  const queue = [entry];
  while (queue.length > 0) {
    const file = queue.pop() as string;
    if (seen.has(file)) continue;
    seen.add(file);
    for (const m of readFileSync(file, "utf8").matchAll(SPECIFIER)) {
      const next = resolveSpecifier(file, m[1], srcRoot);
      if (next && !seen.has(next)) queue.push(next);
    }
  }
  return seen;
}

describe("production bundle reachability", () => {
  it("does not reach any module under src/conformance from the tsup entry", () => {
    const reached = reachableFrom(path.join(SRC, "index.ts"), SRC);
    // A walker that found nothing would make the assertion below vacuous.
    expect(reached.size).toBeGreaterThan(50);
    expect(
      [...reached].some((f) => f.endsWith("lib/metamcp/metamcp-proxy.ts")),
    ).toBe(true);

    const leaked = [...reached].filter((f) =>
      f.includes(`${path.sep}conformance${path.sep}`),
    );
    expect(leaked.map((f) => path.relative(SRC, f))).toEqual([]);
  });

  it("would notice a planted import (negative control for the walker)", () => {
    const root = mkdtempSync(path.join(tmpdir(), "conformance-test-reach-"));
    try {
      mkdirSync(path.join(root, "conformance"));
      mkdirSync(path.join(root, "lib"));
      writeFileSync(
        path.join(root, "index.ts"),
        'import { x } from "./lib/a";\nvoid x;\n',
      );
      writeFileSync(
        path.join(root, "lib", "a.ts"),
        'export const x = await import("@/conformance/proxy");\n',
      );
      writeFileSync(
        path.join(root, "conformance", "proxy.ts"),
        "export const p = 1;\n",
      );

      const reached = reachableFrom(path.join(root, "index.ts"), root);
      expect(
        [...reached].some((f) =>
          f.endsWith(path.join("conformance", "proxy.ts")),
        ),
      ).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
