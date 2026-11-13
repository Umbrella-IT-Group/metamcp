/**
 * Command line for the conformance script and workflow: the guards that decide
 * whether a run may start, whether its output may be published, and how its
 * result is read. The logic lives in sibling modules with their own tests; this
 * file only maps them to exit codes:
 *
 *   0  fine
 *   1  refused, or a finding (a secret, leaked bundle, bootstrap warning or missing Origin evidence)
 *   2  the tool itself could not do its job (never treat as "fine")
 *  10  guard-db refused the database
 */
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";

import { isMainModule } from "./cli";
import {
  checkBootstrapLog,
  checkDatabaseUrl,
  checkOriginPolicyLog,
  classifyRunnerOutput,
  findConformanceLeaks,
} from "./gates";
import {
  allocateRunDir,
  assertOwnedRunDir,
  removeOwnedRunDir,
  RunDirRefusal,
} from "./run-dir";
import { scanDirectory } from "./scan-artifacts";

export interface Io {
  out(text: string): void;
  err(text: string): void;
}

const EXIT_OK = 0;
const EXIT_REFUSED = 1;
const EXIT_TOOL_FAILED = 2;
const EXIT_DATABASE_REFUSED = 10;

const REDACT = /(sk_mt_|confsec_)[0-9a-f]{64}/g;
const redact = (text: string) => text.replace(REDACT, "$1[redacted]");

const message = (error: unknown) =>
  error instanceof Error ? error.message : String(error);

function readTree(root: string): Array<{ path: string; content: string }> {
  const files: Array<{ path: string; content: string }> = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile()) {
        files.push({ path: full, content: readFileSync(full, "utf8") });
      }
    }
  };
  walk(root);
  return files;
}

const OPTIONS = {
  dir: { type: "string" },
  parent: { type: "string" },
  "repo-root": { type: "string" },
  "remove-on-hit": { type: "boolean" },
  url: { type: "string" },
  "allow-any-name": { type: "boolean" },
  log: { type: "string" },
  "exit-code": { type: "string" },
  dist: { type: "string" },
} as const;

function parse(args: readonly string[]) {
  return parseArgs({ args: [...args], options: OPTIONS, strict: true }).values;
}

export async function main(argv: readonly string[], io: Io): Promise<number> {
  const [command, ...rest] = argv;

  let values: ReturnType<typeof parse>;
  try {
    values = parse(rest);
  } catch (error) {
    io.err(`usage error: ${message(error)}\n`);
    return EXIT_TOOL_FAILED;
  }

  const ctx = () => {
    if (values.parent === undefined || values["repo-root"] === undefined) {
      throw new Error("--parent and --repo-root are required");
    }
    return { parent: values.parent, repoRoot: values["repo-root"] };
  };

  try {
    switch (command) {
      case "alloc-run-dir": {
        try {
          io.out(`${allocateRunDir(ctx())}\n`);
          return EXIT_OK;
        } catch (error) {
          if (error instanceof RunDirRefusal) {
            io.err(`refused: ${error.message}\n`);
            return EXIT_REFUSED;
          }
          throw error;
        }
      }

      case "verify-run-dir":
      case "remove-run-dir": {
        const dir = values.dir ?? "";
        try {
          if (command === "verify-run-dir") assertOwnedRunDir(dir, ctx());
          else removeOwnedRunDir(dir, ctx());
          return EXIT_OK;
        } catch (error) {
          // Any failure to PROVE ownership is a refusal: nothing was touched.
          io.err(`refused: ${message(error)}\n`);
          return EXIT_REFUSED;
        }
      }

      case "scan": {
        const dir = values.dir;
        if (!dir) {
          io.err("scan: --dir is required\n");
          return EXIT_TOOL_FAILED;
        }
        let result;
        try {
          result = scanDirectory(dir);
        } catch (error) {
          // Could not look: NOT a clean result, and nothing is deleted.
          io.err(`scan failed: ${redact(message(error))}\n`);
          return EXIT_TOOL_FAILED;
        }
        if (result.hits.length === 0) {
          io.out(`scan clean: ${result.scanned} files\n`);
          return EXIT_OK;
        }
        io.err(
          `a credential-shaped value was found in ${result.hits.length} file(s) (names only, never the value):\n`,
        );
        for (const hit of result.hits) io.err(`  ${redact(hit)}\n`);
        if (values["remove-on-hit"]) {
          try {
            removeOwnedRunDir(dir, ctx());
            io.err("the results directory was deleted\n");
          } catch (error) {
            io.err(
              `could not delete the results directory: ${message(error)}\n`,
            );
          }
        }
        return EXIT_REFUSED;
      }

      case "guard-db": {
        if (values.url === undefined) {
          io.err("guard-db: --url is required\n");
          return EXIT_TOOL_FAILED;
        }
        const verdict = checkDatabaseUrl(values.url, {
          allowAnyName: values["allow-any-name"] === true,
        });
        if (verdict.ok) return EXIT_OK;
        io.err(`refused: ${verdict.reason}\n`);
        return EXIT_DATABASE_REFUSED;
      }

      case "bootstrap-gate":
      case "origin-policy-gate": {
        if (!values.log) {
          io.err(`${command}: --log is required\n`);
          return EXIT_TOOL_FAILED;
        }
        const check =
          command === "bootstrap-gate"
            ? checkBootstrapLog
            : checkOriginPolicyLog;
        const problems = check(readFileSync(values.log, "utf8"));
        for (const problem of problems) io.err(`${redact(problem)}\n`);
        return problems.length === 0 ? EXIT_OK : EXIT_REFUSED;
      }

      case "classify-runner": {
        if (!values.log || values["exit-code"] === undefined) {
          io.err("classify-runner: --log and --exit-code are required\n");
          return EXIT_TOOL_FAILED;
        }
        let log = "";
        try {
          log = readFileSync(values.log, "utf8");
        } catch {
          // No runner output at all classifies as a harness failure below.
        }
        const verdict = classifyRunnerOutput(log, Number(values["exit-code"]));
        io.out(`${verdict.cls} ${verdict.reason}\n`);
        return EXIT_OK;
      }

      case "check-bundle": {
        if (!values.dist) {
          io.err("check-bundle: --dist is required\n");
          return EXIT_TOOL_FAILED;
        }
        const problems = findConformanceLeaks(readTree(values.dist));
        for (const problem of problems) io.err(`${problem}\n`);
        return problems.length === 0 ? EXIT_OK : EXIT_REFUSED;
      }

      default:
        io.err(
          "usage: ci-tools <alloc-run-dir|verify-run-dir|remove-run-dir|scan|guard-db|bootstrap-gate|origin-policy-gate|classify-runner|check-bundle> [options]\n",
        );
        return EXIT_TOOL_FAILED;
    }
  } catch (error) {
    io.err(`${command}: ${redact(message(error))}\n`);
    return EXIT_TOOL_FAILED;
  }
}

if (isMainModule(import.meta.url)) {
  main(process.argv.slice(2), {
    out: (text) => void process.stdout.write(text),
    err: (text) => void process.stderr.write(text),
  }).then((code) => {
    process.exitCode = code;
  });
}
