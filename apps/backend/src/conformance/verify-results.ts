/**
 * The two checks the conformance script layers on the runner's own baseline.
 *
 *   baseline  validate expected-failures.yml before anything starts
 *   results   read the runner's per-scenario `checks.json` files and compare the
 *             failing checks, message fingerprint included, with the committed
 *             snapshot, so a scenario that fails for a NEW reason is caught even
 *             while it stays "expected"
 *
 * Exit codes: 0 ok, 10 baseline invalid, 11 results missing, unreadable or
 * empty, 12 snapshot differs, 2 usage or I/O failure.
 */
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";

import {
  baselineMissingRows,
  type CheckRecord,
  compareSnapshot,
  failingRows,
  locateResults,
  parseBaseline,
  parseScenarioList,
  renderSnapshot,
  type SnapshotRow,
  validateBaseline,
} from "./baseline";
import { isMainModule } from "./cli";

export interface Io {
  out(text: string): void;
  err(text: string): void;
}

const EXIT_BASELINE = 10;
const EXIT_RESULTS = 11;
const EXIT_SNAPSHOT = 12;
const EXIT_USAGE = 2;

const OPTIONS = {
  scenarios: { type: "string" },
  baseline: { type: "string" },
  "expect-count": { type: "string" },
  results: { type: "string" },
  snapshot: { type: "string" },
  update: { type: "boolean" },
} as const;

function parse(args: readonly string[]) {
  return parseArgs({ args: [...args], options: OPTIONS, strict: true }).values;
}

export function main(argv: readonly string[], io: Io): number {
  const [command, ...rest] = argv;
  let values: ReturnType<typeof parse>;
  try {
    values = parse(rest);
  } catch (error) {
    io.err(
      `usage error: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    return EXIT_USAGE;
  }
  if (!values.scenarios || !values.baseline) {
    io.err("--scenarios and --baseline are required\n");
    return EXIT_USAGE;
  }

  try {
    const scenarios = parseScenarioList(readFileSync(values.scenarios, "utf8"));
    const parsedBaseline = parseBaseline(readFileSync(values.baseline, "utf8"));

    if (command === "baseline") {
      const expectCount = Number(values["expect-count"]);
      if (!Number.isInteger(expectCount)) {
        io.err("--expect-count must be an integer\n");
        return EXIT_USAGE;
      }
      const errors = validateBaseline(parsedBaseline, scenarios, expectCount);
      for (const error of errors) io.err(`baseline: ${error}\n`);
      return errors.length === 0 ? 0 : EXIT_BASELINE;
    }

    if (command === "results") {
      if (!values.results || !values.snapshot) {
        io.err("--results and --snapshot are required\n");
        return EXIT_USAGE;
      }
      const { dirs, errors } = locateResults(
        readdirSync(values.results),
        scenarios,
      );
      const rows: SnapshotRow[] = [];
      for (const [scenario, dir] of dirs) {
        const file = path.join(values.results, dir, "checks.json");
        let checks: unknown;
        try {
          checks = JSON.parse(readFileSync(file, "utf8"));
        } catch (error) {
          errors.push(
            `${scenario}: checks.json unreadable (${error instanceof Error ? error.message : String(error)})`,
          );
          continue;
        }
        // A scenario with zero checks never ran: the runner counts it as
        // passing, which is exactly how a missing result could pass.
        if (!Array.isArray(checks) || checks.length === 0) {
          errors.push(`${scenario}: checks.json holds no checks`);
          continue;
        }
        rows.push(...failingRows(scenario, checks as CheckRecord[]));
      }
      if (errors.length > 0) {
        for (const error of errors) io.err(`results: ${error}\n`);
        return EXIT_RESULTS;
      }

      const actual = renderSnapshot(rows);
      if (values.update) {
        writeFileSync(values.snapshot, actual);
        io.out(`snapshot written: ${rows.length} failing checks\n`);
        return 0;
      }

      const expected = readFileSync(values.snapshot, "utf8");
      const { added, removed } = compareSnapshot(expected, actual);
      for (const row of removed) io.err(`- ${row}\n`);
      for (const row of added) io.err(`+ ${row}\n`);
      const missing = baselineMissingRows(
        parsedBaseline.entries.map((e) => e.scenario),
        parseSnapshotRows(expected),
      );
      for (const scenario of missing) {
        io.err(
          `snapshot has no recorded reason for baseline entry "${scenario}"\n`,
        );
      }
      return added.length + removed.length + missing.length === 0
        ? 0
        : EXIT_SNAPSHOT;
    }

    io.err("usage: verify-results <baseline|results> [options]\n");
    return EXIT_USAGE;
  } catch (error) {
    io.err(
      `${command}: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    return EXIT_USAGE;
  }
}

function parseSnapshotRows(text: string): SnapshotRow[] {
  return text
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => {
      const [
        scenario = "",
        status = "",
        id = "",
        digest = "",
        detail = "",
        preview = "",
      ] = line.split("\t");
      return { scenario, status, id, digest, detail, preview };
    });
}

if (isMainModule(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2), {
    out: (text) => void process.stdout.write(text),
    err: (text) => void process.stderr.write(text),
  });
}
