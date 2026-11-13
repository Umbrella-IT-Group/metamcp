/**
 * The result-reading half of the conformance gate, end to end on a throwaway
 * directory: the runner's `server-<scenario>-<ISO>/checks.json` layout in, an
 * exit code out. The pieces (name matching, fingerprints, validation) are
 * pinned in baseline.test.ts; this proves they are wired so that a missing,
 * empty or reworded result cannot slip through.
 *
 * Oracle: the layout and exit codes documented in verify-results.ts; the
 * directory naming from @modelcontextprotocol/conformance 0.1.16 (`_n`, `Cn`).
 */
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { main } from "./verify-results";

let dir: string;

const SCENARIOS = ["ping", "completion-complete", "tools-list"];

function write(name: string, content: string): string {
  const file = path.join(dir, name);
  writeFileSync(file, content);
  return file;
}

function result(
  scenario: string,
  checks: unknown,
  stamp = "2026-11-13T06-17-00-123Z",
) {
  const d = path.join(dir, "results", `server-${scenario}-${stamp}`);
  mkdirSync(d, { recursive: true });
  writeFileSync(
    path.join(d, "checks.json"),
    typeof checks === "string" ? checks : JSON.stringify(checks),
  );
}

const pass = [{ id: "ok", status: "SUCCESS", description: "fine" }];
const failing = (message: string) => [
  { id: "completion", status: "FAILURE", errorMessage: message },
];

beforeEach(() => {
  dir = mkdtempSync(path.join(tmpdir(), "conformance-test-verify-"));
  mkdirSync(path.join(dir, "results"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function run(...argv: string[]) {
  let err = "";
  let out = "";
  const code = main(argv, { out: (t) => (out += t), err: (t) => (err += t) });
  return { code, err, out };
}

function args(extra: string[] = []) {
  return [
    "results",
    "--scenarios",
    write("scenarios.txt", SCENARIOS.map((s) => `  - ${s}`).join("\n")),
    "--baseline",
    write(
      "baseline.yml",
      "server:\n  - completion-complete  # not advertised by the gateway\n",
    ),
    "--results",
    path.join(dir, "results"),
    "--snapshot",
    path.join(dir, "expected-checks.txt"),
    ...extra,
  ];
}

describe("results", () => {
  it("writes a snapshot with --update, then accepts the same results against it", () => {
    result("ping", pass);
    result("tools-list", pass);
    result("completion-complete", failing("Method not found"));
    expect(run(...args(["--update"])).code).toBe(0);
    expect(
      readFileSync(path.join(dir, "expected-checks.txt"), "utf8"),
    ).toContain("completion-complete\tFAILURE");
    expect(run(...args()).code).toBe(0);
  });

  it("exits 12 when a scenario fails for a different reason, even past the preview length", () => {
    result("ping", pass);
    result("tools-list", pass);
    result("completion-complete", failing(`${"x".repeat(300)}first`));
    run(...args(["--update"]));
    result(
      "completion-complete",
      failing(`${"x".repeat(300)}second`),
      "2026-11-13T06-18-00-123Z",
    );
    rmSync(
      path.join(
        dir,
        "results",
        "server-completion-complete-2026-11-13T06-17-00-123Z",
      ),
      { recursive: true },
    );
    const r = run(...args());
    expect(r.code).toBe(12);
    expect(r.err).toMatch(/^[+-] /m);
  });

  it("exits 11 for a missing, unreadable or empty result", () => {
    result("ping", pass);
    result("completion-complete", failing("m"));
    // tools-list has no directory at all.
    expect(run(...args(["--update"])).code).toBe(11);

    result("tools-list", "{ not json");
    expect(run(...args(["--update"])).code).toBe(11);

    rmSync(
      path.join(dir, "results", "server-tools-list-2026-11-13T06-17-00-123Z"),
      { recursive: true },
    );
    result("tools-list", []);
    expect(run(...args(["--update"])).code).toBe(11);
  });

  it("exits 12 when a baseline entry has no recorded reason in the snapshot", () => {
    result("ping", pass);
    result("tools-list", pass);
    result("completion-complete", pass);
    write("expected-checks.txt", "");
    const r = run(...args());
    expect(r.code).toBe(12);
    expect(r.err).toContain("completion-complete");
  });
});

describe("baseline", () => {
  it("exits 10 for an invalid baseline and 0 for a valid one", () => {
    const scenarios = write(
      "scenarios.txt",
      SCENARIOS.map((s) => `  - ${s}`).join("\n"),
    );
    const good = write(
      "good.yml",
      "server:\n  - ping  # a documented reason\n",
    );
    const bad = write("bad.yml", "server:\n  - ping\n");
    expect(
      run(
        "baseline",
        "--scenarios",
        scenarios,
        "--baseline",
        good,
        "--expect-count",
        "3",
      ).code,
    ).toBe(0);
    expect(
      run(
        "baseline",
        "--scenarios",
        scenarios,
        "--baseline",
        bad,
        "--expect-count",
        "3",
      ).code,
    ).toBe(10);
    expect(
      run(
        "baseline",
        "--scenarios",
        scenarios,
        "--baseline",
        good,
        "--expect-count",
        "4",
      ).code,
    ).toBe(10);
  });

  it("exits 2 for a usage error", () => {
    expect(run("baseline").code).toBe(2);
    expect(run("frobnicate", "--scenarios", "a", "--baseline", "b").code).toBe(
      2,
    );
  });
});
