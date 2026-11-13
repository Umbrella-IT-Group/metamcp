/**
 * The command line the conformance script and the workflow call. The point of
 * these tests is the exit codes: the workflow uploads the results directory
 * only when the scrub step exits 0, so a seeded secret AND a scanner that could
 * not do its job must both exit non-zero, and the output on a hit must name the
 * file without ever repeating the secret.
 *
 * Oracle: the documented contract of each subcommand (0 ok, 1 refused or a
 * finding, 2 the tool itself failed, 10 database refused) and the run-directory
 * rules pinned in run-dir.test.ts.
 */
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { main } from "./ci-tools";

const KEY = `sk_mt_${"0123456789abcdef".repeat(4)}`;

let sandbox: string;
let repoRoot: string;
let parent: string;

beforeEach(() => {
  sandbox = realpathSync(mkdtempSync(path.join(tmpdir(), "w6-ci-tools-")));
  repoRoot = path.join(sandbox, "checkout");
  parent = path.join(sandbox, "out");
  mkdirSync(path.join(repoRoot, ".git"), { recursive: true });
  mkdirSync(parent);
});

afterEach(() => {
  rmSync(sandbox, { recursive: true, force: true });
});

async function run(...argv: string[]) {
  let out = "";
  let err = "";
  const code = await main(argv, {
    out: (t) => (out += t),
    err: (t) => (err += t),
  });
  return { code, out, err, all: out + err };
}

async function allocate(): Promise<string> {
  const r = await run(
    "alloc-run-dir",
    "--parent",
    parent,
    "--repo-root",
    repoRoot,
  );
  expect(r.code).toBe(0);
  const dir = r.out.trim();
  // Fail here, before any test writes into it, if the path is not a real one
  // beneath the sandbox.
  expect(path.isAbsolute(dir) && dir.startsWith(`${parent}${path.sep}`)).toBe(
    true,
  );
  return dir;
}

describe("scan", () => {
  it("exits 0 for a clean results directory", async () => {
    const dir = await allocate();
    writeFileSync(path.join(dir, "gateway.log"), "listening\n");
    const r = await run("scan", "--dir", dir);
    expect(r.code).toBe(0);
  });

  it("exits 1 for a seeded secret, names the file and never prints the secret", async () => {
    const dir = await allocate();
    writeFileSync(path.join(dir, "gateway.log"), `Bearer ${KEY}\n`);
    const r = await run("scan", "--dir", dir);
    expect(r.code).toBe(1);
    expect(r.all).toContain("gateway.log");
    expect(r.all).not.toContain(KEY);
  });

  it("with --remove-on-hit deletes only the owned run directory", async () => {
    const keep = path.join(parent, "caller-file.txt");
    writeFileSync(keep, "keep");
    const dir = await allocate();
    writeFileSync(path.join(dir, "gateway.log"), KEY);
    const r = await run(
      "scan",
      "--dir",
      dir,
      "--remove-on-hit",
      "--parent",
      parent,
      "--repo-root",
      repoRoot,
    );
    expect(r.code).toBe(1);
    expect(existsSync(dir)).toBe(false);
    expect(existsSync(keep)).toBe(true);
  });

  it("exits 2 (never 0) when the scanner cannot do its job", async () => {
    expect(
      (await run("scan", "--dir", path.join(sandbox, "missing"))).code,
    ).toBe(2);
    expect((await run("scan", "--dir", "")).code).toBe(2);
    expect((await run("scan")).code).toBe(2);

    const dir = await allocate();
    writeFileSync(path.join(sandbox, "target"), "x");
    symlinkSync(path.join(sandbox, "target"), path.join(dir, "link"));
    expect((await run("scan", "--dir", dir)).code).toBe(2);
  });

  it("does not delete anything when it exits 2, even with --remove-on-hit", async () => {
    const dir = await allocate();
    writeFileSync(path.join(sandbox, "target"), "x");
    symlinkSync(path.join(sandbox, "target"), path.join(dir, "link"));
    const r = await run(
      "scan",
      "--dir",
      dir,
      "--remove-on-hit",
      "--parent",
      parent,
      "--repo-root",
      repoRoot,
    );
    expect(r.code).toBe(2);
    expect(existsSync(dir)).toBe(true);
  });
});

describe("run directory commands", () => {
  it("allocate then verify then remove, and refuse a directory that was never allocated", async () => {
    const dir = await allocate();
    const args = ["--dir", dir, "--parent", parent, "--repo-root", repoRoot];
    expect((await run("verify-run-dir", ...args)).code).toBe(0);
    expect((await run("remove-run-dir", ...args)).code).toBe(0);
    expect(existsSync(dir)).toBe(false);

    const foreign = path.join(parent, "conformance-run-foreign");
    mkdirSync(foreign);
    writeFileSync(path.join(foreign, "x"), "x");
    const bad = ["--dir", foreign, "--parent", parent, "--repo-root", repoRoot];
    expect((await run("verify-run-dir", ...bad)).code).toBe(1);
    expect((await run("remove-run-dir", ...bad)).code).toBe(1);
    expect(existsSync(path.join(foreign, "x"))).toBe(true);
  });

  it("refuses to allocate inside the checkout", async () => {
    const r = await run(
      "alloc-run-dir",
      "--parent",
      repoRoot,
      "--repo-root",
      repoRoot,
    );
    expect(r.code).toBe(1);
  });
});

describe("guard-db, classify-runner, check-bundle", () => {
  it("guard-db exits 10 for a database it will not touch", async () => {
    expect(
      (await run("guard-db", "--url", "postgresql://u@127.0.0.1/metamcp_test"))
        .code,
    ).toBe(0);
    expect(
      (await run("guard-db", "--url", "postgresql://u@127.0.0.1/metamcp")).code,
    ).toBe(10);
    expect(
      (
        await run(
          "guard-db",
          "--url",
          "postgresql://u@127.0.0.1/metamcp",
          "--allow-any-name",
        )
      ).code,
    ).toBe(0);
    expect(
      (
        await run(
          "guard-db",
          "--url",
          "postgresql://u@db.example.com/metamcp_test",
        )
      ).code,
    ).toBe(10);
  });

  it("classify-runner prints the class it decided on", async () => {
    const log = path.join(sandbox, "runner.log");
    writeFileSync(log, "Unexpected failures (not in baseline):\n  ✗ ping\n");
    const r = await run("classify-runner", "--log", log, "--exit-code", "1");
    expect(r.code).toBe(0);
    expect(r.out.trim().split(/\s/)[0]).toBe("REGRESSION");
  });

  it("check-bundle exits 1 when the built bundle names the harness and 2 when there is no bundle", async () => {
    const dist = path.join(sandbox, "dist");
    mkdirSync(dist);
    writeFileSync(path.join(dist, "index.js"), "console.log(1)");
    expect((await run("check-bundle", "--dist", dist)).code).toBe(0);
    writeFileSync(
      path.join(dist, "index.js"),
      "const k = process.env.CONFORMANCE_API_KEY;",
    );
    expect((await run("check-bundle", "--dist", dist)).code).toBe(1);
    expect(
      (await run("check-bundle", "--dist", path.join(sandbox, "nope"))).code,
    ).toBe(2);
  });
});

describe("usage", () => {
  it("exits 2 for an unknown command", async () => {
    expect((await run("frobnicate")).code).toBe(2);
    expect((await run()).code).toBe(2);
  });
});
