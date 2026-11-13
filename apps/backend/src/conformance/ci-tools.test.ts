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
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
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
  sandbox = realpathSync(
    mkdtempSync(path.join(tmpdir(), "conformance-test-ci-tools-")),
  );
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

describe("origin-policy-gate", () => {
  // Wording from logOriginPolicyBootState and formatOriginEventMessage. The
  // pinned runner's DNS-rebinding scenario sends this foreign Origin.
  const boot =
    "[INFO] [origin-policy] MCP_ORIGIN_POLICY=audit: requests with an Origin other than APP_URL, EXTRA_TRUSTED_ORIGINS or MCP_ALLOWED_ORIGINS are served and recorded as would-be refusals (MCP_ALLOWED_ORIGINS: 1 origin(s)).";
  const event =
    '[WARN] [MetaMCP][system][origin-policy] origin-policy audit: Origin "http://evil.example.com", POST mcp, served (200), credential present, sec-fetch-site absent; would be refused under MCP_ORIGIN_POLICY=enforce; ua "node"';

  async function check(log: string) {
    const file = path.join(sandbox, "gateway.log");
    writeFileSync(file, log);
    return run("origin-policy-gate", "--log", file);
  }

  it("exits 0 only when default audit mode and the foreign-Origin event are recorded", async () => {
    expect((await check(`${boot}\n${event}\n`)).code).toBe(0);
  });

  it("exits 1 for off, enforce or missing boot evidence, even beside an audit event", async () => {
    for (const line of [
      "[WARN] [origin-policy] MCP_ORIGIN_POLICY=off: the Origin header on /metamcp requests is not checked.",
      boot.replace("=audit:", "=enforce:"),
      "",
    ]) {
      const result = await check(`${line}\n${event}\n`);
      expect(result.code, line).toBe(1);
      expect(result.err).toContain("boot confirmation");
    }
  });

  it("exits 1 when audit mode was announced but the foreign-Origin event is absent or different", async () => {
    for (const line of [
      "",
      event.replace("evil.example.com", "127.0.0.1:3902"),
      event.replace("POST mcp", "POST openapi"),
      event.replace("served (200)", "served (500)"),
      event.replace("credential present", "credential absent"),
      event.replace("would be refused", "would be allowed"),
    ]) {
      const result = await check(`${boot}\n${line}\n`);
      expect(result.code, line).toBe(1);
      expect(result.err).toContain("no Origin audit event");
    }
  });

  it("exits 2 when it cannot read the gateway log", async () => {
    expect((await run("origin-policy-gate")).code).toBe(2);
    expect(
      (
        await run(
          "origin-policy-gate",
          "--log",
          path.join(sandbox, "missing.log"),
        )
      ).code,
    ).toBe(2);
  });

  it("makes run.sh fail a baselined run as REGRESSION for missing evidence and HARNESS for an unreadable log", () => {
    const script = readFileSync(
      path.resolve(
        import.meta.dirname,
        "../../../../.github/conformance/run.sh",
      ),
      "utf8",
    );
    // Execute the script's gate and final verdict with the real CLI, without
    // starting the database or suite. This catches a lost call or exit mapping.
    const start = script.indexOf("# The DNS-rebinding scenario");
    const end = script.indexOf(
      "# --------------------------------------------- 9.",
    );
    const final = script.lastIndexOf(
      '\nif [ "${#FAILED_CLASSES[@]}" -gt 0 ]; then',
    );
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    expect(final).toBeGreaterThan(end);
    const shell = [
      "set -euo pipefail",
      "FAILED_CLASSES=()",
      'tools() { node --import tsx src/conformance/ci-tools.ts "$@"; }',
      'note() { echo "== $*"; }',
      'annotate() { echo "::error title=$1::$2"; }',
      script.slice(start, end),
      script.slice(final),
    ].join("\n");
    for (const [log, code, result] of [
      [`${boot}\n${event}\n`, 0, "conformance: ok"],
      [boot, 1, "::error title=REGRESSION::"],
      [boot.replace("=audit:", "=off:"), 1, "::error title=REGRESSION::"],
      [undefined, 1, "::error title=HARNESS::"],
    ] as const) {
      const file = path.join(sandbox, "gateway.log");
      if (log === undefined) rmSync(file, { force: true });
      else writeFileSync(file, log);
      const run = spawnSync("bash", ["-c", shell], {
        cwd: path.resolve(import.meta.dirname, "../.."),
        env: { ...process.env, RUN_DIR: sandbox, verdict_class: "OK" },
        encoding: "utf8",
        timeout: 10_000,
      });
      expect(run.error).toBeUndefined();
      expect(run.status, run.stdout + run.stderr).toBe(code);
      expect(run.stdout).toContain(result);
    }
  });
});

describe("usage", () => {
  it("exits 2 for an unknown command", async () => {
    expect((await run("frobnicate")).code).toBe(2);
    expect((await run()).code).toBe(2);
  });
});
