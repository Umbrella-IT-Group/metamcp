/**
 * The pure decisions the conformance script makes before it trusts a run:
 * whether the database is a throwaway, whether the gateway really bootstrapped
 * its key, namespace and endpoint, how a runner exit is classified, and whether
 * the production bundle stayed free of the harness.
 *
 * Oracles: libpq connection URI rules (a `host` query parameter overrides the
 * authority, an absolute path names a unix socket directory); the log lines
 * `lib/bootstrap.service.ts` prints (read at the call sites); the runner's own
 * `G` and `K` functions in @modelcontextprotocol/conformance 0.1.16 for the
 * markers and the exit code; tsup's source map `sources` list for the bundle.
 */
import { describe, expect, it } from "vitest";

import {
  checkBootstrapLog,
  checkDatabaseUrl,
  classifyRunnerOutput,
  findConformanceLeaks,
} from "./gates";

const strict = { allowAnyName: false };

describe("checkDatabaseUrl", () => {
  it("accepts a loopback database whose name marks it as a throwaway", () => {
    for (const url of [
      "postgresql://itest@127.0.0.1:5432/metamcp_test",
      "postgres://u:p@localhost/other_test",
      "postgresql://itest@[::1]:5432/conformance",
      "postgresql://itest@[::1]:5432/conformance?host=::1&hostaddr=::1",
      "postgresql://x@localhost/conformance_run_4",
      "postgresql://postgres@localhost/metamcp_test?host=/tmp/some/socket/dir",
      "postgresql://u@localhost/conformance_test?host=127.0.0.1&host=localhost&hostaddr=127.0.0.1&hostaddr=::1",
    ]) {
      expect(checkDatabaseUrl(url, strict), url).toEqual({ ok: true });
    }
  });

  it("refuses a database whose name does not look like a throwaway", () => {
    for (const name of ["metamcp", "production", "testing", "mytest_prod"]) {
      const r = checkDatabaseUrl(
        `postgresql://u@127.0.0.1:5432/${name}`,
        strict,
      );
      expect(r.ok, name).toBe(false);
    }
  });

  it("lets the override waive the NAME rule for a loopback host", () => {
    const url = "postgresql://u@localhost:5432/metamcp";
    expect(checkDatabaseUrl(url, { allowAnyName: true })).toEqual({ ok: true });
  });

  it("refuses a non-loopback host, even with the override", () => {
    for (const url of [
      "postgresql://u@db.example.com/metamcp_test",
      "postgresql://u@192.0.2.5/metamcp_test",
      "postgresql://u@localhost.example.com/metamcp_test",
    ]) {
      expect(checkDatabaseUrl(url, strict).ok, url).toBe(false);
      expect(checkDatabaseUrl(url, { allowAnyName: true }).ok, url).toBe(false);
    }
  });

  it("refuses a host smuggled in through a query parameter", () => {
    for (const q of [
      "host=db.example.com",
      "hostaddr=192.0.2.5",
      "host=relative/dir",
      "host=127.0.0.1&host=db.example.com",
      "host=db.example.com&host=127.0.0.1",
      "hostaddr=127.0.0.1&hostaddr=192.0.2.5",
      "hostaddr=192.0.2.5&hostaddr=127.0.0.1",
    ]) {
      const url = `postgresql://u@localhost/metamcp_test?${q}`;
      expect(checkDatabaseUrl(url, { allowAnyName: true }).ok, q).toBe(false);
    }
  });

  it("refuses a missing, empty or unparseable URL", () => {
    for (const url of [
      "",
      "not a url",
      "postgresql://localhost",
      "postgresql://localhost/",
    ]) {
      expect(checkDatabaseUrl(url, strict).ok, url).toBe(false);
    }
  });
});

const GOOD = [
  "🚀 Initializing environment-based configuration...",
  '✓ Created public API key "conformance" (public): sk_mt_…abcd',
  '✓ Updated namespace "conformance"',
  '✓ Created public endpoint "conformance" (public) in namespace "conformance"',
  "✅ Environment-based configuration initialized successfully",
].join("\n");

describe("checkBootstrapLog", () => {
  it("accepts a log with the key, namespace and endpoint lines and no warnings", () => {
    expect(checkBootstrapLog(GOOD)).toEqual([]);
    expect(
      checkBootstrapLog(
        GOOD.replace("Created public API key", "Public API key").replace(
          "Updated namespace",
          "Created public namespace",
        ),
      ),
    ).toEqual([]);
  });

  it("requires each of the three positive lines", () => {
    for (const needle of ["API key", "namespace", "endpoint"]) {
      const log = GOOD.split("\n")
        .filter((l) => !l.startsWith("✓") || !l.includes(needle))
        .join("\n");
      const problems = checkBootstrapLog(log);
      expect(problems.length, needle).toBeGreaterThan(0);
    }
  });

  it("fails on every skip or failure line the bootstrap can print, even beside a success", () => {
    for (const bad of [
      '⚠️ Skipping API key "conformance" because the key is too short',
      '⚠️ Skipping private API key "x" because no users are available',
      '⚠️ Skipping namespace "x" because user "a@b" was not found',
      '⚠️ Skipping private namespace "x" because no users are available',
      '⚠️ Skipping endpoint "x" because specified namespace "y" was not found',
      '⚠️ Failed to bootstrap endpoint "conformance": Error: boom',
      "⚠️ Endpoints bootstrap failed: Error: boom",
      "❌ Fatal startup error: Error: boom",
      "❌ Error initializing environment-based configuration (ignored): Error",
      '⚠️ Namespace insert for "x" did not return uuid',
    ]) {
      const problems = checkBootstrapLog(`${GOOD}\n${bad}`);
      expect(
        problems.some((p) => p.includes(bad)),
        bad,
      ).toBe(true);
    }
  });

  it("does not match the success lines against a different name", () => {
    const log = GOOD.replaceAll('"conformance"', '"other"');
    expect(checkBootstrapLog(log).length).toBeGreaterThan(0);
  });
});

const ESC = String.fromCharCode(27);
const ansi = (s: string) => `${ESC}[32m${s}${ESC}[0m`;

describe("classifyRunnerOutput", () => {
  it("is OK only on exit 0 with the baseline-passed marker (ANSI codes tolerated)", () => {
    const log = `=== SUMMARY ===\n${ansi("Baseline check passed: all failures are expected.")}\n`;
    expect(classifyRunnerOutput(log, 0).cls).toBe("OK");
  });

  it("is REGRESSION for an unexpected failure or a stale entry", () => {
    expect(
      classifyRunnerOutput(
        `${ansi("Unexpected failures (not in baseline):")}\n  ✗ ping\n`,
        1,
      ).cls,
    ).toBe("REGRESSION");
    expect(
      classifyRunnerOutput(
        `${ansi("Stale baseline entries (now passing - remove from baseline):")}\n  ✓ ping\n`,
        1,
      ).cls,
    ).toBe("REGRESSION");
  });

  it("is HARNESS for a timeout, a crash with no marker, or a scenario that threw", () => {
    expect(classifyRunnerOutput("Running all suite\n", 124).cls).toBe(
      "HARNESS",
    );
    expect(classifyRunnerOutput("TypeError: boom\n", 1).cls).toBe("HARNESS");
    expect(classifyRunnerOutput("", 0).cls).toBe("HARNESS");
    const threw =
      "Failed to run scenario ping: Error\nUnexpected failures (not in baseline):\n  ✗ ping\n";
    expect(classifyRunnerOutput(threw, 1).cls).toBe("HARNESS");
  });

  it("is HARNESS when the passed marker appears with a non-zero exit", () => {
    expect(
      classifyRunnerOutput(
        "Baseline check passed: all failures are expected.",
        1,
      ).cls,
    ).toBe("HARNESS");
  });
});

describe("findConformanceLeaks", () => {
  const clean = [
    {
      path: "dist/index.js",
      content: 'import express from "express";\nconsole.log(1);\n',
    },
    {
      path: "dist/index.js.map",
      content: JSON.stringify({
        sources: ["../src/index.ts", "../src/lib/bootstrap.service.ts"],
      }),
    },
  ];

  it("passes a bundle that names nothing from the harness", () => {
    expect(findConformanceLeaks(clean)).toEqual([]);
  });

  it("flags a source map that lists a file under src/conformance", () => {
    const leaks = findConformanceLeaks([
      ...clean.slice(0, 1),
      {
        path: "dist/index.js.map",
        content: JSON.stringify({
          sources: ["../src/index.ts", "../src/conformance/alias-proxy.ts"],
        }),
      },
    ]);
    expect(leaks).toEqual([expect.stringContaining("alias-proxy.ts")]);
  });

  it("flags harness identifiers and env names inside the bundle text", () => {
    for (const marker of [
      "createAliasProxy",
      "createFixtureServer",
      "CONFORMANCE_API_KEY",
      "CONFORMANCE_UPSTREAM_URL",
    ]) {
      const leaks = findConformanceLeaks([
        { path: "dist/index.js", content: `function ${marker}() {}` },
      ]);
      expect(leaks, marker).toEqual([expect.stringContaining(marker)]);
    }
  });

  it("fails closed when there is nothing to inspect or the map is unreadable", () => {
    expect(findConformanceLeaks([]).length).toBeGreaterThan(0);
    expect(
      findConformanceLeaks([
        { path: "dist/index.js.map", content: "{ not json" },
      ]).length,
    ).toBeGreaterThan(0);
  });
});
