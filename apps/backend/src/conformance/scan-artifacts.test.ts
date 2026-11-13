/**
 * The results directory of a run is uploaded as a CI artifact, and artifacts of
 * a public repository are public. The scan is therefore a gate, and a gate that
 * reads "no hit" when it could not look (a read error, a symlink it declined to
 * follow, a missing directory) is worse than none. These tests pin both halves:
 * a seeded secret is found, and anything that stops the scan from completing is
 * an error, never a clean result.
 *
 * Oracle: the two credential shapes the harness generates itself, `sk_mt_` and
 * `confsec_` followed by exactly 64 lowercase hex digits (`openssl rand -hex 32`).
 */
import {
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

import { scanDirectory, type ScanFs, SECRET_PATTERN } from "./scan-artifacts";

const HEX64 = "0123456789abcdef".repeat(4);
const KEY = `sk_mt_${HEX64}`;
const AUTH = `confsec_${HEX64}`;

let root: string;

beforeEach(() => {
  root = realpathSync(
    mkdtempSync(path.join(tmpdir(), "conformance-test-scan-")),
  );
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("scanDirectory", () => {
  it("reports a clean tree with the number of files it actually read", () => {
    mkdirSync(path.join(root, "results"));
    writeFileSync(path.join(root, "gateway.log"), "listening on 12009\n");
    writeFileSync(path.join(root, "results", "checks.json"), "[]");
    expect(scanDirectory(root)).toEqual({ hits: [], scanned: 2 });
  });

  it("finds a gateway key in a nested file and names the file, never the line", () => {
    mkdirSync(path.join(root, "results"));
    writeFileSync(
      path.join(root, "results", "runner.log"),
      `Authorization: Bearer ${KEY}\n`,
    );
    const { hits } = scanDirectory(root);
    expect(hits).toEqual([path.join("results", "runner.log")]);
    expect(JSON.stringify(hits)).not.toContain(KEY);
  });

  it("finds the auth-secret shape as well as the key shape", () => {
    writeFileSync(path.join(root, "a.log"), AUTH);
    writeFileSync(path.join(root, "b.log"), KEY);
    expect(scanDirectory(root).hits.sort()).toEqual(["a.log", "b.log"]);
  });

  it("finds a secret in a file NAME", () => {
    writeFileSync(path.join(root, `${KEY}.txt`), "x");
    expect(scanDirectory(root).hits).toHaveLength(1);
  });

  it("finds a secret in a binary file", () => {
    writeFileSync(
      path.join(root, "blob.bin"),
      Buffer.concat([
        Buffer.from([0, 255, 1]),
        Buffer.from(KEY),
        Buffer.from([0, 7]),
      ]),
    );
    expect(scanDirectory(root).hits).toEqual(["blob.bin"]);
  });

  it("does not flag a shorter lookalike (negative control)", () => {
    writeFileSync(
      path.join(root, "ok.log"),
      `sk_mt_${HEX64.slice(1)} confsec_${HEX64.slice(1)} sk_mt_…beef`,
    );
    expect(scanDirectory(root).hits).toEqual([]);
  });

  it("throws, rather than reporting clean, when a file cannot be read", () => {
    writeFileSync(path.join(root, "a.log"), "x");
    const failing: ScanFs = {
      readdirSync: (d) => ["a.log"].filter(() => d === root),
      lstatSync: (f) => ({
        isFile: () => f !== root,
        isDirectory: () => f === root,
        isSymbolicLink: () => false,
      }),
      readFileSync: () => {
        throw new Error("EIO: i/o error");
      },
    };
    expect(() => scanDirectory(root, failing)).toThrow(/EIO/);
  });

  it("throws on a symlink instead of following or skipping it", () => {
    writeFileSync(path.join(root, "real.log"), "x");
    symlinkSync(path.join(root, "real.log"), path.join(root, "link.log"));
    expect(() => scanDirectory(root)).toThrow(/symlink/i);
  });

  it("throws when the directory is missing, or is a file", () => {
    expect(() => scanDirectory(path.join(root, "nope"))).toThrow();
    const file = path.join(root, "f");
    writeFileSync(file, "x");
    expect(() => scanDirectory(file)).toThrow();
    expect(readFileSync(file, "utf8")).toBe("x");
  });
});

describe("SECRET_PATTERN", () => {
  it("is anchored to the exact generated shape", () => {
    expect(SECRET_PATTERN.test(KEY)).toBe(true);
    expect(SECRET_PATTERN.test(AUTH)).toBe(true);
    expect(SECRET_PATTERN.test(`sk_mt_${HEX64.toUpperCase()}`)).toBe(false);
  });
});
