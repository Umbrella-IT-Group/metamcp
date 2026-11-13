/**
 * The pure decisions the conformance script makes before it trusts a run. Kept
 * out of the shell so each one has a refusing and an allowing test.
 */
import path from "node:path";

export type GateResult = { ok: true } | { ok: false; reason: string };

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);
const THROWAWAY_NAME = /(_test$|^conformance)/;

/**
 * Whether `url` names a database this harness may seed and write to.
 *
 * Bootstrap writes registration-control settings unconditionally and idle
 * warmup resets every server's error status, so pointing the run at a real
 * database would change it. The HOST must always be loopback (the override only
 * waives the database-NAME rule), and a `host` or `hostaddr` query parameter is
 * checked too: libpq lets it override the authority, so
 * `postgresql://u@localhost/x_test?host=db.example.com` would otherwise pass a
 * check of the URL's own host.
 */
export function checkDatabaseUrl(
  url: string,
  opts: { allowAnyName: boolean },
): GateResult {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { ok: false, reason: "DATABASE_URL is not a valid URL" };
  }
  if (parsed.protocol !== "postgres:" && parsed.protocol !== "postgresql:") {
    return { ok: false, reason: "DATABASE_URL is not a postgres URL" };
  }

  // Both consumers can use a later duplicate parameter. Validate every value
  // so an earlier loopback value cannot conceal a later remote destination.
  const hostParams = parsed.searchParams.getAll("host");
  for (const hostParam of hostParams) {
    const ok = path.isAbsolute(hostParam) || LOOPBACK_HOSTS.has(hostParam);
    if (!ok) {
      return {
        ok: false,
        reason:
          "the host query parameter must be a loopback name or a socket directory",
      };
    }
  }
  for (const hostaddrParam of parsed.searchParams.getAll("hostaddr")) {
    if (!LOOPBACK_HOSTS.has(hostaddrParam)) {
      return {
        ok: false,
        reason: "the hostaddr query parameter must be loopback",
      };
    }
  }

  const hostParam = hostParams.at(-1);
  const socketOnly =
    parsed.hostname === "" &&
    hostParam !== undefined &&
    path.isAbsolute(hostParam);
  if (!socketOnly && !LOOPBACK_HOSTS.has(parsed.hostname)) {
    return {
      ok: false,
      reason: `host "${parsed.hostname}" is not loopback; the harness only touches a local throwaway database`,
    };
  }

  const name = decodeURIComponent(parsed.pathname.replace(/^\//, ""));
  if (!name) {
    return { ok: false, reason: "DATABASE_URL names no database" };
  }
  if (!opts.allowAnyName && !THROWAWAY_NAME.test(name)) {
    return {
      ok: false,
      reason: `database "${name}" does not look like a throwaway (expected a name ending in _test or starting with conformance)`,
    };
  }
  return { ok: true };
}

/**
 * Bootstrap failures are not fatal and not visible: every step swallows its
 * own error into a warning and the gateway starts anyway (and
 * BOOTSTRAP_FAIL_HARD only rethrows what escapes the whole initialiser). So the
 * log is the only evidence. Any skip or failure line fails the run, and the
 * three success lines must each be present, or smoke would retry for a minute
 * against a gateway that has no key.
 */
const BOOTSTRAP_PROBLEM =
  /Skipping (private )?(API key|namespace|endpoint)|Failed to bootstrap|bootstrap failed|Fatal startup error|Error initializing environment-based configuration|did not return uuid/;

const BOOTSTRAP_REQUIRED: Array<{ label: string; pattern: RegExp }> = [
  { label: 'API key "conformance"', pattern: /^✓ .*API key "conformance"/m },
  {
    label: 'namespace "conformance"',
    pattern: /^✓ .*[Nn]amespace "conformance"/m,
  },
  {
    label: 'endpoint "conformance"',
    pattern: /^✓ .*[Ee]ndpoint "conformance"/m,
  },
];

export function checkBootstrapLog(log: string): string[] {
  const problems: string[] = [];
  for (const line of log.split(/\r?\n/)) {
    if (BOOTSTRAP_PROBLEM.test(line)) problems.push(`gateway log: ${line}`);
  }
  for (const { label, pattern } of BOOTSTRAP_REQUIRED) {
    if (!pattern.test(log)) {
      problems.push(`no bootstrap confirmation for ${label}`);
    }
  }
  return problems;
}

/**
 * A foreign Origin receives 200 in both audit and off modes, so the runner's
 * DNS-rebinding failure cannot distinguish the production default from a
 * disabled policy. Require both the announced mode and the served-request
 * event from that scenario. The Origin is pinned by conformance 0.1.16; match
 * its request, not an unrelated event or the boot line's promise to record.
 */
export function checkOriginPolicyLog(log: string): string[] {
  const problems: string[] = [];
  if (!log.includes("[origin-policy] MCP_ORIGIN_POLICY=audit: ")) {
    problems.push(
      "no boot confirmation for the default MCP_ORIGIN_POLICY=audit",
    );
  }
  const eventHead =
    '[MetaMCP][system][origin-policy] origin-policy audit: Origin "http://evil.example.com", POST mcp, served (200), credential present,';
  const hasEvent = log
    .split(/\r?\n/)
    .some(
      (line) =>
        line.includes(eventHead) &&
        line.includes("; would be refused under MCP_ORIGIN_POLICY=enforce;"),
    );
  if (!hasEvent) {
    problems.push(
      "no Origin audit event for the runner's http://evil.example.com request served with 200",
    );
  }
  return problems;
}

export type RunnerClass = "OK" | "REGRESSION" | "HARNESS";

const ANSI = new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, "g");

/**
 * Classify the runner's exit by the markers its own report prints, never by the
 * exit code alone: a timeout, a crash, or a scenario that threw all exit
 * non-zero too, and calling those a gateway regression would send a reader to
 * the wrong place. Exit 124 is `timeout(1)`.
 */
export function classifyRunnerOutput(
  log: string,
  exitCode: number,
): { cls: RunnerClass; reason: string } {
  const text = log.replace(ANSI, "");
  if (exitCode === 124) {
    return { cls: "HARNESS", reason: "the runner timed out" };
  }
  if (text.includes("Failed to run scenario")) {
    return {
      cls: "HARNESS",
      reason: "a scenario threw before it could record its checks",
    };
  }
  const passed = text.includes("Baseline check passed");
  const unexpected = text.includes("Unexpected failures (not in baseline)");
  const stale = text.includes("Stale baseline entries");
  if (exitCode === 0 && passed && !unexpected && !stale) {
    return { cls: "OK", reason: "baseline check passed" };
  }
  if (exitCode !== 0 && !passed && (unexpected || stale)) {
    return {
      cls: "REGRESSION",
      reason: unexpected
        ? "a scenario failed that the baseline does not list"
        : "a listed scenario now passes; remove it from the baseline",
    };
  }
  return {
    cls: "HARNESS",
    reason: `no recognisable result from the runner (exit ${exitCode})`,
  };
}

export interface BundleFile {
  path: string;
  content: string;
}

/**
 * Identifiers and env names that exist only in the harness. A production bundle
 * naming any of them means the key-injecting proxy (or the fixture) was pulled
 * into the image.
 */
const HARNESS_MARKERS = [
  "createAliasProxy",
  "createFixtureServer",
  "CONFORMANCE_API_KEY",
  "CONFORMANCE_UPSTREAM_URL",
  "CONFORMANCE_FIXTURE_PORT",
  "CONFORMANCE_PROXY_PORT",
  "CONFORMANCE_TOOL_PREFIX",
  "conformance-fixture",
];

/** Problems found in a built backend bundle; empty means it is free of the harness. */
export function findConformanceLeaks(files: readonly BundleFile[]): string[] {
  const problems: string[] = [];
  const hasEntry = files.some(
    (f) => /(^|[\\/])index\.js$/.test(f.path) && f.content.length > 0,
  );
  if (!hasEntry) {
    problems.push(
      "no bundle entry (index.js) to inspect: the check cannot vouch for it",
    );
  }
  for (const file of files) {
    if (file.path.endsWith(".map")) {
      try {
        const sources = (JSON.parse(file.content) as { sources?: unknown })
          .sources;
        for (const source of Array.isArray(sources) ? sources : []) {
          if (
            typeof source === "string" &&
            /(^|[\\/])src[\\/]conformance[\\/]/.test(source)
          ) {
            problems.push(`${file.path}: source map lists ${source}`);
          }
        }
      } catch {
        problems.push(`${file.path}: source map is unreadable`);
      }
    } else if (/\.m?js$/.test(file.path)) {
      for (const marker of HARNESS_MARKERS) {
        if (file.content.includes(marker)) {
          problems.push(`${file.path}: contains ${marker}`);
        }
      }
    }
  }
  return problems;
}
