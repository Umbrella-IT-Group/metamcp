/**
 * Guards around the conformance runner's expected-failures baseline.
 *
 * The runner's own check (@modelcontextprotocol/conformance 0.1.16) is weaker
 * than a reader assumes: it matches scenario NAMES only, silently ignores a
 * listed name that matches no scenario, counts a scenario with zero checks as
 * passing, and says nothing about WHY a scenario fails. So a typo, a missing
 * result directory, or a scenario that starts failing for a different reason
 * would all pass quietly. Everything here is pure so each guard has a refusing
 * case and an allowing case in baseline.test.ts, and so the shell script that
 * calls it stays glue.
 */
import { createHash } from "node:crypto";

export interface CheckRecord {
  id?: unknown;
  name?: unknown;
  description?: unknown;
  status?: unknown;
  errorMessage?: unknown;
  /** What the runner recorded about the check (for a tool call, the tool's own result). */
  details?: unknown;
}

export interface BaselineEntry {
  scenario: string;
  reason: string;
  line: number;
}

export interface ParsedBaseline {
  hasServerHeader: boolean;
  entries: BaselineEntry[];
  problems: string[];
}

export interface SnapshotRow {
  scenario: string;
  status: string;
  id: string;
  /** First 16 hex of sha256 over the whole normalised message. */
  digest: string;
  /**
   * First 16 hex of sha256 over the normalised `details`, or `-` when the check
   * recorded none. For a tool call the runner stores the tool's own result
   * there, so this is what notices a fixture whose failure text changed while
   * the scenario's own message did not.
   */
  detail: string;
  /** Human-readable head of the message; never compared on its own. */
  preview: string;
}

/** Entries must say why: a bare name would let any failure be waved through. */
const MIN_REASON_LENGTH = 10;
const PREVIEW_LENGTH = 120;

/** `list --server` prints `  - <name>` plus an optional ` [versions]` suffix. */
export function parseScenarioList(listOutput: string): string[] {
  const names: string[] = [];
  for (const line of listOutput.split(/\r?\n/)) {
    const match = /^ {2}- (\S+)/.exec(line);
    if (match) names.push(match[1]);
  }
  return names;
}

const ENTRY_LINE = /^ {2}- ([a-z0-9-]+)(?:[ \t]+#[ \t]*(.*))?$/;

export function parseBaseline(text: string): ParsedBaseline {
  const parsed: ParsedBaseline = {
    hasServerHeader: false,
    entries: [],
    problems: [],
  };
  text.split(/\r?\n/).forEach((rawLine, index) => {
    const lineNumber = index + 1;
    const line = rawLine.replace(/\s+$/, "");
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) return;
    if (line === "server:") {
      parsed.hasServerHeader = true;
      return;
    }
    const match = ENTRY_LINE.exec(line);
    if (!match) {
      parsed.problems.push(
        `line ${lineNumber}: unparseable line ${JSON.stringify(rawLine)}`,
      );
      return;
    }
    parsed.entries.push({
      scenario: match[1],
      reason: (match[2] ?? "").trim(),
      line: lineNumber,
    });
  });
  return parsed;
}

export function validateBaseline(
  parsed: ParsedBaseline,
  scenarios: readonly string[],
  expectCount: number,
): string[] {
  const errors: string[] = [];
  if (scenarios.length !== expectCount) {
    errors.push(
      `the runner lists ${scenarios.length} scenarios but the pinned count is ${expectCount}: a runner bump changed the suite, review the new scenarios before updating the count`,
    );
  }
  if (!parsed.hasServerHeader) {
    errors.push("the baseline has no `server:` header");
  }
  errors.push(...parsed.problems);

  const known = new Set(scenarios);
  const seen = new Set<string>();
  for (const entry of parsed.entries) {
    if (seen.has(entry.scenario)) {
      errors.push(`line ${entry.line}: duplicate entry "${entry.scenario}"`);
    }
    seen.add(entry.scenario);
    if (!known.has(entry.scenario)) {
      errors.push(
        `line ${entry.line}: unknown scenario "${entry.scenario}" (the runner would ignore it silently)`,
      );
    }
    if (entry.reason.length < MIN_REASON_LENGTH) {
      errors.push(
        `line ${entry.line}: entry "${entry.scenario}" has no reason of at least ${MIN_REASON_LENGTH} characters`,
      );
    }
  }
  return errors;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * The runner writes `<out>/server-<scenario>-<ISO>` where the ISO timestamp has
 * `:` and `.` replaced by `-` (its `_n` and `Cn` functions), so scenario
 * `server-initialize` lands in `server-server-initialize-<ISO>`. Matching the
 * exact shape per scenario keeps `tools-call-with-logging` and
 * `tools-call-with-progress` (or any future prefix pair) from colliding.
 */
export function locateResults(
  dirNames: readonly string[],
  scenarios: readonly string[],
): { dirs: Map<string, string>; errors: string[] } {
  const dirs = new Map<string, string>();
  const errors: string[] = [];
  for (const scenario of scenarios) {
    const shape = new RegExp(
      `^server-${escapeRegExp(scenario)}-\\d{4}-\\d{2}-\\d{2}T\\d{2}-\\d{2}-\\d{2}-\\d{3}Z$`,
    );
    const matches = dirNames.filter((name) => shape.test(name));
    if (matches.length === 0) {
      errors.push(`${scenario}: result directory missing`);
    } else if (matches.length > 1) {
      errors.push(
        `${scenario}: multiple result directories (${matches.join(", ")})`,
      );
    } else {
      dirs.set(scenario, matches[0]);
    }
  }
  return { dirs, errors };
}

/**
 * Mask only fields known to differ between runs of the same failure, so the
 * comparison stays sensitive to everything else: uuids, ISO timestamps and long
 * hex runs (ids, hashes, session tokens). Whitespace is collapsed because the
 * runner joins messages with `; ` and wraps lines unpredictably.
 */
function normaliseText(message: string): string {
  return message
    .replace(
      /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
      "<uuid>",
    )
    .replace(
      /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/g,
      "<ts>",
    )
    .replace(/\b[0-9a-f]{16,}\b/gi, "<hex>")
    .replace(/\s+/g, " ")
    .trim();
}

/** JSON with object keys sorted at every depth, so key order never matters. */
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function fingerprint(text: string): string {
  return createHash("sha256").update(text).digest("hex").slice(0, 16);
}

/**
 * One row per check the runner counts as failing (FAILURE or WARNING; its `G`
 * function treats both alike). The fingerprint covers the WHOLE normalised
 * message, so a reason that changes anywhere, including past the preview cut,
 * changes the row.
 */
export function failingRows(
  scenario: string,
  checks: readonly CheckRecord[],
): SnapshotRow[] {
  const rows: SnapshotRow[] = [];
  for (const check of checks) {
    if (check.status !== "FAILURE" && check.status !== "WARNING") continue;
    const raw = check.errorMessage ?? check.description ?? "";
    const message = normaliseText(typeof raw === "string" ? raw : String(raw));
    rows.push({
      scenario,
      status: check.status,
      id: String(check.id ?? check.name ?? "").replace(/\s+/g, " "),
      digest: fingerprint(message),
      detail:
        check.details === undefined
          ? "-"
          : fingerprint(normaliseText(canonicalJson(check.details))),
      preview: message.slice(0, PREVIEW_LENGTH),
    });
  }
  return rows;
}

function renderRow(row: SnapshotRow): string {
  return [
    row.scenario,
    row.status,
    row.id,
    row.digest,
    row.detail,
    row.preview,
  ].join("\t");
}

/** Plain code-unit order: a locale compare would make the file machine-dependent. */
export function renderSnapshot(rows: readonly SnapshotRow[]): string {
  const lines = rows
    .map(renderRow)
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return lines.length === 0 ? "" : `${lines.join("\n")}\n`;
}

export function compareSnapshot(
  expected: string,
  actual: string,
): { added: string[]; removed: string[] } {
  const lines = (text: string) => text.split("\n").filter((l) => l !== "");
  const before = lines(expected);
  const after = lines(actual);
  const beforeSet = new Set(before);
  const afterSet = new Set(after);
  return {
    added: after.filter((l) => !beforeSet.has(l)),
    removed: before.filter((l) => !afterSet.has(l)),
  };
}

/** A baseline scenario with no recorded failing row has no recorded reason. */
export function baselineMissingRows(
  baselineScenarios: readonly string[],
  rows: readonly SnapshotRow[],
): string[] {
  const withRows = new Set(rows.map((r) => r.scenario));
  return baselineScenarios.filter((s) => !withRows.has(s));
}
