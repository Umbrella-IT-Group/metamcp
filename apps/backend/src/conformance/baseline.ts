// Stub: a permissive validator and empty result handling, committed first so
// the tests fail on assertions rather than on a missing import. Replaced by the
// real implementation in the next commit.

export interface CheckRecord {
  id?: unknown;
  name?: unknown;
  description?: unknown;
  status?: unknown;
  errorMessage?: unknown;
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
  digest: string;
  detail: string;
  preview: string;
}

export function parseScenarioList(_listOutput: string): string[] {
  return [];
}

export function parseBaseline(_text: string): ParsedBaseline {
  return { hasServerHeader: true, entries: [], problems: [] };
}

export function validateBaseline(
  _parsed: ParsedBaseline,
  _scenarios: readonly string[],
  _expectCount: number,
): string[] {
  return [];
}

export function locateResults(
  _dirNames: readonly string[],
  _scenarios: readonly string[],
): { dirs: Map<string, string>; errors: string[] } {
  return { dirs: new Map(), errors: [] };
}

export function failingRows(
  _scenario: string,
  _checks: readonly CheckRecord[],
): SnapshotRow[] {
  return [];
}

export function renderSnapshot(_rows: readonly SnapshotRow[]): string {
  return "";
}

export function compareSnapshot(
  _expected: string,
  _actual: string,
): { added: string[]; removed: string[] } {
  return { added: [], removed: [] };
}

export function baselineMissingRows(
  _baselineScenarios: readonly string[],
  _rows: readonly SnapshotRow[],
): string[] {
  return [];
}
