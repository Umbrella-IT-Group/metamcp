// Stub: every gate answers "fine", committed first so the tests fail on
// assertions rather than on a missing import. Replaced by the real
// implementation in the next commit.

export type GateResult = { ok: true } | { ok: false; reason: string };

export function checkDatabaseUrl(
  _url: string,
  _opts: { allowAnyName: boolean },
): GateResult {
  return { ok: true };
}

export function checkBootstrapLog(_log: string): string[] {
  return [];
}

export type RunnerClass = "OK" | "REGRESSION" | "HARNESS";

export function classifyRunnerOutput(
  _log: string,
  _exitCode: number,
): { cls: RunnerClass; reason: string } {
  return { cls: "OK", reason: "" };
}

export interface BundleFile {
  path: string;
  content: string;
}

export function findConformanceLeaks(_files: readonly BundleFile[]): string[] {
  return [];
}
