/**
 * The conformance runner's own baseline check is weaker than it looks: it
 * matches scenario names only, silently ignores a listed name that matches no
 * scenario, counts a scenario with zero checks as passing, and a missing
 * `checks.json` is invisible to it. These tests pin the guards we layer on top
 * so a typo, a vanished result or a changed failure reason cannot pass quietly.
 *
 * Oracle: @modelcontextprotocol/conformance 0.1.16 `dist/index.js`. `G` counts
 * a scenario as failing when any check is FAILURE or WARNING; `W` reads the
 * baseline file as `server: [names]`; `_n` and `Cn` write
 * `<out>/server-<scenario>-<ISO with : and . replaced by ->/checks.json`; the
 * `list` command prints `  - <name>` plus an optional ` [versions]` suffix.
 */
import { describe, expect, it } from "vitest";

import {
  baselineMissingRows,
  compareSnapshot,
  failingRows,
  locateResults,
  parseBaseline,
  parseScenarioList,
  renderSnapshot,
  validateBaseline,
} from "./baseline";

const SCENARIOS = [
  "server-initialize",
  "logging-set-level",
  "ping",
  "completion-complete",
  "tools-list",
  "tools-call-simple-text",
  "tools-call-image",
  "tools-call-audio",
  "tools-call-embedded-resource",
  "tools-call-mixed-content",
  "tools-call-with-logging",
  "tools-call-error",
  "tools-call-with-progress",
  "tools-call-sampling",
  "tools-call-elicitation",
  "json-schema-2020-12",
  "elicitation-sep1034-defaults",
  "server-sse-polling",
  "server-sse-multiple-streams",
  "elicitation-sep1330-enums",
  "resources-list",
  "resources-read-text",
  "resources-read-binary",
  "resources-templates-read",
  "resources-subscribe",
  "resources-unsubscribe",
  "prompts-list",
  "prompts-get-simple",
  "prompts-get-with-args",
  "prompts-get-embedded-resource",
  "prompts-get-with-image",
  "dns-rebinding-protection",
];

const LIST_OUTPUT = [
  "Server scenarios (test against a server):",
  ...SCENARIOS.map(
    (s, i) => `  - ${s}${i % 2 === 0 ? " [2025-06-18,2025-11-25]" : ""}`,
  ),
  "",
].join("\n");

function baseline(lines: string[], header = "server:"): string {
  return ["# header comment", "", header, ...lines, ""].join("\n");
}

const REASON = "this is a documented reason";

function errorsFor(text: string, count = 32): string[] {
  return validateBaseline(parseBaseline(text), SCENARIOS, count);
}

describe("parseScenarioList", () => {
  it("reads one name per `  - name` line and ignores the header and version suffix", () => {
    expect(parseScenarioList(LIST_OUTPUT)).toEqual(SCENARIOS);
  });
});

describe("validateBaseline", () => {
  it("accepts a well-formed baseline (comment-only and blank lines allowed)", () => {
    const text = baseline([
      "  # a section comment",
      `  - completion-complete   # ${REASON}`,
      "",
      `  - logging-set-level     # ${REASON}`,
    ]);
    expect(errorsFor(text)).toEqual([]);
  });

  it("refuses an entry with no reason, accepts one of exactly 10 characters, refuses 9", () => {
    expect(errorsFor(baseline(["  - completion-complete"]))).toEqual([
      expect.stringContaining("completion-complete"),
    ]);
    expect(
      errorsFor(baseline(["  - completion-complete  # 123456789"])),
    ).toEqual([expect.stringContaining("completion-complete")]);
    expect(
      errorsFor(baseline(["  - completion-complete  # 1234567890"])),
    ).toEqual([]);
  });

  it("refuses a duplicate entry", () => {
    const text = baseline([
      `  - completion-complete  # ${REASON}`,
      `  - completion-complete  # ${REASON}`,
    ]);
    expect(errorsFor(text)).toEqual([expect.stringMatching(/duplicate/i)]);
  });

  it("refuses an entry that names no scenario the runner lists", () => {
    const text = baseline([`  - completion-compete  # ${REASON}`]);
    expect(errorsFor(text)).toEqual([
      expect.stringMatching(/unknown scenario.*completion-compete/i),
    ]);
  });

  it("refuses a wrong scenario count and accepts the pinned one (31 and 33 refused)", () => {
    const text = baseline([`  - completion-complete  # ${REASON}`]);
    expect(errorsFor(text, 32)).toEqual([]);
    expect(errorsFor(text, 31)).toEqual([
      expect.stringMatching(/32.*31|31.*32/),
    ]);
    expect(errorsFor(text, 33)).toEqual([
      expect.stringMatching(/32.*33|33.*32/),
    ]);
    // The runner itself listing a different count is the same failure.
    expect(
      validateBaseline(parseBaseline(text), SCENARIOS.slice(1), 32),
    ).toEqual([expect.stringMatching(/31.*32|32.*31/)]);
  });

  it("refuses a file with no `server:` header", () => {
    const text = baseline([`  - completion-complete  # ${REASON}`], "client:");
    const errors = errorsFor(text);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.join("\n")).toMatch(/server:/);
  });

  it("refuses a line it cannot parse", () => {
    for (const bad of [
      `  - Completion Complete  # ${REASON}`,
      `- completion-complete  # ${REASON}`,
      `  completion-complete  # ${REASON}`,
    ]) {
      const errors = errorsFor(baseline([bad]));
      expect(errors, bad).toEqual([expect.stringMatching(/unparseable/i)]);
    }
  });
});

const ISO = (hhmm: string) => `2026-11-13T${hhmm}-00-123Z`;

describe("locateResults", () => {
  it("resolves the runner's `server-<scenario>-<ISO>` directories", () => {
    const { dirs, errors } = locateResults(
      [
        `server-server-initialize-${ISO("06-17")}`,
        `server-ping-${ISO("06-17")}`,
      ],
      ["server-initialize", "ping"],
    );
    expect(errors).toEqual([]);
    expect(dirs.get("server-initialize")).toBe(
      `server-server-initialize-${ISO("06-17")}`,
    );
    expect(dirs.get("ping")).toBe(`server-ping-${ISO("06-17")}`);
  });

  it("does not confuse tools-call-with-logging and tools-call-with-progress", () => {
    const names = [
      `server-tools-call-with-logging-${ISO("06-17")}`,
      `server-tools-call-with-progress-${ISO("06-17")}`,
    ];
    const { dirs, errors } = locateResults(names, [
      "tools-call-with-logging",
      "tools-call-with-progress",
    ]);
    expect(errors).toEqual([]);
    expect(dirs.get("tools-call-with-logging")).toBe(names[0]);
    expect(dirs.get("tools-call-with-progress")).toBe(names[1]);
  });

  it("reports a scenario with no directory", () => {
    const { errors } = locateResults([], ["ping"]);
    expect(errors).toEqual([
      expect.stringMatching(/ping.*missing|missing.*ping/i),
    ]);
  });

  it("reports a scenario with two directories instead of guessing", () => {
    const { errors } = locateResults(
      [`server-ping-${ISO("06-17")}`, `server-ping-${ISO("06-18")}`],
      ["ping"],
    );
    expect(errors).toEqual([
      expect.stringMatching(/ping.*(multiple|duplicate)/i),
    ]);
  });

  it("ignores unrelated entries and near-miss names", () => {
    const { dirs, errors } = locateResults(
      [
        `server-ping-${ISO("06-17")}`,
        "summary.txt",
        `server-ping-extra-${ISO("06-17")}`,
        `server-ping-${ISO("06-17")}.bak`,
      ],
      ["ping"],
    );
    expect(errors).toEqual([]);
    expect(dirs.get("ping")).toBe(`server-ping-${ISO("06-17")}`);
  });
});

const check = (over: Record<string, unknown>) => ({
  id: "c1",
  name: "C1",
  description: "a check",
  status: "FAILURE",
  errorMessage: "it failed",
  ...over,
});

/** The single failing row a one-check input must produce (an assertion, not a crash). */
function oneRow(scenario: string, checks: Parameters<typeof failingRows>[1]) {
  const rows = failingRows(scenario, checks);
  expect(rows).toHaveLength(1);
  return rows[0];
}

describe("failingRows", () => {
  it("includes FAILURE and WARNING and excludes SUCCESS and other statuses", () => {
    const rows = failingRows("ping", [
      check({ id: "a", status: "FAILURE" }),
      check({ id: "b", status: "WARNING" }),
      check({ id: "c", status: "SUCCESS" }),
      check({ id: "d", status: "INFO" }),
      check({ id: "e", status: "SKIPPED" }),
    ]);
    expect(rows.map((r) => [r.id, r.status])).toEqual([
      ["a", "FAILURE"],
      ["b", "WARNING"],
    ]);
    expect(rows.every((r) => r.scenario === "ping")).toBe(true);
  });

  it("falls back to the description when a check has no errorMessage", () => {
    const row = oneRow("ping", [
      check({ errorMessage: undefined, description: "described only" }),
    ]);
    expect(row.preview).toBe("described only");
  });

  it("masks volatile fields so two runs of the same failure compare equal", () => {
    const a = oneRow("s", [
      check({
        errorMessage:
          "session 123e4567-e89b-12d3-a456-426614174000 at 2026-11-13T06:17:00.123Z saw  deadbeefdeadbeefdeadbeef0123",
      }),
    ]);
    const b = oneRow("s", [
      check({
        errorMessage:
          "session 00000000-1111-2222-3333-444444444444 at 2027-01-01T00:00:00.000Z saw  0123456789abcdef0123456789abcdef",
      }),
    ]);
    expect(a.digest).toBe(b.digest);
    expect(a.preview).toBe(b.preview);
  });

  it("changes the digest when stable text changes, including past the preview cut", () => {
    const base = "x".repeat(300);
    const a = oneRow("s", [check({ errorMessage: `${base}A` })]);
    const b = oneRow("s", [check({ errorMessage: `${base}B` })]);
    // The human preview is cut short, but the fingerprint covers the whole message.
    expect(a.preview.length).toBeLessThanOrEqual(120);
    expect(a.preview).toBe(b.preview);
    expect(a.digest).not.toBe(b.digest);
  });

  it("collapses whitespace so formatting noise does not change the digest", () => {
    const a = oneRow("s", [check({ errorMessage: "one  two\n\tthree" })]);
    const b = oneRow("s", [check({ errorMessage: "one two three" })]);
    expect(a.digest).toBe(b.digest);
  });

  it("fingerprints the recorded details, ignoring key order and volatile fields", () => {
    const detailed = (details: unknown) =>
      oneRow("s", [check({ details })]).detail;
    const a = detailed({
      result: { text: "x" },
      requested: false,
      at: "2026-11-13T06:17:00.123Z",
    });
    const b = detailed({
      requested: false,
      at: "2027-01-01T00:00:00.000Z",
      result: { text: "x" },
    });
    const c = detailed({
      requested: false,
      at: "2027-01-01T00:00:00.000Z",
      result: { text: "y" },
    });
    expect(a).toBe(b);
    expect(a).not.toBe(c);
    expect(oneRow("s", [check({})]).detail).toBe("-");
  });
});

describe("renderSnapshot and compareSnapshot", () => {
  const row = (scenario: string, id: string, message: string) =>
    oneRow(scenario, [check({ id, errorMessage: message })]);

  it("sorts by plain code-unit order, one tab-separated row per line", () => {
    const text = renderSnapshot([
      row("s", "b-check", "m"),
      row("s", "a-check", "m"),
      row("s", "B-check", "m"),
    ]);
    const ids = text
      .trimEnd()
      .split("\n")
      .map((l) => l.split("\t")[2]);
    // Uppercase sorts before lowercase in code-unit order; a locale compare
    // would interleave them and make the file machine-dependent.
    expect(ids).toEqual(["B-check", "a-check", "b-check"]);
    expect(text.endsWith("\n")).toBe(true);
    expect(text.split("\n")[0].split("\t")).toHaveLength(6);
  });

  it("reports nothing for equal snapshots and rows added or removed otherwise", () => {
    const one = renderSnapshot([row("s", "a", "first reason")]);
    expect(compareSnapshot(one, one)).toEqual({ added: [], removed: [] });

    const changed = renderSnapshot([row("s", "a", "second reason")]);
    const diff = compareSnapshot(one, changed);
    expect(diff.added).toHaveLength(1);
    expect(diff.removed).toHaveLength(1);
  });

  it("notices a reason that differs only beyond the preview cut", () => {
    const base = "y".repeat(400);
    const before = renderSnapshot([row("s", "a", `${base}1`)]);
    const after = renderSnapshot([row("s", "a", `${base}2`)]);
    const diff = compareSnapshot(before, after);
    expect(diff.added.length + diff.removed.length).toBe(2);
  });

  it("notices a vanished failing check (a deleted fixture tool changes the rows)", () => {
    const before = renderSnapshot([
      row(
        "tools-call-sampling",
        "tools-call-sampling",
        "Sampling is not available",
      ),
    ]);
    const after = renderSnapshot([
      row(
        "tools-call-sampling",
        "tools-call-sampling",
        "Unknown tool: test_sampling",
      ),
    ]);
    expect(compareSnapshot(before, after).added).toHaveLength(1);
  });

  it("notices a changed tool result recorded in the details when the check's own message is unchanged", () => {
    // The sampling scenario reports "did not request sampling" whatever the
    // fixture's own failure text says, so only the recorded result differs.
    const withText = (text: string) =>
      renderSnapshot([
        oneRow("tools-call-sampling", [
          check({
            id: "tools-call-sampling",
            errorMessage: "Server did not request sampling from client",
            details: {
              result: { content: [{ type: "text", text }], isError: true },
            },
          }),
        ]),
      ]);
    const diff = compareSnapshot(
      withText("Sampling is not available"),
      withText("Sampling is unavailable"),
    );
    expect(diff.added).toHaveLength(1);
    expect(diff.removed).toHaveLength(1);
  });
});

describe("baselineMissingRows", () => {
  it("lists a baseline scenario that has no recorded failing row", () => {
    const rows = failingRows("completion-complete", [check({})]);
    expect(
      baselineMissingRows(["completion-complete", "logging-set-level"], rows),
    ).toEqual(["logging-set-level"]);
    expect(baselineMissingRows(["completion-complete"], rows)).toEqual([]);
  });
});
