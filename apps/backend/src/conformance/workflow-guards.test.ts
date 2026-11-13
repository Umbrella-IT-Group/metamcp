/**
 * Guards on the shape of the conformance workflow. The job handles a throwaway
 * gateway key and publishes artifacts of a public repository, so the properties
 * that keep it safe are read from the file itself, the same source-reading
 * technique as supply-chain-pinning.test.ts: a later edit that quietly widens
 * the trigger, adds a secret, loosens a pin or lets the upload run after a
 * failed scrub fails here.
 *
 * Oracles: GitHub Actions workflow syntax (`pull_request_target` runs with the
 * base repository's secrets and write token against fork-controlled refs;
 * `steps.<id>.outcome` is `success` only for a step that ran and exited 0);
 * the upstream commits behind each action tag, resolved with
 * `gh api repos/<repo>/git/ref/tags/<tag>` and dereferenced when the tag object
 * is annotated (pnpm/action-setup v4.3.0 is annotated; the others point
 * straight at a commit).
 */
import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

const REPO_ROOT = path.resolve(import.meta.dirname, "../../../..");
const WORKFLOWS = path.join(REPO_ROOT, ".github", "workflows");
const workflow = readFileSync(
  path.join(WORKFLOWS, "umbrella-conformance.yml"),
  "utf8",
);

/** Upstream commit behind each tag, verified against the upstream Git objects. */
const PINS: Record<string, string> = {
  "actions/checkout": "11d5960a326750d5838078e36cf38b85af677262", // v4.4.0
  "pnpm/action-setup": "b906affcce14559ad1aafd4ab0e942779e9f58b1", // v4.3.0 (annotated tag, dereferenced)
  "actions/setup-node": "49933ea5288caeca8642d1e84afbd3f7d6820020", // v4.4.0
  "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02", // v4.6.2
};

/** The steps of the single job, as raw text blocks. */
function steps(): string[] {
  const body = workflow.slice(workflow.indexOf("\n    steps:\n") + 12);
  return body.split(/\n(?= {6}- )/).filter((s) => s.trim().startsWith("- "));
}

const stepWith = (needle: RegExp) => {
  const i = steps().findIndex((s) => needle.test(s));
  return { index: i, text: i >= 0 ? steps()[i] : "" };
};

describe("umbrella-conformance.yml", () => {
  it("triggers on pull_request, never pull_request_target or workflow_run", () => {
    expect(workflow).toMatch(/^on:\s*\n(?:\s+#.*\n)*\s+pull_request:/m);
    expect(workflow).not.toMatch(/pull_request_target/);
    expect(workflow).not.toMatch(/workflow_run/);
  });

  it("references no repository secret and never the write-capable token", () => {
    // Comments may explain the rule; only live syntax is checked.
    const live = workflow
      .split("\n")
      .filter((l) => !l.trim().startsWith("#"))
      .join("\n");
    expect(live).not.toMatch(/secrets\./);
    expect(live).not.toMatch(/GITHUB_TOKEN/);
    expect(live).not.toMatch(
      /(contents|packages|id-token|pull-requests):\s*write/,
    );
  });

  it("pins every action to the verified upstream commit it claims", () => {
    const uses = [...workflow.matchAll(/^\s*(?:-\s*)?uses:\s*(\S+)/gm)].map(
      (m) => m[1],
    );
    expect(uses.length).toBeGreaterThanOrEqual(4);
    for (const ref of uses) {
      const [action, sha] = ref.split("@");
      expect(
        PINS[action],
        `${action} is not a known, verified action`,
      ).toBeDefined();
      expect(sha, `${action} pin`).toBe(PINS[action]);
    }
  });

  it("uses the same pnpm/action-setup commit as the required CI workflow", () => {
    const ci = readFileSync(path.join(WORKFLOWS, "umbrella-ci.yml"), "utf8");
    const ciPin = ci.match(/pnpm\/action-setup@([0-9a-f]{40})/)?.[1];
    expect(ciPin).toBe(PINS["pnpm/action-setup"]);
  });

  it("does not use the runner context where GitHub does not provide it", () => {
    // `runner.*` exists only inside steps. In a job-level `env:` it makes the
    // whole file invalid ("workflow file issue"), so the run never starts and
    // no local test of the harness notices. Steps read $RUNNER_TEMP instead.
    const start = workflow.indexOf("\n    env:\n");
    const end = workflow.indexOf("\n    steps:\n");
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    expect(workflow.slice(start, end)).not.toMatch(/\$\{\{\s*runner\./);
  });

  it("checks out without persisting credentials", () => {
    expect(stepWith(/actions\/checkout@/).text).toMatch(
      /persist-credentials:\s*false/,
    );
  });

  it("uploads only after a scrub step that always runs and is allowed to fail the job", () => {
    const scrub = stepWith(/^\s*-\s*name:[^\n]*\n\s+id:\s*scrub\b/);
    const upload = stepWith(/actions\/upload-artifact@/);

    expect(scrub.index, "no step with id: scrub").toBeGreaterThanOrEqual(0);
    expect(upload.index, "no upload step").toBeGreaterThan(scrub.index);

    // Runs after a failed or crashed harness, so a leak cannot hide behind it.
    expect(scrub.text).toMatch(/if:\s*\$\{\{\s*always\(\)\s*\}\}/);
    // A scanner that crashes must fail the job, not be waved through.
    expect(scrub.text).not.toMatch(/continue-on-error/);

    // `always()` alone would upload after a failed scrub; the outcome check is
    // what keeps a failed or crashed scanner from publishing the directory.
    expect(upload.text).toMatch(/steps\.scrub\.outcome\s*==\s*'success'/);
    expect(upload.text).toMatch(/always\(\)/);
    expect(upload.text).not.toMatch(/continue-on-error/);
  });

  it("uploads only the owned run directory, never a caller-chosen parent", () => {
    const upload = stepWith(/actions\/upload-artifact@/).text;
    expect(upload).toMatch(/path:\s*\$\{\{\s*env\.CONFORMANCE_RUN_DIR\s*\}\}/);
  });
});
