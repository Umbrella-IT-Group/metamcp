/**
 * Supply-chain pinning guard for the fork's build and deploy path.
 *
 * A mutable action tag or a floating base-image tag lets whoever controls (or
 * compromises) an upstream tag move new code into a build that runs with
 * packages:write and id-token:write, or shift the deployed image out from
 * under a digest nobody reviewed. So every `uses:` in .github/workflows is
 * pinned to a full 40-char commit SHA, the root Dockerfile base image is
 * pinned to a sha256 digest, and its Node install names an exact version.
 * This reads those files from source and fails the moment any of them drifts
 * back to a moving reference, including in a workflow added later. Same
 * source-reading technique as the cors() call-site guard in
 * routers/cors-policy.test.ts.
 */
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

// apps/backend/src -> repo root.
const REPO_ROOT = path.resolve(import.meta.dirname, "../../..");
const WORKFLOWS_DIR = path.join(REPO_ROOT, ".github", "workflows");
const DOCKERFILE = path.join(REPO_ROOT, "Dockerfile");
const DEPENDABOT = path.join(REPO_ROOT, ".github", "dependabot.yml");

function workflowFiles(): string[] {
  return readdirSync(WORKFLOWS_DIR).filter(
    (f) => f.endsWith(".yml") || f.endsWith(".yaml"),
  );
}

/** Every `uses:` reference across the workflow files, with its raw line. */
const USES: { file: string; line: string; ref: string }[] = [];
for (const file of workflowFiles()) {
  const source = readFileSync(path.join(WORKFLOWS_DIR, file), "utf8");
  for (const line of source.split("\n")) {
    const m = line.match(/^\s*(?:-\s*)?uses:\s*(\S+)/);
    if (m) USES.push({ file, line, ref: m[1] });
  }
}

describe("supply-chain pinning", () => {
  it("finds the workflow uses: references it is meant to be guarding", () => {
    // A regex that silently matched nothing would make the pin assertions
    // below pass without checking anything.
    expect(USES.length).toBeGreaterThanOrEqual(10);
  });

  it("pins every external action to a full commit SHA", () => {
    for (const { file, ref } of USES) {
      // Local composite actions (./path) carry no version to pin.
      if (ref.startsWith("./")) continue;
      const version = ref.split("@")[1];
      expect(version, `${file}: ${ref} is not @<40-hex-sha>`).toMatch(
        /^[0-9a-f]{40}$/,
      );
    }
  });

  it("gives every SHA-pinned action a trailing version comment", () => {
    for (const { file, line, ref } of USES) {
      if (ref.startsWith("./")) continue;
      expect(
        line,
        `${file}: ${ref} pinned SHA has no # version comment`,
      ).toMatch(/@[0-9a-f]{40}\s+#\s*v?\d/);
    }
  });

  it("digest-pins every external Dockerfile base image", () => {
    const dockerfile = readFileSync(DOCKERFILE, "utf8");
    // `FROM base AS ...` re-references an internal stage, not a registry
    // image; only external images need a digest.
    const stages = new Set(
      [...dockerfile.matchAll(/^FROM\s+\S+\s+AS\s+(\S+)/gim)].map((m) =>
        m[1].toLowerCase(),
      ),
    );
    const external = [...dockerfile.matchAll(/^FROM\s+(\S+)/gim)]
      .map((m) => m[1])
      .filter((img) => !stages.has(img.toLowerCase()));

    expect(external.length).toBeGreaterThanOrEqual(1);
    for (const img of external) {
      expect(img, `Dockerfile FROM ${img} is not digest-pinned`).toMatch(
        /@sha256:[0-9a-f]{64}$/,
      );
    }
  });

  it("pins the Dockerfile Node install to an exact version", () => {
    const dockerfile = readFileSync(DOCKERFILE, "utf8");
    // Bare `apt-get install -y nodejs` takes whatever 20.x is current at
    // build time; the pinned form names the nodesource version explicitly.
    expect(dockerfile, "Dockerfile installs a floating nodejs").toMatch(
      /apt-get install -y nodejs=\d+\.\d+\.\d+/,
    );
  });

  it("watches the docker ecosystem in dependabot so digests get bump PRs", () => {
    const dependabot = readFileSync(DEPENDABOT, "utf8");
    expect(dependabot).toMatch(/package-ecosystem:\s*"docker"/);
  });
});
