/**
 * The bootstrap account must not quietly come up on a password this
 * repository publishes.
 *
 * `example.env` shipped `BOOTSTRAP_USER_PASSWORD=changeme` for the whole life
 * of the file. That account is an ADMINISTRATOR of the gateway, so the shipped
 * default was a shipped administrator credential: the first thing anyone who
 * had read the repository would try, and still live on any deployment that
 * copied the example and edited only the lines it noticed. The example now
 * ships an obvious non-usable placeholder instead, and the backend says so out
 * loud if either string reaches a real boot.
 *
 * A WARNING rather than a refusal, deliberately: the account is created at
 * boot, so a hard failure would brick a throwaway local dev stack, and the
 * case being addressed is an operator who needs to be told rather than
 * stopped.
 *
 * `bootstrap.service` is imported for one pure exported function; the module
 * reaches `@/db` at load, so `DATABASE_URL` is stubbed for the import the same
 * way the sibling bootstrap suites do.
 */

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// `bootstrap.service` reaches `../auth` (which throws without
// BETTER_AUTH_SECRET) and `../db` (which connects to postgres) at module load.
// Both are stubbed at the seam, the same way `bootstrap.order.test.ts` does
// it: the function under test is pure and touches neither.
vi.mock("../auth", () => ({ auth: { handler: vi.fn() } }));
vi.mock("../db", () => ({ db: {} }));
vi.mock("./audit/admin-event", () => ({ emitAdminEvent: vi.fn() }));

const { warnOnPlaceholderBootstrapPassword } = await import(
  "./bootstrap.service"
);

let warnSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
  warnSpy.mockRestore();
});

const warnedText = () => warnSpy.mock.calls.map(String).join("\n");

describe("warnOnPlaceholderBootstrapPassword", () => {
  it.each([["changeme"], ["REPLACE_ME__generate_a_strong_password"]])(
    "warns loudly on the published placeholder %o",
    (password) => {
      const warned = warnOnPlaceholderBootstrapPassword(
        "admin@example.com",
        password,
      );

      expect(warned).toBe(true);
      expect(warnedText()).toContain("INSECURE BOOTSTRAP PASSWORD");
      expect(warnedText()).toContain("admin@example.com");
      // The operator has to be told what to do about it, not just that
      // something is wrong.
      expect(warnedText()).toContain("BOOTSTRAP_USER_PASSWORD");
    },
  );

  it("stays quiet for a real password", () => {
    // The guard must not be satisfiable by warning about everything: a
    // warning that always fires is a warning nobody reads.
    const warned = warnOnPlaceholderBootstrapPassword(
      "admin@example.com",
      "correct-horse-battery-staple",
    );

    expect(warned).toBe(false);
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it("stays quiet when no password is configured at all", () => {
    // That case has its own existing warning in validateConfig; this one must
    // not double up on it or crash on undefined.
    expect(
      warnOnPlaceholderBootstrapPassword("admin@example.com", undefined),
    ).toBe(false);
    expect(warnOnPlaceholderBootstrapPassword(undefined, "")).toBe(false);
    expect(warnSpy).not.toHaveBeenCalled();
  });
});

describe("example.env ships no usable credential", () => {
  const exampleEnv = readFileSync(
    path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      "../../../../example.env",
    ),
    "utf-8",
  );

  it.each([
    ["BOOTSTRAP_USER_PASSWORD", "changeme"],
    ["POSTGRES_PASSWORD", "m3t4mcp"],
  ])("does not assign %s the old guessable default", (key, oldDefault) => {
    // Pinned against the file rather than trusted to review: the whole point
    // of these two lines is that they are copied verbatim into real
    // deployments, so a re-introduction has to fail a test rather than survive
    // a skim.
    expect(exampleEnv).not.toContain(`${key}=${oldDefault}`);
    expect(exampleEnv).toContain(
      `${key}=REPLACE_ME__generate_a_strong_password`,
    );
  });

  it("documents the unauthenticated-endpoint flag as off by default", () => {
    expect(exampleEnv).toContain("# ALLOW_UNAUTHENTICATED_ENDPOINTS=false");
  });
});
