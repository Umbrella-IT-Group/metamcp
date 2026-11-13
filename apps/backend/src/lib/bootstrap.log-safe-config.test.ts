import { format } from "node:util";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../auth", () => ({ auth: { handler: vi.fn() } }));
vi.mock("../db", () => ({
  db: {
    // A completed bootstrap skips account creation while still running the
    // real environment parser and registration-control writes against stubs.
    query: {
      configTable: { findFirst: vi.fn(async () => ({ value: "true" })) },
    },
    insert: vi.fn(() => ({
      values: () => ({ onConflictDoUpdate: async () => undefined }),
    })),
  },
}));
vi.mock("./audit/admin-event", () => ({ emitAdminEvent: vi.fn() }));

import { initializeEnvironmentConfiguration } from "./bootstrap.service";

const SECRET = "fake-json-secret-ffff6666";
const VARIABLES = ["BOOTSTRAP_USERS", "BOOTSTRAP_API_KEYS"] as const;

beforeEach(() => {
  for (const key of [
    ...VARIABLES,
    "BOOTSTRAP_NAMESPACES",
    "BOOTSTRAP_ENDPOINTS",
    "BOOTSTRAP_USER_EMAIL",
    "BOOTSTRAP_USER_PASSWORD",
  ]) {
    vi.stubEnv(key, "");
  }
  vi.stubEnv("BOOTSTRAP_ONLY_FIRST_RUN", "true");
  vi.spyOn(console, "log").mockImplementation(() => undefined);
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

describe.each(VARIABLES)("bootstrap JSON diagnostics for %s", (variable) => {
  it.each([
    ["malformed JSON", `${SECRET}{`],
    ["a non-array value", JSON.stringify({ password: SECRET, key: SECRET })],
  ])("does not log the value for %s", async (_kind, value) => {
    vi.stubEnv(variable, value);

    await initializeEnvironmentConfiguration();

    const warnings = vi.mocked(console.warn).mock.calls;
    const text = warnings.map((args) => format(...args)).join("\n");
    expect(text).not.toContain(SECRET);
    // V8 can quote only a prefix of malformed input in its parse message.
    expect(text).not.toContain("fake-json");
    expect(text).toContain(variable);
    if (_kind === "malformed JSON") expect(text).toContain("SyntaxError");
  });

  it("keeps a numeric parse position without the offending value", async () => {
    const value = `["${SECRET}" 0]`;
    vi.stubEnv(variable, value);

    await initializeEnvironmentConfiguration();

    expect(console.warn).toHaveBeenCalledWith(
      `⚠️ Failed to parse ${variable} as a JSON array (SyntaxError at position ${value.indexOf("0]")}); using default`,
    );
    expect(format(vi.mocked(console.warn).mock.calls)).not.toContain(SECRET);
  });
});
