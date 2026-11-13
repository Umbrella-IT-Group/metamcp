/**
 * The boot converge of M365 refresh-token envelopes. The repository is an
 * in-memory stub of its two-method contract (compare-and-swap on the ciphertext
 * that was read; the SQL itself is pinned in
 * `db/repositories/m365-tokens.cas.integration.test.ts`); the crypto is real, so
 * "rewrapped to v2 bound to its own user" is checked by decrypting, not by
 * trusting a mock.
 *
 * Oracle for the target rules: the operator rule that ONLY an explicit
 * `M365_ENVELOPE_WRITE_VERSION=1` ever lowers a row (so `keep`, from unset or
 * any invalid value, writes nothing at all), and that strict forces v2.
 */
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const loggerMock = vi.hoisted(() => ({
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
}));
vi.mock("@/utils/logger", () => ({ default: loggerMock }));

import { decryptRefreshToken, encryptRefreshToken } from "./crypto";
import {
  __resetEnvelopePolicyLogsForTesting,
  peekEnvelopeVersion,
  refreshTokenContext,
} from "./envelope";
import {
  convergeM365Envelopes,
  type EnvelopeConvergeRepo,
} from "./envelope-converge";

const KEK = randomBytes(32);

class MemoryRepo implements EnvelopeConvergeRepo {
  rows = new Map<string, string>();
  kekIds = new Map<string, string>();
  replaceCalls: {
    userId: string;
    expected: string;
    next: string;
    kekId: string;
  }[] = [];
  /** Users whose next swap reports "the row moved on". */
  missFor = new Set<string>();
  throwOnReplaceFor = new Set<string>();
  listFails = false;

  listEnvelopes = vi.fn(async () => {
    if (this.listFails) throw new Error("pg down");
    return [...this.rows].map(([user_id, rt_ciphertext]) => ({
      user_id,
      rt_ciphertext,
    }));
  });

  replaceCiphertextIfUnchanged = vi.fn(
    async (userId: string, expected: string, next: string, kekId: string) => {
      this.replaceCalls.push({ userId, expected, next, kekId });
      if (this.throwOnReplaceFor.has(userId)) throw new Error("pg down");
      if (this.missFor.has(userId)) return false;
      if (this.rows.get(userId) !== expected) return false;
      this.rows.set(userId, next);
      this.kekIds.set(userId, kekId);
      return true;
    },
  );
}

function envelopeOf(repo: MemoryRepo, userId: string): string {
  const envelope = repo.rows.get(userId);
  if (envelope === undefined) throw new Error(`no row for ${userId}`);
  return envelope;
}

const v1 = (plaintext: string) => encryptRefreshToken(plaintext, KEK, "k1");
const v2 = (userId: string, plaintext: string) =>
  encryptRefreshToken(plaintext, KEK, "k1", refreshTokenContext(userId));

function summary(): string {
  const line = loggerMock.info.mock.calls
    .map((call) => String(call[0]))
    .find((text) => text.includes("envelope converge:"));
  expect(line).toBeDefined();
  return line as string;
}
const warnings = () =>
  loggerMock.warn.mock.calls.map((call) => String(call[0]));

beforeEach(() => {
  __resetEnvelopePolicyLogsForTesting();
  vi.stubEnv("M365_TOKEN_KEK", KEK.toString("base64"));
  vi.stubEnv("M365_KEK_ID", "k1");
  vi.stubEnv("M365_ENVELOPE_WRITE_VERSION", "");
  vi.stubEnv("M365_ENVELOPE_STRICT", "");
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.clearAllMocks();
});

describe("target v2 (M365_ENVELOPE_WRITE_VERSION=2)", () => {
  beforeEach(() => vi.stubEnv("M365_ENVELOPE_WRITE_VERSION", "2"));

  it("rewraps v1 rows to v2 bound to their own user, keeping the plaintext, and skips v2 rows", async () => {
    const repo = new MemoryRepo();
    const oldA = v1("rt-a");
    repo.rows.set("user-a", oldA);
    repo.rows.set("user-b", v1("rt-b"));
    const boundC = v2("user-c", "rt-c");
    repo.rows.set("user-c", boundC);

    await convergeM365Envelopes(repo);

    expect(repo.replaceCalls.map((c) => c.userId).sort()).toEqual([
      "user-a",
      "user-b",
    ]);
    // The swap is conditioned on the ciphertext that was read.
    expect(repo.replaceCalls.find((c) => c.userId === "user-a")?.expected).toBe(
      oldA,
    );
    for (const [user, plaintext] of [
      ["user-a", "rt-a"],
      ["user-b", "rt-b"],
    ]) {
      const stored = envelopeOf(repo, user);
      expect(peekEnvelopeVersion(stored)).toBe("v2");
      expect(decryptRefreshToken(stored, KEK, refreshTokenContext(user))).toBe(
        plaintext,
      );
      expect(() =>
        decryptRefreshToken(stored, KEK, refreshTokenContext("someone-else")),
      ).toThrow();
    }
    expect(repo.rows.get("user-c")).toBe(boundC);
    expect(summary()).toContain(
      "mode=v2 strict=off write_version=v2 scanned=3 rewrapped=2 already=1 skipped_changed=0 failed=0 v1_remaining=0 v2_remaining=3 unreadable=0",
    );
    expect(warnings()).toEqual([]);
  });

  it("is idempotent: a second pass writes nothing", async () => {
    const repo = new MemoryRepo();
    repo.rows.set("user-a", v1("rt-a"));
    await convergeM365Envelopes(repo);
    repo.replaceCalls.length = 0;
    await convergeM365Envelopes(repo);
    expect(repo.replaceCalls).toEqual([]);
  });

  it("counts a swap that missed (the row moved on) and leaves the row", async () => {
    const repo = new MemoryRepo();
    const original = v1("rt-a");
    repo.rows.set("user-a", original);
    repo.missFor.add("user-a");

    await convergeM365Envelopes(repo);

    expect(repo.rows.get("user-a")).toBe(original);
    expect(summary()).toContain("rewrapped=0");
    expect(summary()).toContain("skipped_changed=1");
    expect(summary()).toContain("v1_remaining=1");
  });

  it("counts a wrong-KEK or malformed row, logs it without throwing, and still rewraps the others", async () => {
    const repo = new MemoryRepo();
    repo.rows.set(
      "user-bad",
      encryptRefreshToken("rt-x", randomBytes(32), "k1"),
    );
    repo.rows.set("user-junk", "not-an-envelope");
    repo.rows.set("user-ok", v1("rt-ok"));

    await expect(convergeM365Envelopes(repo)).resolves.toBeUndefined();

    expect(peekEnvelopeVersion(repo.rows.get("user-ok"))).toBe("v2");
    expect(summary()).toContain("rewrapped=1");
    expect(summary()).toContain("failed=2");
    expect(summary()).toContain("unreadable=1");
    expect(warnings().some((w) => w.includes("user-bad"))).toBe(true);
    expect(warnings().some((w) => w.includes("user-junk"))).toBe(true);
  });

  it("counts a swap that throws as a failure and continues", async () => {
    const repo = new MemoryRepo();
    repo.rows.set("user-a", v1("rt-a"));
    repo.rows.set("user-b", v1("rt-b"));
    repo.throwOnReplaceFor.add("user-a");

    await convergeM365Envelopes(repo);

    expect(peekEnvelopeVersion(repo.rows.get("user-b"))).toBe("v2");
    expect(summary()).toContain("failed=1");
  });

  it("keeps ciphertext, plaintext and key bytes out of every log line", async () => {
    const repo = new MemoryRepo();
    const bad = encryptRefreshToken("super-secret-rt", randomBytes(32), "k1");
    repo.rows.set("user-bad", bad);
    repo.rows.set("user-ok", v1("another-secret-rt"));

    await convergeM365Envelopes(repo);

    const all = [
      ...loggerMock.info.mock.calls,
      ...loggerMock.warn.mock.calls,
      ...loggerMock.error.mock.calls,
    ]
      .flat()
      .map((value) => String(value))
      .join("\n");
    expect(all).toContain("user-bad");
    expect(all).not.toContain(bad);
    expect(all).not.toContain("super-secret-rt");
    expect(all).not.toContain("another-secret-rt");
    expect(all).not.toContain(KEK.toString("base64"));
    expect(all).not.toContain(KEK.toString("hex"));
    expect(all).not.toContain(envelopeOf(repo, "user-ok"));
  });
});

describe("target v1 (explicit M365_ENVELOPE_WRITE_VERSION=1, the rollback)", () => {
  it("rewraps v2 rows to v1 and leaves v1 rows", async () => {
    vi.stubEnv("M365_ENVELOPE_WRITE_VERSION", "1");
    const repo = new MemoryRepo();
    repo.rows.set("user-a", v2("user-a", "rt-a"));
    const plain = v1("rt-b");
    repo.rows.set("user-b", plain);

    await convergeM365Envelopes(repo);

    expect(peekEnvelopeVersion(repo.rows.get("user-a"))).toBe("v1");
    expect(decryptRefreshToken(envelopeOf(repo, "user-a"), KEK)).toBe("rt-a");
    expect(repo.rows.get("user-b")).toBe(plain);
    expect(summary()).toContain(
      "mode=v1 strict=off write_version=v1 scanned=2 rewrapped=1 already=1",
    );
    expect(summary()).toContain("v2_remaining=0");
    expect(warnings()).toEqual([]);
  });

  it("warns that the rollback is incomplete while bound rows remain", async () => {
    vi.stubEnv("M365_ENVELOPE_WRITE_VERSION", "1");
    const repo = new MemoryRepo();
    repo.rows.set("user-a", v2("user-a", "rt-a"));
    repo.missFor.add("user-a");

    await convergeM365Envelopes(repo);

    expect(summary()).toContain("v2_remaining=1");
    expect(
      warnings().some((w) => w.includes("rollback to v1 is incomplete")),
    ).toBe(true);
  });
});

describe("keep (unset or invalid write version): no write at all", () => {
  it.each<[string, string | undefined]>([
    ["unset", undefined],
    ["empty", ""],
    ["a typo (v2)", "v2"],
    ["a typo (3)", "3"],
    ["a trailing space", "2 "],
  ])(
    "makes no repo write and leaves a v2 row bound when the flag is %s",
    async (_label, value) => {
      vi.stubEnv("M365_ENVELOPE_WRITE_VERSION", value);
      const repo = new MemoryRepo();
      const bound = v2("user-a", "rt-a");
      const legacy = v1("rt-b");
      repo.rows.set("user-a", bound);
      repo.rows.set("user-b", legacy);

      await convergeM365Envelopes(repo);

      expect(repo.replaceCiphertextIfUnchanged).not.toHaveBeenCalled();
      expect(repo.rows.get("user-a")).toBe(bound);
      expect(repo.rows.get("user-b")).toBe(legacy);
      // The baseline an operator reads before flipping anything.
      expect(summary()).toContain(
        "mode=keep strict=off write_version=v1 scanned=2 rewrapped=0 already=0 skipped_changed=0 failed=0 v1_remaining=1 v2_remaining=1 unreadable=0",
      );
    },
  );

  it("warns when bound rows exist but the effective write version is v1", async () => {
    const repo = new MemoryRepo();
    repo.rows.set("user-a", v2("user-a", "rt-a"));
    await convergeM365Envelopes(repo);
    expect(
      warnings().some((w) => w.includes("effective write version is v1")),
    ).toBe(true);
  });

  it("does not warn when every row is v1 (nothing is bound yet)", async () => {
    const repo = new MemoryRepo();
    repo.rows.set("user-a", v1("rt-a"));
    await convergeM365Envelopes(repo);
    expect(warnings()).toEqual([]);
  });

  it("does not warn when binding is on", async () => {
    vi.stubEnv("M365_ENVELOPE_WRITE_VERSION", "2");
    const repo = new MemoryRepo();
    repo.rows.set("user-a", v2("user-a", "rt-a"));
    await convergeM365Envelopes(repo);
    expect(warnings()).toEqual([]);
  });
});

describe("strict", () => {
  it("prints strict=on with the effective write version and binds what is still v1", async () => {
    vi.stubEnv("M365_ENVELOPE_STRICT", "1");
    const repo = new MemoryRepo();
    repo.rows.set("user-a", v1("rt-a"));

    await convergeM365Envelopes(repo);

    expect(peekEnvelopeVersion(repo.rows.get("user-a"))).toBe("v2");
    expect(summary()).toContain("mode=v2 strict=on write_version=v2");
    expect(summary()).toContain("v1_remaining=0");
  });

  it("warns that users will be asked to re-enroll when v1 rows could not be bound", async () => {
    vi.stubEnv("M365_ENVELOPE_STRICT", "1");
    const repo = new MemoryRepo();
    repo.rows.set("user-a", v1("rt-a"));
    repo.missFor.add("user-a");

    await convergeM365Envelopes(repo);

    expect(summary()).toContain("v1_remaining=1");
    expect(warnings().some((w) => w.includes("asked to re-enroll"))).toBe(true);
  });

  it("an unrecognised strict value fails closed: strict on, an ERROR line, and the summary says so", async () => {
    vi.stubEnv("M365_ENVELOPE_STRICT", "yes");
    const repo = new MemoryRepo();
    repo.rows.set("user-a", v1("rt-a"));

    await convergeM365Envelopes(repo);

    expect(loggerMock.error).toHaveBeenCalledTimes(1);
    expect(String(loggerMock.error.mock.calls[0][0])).toContain(
      "M365_ENVELOPE_STRICT",
    );
    expect(summary()).toContain("strict=on");
    expect(peekEnvelopeVersion(repo.rows.get("user-a"))).toBe("v2");
  });
});

describe("environment and repository failures never throw", () => {
  it("makes no repo call and says strict/write version when no KEK is configured", async () => {
    vi.stubEnv("M365_TOKEN_KEK", "");
    const repo = new MemoryRepo();
    repo.rows.set("user-a", v1("rt-a"));

    await expect(convergeM365Envelopes(repo)).resolves.toBeUndefined();

    expect(repo.listEnvelopes).not.toHaveBeenCalled();
    expect(repo.replaceCiphertextIfUnchanged).not.toHaveBeenCalled();
    expect(summary()).toContain("skipped, M365_TOKEN_KEK is not configured");
    expect(summary()).toContain("strict=off");
  });

  it("logs and returns on a malformed KEK, without touching the repo", async () => {
    vi.stubEnv("M365_TOKEN_KEK", Buffer.alloc(16).toString("base64"));
    const repo = new MemoryRepo();
    await expect(convergeM365Envelopes(repo)).resolves.toBeUndefined();
    expect(repo.listEnvelopes).not.toHaveBeenCalled();
    expect(
      loggerMock.error.mock.calls.some((c) =>
        String(c[0]).includes("malformed"),
      ),
    ).toBe(true);
  });

  it("logs and returns when the list fails", async () => {
    const repo = new MemoryRepo();
    repo.listFails = true;
    await expect(convergeM365Envelopes(repo)).resolves.toBeUndefined();
    expect(repo.replaceCiphertextIfUnchanged).not.toHaveBeenCalled();
    expect(
      loggerMock.error.mock.calls.some((c) =>
        String(c[0]).includes("could not list"),
      ),
    ).toBe(true);
  });
});

/**
 * The converge is worth nothing if the boot never calls it, and a wrong order
 * matters: it must run before the server listens (no request of this process
 * mints against a half-converged table). `index.ts` starts the server at
 * import, so the wiring is pinned against its source (the technique of
 * `stdio-policy.test.ts`).
 */
describe("boot wiring", () => {
  const INDEX = readFileSync(
    path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      "../../index.ts",
    ),
    "utf8",
  );

  it("index.ts calls convergeM365Envelopes() after the bearer converge and before listening", () => {
    const bearer = INDEX.indexOf("await convergeServerBearerTokens();");
    const envelope = INDEX.indexOf("await convergeM365Envelopes();");
    const listen = INDEX.indexOf("app.listen(12009");

    expect(INDEX).toContain(
      'import { convergeM365Envelopes } from "./lib/m365/envelope-converge";',
    );
    expect(bearer).toBeGreaterThan(-1);
    expect(envelope).toBeGreaterThan(bearer);
    expect(listen).toBeGreaterThan(envelope);
  });
});
