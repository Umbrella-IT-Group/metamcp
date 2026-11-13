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
 * any invalid value, writes nothing at all), and the foreman ruling on the
 * first review round: the converge may rewrap a v1 row into a bound v2 envelope
 * ONLY while strict is off (the planned migration window). A v1 ciphertext
 * carries no proof of which user it belongs to, so under strict the converge
 * must never read one and never write a v2 envelope from it.
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

// A pass-through spy on the real decrypt, so the strict tests can assert that
// the converge never opened a v1 row at all (not merely that it did not write).
vi.mock("./crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./crypto")>();
  return {
    ...actual,
    decryptRefreshToken: vi.fn(actual.decryptRefreshToken),
  };
});

import { decryptRefreshToken, encryptRefreshToken } from "./crypto";
import {
  __resetEnvelopePolicyLogsForTesting,
  openUserRefreshToken,
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
  it("prints strict=on with the effective write version and leaves a v1 row exactly as it was", async () => {
    vi.stubEnv("M365_ENVELOPE_STRICT", "1");
    const repo = new MemoryRepo();
    const legacy = v1("rt-a");
    repo.rows.set("user-a", legacy);

    await convergeM365Envelopes(repo);

    expect(repo.rows.get("user-a")).toBe(legacy);
    expect(summary()).toContain("mode=v2 strict=on write_version=v2");
    expect(summary()).toContain("v1_remaining=1");
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
    expect(peekEnvelopeVersion(repo.rows.get("user-a"))).toBe("v1");
  });
});

/**
 * THE FINDING FROM CODE REVIEW ROUND 1. Bind users A and B in the migration
 * window, copy A's retained (pre-binding) v1 ciphertext into B's row, then boot
 * with strict on. Before the fix the converge targeted v2 under strict, opened
 * the planted v1 ciphertext, and sealed A's token into a v2 envelope bound to B,
 * so B's mint opened to A's token. Redeeming A's token at Entra does not
 * invalidate a token retained from before the rotation, so the planted copy is
 * live: the rewrap turned an unproven v1 ciphertext into a trusted bound one.
 */
async function bindThenPlant(repo: MemoryRepo): Promise<string> {
  const retainedA = v1("rt-a");
  repo.rows.set("user-a", retainedA);
  repo.rows.set("user-b", v1("rt-b"));

  // The migration window: write version 2, strict off. Both users are bound.
  vi.stubEnv("M365_ENVELOPE_WRITE_VERSION", "2");
  vi.stubEnv("M365_ENVELOPE_STRICT", "");
  await convergeM365Envelopes(repo);
  expect(peekEnvelopeVersion(repo.rows.get("user-a"))).toBe("v2");
  expect(peekEnvelopeVersion(repo.rows.get("user-b"))).toBe("v2");

  // The plant: a database writer copies A's retained v1 ciphertext into B.
  repo.rows.set("user-b", retainedA);

  repo.replaceCalls.length = 0;
  vi.clearAllMocks();
  __resetEnvelopePolicyLogsForTesting();
  return retainedA;
}

describe("strict: a v1 row is never read or rewrapped (the planted-ciphertext finding)", () => {
  it.each<[string, { strict: string; write: string }]>([
    ["strict=1 with write version 2", { strict: "1", write: "2" }],
    ["strict=1 alone", { strict: "1", write: "" }],
    [
      "an unrecognised strict value (resolves to strict) with write version 2",
      { strict: "yes", write: "2" },
    ],
    [
      "strict=1 with an explicit write version of 1",
      { strict: "1", write: "1" },
    ],
  ])(
    "%s: B's planted v1 row stays v1 and unreadable, and A's token never lands in a v2 envelope under B",
    async (_label, flags) => {
      const repo = new MemoryRepo();
      const retainedA = await bindThenPlant(repo);
      vi.stubEnv("M365_ENVELOPE_STRICT", flags.strict);
      vi.stubEnv("M365_ENVELOPE_WRITE_VERSION", flags.write);

      await convergeM365Envelopes(repo);

      // No row was written, so B's row is byte-identical to the planted copy.
      expect(repo.replaceCiphertextIfUnchanged).not.toHaveBeenCalled();
      expect(repo.rows.get("user-b")).toBe(retainedA);
      expect(peekEnvelopeVersion(repo.rows.get("user-b"))).toBe("v1");
      // The converge never opened any row, v1 or v2: a v1 ciphertext carries no
      // proof of whose token it is, so it is not read at all under strict.
      expect(decryptRefreshToken).not.toHaveBeenCalled();
      // Strict refuses to read B's row (the user re-enrolls)...
      expect(() =>
        openUserRefreshToken(envelopeOf(repo, "user-b"), KEK, "user-b"),
      ).toThrow(/strict/i);
      // ...and no stored envelope, anywhere, is a v2 envelope that opens to
      // A's token under B's own context.
      for (const [, stored] of repo.rows) {
        if (peekEnvelopeVersion(stored) !== "v2") continue;
        expect(() =>
          decryptRefreshToken(stored, KEK, refreshTokenContext("user-b")),
        ).toThrow();
      }
      // A's own bound row is untouched.
      expect(
        decryptRefreshToken(
          envelopeOf(repo, "user-a"),
          KEK,
          refreshTokenContext("user-a"),
        ),
      ).toBe("rt-a");
    },
  );

  it("strict off, write version 2: the same planted row IS bound to B (the documented migration behaviour, trust on first binding)", async () => {
    // Documented, not a defect: during the planned migration window the
    // converge binds WHATEVER a v1 row holds to that row, because a v1
    // ciphertext cannot be told apart from a genuine one without an Entra call.
    // A swap that predates the converge therefore becomes permanent; that is why
    // strict (which never rewraps) is turned on only after `v1_remaining=0`, and
    // why an operator who suspects an earlier swap has the user re-enroll.
    const repo = new MemoryRepo();
    await bindThenPlant(repo);
    vi.stubEnv("M365_ENVELOPE_STRICT", "");
    vi.stubEnv("M365_ENVELOPE_WRITE_VERSION", "2");

    await convergeM365Envelopes(repo);

    const stored = envelopeOf(repo, "user-b");
    expect(peekEnvelopeVersion(stored)).toBe("v2");
    expect(
      decryptRefreshToken(stored, KEK, refreshTokenContext("user-b")),
    ).toBe("rt-a");
    expect(summary()).toContain("rewrapped=1");
  });

  it("counts the v1 rows as needing re-enrollment in the summary, and logs that count", async () => {
    vi.stubEnv("M365_ENVELOPE_STRICT", "1");
    const repo = new MemoryRepo();
    repo.rows.set("user-a", v1("rt-a"));
    repo.rows.set("user-b", v1("rt-b"));
    repo.rows.set("user-c", v2("user-c", "rt-c"));

    await convergeM365Envelopes(repo);

    expect(summary()).toContain(
      "scanned=3 rewrapped=0 already=0 skipped_changed=0 failed=0 v1_remaining=2 v2_remaining=1 unreadable=0 needs_reenroll=2",
    );
    const note = warnings().find((w) => w.includes("asked to re-enroll"));
    expect(note).toBeDefined();
    expect(note).toContain("2 v1 row(s)");
    expect(note).toContain("never rewrapped");
    expect(repo.replaceCiphertextIfUnchanged).not.toHaveBeenCalled();
    expect(decryptRefreshToken).not.toHaveBeenCalled();
  });

  it("strict with only bound rows has nothing to re-enroll and no warning", async () => {
    vi.stubEnv("M365_ENVELOPE_STRICT", "1");
    const repo = new MemoryRepo();
    repo.rows.set("user-a", v2("user-a", "rt-a"));

    await convergeM365Envelopes(repo);

    expect(summary()).toContain("v1_remaining=0 v2_remaining=1");
    expect(summary()).toContain("needs_reenroll=0");
    expect(warnings()).toEqual([]);
    expect(repo.replaceCiphertextIfUnchanged).not.toHaveBeenCalled();
  });

  it("strict with an explicit write version of 1 is a no-op that says so: no row is lowered", async () => {
    vi.stubEnv("M365_ENVELOPE_STRICT", "1");
    vi.stubEnv("M365_ENVELOPE_WRITE_VERSION", "1");
    const repo = new MemoryRepo();
    const bound = v2("user-a", "rt-a");
    const legacy = v1("rt-b");
    repo.rows.set("user-a", bound);
    repo.rows.set("user-b", legacy);

    await convergeM365Envelopes(repo);

    expect(repo.replaceCiphertextIfUnchanged).not.toHaveBeenCalled();
    expect(repo.rows.get("user-a")).toBe(bound);
    expect(repo.rows.get("user-b")).toBe(legacy);
    const boot = warnings().find((w) =>
      w.includes("M365_ENVELOPE_WRITE_VERSION=1"),
    );
    expect(boot).toBeDefined();
    expect(boot).toMatch(/no rollback/i);
    expect(boot).toContain("M365_ENVELOPE_STRICT");
  });

  it("strict counts an unreadable row without throwing, rewrapping or reporting a failure", async () => {
    vi.stubEnv("M365_ENVELOPE_STRICT", "1");
    const repo = new MemoryRepo();
    repo.rows.set("user-junk", "not-an-envelope");
    repo.rows.set("user-a", v1("rt-a"));

    await expect(convergeM365Envelopes(repo)).resolves.toBeUndefined();

    expect(summary()).toContain("failed=0");
    expect(summary()).toContain("unreadable=1");
    expect(repo.replaceCiphertextIfUnchanged).not.toHaveBeenCalled();
    expect(decryptRefreshToken).not.toHaveBeenCalled();
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
