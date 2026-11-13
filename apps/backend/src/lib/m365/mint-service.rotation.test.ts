/**
 * The mint service's rotation lineage, compare-and-swap reconciliation,
 * generation-guarded state and envelope policy.
 *
 * The repository here is an in-memory mirror of its conditional-write CONTRACT
 * (a rotation applies only while the row still holds the ciphertext the mint
 * read and is active; a reauth mark applies only against the ciphertext it was
 * rejected for). That is the right seam for these tests: what is under test is
 * the SERVICE's reaction to the contract, and the SQL that enforces it is
 * pinned against a real Postgres in
 * `db/repositories/m365-tokens.cas.integration.test.ts`, where it cannot be
 * faked. The Entra token endpoint is faked at the transport (`fetch`).
 *
 * Refresh tokens are named so a failure reads as a chain: "A" is the grant
 * stored in the row, and Entra answers a redemption of X with the rotated token
 * "X>" (so A rotates to "A>", then "A>>").
 *
 * Time is the system clock only (fake Date), advanced to expire the cached
 * access token between mints; nothing sleeps.
 *
 * Nothing here imports `./envelope`: fixtures are built with the crypto
 * primitive and the bound context is inlined, so every case exercises the
 * service's behaviour rather than a shared helper.
 */
import { randomBytes } from "node:crypto";

import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  type MockInstance,
  vi,
} from "vitest";

vi.mock("../../db/index", () => ({ db: {} }));

import logger from "@/utils/logger";

import type {
  M365TokensRepository,
  M365UserTokenRow,
} from "../../db/repositories/m365-tokens.repo";
import { decryptRefreshToken, encryptRefreshToken } from "./crypto";
import { M365MintService } from "./mint-service";

const KEK = randomBytes(32);
const HOUR = 3_600_000;

// ---------------------------------------------------------------- fixtures

const ctxFor = (userId: string) => `m365-refresh-token:${userId}`;

function seal(
  userId: string,
  plaintext: string,
  version: "v1" | "v2" = "v1",
): string {
  return encryptRefreshToken(
    plaintext,
    KEK,
    "k1",
    version === "v2" ? ctxFor(userId) : undefined,
  );
}

function rowFor(
  plaintext: string,
  version: "v1" | "v2" = "v1",
  overrides: Partial<M365UserTokenRow> = {},
): M365UserTokenRow {
  return {
    uuid: "row-uuid",
    user_id: "user-1",
    entra_oid: "oid-1",
    tenant_id: "tid-1",
    entra_upn: "admin@example.com",
    rt_ciphertext: seal("user-1", plaintext, version),
    kek_id: "k1",
    scopes_granted: "User.Read",
    status: "active",
    created_at: new Date(0),
    rotated_at: null,
    last_used_at: null,
    ...overrides,
  };
}

const versionOf = (envelope: string) => envelope.split(".")[0];

type RotateMode = "ok" | "down" | "commit-then-throw" | "commit-then-down";

class FakeTokensRepo {
  row: M365UserTokenRow | undefined;
  rotateMode: RotateMode = "ok";
  /** Runs at the start of each rotation, to land a change "during the swap". */
  beforeRotate: (() => void) | undefined;
  private committedThenFailed = false;
  readonly rotateCalls: { userId: string; rt: string; expected: string }[] = [];
  readonly markCalls: { userId: string; expected: string }[] = [];

  constructor(row: M365UserTokenRow | undefined) {
    this.row = row;
  }

  /** The stored envelope; the fixture must have a row. */
  ciphertext(): string {
    if (!this.row) throw new Error("the fixture row is missing");
    return this.row.rt_ciphertext;
  }

  /** The plaintext the row currently opens to, or undefined with no row. */
  stored(): string | undefined {
    if (!this.row) return undefined;
    return decryptRefreshToken(
      this.row.rt_ciphertext,
      KEK,
      ctxFor(this.row.user_id),
    );
  }

  private cas(
    userId: string,
    rt: string,
    kekId: string,
    expected: string,
  ): boolean {
    const row = this.row;
    if (
      !row ||
      row.user_id !== userId ||
      row.rt_ciphertext !== expected ||
      row.status !== "active"
    ) {
      return false;
    }
    this.row = { ...row, rt_ciphertext: rt, kek_id: kekId };
    return true;
  }

  findByUserId = vi.fn(async (userId: string) =>
    this.row && this.row.user_id === userId ? { ...this.row } : undefined,
  );

  rotateRefreshToken = vi.fn(
    async (userId: string, rt: string, kekId: string, expected: string) => {
      this.rotateCalls.push({ userId, rt, expected });
      this.beforeRotate?.();
      if (this.rotateMode === "down") throw new Error("pg down");
      if (this.rotateMode === "commit-then-down" && this.committedThenFailed) {
        throw new Error("pg down");
      }
      const applied = this.cas(userId, rt, kekId, expected);
      if (
        applied &&
        !this.committedThenFailed &&
        (this.rotateMode === "commit-then-throw" ||
          this.rotateMode === "commit-then-down")
      ) {
        // The write committed, then the connection failed before the answer.
        this.committedThenFailed = true;
        throw new Error("connection reset after commit");
      }
      return applied;
    },
  );

  markReauthRequired = vi.fn(async (userId: string, expected: string) => {
    this.markCalls.push({ userId, expected });
    if (
      this.row &&
      this.row.user_id === userId &&
      this.row.rt_ciphertext === expected
    ) {
      this.row = { ...this.row, status: "reauth_required" };
    }
  });

  asRepo(): M365TokensRepository {
    return this as unknown as M365TokensRepository;
  }
}

function tokenResponse(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** An Entra that rotates every redeemed token X to "X>" and signs the AT with X. */
function entraChain(options: { onRedeem?: (rt: string) => void } = {}) {
  const sent: string[] = [];
  const fetchStub = vi.fn(async (_url: string | URL, init?: RequestInit) => {
    const presented =
      new URLSearchParams(String(init?.body)).get("refresh_token") ?? "";
    sent.push(presented);
    options.onRedeem?.(presented);
    return tokenResponse({
      access_token: `at:${presented}`,
      refresh_token: `${presented}>`,
      expires_in: 3600,
      scope: "User.Read",
    });
  });
  return { sent, fetchStub: fetchStub as unknown as typeof fetch };
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
}
function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

/** An Entra whose nth redemption waits until the test answers it. */
function controlledEntra() {
  const slots: {
    rt?: string;
    arrived: Deferred<void>;
    response: Deferred<Response>;
  }[] = [];
  const slot = (n: number) =>
    (slots[n] ??= {
      arrived: deferred<void>(),
      response: deferred<Response>(),
    });
  let next = 0;
  const fetchStub = vi.fn(async (_url: string | URL, init?: RequestInit) => {
    const s = slot(next++);
    s.rt = new URLSearchParams(String(init?.body)).get("refresh_token") ?? "";
    s.arrived.resolve();
    return s.response.promise;
  });
  return {
    fetchStub: fetchStub as unknown as typeof fetch,
    calls: fetchStub,
    arrived: (n: number) => slot(n).arrived.promise,
    /**
     * Assert (rather than wait for) the nth redemption having started once the
     * queued work has run: a mint that was wrongly joined to an earlier one never
     * starts it, and that should fail on the assertion, not hang.
     */
    reached: async (n: number) => {
      await flush();
      expect(
        slots[n]?.rt,
        `redemption #${n} should have started`,
      ).toBeDefined();
    },
    rtOf: (n: number) => slots[n]?.rt,
    respond: (n: number, response: Response) =>
      slot(n).response.resolve(response),
    ok: (n: number, presented: string) =>
      slot(n).response.resolve(
        tokenResponse({
          access_token: `at:${presented}`,
          refresh_token: `${presented}>`,
          expires_in: 3600,
          scope: "User.Read",
        }),
      ),
  };
}

function pastExpiry(): void {
  vi.setSystemTime(Date.now() + 2 * HOUR);
}

/** Let every already-queued promise continuation run (no timers involved). */
async function flush(): Promise<void> {
  for (let i = 0; i < 25; i++) await Promise.resolve();
}

// ------------------------------------------------------------- log capture

let infoSpy: MockInstance<typeof logger.info>;
let warnSpy: MockInstance<typeof logger.warn>;
let errorSpy: MockInstance<typeof logger.error>;

function mintAudits(): Record<string, unknown>[] {
  return infoSpy.mock.calls
    .map((call) => String(call[0]))
    .filter((line) => line.startsWith("{"))
    .map((line) => JSON.parse(line) as Record<string, unknown>)
    .filter((entry) => entry.event === "m365_mint");
}
const warnLines = () => warnSpy.mock.calls.map((call) => String(call[0]));

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2026-11-12T12:00:00Z"));
  vi.stubEnv("M365_TENANT_ID", "tid-1");
  vi.stubEnv("M365_CLIENT_ID", "cid-1");
  vi.stubEnv("M365_CLIENT_SECRET", "secret-1");
  vi.stubEnv("M365_TOKEN_KEK", KEK.toString("base64"));
  vi.stubEnv("APP_URL", "https://mcp.example.com");
  vi.stubEnv("M365_ENVELOPE_WRITE_VERSION", "");
  vi.stubEnv("M365_ENVELOPE_STRICT", "");
  infoSpy = vi.spyOn(logger, "info").mockImplementation(() => undefined);
  warnSpy = vi.spyOn(logger, "warn").mockImplementation(() => undefined);
  errorSpy = vi.spyOn(logger, "error").mockImplementation(() => undefined);
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

// ------------------------------------------------------------ row binding

describe("a bound (v2) row", () => {
  it("mints for the user the envelope is bound to", async () => {
    const repo = new FakeTokensRepo(rowFor("A", "v2"));
    const { sent, fetchStub } = entraChain();
    const service = new M365MintService(repo.asRepo(), fetchStub);

    expect(await service.getAccessToken("user-1")).toBe("at:A");
    expect(sent).toEqual(["A"]);
  });

  it("refuses a ciphertext copied from another user's row without calling Entra", async () => {
    // User A's bound envelope, sitting in user-1's row.
    const foreign = encryptRefreshToken("A-rt", KEK, "k1", ctxFor("user-A"));
    const repo = new FakeTokensRepo(
      rowFor("unused", "v1", { rt_ciphertext: foreign }),
    );
    const { sent, fetchStub } = entraChain();
    const service = new M365MintService(repo.asRepo(), fetchStub);

    await expect(service.getAccessToken("user-1")).rejects.toMatchObject({
      code: "credential_missing",
    });
    expect(sent).toEqual([]);
    expect(mintAudits().map((a) => a.outcome)).toEqual(["decrypt_failed"]);
    expect(mintAudits()[0].envelope).toBe("v2");
  });
});

// ------------------------------------------------- compare-and-swap results

describe("rotation persist reconciliation", () => {
  it("does not apply, cache or hold a rotation when the row was replaced by a different grant", async () => {
    const repo = new FakeTokensRepo(rowFor("A"));
    const { sent, fetchStub } = entraChain({
      // Another writer replaces the grant while the redemption is in flight.
      onRedeem: (rt) => {
        if (rt === "A") repo.row = rowFor("NEW");
      },
    });
    const service = new M365MintService(repo.asRepo(), fetchStub);

    // The in-flight caller still gets the token it legitimately redeemed.
    expect(await service.getAccessToken("user-1")).toBe("at:A");
    // The replacement grant was kept, untouched.
    expect(repo.stored()).toBe("NEW");
    expect(mintAudits()[0].rotation).toBe("skipped");

    // Not cached: the next call mints again, from the row as it is NOW, not
    // from the stale rotated token.
    expect(await service.getAccessToken("user-1")).toBe("at:NEW");
    expect(sent).toEqual(["A", "NEW"]);
    expect(
      warnLines().some((line) => line.includes("rotation not applied")),
    ).toBe(true);
  });

  it("re-seals and retries against the current ciphertext when the same grant was rewrapped, then caches", async () => {
    const repo = new FakeTokensRepo(rowFor("A"));
    const original = repo.ciphertext();
    const rewrapped = rowFor("A", "v2");
    const { sent, fetchStub } = entraChain({
      onRedeem: (rt) => {
        // A boot converge in another process rewraps the SAME grant to v2.
        if (rt === "A") repo.row = rewrapped;
      },
    });
    const service = new M365MintService(repo.asRepo(), fetchStub);

    expect(await service.getAccessToken("user-1")).toBe("at:A");

    expect(repo.rotateCalls).toHaveLength(2);
    // The first swap was conditioned on what the mint read and missed; the
    // second is conditioned on the CURRENT (rewrapped) ciphertext and sealed at
    // that row's version.
    expect(repo.rotateCalls[0].expected).toBe(original);
    expect(repo.rotateCalls[1].expected).toBe(rewrapped.rt_ciphertext);
    expect(versionOf(repo.rotateCalls[1].rt)).toBe("v2");
    expect(versionOf(repo.ciphertext())).toBe("v2");
    expect(repo.stored()).toBe("A>");
    expect(mintAudits()[0].rotation).toBe("applied");
    // Cached: no second redemption.
    await service.getAccessToken("user-1");
    expect(sent).toEqual(["A"]);
  });

  it("treats a write that committed before throwing as applied, not skipped", async () => {
    const repo = new FakeTokensRepo(rowFor("A"));
    repo.rotateMode = "commit-then-throw";
    const { sent, fetchStub } = entraChain();
    const service = new M365MintService(repo.asRepo(), fetchStub);

    expect(await service.getAccessToken("user-1")).toBe("at:A");

    // Attempt 1 committed and threw; attempt 2 missed (the row had moved on)
    // and the fresh read showed the rotated token already stored.
    expect(repo.rotateCalls).toHaveLength(2);
    expect(repo.stored()).toBe("A>");
    expect(mintAudits()[0].rotation).toBe("applied");
    await service.getAccessToken("user-1");
    expect(sent).toEqual(["A"]);
  });

  it.each(["re-enrollment", "revoke", "delete"] as const)(
    "does not cache or hold the old grant after a %s beats the reconcile swap",
    async (change) => {
      const repo = new FakeTokensRepo(rowFor("A"));
      const { sent, fetchStub } = entraChain({
        onRedeem: (rt) => {
          if (rt === "A") repo.row = rowFor("A", "v2");
        },
      });
      repo.beforeRotate = () => {
        if (repo.rotateCalls.length !== 2) return;
        // This change lands after reconciliation read the same grant, but
        // before its one retry. A second CAS miss is still a definite miss.
        repo.row =
          change === "delete"
            ? undefined
            : change === "revoke"
              ? { ...rowFor("A", "v2"), status: "reauth_required" }
              : rowFor("NEW", "v2");
      };
      const service = new M365MintService(repo.asRepo(), fetchStub);

      expect(await service.getAccessToken("user-1")).toBe("at:A");
      expect(repo.rotateCalls).toHaveLength(2);
      expect(mintAudits()[0].rotation).toBe("skipped");
      expect(
        errorSpy.mock.calls.some((call) =>
          String(call[0]).includes("holding rotation in memory"),
        ),
      ).toBe(false);

      repo.beforeRotate = undefined;
      if (change === "re-enrollment") {
        expect(await service.getAccessToken("user-1")).toBe("at:NEW");
        expect(sent).toEqual(["A", "NEW"]);
      } else {
        await expect(service.getAccessToken("user-1")).rejects.toMatchObject({
          code: "credential_missing",
        });
        expect(sent).toEqual(["A"]);
      }
    },
  );

  it("holds the rotation without another write if a second rewrap beats the reconcile swap", async () => {
    const repo = new FakeTokensRepo(rowFor("A"));
    const { sent, fetchStub } = entraChain({
      onRedeem: (rt) => {
        if (rt === "A") repo.row = rowFor("A", "v2");
      },
    });
    repo.beforeRotate = () => {
      if (repo.rotateCalls.length === 2) repo.row = rowFor("A", "v2");
    };
    const service = new M365MintService(repo.asRepo(), fetchStub);

    expect(await service.getAccessToken("user-1")).toBe("at:A");
    expect(repo.rotateCalls).toHaveLength(2);
    expect(repo.stored()).toBe("A");
    expect(mintAudits()[0].rotation).toBe("held");

    repo.beforeRotate = undefined;
    pastExpiry();
    expect(await service.getAccessToken("user-1")).toBe("at:A>");
    expect(sent).toEqual(["A", "A>"]);
    expect(repo.stored()).toBe("A>>");
  });
});

// -------------------------------------------------------- pending lineage

describe("a held rotation stays anchored to the stored grant", () => {
  it("survives successive failed persists and the latest token is redeemed and persisted once the database recovers", async () => {
    const repo = new FakeTokensRepo(rowFor("A"));
    repo.rotateMode = "down";
    const { sent, fetchStub } = entraChain();
    const service = new M365MintService(repo.asRepo(), fetchStub);

    // Cycle 1: redeem A, persist fails twice, A> held.
    expect(await service.getAccessToken("user-1")).toBe("at:A");
    pastExpiry();
    // Cycle 2: the database still opens to A, so A> is redeemed (not A), and
    // its rotation A>> is held in turn.
    expect(await service.getAccessToken("user-1")).toBe("at:A>");
    pastExpiry();
    // The database recovers. Cycle 3 redeems the LATEST held token (A>>) and
    // persists its rotation.
    repo.rotateMode = "ok";
    expect(await service.getAccessToken("user-1")).toBe("at:A>>");

    expect(sent).toEqual(["A", "A>", "A>>"]);
    expect(repo.stored()).toBe("A>>>");
    expect(mintAudits().map((a) => a.rotation)).toEqual([
      "held",
      "held",
      "applied",
    ]);

    // The chain is spent: the next mint redeems what is stored.
    pastExpiry();
    await service.getAccessToken("user-1");
    expect(sent[3]).toBe("A>>>");
  });

  it("survives successive failed persists across a ciphertext-only rewrap of the same grant", async () => {
    const repo = new FakeTokensRepo(rowFor("A"));
    repo.rotateMode = "down";
    const { sent, fetchStub } = entraChain();
    const service = new M365MintService(repo.asRepo(), fetchStub);

    await service.getAccessToken("user-1");
    // Another process rewraps the same grant (v1 to v2) between the cycles.
    repo.row = rowFor("A", "v2");
    pastExpiry();
    await service.getAccessToken("user-1");
    pastExpiry();
    repo.rotateMode = "ok";
    await service.getAccessToken("user-1");

    expect(sent).toEqual(["A", "A>", "A>>"]);
    expect(repo.stored()).toBe("A>>>");
    // The recovery persist is conditioned on the rewrapped ciphertext and, in
    // keep mode, the row stays bound.
    expect(versionOf(repo.ciphertext())).toBe("v2");
  });

  it("keeps the freshest token when the row is rewrapped DURING a mint that redeems a held token", async () => {
    const repo = new FakeTokensRepo(rowFor("A"));
    repo.rotateMode = "down";
    const { sent, fetchStub } = entraChain({
      onRedeem: (rt) => {
        // Redeeming the held A> while a converge rewraps the stored grant.
        if (rt === "A>") repo.row = rowFor("A", "v2");
      },
    });
    const service = new M365MintService(repo.asRepo(), fetchStub);

    await service.getAccessToken("user-1"); // A held as A>, persist down
    repo.rotateMode = "ok";
    pastExpiry();
    expect(await service.getAccessToken("user-1")).toBe("at:A>");

    // The swap missed once (the ciphertext moved), the reconcile recognised the
    // stored grant as the one the held chain descends from, and re-sealed A>>.
    expect(repo.stored()).toBe("A>>");
    expect(versionOf(repo.ciphertext())).toBe("v2");
    expect(mintAudits()[1].rotation).toBe("applied");
    pastExpiry();
    await service.getAccessToken("user-1");
    expect(sent).toEqual(["A", "A>", "A>>"]);
  });

  it("recognises a held rotation that had in fact committed (write then connection loss) and does not discard it as a foreign grant", async () => {
    const repo = new FakeTokensRepo(rowFor("A"));
    repo.rotateMode = "commit-then-down";
    const { sent, fetchStub } = entraChain();
    const service = new M365MintService(repo.asRepo(), fetchStub);

    await service.getAccessToken("user-1");
    // Both persist attempts reported failure, but the first had committed.
    expect(repo.stored()).toBe("A>");
    expect(mintAudits()[0].rotation).toBe("held");

    pastExpiry();
    repo.rotateMode = "ok";
    expect(await service.getAccessToken("user-1")).toBe("at:A>");
    expect(sent).toEqual(["A", "A>"]);
    expect(warnLines().some((line) => line.includes("discarding a held"))).toBe(
      false,
    );
    expect(repo.stored()).toBe("A>>");
  });

  it("commit-then-throw in the middle of a chain applies the latest token and clears the held one", async () => {
    const repo = new FakeTokensRepo(rowFor("A"));
    repo.rotateMode = "down";
    const { sent, fetchStub } = entraChain();
    const service = new M365MintService(repo.asRepo(), fetchStub);

    await service.getAccessToken("user-1"); // A> held, anchor A
    pastExpiry();
    repo.rotateMode = "commit-then-throw";
    await service.getAccessToken("user-1"); // redeem A>, A>> commits then throws

    expect(repo.stored()).toBe("A>>");
    expect(mintAudits()[1].rotation).toBe("applied");
    pastExpiry();
    await service.getAccessToken("user-1");
    expect(sent).toEqual(["A", "A>", "A>>"]);
    expect(warnLines().some((line) => line.includes("discarding a held"))).toBe(
      false,
    );
  });

  it("discards a held chain when the stored credential is a different grant (a real re-enrollment)", async () => {
    const repo = new FakeTokensRepo(rowFor("A"));
    repo.rotateMode = "down";
    const { sent, fetchStub } = entraChain();
    const service = new M365MintService(repo.asRepo(), fetchStub);

    await service.getAccessToken("user-1"); // A> held, anchor A

    // The row now opens to a different grant, with no invalidation call (another
    // writer, or an instance that does not share this process's memory).
    repo.row = rowFor("NEW");
    repo.rotateMode = "ok";
    pastExpiry();
    expect(await service.getAccessToken("user-1")).toBe("at:NEW");

    expect(sent).toEqual(["A", "NEW"]);
    expect(warnLines().some((line) => line.includes("discarding a held"))).toBe(
      true,
    );
  });

  it("drops a held chain on invalidation too", async () => {
    const repo = new FakeTokensRepo(rowFor("A"));
    repo.rotateMode = "down";
    const { sent, fetchStub } = entraChain();
    const service = new M365MintService(repo.asRepo(), fetchStub);

    await service.getAccessToken("user-1");
    repo.row = rowFor("NEW");
    service.invalidateUser("user-1");
    repo.rotateMode = "ok";
    expect(await service.getAccessToken("user-1")).toBe("at:NEW");
    expect(sent).toEqual(["A", "NEW"]);
  });
});

// ------------------------------------------------- generation-guarded state

describe("an invalidation retires the mints that were running", () => {
  it.each(["fresh", "missing"] as const)(
    "joins the current mint when invalidation lands during a row read returning a %s row",
    async (readOutcome) => {
      const repo = new FakeTokensRepo(rowFor("A"));
      const readStarted = deferred<void>();
      const readResult = deferred<M365UserTokenRow | undefined>();
      repo.findByUserId.mockImplementationOnce(async () => {
        readStarted.resolve();
        return readResult.promise;
      });
      const entra = controlledEntra();
      const service = new M365MintService(repo.asRepo(), entra.fetchStub);
      const oldCaller = service.getAccessToken("user-1").then(
        (token) => token,
        (error: { code: string }) => error.code,
      );
      await readStarted.promise;

      repo.row = rowFor("NEW");
      service.invalidateUser("user-1");
      const newCaller = service.getAccessToken("user-1");
      await entra.reached(0);
      expect(entra.rtOf(0)).toBe("NEW");

      // The retired mint has not redeemed anything yet. Its read can now see
      // the fresh grant too, so it must join rather than redeem NEW twice.
      readResult.resolve(readOutcome === "fresh" ? repo.row : undefined);
      await flush();
      expect(entra.calls).toHaveBeenCalledTimes(1);
      entra.ok(0, "NEW");
      expect(await newCaller).toBe("at:NEW");
      expect(await oldCaller).toBe("at:NEW");
      expect(mintAudits()).toHaveLength(1);
    },
  );

  it("does not cache the old mint's token, starts a new mint for a later caller, and does not hold a late persist failure", async () => {
    const repo = new FakeTokensRepo(rowFor("A"));
    const entra = controlledEntra();
    const service = new M365MintService(repo.asRepo(), entra.fetchStub);

    const oldCaller = service.getAccessToken("user-1");
    await entra.arrived(0);

    // Re-enrollment lands: a new grant, and the router's invalidation.
    repo.row = rowFor("NEW");
    service.invalidateUser("user-1");

    // A caller arriving after the invalidation must NOT join the old mint: it
    // starts its own, from the row as it is now.
    const newCaller = service.getAccessToken("user-1");
    await entra.reached(1);
    expect(entra.rtOf(1)).toBe("NEW");
    entra.ok(1, "NEW");
    expect(await newCaller).toBe("at:NEW");

    // The old mint finishes LAST, with its persist failing (database trouble).
    // It must neither cache its token over the new one nor hold its rotation.
    repo.rotateMode = "down";
    entra.ok(0, "A");
    expect(await oldCaller).toBe("at:A");
    repo.rotateMode = "ok";

    expect(mintAudits().map((a) => a.rotation)).toEqual(["applied", "skipped"]);
    // The cache still answers with the NEW mint's token.
    expect(await service.getAccessToken("user-1")).toBe("at:NEW");
    expect(entra.calls).toHaveBeenCalledTimes(2);
    // Nothing was held from the old generation: the next mint redeems what is
    // stored (NEW's rotation) and discards nothing.
    pastExpiry();
    const third = service.getAccessToken("user-1");
    await entra.reached(2);
    expect(entra.rtOf(2)).toBe("NEW>");
    entra.ok(2, "NEW>");
    expect(await third).toBe("at:NEW>");
    expect(warnLines().some((line) => line.includes("discarding a held"))).toBe(
      false,
    );
  });

  it("an old mint's late success does not erase the new generation's cache or held rotation", async () => {
    const repo = new FakeTokensRepo(rowFor("A"));
    const entra = controlledEntra();
    const service = new M365MintService(repo.asRepo(), entra.fetchStub);

    const oldCaller = service.getAccessToken("user-1");
    await entra.arrived(0);

    repo.row = rowFor("NEW");
    service.invalidateUser("user-1");

    // The new generation mints, but its persist fails: it holds a rotation and
    // caches its token.
    repo.rotateMode = "down";
    const newCaller = service.getAccessToken("user-1");
    await entra.reached(1);
    entra.ok(1, "NEW");
    expect(await newCaller).toBe("at:NEW");
    repo.rotateMode = "ok";

    // The old mint now completes: a success whose swap misses the new row, so
    // its cleanup (`skipped`) runs.
    entra.ok(0, "A");
    expect(await oldCaller).toBe("at:A");

    // The new generation's cached token survived the old mint's cleanup...
    expect(await service.getAccessToken("user-1")).toBe("at:NEW");
    expect(entra.calls).toHaveBeenCalledTimes(2);
    // ...and so did its held rotation: after expiry the next mint redeems the
    // held NEW>, not the stored NEW (the database still opens to NEW).
    pastExpiry();
    const third = service.getAccessToken("user-1");
    await entra.reached(2);
    expect(entra.rtOf(2)).toBe("NEW>");
    entra.ok(2, "NEW>");
    expect(await third).toBe("at:NEW>");
    expect(repo.stored()).toBe("NEW>>");
  });

  it("the old mint's finally does not remove a newer in-flight entry", async () => {
    const repo = new FakeTokensRepo(rowFor("A"));
    const entra = controlledEntra();
    const service = new M365MintService(repo.asRepo(), entra.fetchStub);

    const oldCaller = service.getAccessToken("user-1");
    await entra.arrived(0);

    repo.row = rowFor("NEW");
    service.invalidateUser("user-1");

    // A newer mint is running when the old one completes.
    const newer = service.getAccessToken("user-1");
    await entra.reached(1);
    entra.ok(0, "A");
    expect(await oldCaller).toBe("at:A");

    // The old mint's cleanup has run. A caller arriving now must JOIN the newer
    // mint: no third redemption is started.
    const joiner = service.getAccessToken("user-1");
    await flush();
    expect(entra.calls).toHaveBeenCalledTimes(2);

    entra.ok(1, "NEW");
    expect(await newer).toBe("at:NEW");
    expect(await joiner).toBe("at:NEW");
    expect(entra.calls).toHaveBeenCalledTimes(2);
  });

  it("an old mint's credential-terminal failure after a re-enrollment leaves the new cache, held rotation and row intact", async () => {
    const repo = new FakeTokensRepo(rowFor("A"));
    const entra = controlledEntra();
    const service = new M365MintService(repo.asRepo(), entra.fetchStub);
    const staleCiphertext = repo.ciphertext();

    const oldCaller = service.getAccessToken("user-1");
    const oldOutcome = oldCaller.then(
      () => "resolved",
      (error: { code: string }) => error.code,
    );
    await entra.arrived(0);

    repo.row = rowFor("NEW");
    service.invalidateUser("user-1");

    // New generation: mints, caches, and holds a rotation (persist down).
    repo.rotateMode = "down";
    const newCaller = service.getAccessToken("user-1");
    await entra.reached(1);
    entra.ok(1, "NEW");
    expect(await newCaller).toBe("at:NEW");
    repo.rotateMode = "ok";

    // The old grant is now rejected by Entra, long after the replacement.
    entra.respond(
      0,
      tokenResponse(
        {
          error: "invalid_grant",
          error_description: "AADSTS700082: expired",
          error_codes: [700082],
        },
        400,
      ),
    );
    expect(await oldOutcome).toBe("credential_expired");

    // The conditional mark targeted the OLD ciphertext, so the re-enrolled row
    // is still active.
    await flush();
    expect(repo.markCalls).toHaveLength(1);
    expect(repo.markCalls[0].expected).toBe(staleCiphertext);
    expect(repo.row?.status).toBe("active");

    // The new generation's cache survived: no new redemption.
    expect(await service.getAccessToken("user-1")).toBe("at:NEW");
    expect(entra.calls).toHaveBeenCalledTimes(2);

    // So did its held rotation: after expiry the next mint redeems NEW>, the
    // held token (the database still opens to NEW).
    pastExpiry();
    const third = service.getAccessToken("user-1");
    await entra.reached(2);
    expect(entra.rtOf(2)).toBe("NEW>");
    entra.ok(2, "NEW>");
    expect(await third).toBe("at:NEW>");
    expect(repo.stored()).toBe("NEW>>");
  });

  it("does not cache a token issued for a grant that was replaced mid-mint, even when Entra issued no new refresh token", async () => {
    const repo = new FakeTokensRepo(rowFor("A"));
    const entra = controlledEntra();
    const service = new M365MintService(repo.asRepo(), entra.fetchStub);

    const oldCaller = service.getAccessToken("user-1");
    await entra.arrived(0);
    repo.row = rowFor("NEW");
    service.invalidateUser("user-1");
    entra.respond(
      0,
      tokenResponse({ access_token: "at-old", expires_in: 3600 }),
    );
    expect(await oldCaller).toBe("at-old");

    // Not cached: the next caller mints again, from the row as it is now.
    const next = service.getAccessToken("user-1");
    await entra.reached(1);
    expect(entra.rtOf(1)).toBe("NEW");
    entra.ok(1, "NEW");
    expect(await next).toBe("at:NEW");
  });

  it("does not cache a token whose rotation applied while an invalidation landed during the swap", async () => {
    const repo = new FakeTokensRepo(rowFor("A"));
    const { sent, fetchStub } = entraChain();
    const service = new M365MintService(repo.asRepo(), fetchStub);
    // The user disconnects between the redemption and the swap's answer: the
    // swap itself still matches the row it read.
    repo.beforeRotate = () => service.invalidateUser("user-1");

    expect(await service.getAccessToken("user-1")).toBe("at:A");
    expect(mintAudits()[0].rotation).toBe("applied");

    // The access token was not cached for the replaced generation, so the next
    // caller mints again (from the rotation the swap stored).
    repo.beforeRotate = undefined;
    expect(await service.getAccessToken("user-1")).toBe("at:A>");
    expect(sent).toEqual(["A", "A>"]);
  });
});

// ---------------------------------------------------------- envelope policy

describe("envelope write policy", () => {
  async function mintOnce(row: M365UserTokenRow) {
    const repo = new FakeTokensRepo(row);
    const { fetchStub } = entraChain();
    const service = new M365MintService(repo.asRepo(), fetchStub);
    await service.getAccessToken("user-1");
    return repo;
  }

  it("unset keeps a v1 row v1 and a v2 row v2 (never lowers)", async () => {
    expect(versionOf((await mintOnce(rowFor("A", "v1"))).ciphertext())).toBe(
      "v1",
    );
    expect(versionOf((await mintOnce(rowFor("A", "v2"))).ciphertext())).toBe(
      "v2",
    );
  });

  it("M365_ENVELOPE_WRITE_VERSION=2 writes a v2 envelope bound to this user only", async () => {
    vi.stubEnv("M365_ENVELOPE_WRITE_VERSION", "2");
    const repo = await mintOnce(rowFor("A", "v1"));
    const written = repo.ciphertext();
    expect(versionOf(written)).toBe("v2");
    expect(decryptRefreshToken(written, KEK, ctxFor("user-1"))).toBe("A>");
    expect(() => decryptRefreshToken(written, KEK, ctxFor("user-2"))).toThrow();
  });

  it("an explicit M365_ENVELOPE_WRITE_VERSION=1 writes v1 even over a v2 row", async () => {
    vi.stubEnv("M365_ENVELOPE_WRITE_VERSION", "1");
    const repo = await mintOnce(rowFor("A", "v2"));
    expect(versionOf(repo.ciphertext())).toBe("v1");
  });

  it("an unrecognised write version keeps the row's version and warns once", async () => {
    vi.stubEnv("M365_ENVELOPE_WRITE_VERSION", "bogus-mint-policy");
    const repo = new FakeTokensRepo(rowFor("A", "v2"));
    const { fetchStub } = entraChain();
    const service = new M365MintService(repo.asRepo(), fetchStub);
    await service.getAccessToken("user-1");
    pastExpiry();
    await service.getAccessToken("user-1");
    expect(versionOf(repo.ciphertext())).toBe("v2");
    expect(
      warnLines().filter((line) => line.includes("bogus-mint-policy")),
    ).toHaveLength(1);
  });

  it("strict refuses a v1 row with decrypt_failed and never calls Entra", async () => {
    vi.stubEnv("M365_ENVELOPE_STRICT", "1");
    const repo = new FakeTokensRepo(rowFor("A", "v1"));
    const { sent, fetchStub } = entraChain();
    const service = new M365MintService(repo.asRepo(), fetchStub);

    await expect(service.getAccessToken("user-1")).rejects.toMatchObject({
      code: "credential_missing",
    });
    expect(sent).toEqual([]);
    expect(mintAudits().map((a) => a.outcome)).toEqual(["decrypt_failed"]);
  });

  it("strict accepts a v2 row and keeps writing v2", async () => {
    vi.stubEnv("M365_ENVELOPE_STRICT", "1");
    const repo = await mintOnce(rowFor("A", "v2"));
    expect(versionOf(repo.ciphertext())).toBe("v2");
    expect(errorSpy).not.toHaveBeenCalled();
  });
});

// -------------------------------------------------------------- audit line

describe("mint audit line", () => {
  it("carries the stored row's envelope version and the rotation outcome", async () => {
    const repo = new FakeTokensRepo(rowFor("A", "v2"));
    const { fetchStub } = entraChain();
    const service = new M365MintService(repo.asRepo(), fetchStub);
    await service.getAccessToken("user-1");

    const [line] = mintAudits();
    expect(line.outcome).toBe("minted");
    expect(line.envelope).toBe("v2");
    expect(line.rotation).toBe("applied");
    expect(JSON.stringify(line)).not.toContain("A>");
  });

  it("reports rotation none when Entra issued no new refresh token", async () => {
    const repo = new FakeTokensRepo(rowFor("A"));
    const fetchStub = vi.fn(async () =>
      tokenResponse({ access_token: "at-only", expires_in: 3600 }),
    ) as unknown as typeof fetch;
    const service = new M365MintService(repo.asRepo(), fetchStub);
    await service.getAccessToken("user-1");
    expect(mintAudits()[0].rotation).toBe("none");
    expect(mintAudits()[0].envelope).toBe("v1");
  });
});
