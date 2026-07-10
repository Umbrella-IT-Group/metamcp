import { randomBytes } from "node:crypto";

import { afterEach, beforeEach, describe, expect, it, Mock, vi } from "vitest";

// The mint service's default repo import pulls in the drizzle client,
// which hard-requires DATABASE_URL at module load. Tests inject their
// own repo stub, so mock the db module away (same pattern as
// `db/repositories/mcp-sessions.repo.test.ts`).
vi.mock("../../db/index", () => ({ db: {} }));

import type {
  M365TokensRepository,
  M365UserTokenRow,
} from "../../db/repositories/m365-tokens.repo";
import { encryptRefreshToken } from "./crypto";
import { M365BrokerError } from "./errors";
import { M365MintService } from "./mint-service";

const KEK = randomBytes(32);
const KEK_B64 = KEK.toString("base64");

function activeRow(
  overrides: Partial<M365UserTokenRow> = {},
): M365UserTokenRow {
  return {
    uuid: "row-uuid",
    user_id: "user-1",
    entra_oid: "oid-1",
    tenant_id: "tid-1",
    entra_upn: "alex@umbrellaitgroup.com",
    rt_ciphertext: encryptRefreshToken("stored-rt", KEK, "k1"),
    kek_id: "k1",
    scopes_granted: "User.Read Mail.ReadWrite",
    status: "active",
    created_at: new Date(),
    rotated_at: null,
    last_used_at: null,
    ...overrides,
  };
}

type RepoStub = M365TokensRepository & {
  findByUserId: Mock<(userId: string) => Promise<M365UserTokenRow | undefined>>;
  rotateRefreshToken: Mock<
    (userId: string, rt: string, kekId: string) => Promise<boolean>
  >;
  markReauthRequired: Mock<(userId: string) => Promise<void>>;
};

function makeRepo(row: M365UserTokenRow | undefined): RepoStub {
  return {
    findByUserId: vi.fn(async () => row),
    rotateRefreshToken: vi.fn(async () => true),
    markReauthRequired: vi.fn(async () => undefined),
    touchLastUsed: vi.fn(async () => undefined),
    deleteByUserId: vi.fn(async () => true),
    upsertEnrollment: vi.fn(),
  } as unknown as RepoStub;
}

function tokenResponse(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function goodMintBody(overrides: Record<string, unknown> = {}) {
  return {
    access_token: "fresh-graph-at",
    refresh_token: "rotated-rt",
    expires_in: 3600,
    scope: "User.Read Mail.ReadWrite",
    ...overrides,
  };
}

describe("M365MintService", () => {
  beforeEach(() => {
    vi.stubEnv("M365_TENANT_ID", "tid-1");
    vi.stubEnv("M365_CLIENT_ID", "cid-1");
    vi.stubEnv("M365_CLIENT_SECRET", "secret-1");
    vi.stubEnv("M365_TOKEN_KEK", KEK_B64);
    vi.stubEnv("APP_URL", "https://mcp.example.com");
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it("throws not_configured when broker env is absent", async () => {
    vi.stubEnv("M365_CLIENT_SECRET", "");
    const service = new M365MintService(makeRepo(activeRow()), vi.fn());
    await expect(service.getAccessToken("user-1")).rejects.toMatchObject({
      name: "M365BrokerError",
      code: "not_configured",
    });
  });

  it("throws credential_missing (with enroll URL) when no row exists", async () => {
    const service = new M365MintService(makeRepo(undefined), vi.fn());
    await expect(service.getAccessToken("user-1")).rejects.toMatchObject({
      code: "credential_missing",
      enrollUrl: "https://mcp.example.com/m365/enroll",
    });
  });

  it("treats a reauth_required row as credential_missing", async () => {
    const repo = makeRepo(activeRow({ status: "reauth_required" }));
    const service = new M365MintService(repo, vi.fn());
    await expect(service.getAccessToken("user-1")).rejects.toMatchObject({
      code: "credential_missing",
    });
  });

  it("mints via the refresh grant, sends the stored RT, and rotates-and-persists", async () => {
    const repo = makeRepo(activeRow());
    const fetchStub = vi.fn(async (_url: string | URL, init?: RequestInit) => {
      const params = new URLSearchParams(String(init?.body));
      expect(params.get("grant_type")).toBe("refresh_token");
      expect(params.get("refresh_token")).toBe("stored-rt");
      expect(params.get("client_id")).toBe("cid-1");
      return tokenResponse(goodMintBody());
    });
    const service = new M365MintService(repo, fetchStub as typeof fetch);

    const token = await service.getAccessToken("user-1");

    expect(token).toBe("fresh-graph-at");
    expect(fetchStub).toHaveBeenCalledTimes(1);
    expect(String(fetchStub.mock.calls[0][0])).toContain(
      "login.microsoftonline.com/tid-1",
    );
    // Rotated RT persisted encrypted — never plaintext.
    expect(repo.rotateRefreshToken).toHaveBeenCalledTimes(1);
    const persistedEnvelope = repo.rotateRefreshToken.mock.calls[0][1];
    expect(persistedEnvelope).not.toContain("rotated-rt");
    expect(persistedEnvelope.startsWith("v1.")).toBe(true);
  });

  it("serves the cached AT within the expiry buffer without re-minting", async () => {
    const repo = makeRepo(activeRow());
    const fetchStub = vi.fn(async () => tokenResponse(goodMintBody()));
    const service = new M365MintService(repo, fetchStub as typeof fetch);

    await service.getAccessToken("user-1");
    await service.getAccessToken("user-1");
    await service.getAccessToken("user-1");

    expect(fetchStub).toHaveBeenCalledTimes(1);
  });

  it("re-mints when the cached AT is inside the 60s expiry buffer", async () => {
    const repo = makeRepo(activeRow());
    const fetchStub = vi.fn(async () =>
      tokenResponse(goodMintBody({ expires_in: 30 })),
    );
    const service = new M365MintService(repo, fetchStub as typeof fetch);

    await service.getAccessToken("user-1");
    await service.getAccessToken("user-1");

    expect(fetchStub).toHaveBeenCalledTimes(2);
  });

  it("single-flights concurrent mints for one user", async () => {
    const repo = makeRepo(activeRow());
    let release!: (r: Response) => void;
    const gate = new Promise<Response>((resolve) => {
      release = resolve;
    });
    const fetchStub = vi.fn(() => gate);
    const service = new M365MintService(
      repo,
      fetchStub as unknown as typeof fetch,
    );

    const [a, b] = [
      service.getAccessToken("user-1"),
      service.getAccessToken("user-1"),
    ];
    release(tokenResponse(goodMintBody()));
    expect(await a).toBe("fresh-graph-at");
    expect(await b).toBe("fresh-graph-at");
    // One refresh redemption despite two callers — RT rotation safety.
    expect(fetchStub).toHaveBeenCalledTimes(1);
  });

  it("holds the rotated RT in memory when persist fails and retries it next mint", async () => {
    const repo = makeRepo(activeRow());
    repo.rotateRefreshToken
      .mockRejectedValueOnce(new Error("pg down"))
      .mockRejectedValueOnce(new Error("pg down"))
      .mockResolvedValue(true);
    const sentRefreshTokens: string[] = [];
    const fetchStub = vi.fn(async (_url: string | URL, init?: RequestInit) => {
      sentRefreshTokens.push(
        new URLSearchParams(String(init?.body)).get("refresh_token") ?? "",
      );
      return tokenResponse(
        goodMintBody({
          refresh_token: `rotated-rt-${sentRefreshTokens.length}`,
          expires_in: 30, // force a fresh mint on the next call
        }),
      );
    });
    const service = new M365MintService(repo, fetchStub as typeof fetch);

    // Mint 1: succeeds, but both persist attempts fail → rotation held.
    await service.getAccessToken("user-1");
    // Mint 2: must redeem the HELD rotation, not the stale stored RT.
    await service.getAccessToken("user-1");

    expect(sentRefreshTokens).toEqual(["stored-rt", "rotated-rt-1"]);
    // Third persist call (attempt for mint 2) succeeded.
    expect(repo.rotateRefreshToken).toHaveBeenCalledTimes(3);
  });

  it("maps invalid_grant to credential_expired and marks reauth_required", async () => {
    const repo = makeRepo(activeRow());
    const fetchStub = vi.fn(async () =>
      tokenResponse(
        {
          error: "invalid_grant",
          error_description: "AADSTS700082: expired",
          error_codes: [700082],
        },
        400,
      ),
    );
    const service = new M365MintService(repo, fetchStub as typeof fetch);

    await expect(service.getAccessToken("user-1")).rejects.toMatchObject({
      code: "credential_expired",
      enrollUrl: "https://mcp.example.com/m365/enroll",
    });
    expect(repo.markReauthRequired).toHaveBeenCalledWith("user-1");
  });

  it("maps Conditional Access / MFA error codes to mfa_required", async () => {
    const repo = makeRepo(activeRow());
    const fetchStub = vi.fn(async () =>
      tokenResponse(
        {
          error: "invalid_grant",
          error_description: "AADSTS50076: MFA required",
          error_codes: [50076],
        },
        400,
      ),
    );
    const service = new M365MintService(repo, fetchStub as typeof fetch);
    await expect(service.getAccessToken("user-1")).rejects.toMatchObject({
      code: "mfa_required",
    });
  });

  it("maps revocation error codes to credential_revoked", async () => {
    const repo = makeRepo(activeRow());
    const fetchStub = vi.fn(async () =>
      tokenResponse(
        {
          error: "invalid_grant",
          error_description: "AADSTS50173: token revoked",
          error_codes: [50173],
        },
        400,
      ),
    );
    const service = new M365MintService(repo, fetchStub as typeof fetch);
    await expect(service.getAccessToken("user-1")).rejects.toMatchObject({
      code: "credential_revoked",
    });
  });

  it("treats Entra 5xx as transient mint_failed without burning the grant", async () => {
    const repo = makeRepo(activeRow());
    const fetchStub = vi.fn(async () =>
      tokenResponse({ error: "temporarily_unavailable" }, 503),
    );
    const service = new M365MintService(repo, fetchStub as typeof fetch);

    await expect(service.getAccessToken("user-1")).rejects.toMatchObject({
      code: "mint_failed",
    });
    expect(repo.markReauthRequired).not.toHaveBeenCalled();
  });

  it("treats network failure as mint_failed", async () => {
    const repo = makeRepo(activeRow());
    const fetchStub = vi.fn(async () => {
      throw new Error("ECONNREFUSED");
    });
    const service = new M365MintService(repo, fetchStub as typeof fetch);
    await expect(service.getAccessToken("user-1")).rejects.toMatchObject({
      code: "mint_failed",
    });
  });

  it("invalidateUser drops the cached AT", async () => {
    const repo = makeRepo(activeRow());
    const fetchStub = vi.fn(async () => tokenResponse(goodMintBody()));
    const service = new M365MintService(repo, fetchStub as typeof fetch);

    await service.getAccessToken("user-1");
    service.invalidateUser("user-1");
    await service.getAccessToken("user-1");

    expect(fetchStub).toHaveBeenCalledTimes(2);
  });

  it("mint failures are M365BrokerError instances end to end", async () => {
    const service = new M365MintService(makeRepo(undefined), vi.fn());
    try {
      await service.getAccessToken("user-1");
      expect.unreachable("should have thrown");
    } catch (error) {
      expect(error).toBeInstanceOf(M365BrokerError);
    }
  });
});
