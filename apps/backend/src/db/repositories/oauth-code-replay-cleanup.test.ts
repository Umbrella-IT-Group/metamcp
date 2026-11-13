import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { deleteMock } = vi.hoisted(() => ({ deleteMock: vi.fn() }));
vi.mock("../index", () => ({ db: { delete: deleteMock } }));

const { oauthRepository } = await import("./oauth.repo");
const {
  oauthAccessTokensTable,
  oauthAuthorizationCodesTable,
  oauthRotatedRefreshTokensTable,
  oauthSpentAuthorizationCodesTable,
} = await import("../schema");

beforeEach(() => {
  vi.stubEnv("OAUTH_CODE_REPLAY", undefined);
  deleteMock.mockReset().mockImplementation(() => ({
    where: vi.fn().mockResolvedValue(undefined),
  }));
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("spent-code cleanup and the rollback switch", () => {
  it.each(["off", " OFF "])(
    "%j does not access a missing spent-code table",
    async (mode) => {
      vi.stubEnv("OAUTH_CODE_REPLAY", mode);
      deleteMock.mockImplementation((table) => {
        if (table === oauthSpentAuthorizationCodesTable) {
          throw new Error(
            'relation "oauth_spent_authorization_codes" does not exist',
          );
        }
        return { where: vi.fn().mockResolvedValue(undefined) };
      });

      await expect(oauthRepository.cleanupExpired()).resolves.toBeUndefined();

      // Full rollback also covers the periodic cleanup job. The existing live
      // code/token and rotated-token sweeps must still run without the new table.
      for (const table of [
        oauthAccessTokensTable,
        oauthAuthorizationCodesTable,
        oauthRotatedRefreshTokensTable,
      ]) {
        expect(deleteMock).toHaveBeenCalledWith(table);
      }
      expect(deleteMock).not.toHaveBeenCalledWith(
        oauthSpentAuthorizationCodesTable,
      );
    },
  );

  it.each([undefined, "log", "revoke", "revke"])(
    "%j still reaps expired spent-code rows",
    async (mode) => {
      vi.stubEnv("OAUTH_CODE_REPLAY", mode);

      await oauthRepository.cleanupExpired();

      expect(deleteMock).toHaveBeenCalledWith(
        oauthSpentAuthorizationCodesTable,
      );
    },
  );
});
