/**
 * Boot-time converge that encrypts any legacy plaintext `mcp_servers.bearer_token`
 * once, then arms the read path's fail-closed rule.
 *
 * The arming is the load-bearing assertion: the read path only treats an
 * untagged value as a fault AFTER the converge has confirmed every legacy row
 * is encrypted. So the flag must be set on a clean pass (including the zero-row
 * common case) and must stay UNSET whenever a plaintext row could still exist,
 * no KEK to encrypt with, or a row that failed to convert, because arming it
 * then would refuse a credential the read path would otherwise still honour.
 */
import { randomBytes } from "node:crypto";

import { beforeEach, describe, expect, it, vi } from "vitest";

const loggerMock = vi.hoisted(() => ({
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

const mcpServersRepositoryMock = vi.hoisted(() => ({
  findServersWithPlaintextBearerToken: vi.fn(),
  writeBearerTokenCiphertext: vi.fn(),
}));

vi.mock("../../db/repositories", () => ({
  mcpServersRepository: mcpServersRepositoryMock,
}));

import { convergeServerBearerTokens } from "./server-bearer-converge";
import {
  __resetServerBearerConvergeForTests,
  isEncryptedBearerToken,
  isServerBearerConvergeComplete,
  resolveServerBearerToken,
} from "./server-bearer-crypto";

const VALID_KEK = randomBytes(32).toString("base64");

beforeEach(() => {
  vi.clearAllMocks();
  __resetServerBearerConvergeForTests();
  process.env.M365_TOKEN_KEK = VALID_KEK;
  delete process.env.M365_KEK_ID;
  mcpServersRepositoryMock.writeBearerTokenCiphertext.mockResolvedValue(
    undefined,
  );
});

describe("convergeServerBearerTokens", () => {
  it("arms the fail-closed rule with no writes when there is nothing legacy", async () => {
    mcpServersRepositoryMock.findServersWithPlaintextBearerToken.mockResolvedValue(
      [],
    );

    await convergeServerBearerTokens();

    expect(
      mcpServersRepositoryMock.writeBearerTokenCiphertext,
    ).not.toHaveBeenCalled();
    expect(isServerBearerConvergeComplete()).toBe(true);
  });

  it("encrypts each legacy row and arms the fail-closed rule", async () => {
    mcpServersRepositoryMock.findServersWithPlaintextBearerToken.mockResolvedValue(
      [
        { uuid: "srv-1", bearerToken: "mcp_legacy_one" },
        { uuid: "srv-2", bearerToken: "mcp_legacy_two" },
      ],
    );

    await convergeServerBearerTokens();

    expect(
      mcpServersRepositoryMock.writeBearerTokenCiphertext,
    ).toHaveBeenCalledTimes(2);

    for (const call of mcpServersRepositoryMock.writeBearerTokenCiphertext.mock
      .calls) {
      const [, ciphertext] = call;
      expect(isEncryptedBearerToken(ciphertext)).toBe(true);
    }
    // The stored ciphertext decrypts back to the original plaintext, per uuid.
    const byUuid = Object.fromEntries(
      mcpServersRepositoryMock.writeBearerTokenCiphertext.mock.calls,
    );
    expect(resolveServerBearerToken(byUuid["srv-1"])).toBe("mcp_legacy_one");
    expect(resolveServerBearerToken(byUuid["srv-2"])).toBe("mcp_legacy_two");

    expect(isServerBearerConvergeComplete()).toBe(true);
  });

  it("leaves legacy rows untouched and DOES NOT arm the rule with no KEK", async () => {
    // Without a KEK the converge cannot encrypt. It must not rewrite anything
    // and must not arm the fail-closed rule, so the read path keeps honouring
    // the still-plaintext rows and the converge retries next boot.
    delete process.env.M365_TOKEN_KEK;
    mcpServersRepositoryMock.findServersWithPlaintextBearerToken.mockResolvedValue(
      [{ uuid: "srv-1", bearerToken: "mcp_legacy_one" }],
    );

    await convergeServerBearerTokens();

    expect(
      mcpServersRepositoryMock.writeBearerTokenCiphertext,
    ).not.toHaveBeenCalled();
    expect(isServerBearerConvergeComplete()).toBe(false);
    expect(loggerMock.error).toHaveBeenCalled();
  });

  it("does not arm the rule when a row fails to convert", async () => {
    // One row that will not persist means a plaintext row can still exist, so
    // arming the fail-closed rule would refuse a credential the read path would
    // otherwise honour. Leave it unarmed until every row converts.
    mcpServersRepositoryMock.findServersWithPlaintextBearerToken.mockResolvedValue(
      [
        { uuid: "srv-1", bearerToken: "mcp_legacy_one" },
        { uuid: "srv-2", bearerToken: "mcp_legacy_two" },
      ],
    );
    mcpServersRepositoryMock.writeBearerTokenCiphertext
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error("write failed"));

    await convergeServerBearerTokens();

    expect(isServerBearerConvergeComplete()).toBe(false);
    expect(loggerMock.error).toHaveBeenCalled();
  });
});
