/**
 * RFC 6749 §10.12 state CSRF validation for the OAuth client flow.
 *
 * Our fork exchanges the authorization code CLIENT-side (the MCP SDK's auth()
 * runs in the browser), so there is no backend exchangeToken. The CSRF check
 * therefore lives in `oauth.validateState`, invoked by the callback BEFORE the
 * client-side exchange. These tests pin its behaviour:
 *   - expected_state truthy → must match input.state (missing input.state is a
 *     mismatch, NOT a bypass); on match the nonce is cleared one-shot.
 *   - no session / expected_state null → back-compat accept for in-flight
 *     pre-fix flows; the nonce is NOT cleared (nothing to clear).
 *   - a repo failure fails CLOSED so a validation outage can't silently
 *     complete an unvalidated exchange.
 * They also pin that the upsert handler FORWARDS expected_state to the repo —
 * dropping it there would leave the column NULL and disable the check.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

vi.mock("../db/repositories", () => ({
  oauthSessionsRepository: {
    findByMcpServerUuid: vi.fn(),
    upsert: vi.fn(),
    clearExpectedState: vi.fn(),
  },
}));

const SERVER_UUID = "00000000-0000-0000-0000-0000000000aa";

const loadModule = async () => {
  const repos = await import("../db/repositories");
  const impl = await import("./oauth.impl");
  return {
    oauthImplementations: impl.oauthImplementations,
    findByMcpServerUuid: repos.oauthSessionsRepository
      .findByMcpServerUuid as ReturnType<typeof vi.fn>,
    upsert: repos.oauthSessionsRepository.upsert as ReturnType<typeof vi.fn>,
    clearExpectedState: repos.oauthSessionsRepository
      .clearExpectedState as ReturnType<typeof vi.fn>,
  };
};

describe("oauthImplementations.validateState", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("no session in DB → valid, no clear (back-compat)", async () => {
    const { oauthImplementations, findByMcpServerUuid, clearExpectedState } =
      await loadModule();
    findByMcpServerUuid.mockResolvedValue(undefined);

    const result = await oauthImplementations.validateState({
      mcp_server_uuid: SERVER_UUID,
      state: "anything",
    });

    expect(result).toEqual({ valid: true });
    expect(clearExpectedState).not.toHaveBeenCalled();
  });

  it("expected_state null → valid, no clear (in-flight pre-fix flow)", async () => {
    const { oauthImplementations, findByMcpServerUuid, clearExpectedState } =
      await loadModule();
    findByMcpServerUuid.mockResolvedValue({
      mcp_server_uuid: SERVER_UUID,
      expected_state: null,
    });

    const result = await oauthImplementations.validateState({
      mcp_server_uuid: SERVER_UUID,
      state: "from-upstream",
    });

    expect(result).toEqual({ valid: true });
    expect(clearExpectedState).not.toHaveBeenCalled();
  });

  it("expected_state matches input.state → valid, clears the nonce once", async () => {
    const { oauthImplementations, findByMcpServerUuid, clearExpectedState } =
      await loadModule();
    findByMcpServerUuid.mockResolvedValue({
      mcp_server_uuid: SERVER_UUID,
      expected_state: "the-nonce",
    });
    clearExpectedState.mockResolvedValue({});

    const result = await oauthImplementations.validateState({
      mcp_server_uuid: SERVER_UUID,
      state: "the-nonce",
    });

    expect(result).toEqual({ valid: true });
    expect(clearExpectedState).toHaveBeenCalledWith(SERVER_UUID);
    expect(clearExpectedState).toHaveBeenCalledTimes(1);
  });

  it("expected_state mismatches input.state → invalid_state, no clear", async () => {
    const { oauthImplementations, findByMcpServerUuid, clearExpectedState } =
      await loadModule();
    findByMcpServerUuid.mockResolvedValue({
      mcp_server_uuid: SERVER_UUID,
      expected_state: "the-nonce",
    });

    const result = await oauthImplementations.validateState({
      mcp_server_uuid: SERVER_UUID,
      state: "different-value",
    });

    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error).toBe("invalid_state");
    expect(clearExpectedState).not.toHaveBeenCalled();
  });

  it("expected_state present but input.state missing → invalid_state (no bypass)", async () => {
    const { oauthImplementations, findByMcpServerUuid, clearExpectedState } =
      await loadModule();
    findByMcpServerUuid.mockResolvedValue({
      mcp_server_uuid: SERVER_UUID,
      expected_state: "the-nonce",
    });

    const result = await oauthImplementations.validateState({
      mcp_server_uuid: SERVER_UUID,
      // no state
    });

    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error).toBe("invalid_state");
    expect(clearExpectedState).not.toHaveBeenCalled();
  });

  it("repo failure fails CLOSED (validation_error, not a silent pass)", async () => {
    const { oauthImplementations, findByMcpServerUuid } = await loadModule();
    findByMcpServerUuid.mockRejectedValue(new Error("db down"));

    const result = await oauthImplementations.validateState({
      mcp_server_uuid: SERVER_UUID,
      state: "x",
    });

    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.error).toBe("validation_error");
  });
});

describe("oauthImplementations.upsert forwards expected_state", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // Regression guard: the tRPC upsert handler previously stripped
  // expected_state before calling the repo, leaving the column NULL and
  // silently disabling the CSRF check (validateState then hits the back-compat
  // branch). Pins the forward-through so a spread refactor can't regress it.
  it("passes expected_state through to the repository", async () => {
    const { oauthImplementations, upsert } = await loadModule();
    upsert.mockResolvedValue({
      uuid: "sess",
      mcp_server_uuid: SERVER_UUID,
      client_information: null,
      tokens: null,
      code_verifier: null,
      created_at: new Date(),
      updated_at: new Date(),
    });

    await oauthImplementations.upsert({
      mcp_server_uuid: SERVER_UUID,
      expected_state: "the-csrf-nonce",
    });

    expect(upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        mcp_server_uuid: SERVER_UUID,
        expected_state: "the-csrf-nonce",
      }),
    );
  });
});
