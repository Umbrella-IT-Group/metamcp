import { describe, expect, it } from "vitest";

import {
  BACKEND_UNAVAILABLE,
  BackendUnavailableError,
  isBackendUnavailableError,
} from "./backend-unavailable";
import { isUnknownToolError, looksLikeUnknownTool } from "./unknown-tool";

describe("BackendUnavailableError", () => {
  const error = new BackendUnavailableError(
    "gamma__run_report",
    "gamma",
    "no_session",
  );

  it("says the server was unavailable and the tool did not run", () => {
    expect(error.message).toBe(
      'Backend "gamma" is unavailable (no_session): tool "gamma__run_report" was not run. Retry the call.',
    );
    expect(error.name).toBe("BackendUnavailableError");
  });

  it("carries a machine-readable code and data for the JSON-RPC answer", () => {
    expect(error.code).toBe(BACKEND_UNAVAILABLE);
    expect(error.data).toEqual({
      code: "backend_unavailable",
      server: "gamma",
      tool: "gamma__run_report",
      reason: "no_session",
      executed: false,
      retryable: true,
    });
  });

  it("is never read as an unknown tool, bare or SDK-wrapped", () => {
    expect(isUnknownToolError(error)).toBe(false);
    expect(isUnknownToolError(error, "gamma__run_report")).toBe(false);
    expect(looksLikeUnknownTool(error.message)).toBe(false);
    expect(looksLikeUnknownTool(`MCP error -32603: ${error.message}`)).toBe(
      false,
    );
  });

  it("quotes caller-controlled names so a CR/LF cannot forge a log line", () => {
    const forged = new BackendUnavailableError(
      "gamma__x\r\n[fake] line",
      "gamma",
      "error_gated",
    );
    expect(forged.message).not.toMatch(/[\r\n]/);
  });
});

describe("isBackendUnavailableError", () => {
  it("recognises the class and a copy carrying its code", () => {
    expect(
      isBackendUnavailableError(
        new BackendUnavailableError("a__b", "a", "error_gated"),
      ),
    ).toBe(true);
    expect(isBackendUnavailableError({ code: "backend_unavailable" })).toBe(
      true,
    );
  });

  it("rejects everything else, including an unknown tool and an opaque value", () => {
    expect(isBackendUnavailableError(new Error("Unknown tool: a__b"))).toBe(
      false,
    );
    expect(isBackendUnavailableError({ code: -32603 })).toBe(false);
    expect(isBackendUnavailableError(null)).toBe(false);
    expect(isBackendUnavailableError("backend_unavailable")).toBe(false);
    const opaque = Object.defineProperty({}, "code", {
      get() {
        throw new Error("boom");
      },
    });
    expect(isBackendUnavailableError(opaque)).toBe(false);
  });
});
