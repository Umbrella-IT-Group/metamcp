/**
 * How the auditing middleware records two thrown outcomes: a consumer cancel
 * and a backend's HTTP 401/403 answer.
 *
 * Oracles: the audit recorder row contract (`error_code` is a short class or
 * the numeric protocol code, `error_detail` a token, in auditing.functional.ts),
 * the SDK's real `StreamableHTTPError` shape for a refused POST
 * (client/streamableHttp.js), and the dashboards' failure vocabulary (the log
 * panels count any line with error, fatal, panic or exception).
 */
import { StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { CallToolRequest, McpError } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { metamcpLogStore } from "../log-store";
import { ToolCallCancelledError } from "../tool-call-cancelled";
import {
  createAuditingMiddleware,
  setAuditRecorderForTesting,
} from "./auditing.functional";
import { MetaMCPHandlerContext } from "./functional-middleware";

const DASHBOARD_ERROR_WORDS = /\b(error|fatal|panic|exception)\b/i;
const BODY_SECRET = "backend-body-text-that-must-not-be-logged";

const context: MetaMCPHandlerContext = {
  namespaceUuid: "ns-1",
  sessionId: "sess-1",
};
const request = {
  method: "tools/call",
  params: { name: "autotask__search", arguments: { q: "x" } },
} as CallToolRequest;

const flush = () => new Promise((r) => setTimeout(r, 0));

afterEach(() => {
  setAuditRecorderForTesting(null);
  vi.restoreAllMocks();
});

async function run(thrown: unknown) {
  const recorder = vi.fn().mockResolvedValue(undefined);
  setAuditRecorderForTesting(recorder);
  const live = vi
    .spyOn(metamcpLogStore, "record")
    .mockImplementation(() => undefined);
  await expect(
    createAuditingMiddleware()(vi.fn().mockRejectedValue(thrown))(
      request,
      context,
    ),
  ).rejects.toBe(thrown);
  await flush();
  expect(recorder).toHaveBeenCalledTimes(1);
  expect(live).toHaveBeenCalledTimes(1);
  return { row: recorder.mock.calls[0][0], entry: live.mock.calls[0][0] };
}

describe("a cancelled call", () => {
  it("is recorded as failed, cancelled, outcome unknown, logged at warn with no error attached", async () => {
    const { row, entry } = await run(new ToolCallCancelledError());

    expect(row.success).toBe(false);
    expect(row.error_code).toBe("cancelled");
    expect(row.error_detail).toBe("outcome_unknown");
    expect(entry.level).toBe("warn");
    expect(entry.message).toMatch(
      /^search cancelled by the caller; outcome unknown \(\d+ms\)$/,
    );
    expect(entry.message).not.toMatch(DASHBOARD_ERROR_WORDS);
    expect(entry.error).toBeUndefined();
  });

  it("is not claimed by a backend's own McpError that carries the same code", async () => {
    const forged = new McpError(-32800, "Tool call cancelled by the caller");
    const { row, entry } = await run(forged);

    expect(row.error_code).toBe("-32800");
    expect(row.error_detail).toBeUndefined();
    expect(entry.level).toBe("error");
  });

  it("leaves a request timeout exactly as it was (negative control)", async () => {
    const timeout = McpError.fromError(-32001, "Request timed out", {
      timeout: 500,
    });
    const { row, entry } = await run(timeout);

    expect(row.error_code).toBe("-32001");
    expect(row.error_detail).toBeUndefined();
    expect(entry.level).toBe("error");
    expect(entry.error).toBe(timeout);
  });
});

describe("a backend's HTTP 401 or 403 answer to the call", () => {
  it.each([401, 403] as const)(
    "keeps code %s, adds no detail, names the status neutrally, and logs no body",
    async (status) => {
      const refused = new StreamableHTTPError(
        status,
        `Error POSTing to endpoint: ${BODY_SECRET}`,
      );
      const { row, entry } = await run(refused);

      expect(row.error_code).toBe(String(status));
      expect(row.error_detail).toBeUndefined();
      expect(entry.level).toBe("error");
      expect(entry.message).toMatch(
        new RegExp(
          `^search failed: the backend answered the request with HTTP ${status} \\(\\d+ms\\)$`,
        ),
      );
      // A call-time refusal can be about this one caller, so it never claims
      // the gateway's credentials were the problem, and carries no body.
      expect(entry.message).not.toContain("credentials");
      expect(entry.error).toBeUndefined();
      expect(JSON.stringify(entry)).not.toContain(BODY_SECRET);
    },
  );

  it("leaves a 502 exactly as it was, error attached (negative control)", async () => {
    const failed = new StreamableHTTPError(
      502,
      "Error POSTing to endpoint: bad gateway",
    );
    const { row, entry } = await run(failed);

    expect(row.error_code).toBe("502");
    expect(entry.message).toMatch(/^search failed \(\d+ms\)$/);
    expect(entry.error).toBe(failed);
  });
});
