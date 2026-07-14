import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { describe, expect, it } from "vitest";

import { buildM365BrokerErrorResult } from "./broker-error-result";
import { M365BrokerError } from "./errors";
import {
  getM365UserContext,
  recordConnectBrokerFailure,
  runWithM365UserContext,
  takeConnectBrokerFailure,
} from "./request-context";

const ENROLL = "https://mcp.example.com/m365/enroll";

function serverStub(): Server {
  return {
    getClientCapabilities: () => ({}),
    request: async () => ({}),
  } as unknown as Server;
}

describe("cold-connect broker-failure latch", () => {
  it("latches and drains within a request context", () => {
    runWithM365UserContext({ userId: "ray" }, () => {
      expect(takeConnectBrokerFailure()).toBeUndefined();

      const error = new M365BrokerError(
        "credential_missing",
        "Not connected.",
        ENROLL,
      );
      recordConnectBrokerFailure({ serverName: "m365", error });

      // Visible on the shared context object mid-request.
      expect(getM365UserContext()?.connectBroker?.serverName).toBe("m365");

      const drained = takeConnectBrokerFailure();
      expect(drained?.serverName).toBe("m365");
      expect(drained?.error).toBe(error);

      // Drain clears it — a second take returns nothing.
      expect(takeConnectBrokerFailure()).toBeUndefined();
    });
  });

  it("fails open (no-op) when there is no request context", () => {
    // API-key consumer / idle warmup: no ALS store. record must not throw,
    // and take returns undefined.
    expect(() =>
      recordConnectBrokerFailure({
        serverName: "m365",
        error: new M365BrokerError("credential_missing", "x", ENROLL),
      }),
    ).not.toThrow();
    expect(takeConnectBrokerFailure()).toBeUndefined();
  });

  it("does not leak across separate request contexts", () => {
    runWithM365UserContext({ userId: "a" }, () => {
      recordConnectBrokerFailure({
        serverName: "m365",
        error: new M365BrokerError("credential_missing", "x", ENROLL),
      });
    });
    // A fresh context (fresh object) starts clean.
    runWithM365UserContext({ userId: "b" }, () => {
      expect(takeConnectBrokerFailure()).toBeUndefined();
    });
  });

  it("the drained failure builds the same enrollment result as the warm path", () => {
    // End-to-end at the unit level: an unlinked user's cold connect latches
    // the broker error; draining it and building the consumer surface yields
    // a structured isError result carrying the enroll URL — identical to what
    // the warm tools/call path returns.
    const result = runWithM365UserContext({ userId: "ray" }, () => {
      recordConnectBrokerFailure({
        serverName: "m365",
        error: new M365BrokerError(
          "credential_missing",
          "No stored M365 grant for this user.",
          ENROLL,
        ),
      });
      const failure = takeConnectBrokerFailure();
      if (!failure) {
        throw new Error("expected a latched broker failure");
      }
      return buildM365BrokerErrorResult(failure.error, serverStub());
    });

    expect(result.isError).toBe(true);
    const payload = JSON.parse((result.content?.[0] as { text: string }).text);
    expect(payload.error).toBe("credential_missing");
    expect(payload.enroll_url).toBe(ENROLL);
    expect(payload.action).toContain("enrollment URL");
  });
});
