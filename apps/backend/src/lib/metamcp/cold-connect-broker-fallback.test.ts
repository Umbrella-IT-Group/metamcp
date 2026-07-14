/**
 * Direct tests for the `tools/call` catch's drain + ownership-gate glue
 * (Track A5 review follow-up). Every piece this function composes
 * (`takeConnectBrokerFailure`, `parseToolName`, `sanitizeName`,
 * `buildM365BrokerErrorResult`) already has its own unit coverage, but the
 * WIRING between them — the actual code path `metamcp-proxy.ts`'s
 * `CallToolRequestSchema` handler calls on a cold-connect failure — had
 * none. This exercises `resolveColdConnectBrokerFallback` itself, which is
 * the exact function the handler calls, kept in its own module precisely
 * so it's reachable without standing up `createServer`'s full DB-backed
 * dependency graph.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { describe, expect, it, vi } from "vitest";

// `./cold-connect-broker-fallback` pulls in `./utils` for `sanitizeName`,
// and that module also imports `oauthSessionsRepository` (unrelated to
// `sanitizeName` — a shared-module artifact) which throws at import time
// without a live DATABASE_URL. Same workaround `client-connect.test.ts`
// uses to keep this a pure unit test.
vi.mock("../../db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: {},
}));

import { M365BrokerError } from "../m365/errors";
import {
  recordConnectBrokerFailure,
  runWithM365UserContext,
  takeConnectBrokerFailure,
} from "../m365/request-context";
import { resolveColdConnectBrokerFallback } from "./cold-connect-broker-fallback";

const ENROLL = "https://mcp.example.com/m365/enroll";

function serverStub(): Server {
  return {
    getClientCapabilities: () => ({}),
    request: async () => ({}),
  } as unknown as Server;
}

describe("resolveColdConnectBrokerFallback", () => {
  it("returns the enrollment result for a matching-prefix tool call", () => {
    runWithM365UserContext({ userId: "ray" }, () => {
      recordConnectBrokerFailure({
        serverName: "m365",
        error: new M365BrokerError(
          "credential_missing",
          "No stored M365 grant for this user.",
          ENROLL,
        ),
      });

      const result = resolveColdConnectBrokerFallback(
        "m365__list_mail",
        serverStub(),
      );

      expect(result).toBeDefined();
      expect(result?.isError).toBe(true);
      const payload = JSON.parse(
        (result?.content?.[0] as { text: string }).text,
      );
      expect(payload.error).toBe("credential_missing");
      expect(payload.enroll_url).toBe(ENROLL);
    });
  });

  it("re-throws (returns undefined) for a non-matching prefix AND still drains the latch", () => {
    runWithM365UserContext({ userId: "ray" }, () => {
      recordConnectBrokerFailure({
        serverName: "m365",
        error: new M365BrokerError(
          "credential_missing",
          "No stored M365 grant for this user.",
          ENROLL,
        ),
      });

      // A different tool's server prefix — the latched m365 failure must
      // not hijack this unrelated tool's real error.
      const result = resolveColdConnectBrokerFallback(
        "Autotask__create_ticket",
        serverStub(),
      );
      expect(result).toBeUndefined();

      // Drained despite the non-match — doesn't linger for a later call
      // within the same request context.
      expect(takeConnectBrokerFailure()).toBeUndefined();
    });
  });

  it("drains once — a second call in the same context sees nothing latched", () => {
    runWithM365UserContext({ userId: "ray" }, () => {
      recordConnectBrokerFailure({
        serverName: "m365",
        error: new M365BrokerError(
          "credential_missing",
          "No stored M365 grant for this user.",
          ENROLL,
        ),
      });

      const first = resolveColdConnectBrokerFallback(
        "m365__list_mail",
        serverStub(),
      );
      expect(first).toBeDefined();

      const second = resolveColdConnectBrokerFallback(
        "m365__list_mail",
        serverStub(),
      );
      expect(second).toBeUndefined();
    });
  });

  it("returns undefined when nothing is latched", () => {
    runWithM365UserContext({ userId: "ray" }, () => {
      expect(
        resolveColdConnectBrokerFallback("m365__list_mail", serverStub()),
      ).toBeUndefined();
    });
  });

  it("returns undefined outside any request context (fail-open, matches recordConnectBrokerFailure's no-op)", () => {
    // No runWithM365UserContext wrapper — mirrors an API-key consumer /
    // idle warmup, which never has a latch to drain.
    expect(
      resolveColdConnectBrokerFallback("m365__list_mail", serverStub()),
    ).toBeUndefined();
  });
});
