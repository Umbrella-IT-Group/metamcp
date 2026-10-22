import { createHash } from "node:crypto";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { afterEach, describe, expect, it, vi } from "vitest";

import logger from "@/utils/logger";

import { buildM365BrokerErrorResult } from "./broker-error-result";
import { M365BrokerError } from "./errors";
import { runWithM365UserContext } from "./request-context";

const ENROLL = "https://mcp.example.com/m365/enroll";

function makeServerStub(options: {
  elicitation?: boolean;
  requestImpl?: () => Promise<unknown>;
}) {
  const request = vi.fn<(req: unknown, schema: unknown) => Promise<unknown>>(
    options.requestImpl ?? (async () => ({})),
  );
  return {
    server: {
      getClientCapabilities: () =>
        options.elicitation ? { elicitation: {} } : {},
      request,
    } as unknown as Server,
    request,
  };
}

describe("buildM365BrokerErrorResult", () => {
  it("returns a structured isError result carrying code + enroll URL", () => {
    const { server } = makeServerStub({ elicitation: false });
    const result = buildM365BrokerErrorResult(
      new M365BrokerError("credential_missing", "Not connected.", ENROLL),
      server,
    );

    expect(result.isError).toBe(true);
    const payload = JSON.parse((result.content?.[0] as { text: string }).text);
    expect(payload.error).toBe("credential_missing");
    expect(payload.enroll_url).toBe(ENROLL);
    expect(payload.action).toContain("enrollment URL");
  });

  it("fires a URL-mode elicitation when the client declares the capability", () => {
    const { server, request } = makeServerStub({ elicitation: true });
    buildM365BrokerErrorResult(
      new M365BrokerError("credential_expired", "Expired.", ENROLL),
      server,
    );

    expect(request).toHaveBeenCalledTimes(1);
    const sent = request.mock.calls[0]?.[0] as unknown as {
      method: string;
      params: { mode: string; url: string };
    };
    expect(sent.method).toBe("elicitation/create");
    expect(sent.params.mode).toBe("url");
    expect(sent.params.url).toBe(ENROLL);
  });

  it("skips elicitation when the client lacks the capability", () => {
    const { server, request } = makeServerStub({ elicitation: false });
    buildM365BrokerErrorResult(
      new M365BrokerError("credential_missing", "Not connected.", ENROLL),
      server,
    );
    expect(request).not.toHaveBeenCalled();
  });

  it("skips elicitation for non-reauth codes (no enroll URL)", () => {
    const { server, request } = makeServerStub({ elicitation: true });
    const result = buildM365BrokerErrorResult(
      new M365BrokerError("mint_failed", "Transient failure."),
      server,
    );
    expect(request).not.toHaveBeenCalled();
    const payload = JSON.parse((result.content?.[0] as { text: string }).text);
    expect(payload.enroll_url).toBeUndefined();
  });

  it("survives a rejecting elicitation (fallback text path unaffected)", async () => {
    const { server } = makeServerStub({
      elicitation: true,
      requestImpl: async () => {
        throw new Error("client rejected elicitation/create");
      },
    });
    const result = buildM365BrokerErrorResult(
      new M365BrokerError("mfa_required", "MFA required.", ENROLL),
      server,
    );
    expect(result.isError).toBe(true);
    // Give the rejected promise a tick to prove nothing unhandled leaks.
    await new Promise((resolve) => setImmediate(resolve));
  });
});

describe("buildM365BrokerErrorResult: the refusal log line", () => {
  // The one INFO signal for "who has not enrolled". It carries a short hash
  // of the user id (the operator can hash a known id to find the user), never
  // the id itself, an email or the enrollment link.
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const refusalLines = (infoSpy: ReturnType<typeof vi.spyOn>): string[] =>
    infoSpy.mock.calls
      .map((call: unknown[]) => String(call[0]))
      .filter((line: string) => line.includes("m365_broker_refusal"));

  it("logs one structured line with a 12-hex user hash, never the raw id, an email or the URL", () => {
    const infoSpy = vi.spyOn(logger, "info").mockImplementation(() => {});
    const { server } = makeServerStub({ elicitation: true });
    const userId = "someone.private@example.com";

    runWithM365UserContext({ userId }, () =>
      buildM365BrokerErrorResult(
        new M365BrokerError("credential_missing", "Not connected.", ENROLL),
        server,
      ),
    );

    const lines = refusalLines(infoSpy);
    expect(lines).toHaveLength(1);
    const logged = JSON.parse(lines[0]);
    expect(logged).toEqual({
      event: "m365_broker_refusal",
      code: "credential_missing",
      user_hash: createHash("sha256").update(userId).digest("hex").slice(0, 12),
      elicitation: true,
    });
    expect(logged.user_hash).toMatch(/^[0-9a-f]{12}$/);
    expect(lines[0]).not.toContain(userId);
    expect(lines[0]).not.toContain("@");
    expect(lines[0]).not.toContain("someone");
    expect(lines[0]).not.toContain(ENROLL);
    expect(lines[0]).not.toContain("http");
  });

  it("hashes an opaque id the same way, so the same user always logs the same hash", () => {
    const infoSpy = vi.spyOn(logger, "info").mockImplementation(() => {});
    const { server } = makeServerStub({ elicitation: false });
    for (let i = 0; i < 2; i++) {
      runWithM365UserContext({ userId: "opaque-user-id-0001" }, () =>
        buildM365BrokerErrorResult(
          new M365BrokerError("credential_expired", "Expired.", ENROLL),
          server,
        ),
      );
    }
    const hashes = refusalLines(infoSpy).map((l) => JSON.parse(l).user_hash);
    expect(hashes).toEqual([
      createHash("sha256")
        .update("opaque-user-id-0001")
        .digest("hex")
        .slice(0, 12),
      createHash("sha256")
        .update("opaque-user-id-0001")
        .digest("hex")
        .slice(0, 12),
    ]);
  });

  it("says none when there is no user context, and elicitation false when none was sent", () => {
    const infoSpy = vi.spyOn(logger, "info").mockImplementation(() => {});
    const { server, request } = makeServerStub({ elicitation: false });

    buildM365BrokerErrorResult(
      new M365BrokerError("credential_missing", "Not connected.", ENROLL),
      server,
    );

    expect(request).not.toHaveBeenCalled();
    const lines = refusalLines(infoSpy);
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0])).toMatchObject({
      user_hash: "none",
      elicitation: false,
    });
  });

  it("logs elicitation false for a code that has no enrollment URL, even when the client could elicit", () => {
    const infoSpy = vi.spyOn(logger, "info").mockImplementation(() => {});
    const { server, request } = makeServerStub({ elicitation: true });

    buildM365BrokerErrorResult(
      new M365BrokerError("not_configured", "Broker not configured."),
      server,
    );

    expect(request).not.toHaveBeenCalled();
    expect(JSON.parse(refusalLines(infoSpy)[0])).toMatchObject({
      code: "not_configured",
      elicitation: false,
    });
  });

  it("still logs the line when the elicitation cannot be dispatched", () => {
    const infoSpy = vi.spyOn(logger, "info").mockImplementation(() => {});
    vi.spyOn(logger, "debug").mockImplementation(() => {});
    const server = {
      getClientCapabilities: () => {
        throw new Error("no client capabilities yet");
      },
      request: vi.fn(),
    } as unknown as Server;

    const result = buildM365BrokerErrorResult(
      new M365BrokerError("credential_missing", "Not connected.", ENROLL),
      server,
    );

    expect(result.isError).toBe(true);
    expect(JSON.parse(refusalLines(infoSpy)[0])).toMatchObject({
      elicitation: false,
    });
  });
});
