import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { describe, expect, it, vi } from "vitest";

import { buildM365BrokerErrorResult } from "./broker-error-result";
import { M365BrokerError } from "./errors";

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
