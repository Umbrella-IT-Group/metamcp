/**
 * Classification of a backend's HTTP 401/403 by the SDK transports' own error
 * shapes. The errors here come from the real SDK transport classes driven with
 * a fake `fetch` that returns a real `Response`, so a change in the SDK's
 * message or code shape fails this file instead of silently breaking the match.
 *
 * Oracles: the SDK sources (client/streamableHttp.js: StreamableHTTPError and
 * the POST / stream-open messages; client/sse.js: SseError and the POST
 * message), RFC 9110 sections 15.5.2 (401) and 15.5.4 (403), and the MCP
 * authorization spec page (a 401 is the server asking for credentials).
 */
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";

import {
  classifyBackendAuthRejection,
  describeBackendAuthRejection,
} from "./backend-auth-rejection";

const ORIGIN = "https://backend.test/mcp";
const INIT = {
  jsonrpc: "2.0" as const,
  id: 1,
  method: "initialize",
  params: {},
};

async function postError(status: number, body: string): Promise<Error> {
  const transport = new StreamableHTTPClientTransport(new URL(ORIGIN), {
    fetch: async () => new Response(body, { status }),
  });
  await transport.start();
  try {
    await transport.send(INIT);
  } catch (error) {
    return error as Error;
  }
  throw new Error("expected the POST to fail");
}

async function streamOpenError(status: number): Promise<Error> {
  // A GET stream open that the backend refuses: the SDK opens it after the
  // initialized notification, so drive the private open directly.
  const transport = new StreamableHTTPClientTransport(new URL(ORIGIN), {
    fetch: async () => new Response("denied", { status }),
  });
  await transport.start();
  try {
    await (
      transport as unknown as { _startOrAuthSse: (o: object) => Promise<void> }
    )._startOrAuthSse({});
  } catch (error) {
    return error as Error;
  }
  throw new Error("expected the stream open to fail");
}

async function sseOpenError(status: number): Promise<Error> {
  const transport = new SSEClientTransport(new URL(ORIGIN), {
    fetch: async () => new Response("denied", { status }),
  });
  try {
    await transport.start();
  } catch (error) {
    return error as Error;
  }
  throw new Error("expected the SSE open to fail");
}

async function ssePostError(status: number, body: string): Promise<Error> {
  const transport = new SSEClientTransport(new URL(ORIGIN), {
    fetch: async () => new Response(body, { status }),
  });
  // Skip the stream: the endpoint event is what send() needs.
  (transport as unknown as { _endpoint: URL })._endpoint = new URL(ORIGIN);
  try {
    await transport.send(INIT);
  } catch (error) {
    return error as Error;
  }
  throw new Error("expected the POST to fail");
}

describe("classifyBackendAuthRejection", () => {
  it.each([401, 403] as const)(
    "names a Streamable HTTP POST refused with %s as a post answer",
    async (status) => {
      expect(
        classifyBackendAuthRejection(await postError(status, "denied")),
      ).toEqual({ status, via: "post" });
    },
  );

  it.each([401, 403] as const)(
    "names a refused Streamable HTTP stream open (%s) as a stream refusal",
    async (status) => {
      expect(
        classifyBackendAuthRejection(await streamOpenError(status)),
      ).toEqual({ status, via: "stream" });
    },
  );

  it.each([401, 403] as const)(
    "names a refused legacy SSE stream open (%s) as a stream refusal",
    async (status) => {
      expect(classifyBackendAuthRejection(await sseOpenError(status))).toEqual({
        status,
        via: "stream",
      });
    },
  );

  it.each([401, 403] as const)(
    "names a legacy SSE POST refused with %s as a post answer",
    async (status) => {
      expect(
        classifyBackendAuthRejection(await ssePostError(status, "denied")),
      ).toEqual({ status, via: "post" });
    },
  );

  it("finds the rejection in a cause chain and survives a cycle", async () => {
    const inner = await postError(403, "denied");
    const wrapper = new Error("transport failed", { cause: inner });
    expect(classifyBackendAuthRejection(wrapper)).toEqual({
      status: 403,
      via: "post",
    });

    const a = new Error("a");
    const b = new Error("b", { cause: a });
    (a as { cause?: unknown }).cause = b;
    expect(classifyBackendAuthRejection(a)).toBeUndefined();
  });

  describe("does not match", () => {
    it("a 502 whose body quotes an HTTP 401 answer", async () => {
      expect(
        classifyBackendAuthRejection(
          await ssePostError(502, "upstream said (HTTP 401): nope"),
        ),
      ).toBeUndefined();
      expect(
        classifyBackendAuthRejection(
          await postError(502, "upstream returned HTTP 401 Unauthorized"),
        ),
      ).toBeUndefined();
    });

    it("a 404, or a non-auth status in the SSE POST shape", async () => {
      expect(
        classifyBackendAuthRejection(await postError(404, "Session not found")),
      ).toBeUndefined();
      expect(
        classifyBackendAuthRejection(await ssePostError(404, "gone")),
      ).toBeUndefined();
    });

    it("an McpError, including the SDK timeout and a forged -32001/401 shape", () => {
      expect(
        classifyBackendAuthRejection(
          McpError.fromError(-32001, "Request timed out", { timeout: 500 }),
        ),
      ).toBeUndefined();
      const forged = new McpError(
        401,
        "Error POSTing to endpoint (HTTP 401): x",
      );
      expect(classifyBackendAuthRejection(forged)).toBeUndefined();
    });

    it("a network failure", () => {
      const refused = new TypeError("fetch failed", {
        cause: Object.assign(new Error("connect ECONNREFUSED 10.0.0.1:3000"), {
          code: "ECONNREFUSED",
        }),
      });
      expect(classifyBackendAuthRejection(refused)).toBeUndefined();
    });

    it("an Error that carries code 401 without the transport's own message prefix", () => {
      const lookalike = Object.assign(new Error("something else entirely"), {
        code: 401,
      });
      expect(classifyBackendAuthRejection(lookalike)).toBeUndefined();
      expect(classifyBackendAuthRejection("HTTP 401")).toBeUndefined();
      expect(classifyBackendAuthRejection(undefined)).toBeUndefined();
    });
  });
});

describe("describeBackendAuthRejection", () => {
  it("names the gateway's credentials at connect, neutrally per request, and carries no body", () => {
    expect(describeBackendAuthRejection(401, "connect")).toBe(
      "the backend rejected the gateway's credentials (HTTP 401)",
    );
    expect(describeBackendAuthRejection(403, "connect")).toBe(
      "the backend refused the gateway's access (HTTP 403)",
    );
    expect(describeBackendAuthRejection(401, "request")).toBe(
      "the backend answered the request with HTTP 401",
    );
    expect(describeBackendAuthRejection(403, "request")).not.toContain(
      "credentials",
    );
  });
});
