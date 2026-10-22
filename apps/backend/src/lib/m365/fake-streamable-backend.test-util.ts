/**
 * Test support: the pieces needed to drive the REAL m365 per-user injection
 * path without a network. A minimal stateful Streamable-HTTP MCP backend
 * (`makeFakeBackend`) that, like the real m365 backend outside its tool
 * bodies, never looks at the Authorization header; a mint stub for users who
 * are or are not enrolled (`makeMint`); and a `createClient` factory that
 * builds the production transport and client over the injected fetch
 * (`makeCreateClient`). Not a test file: it has no tests and is imported only
 * by tests.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ServerParameters } from "@repo/zod-types";
import { vi } from "vitest";

import type { createMetaMcpClient } from "../metamcp/client";
import { M365BrokerError } from "./errors";
import { makeM365InjectedFetch, USER_ID_HEADER } from "./injected-fetch";
import type { M365MintService } from "./mint-service";

export const ENROLL = "https://mcp.example.com/m365/enroll";
export const BACKEND_URL = "http://backend:3000/mcp";
export const SESSION_ID = "backend-session-1";

export const m365ServerParams = {
  uuid: "srv-m365",
  name: "m365",
  description: "",
  type: "STREAMABLE_HTTP",
  url: BACKEND_URL,
  created_at: new Date().toISOString(),
  status: "active",
} as unknown as ServerParameters;

export interface SeenRequest {
  httpMethod: string;
  rpcMethod?: string;
  authorization: string | null;
  userId: string | null;
}

/**
 * A minimal stateful Streamable-HTTP MCP backend. It never looks at the
 * Authorization header, like the real m365 backend outside its tool bodies.
 */
export function makeFakeBackend() {
  const seen: SeenRequest[] = [];
  const json = (body: unknown, extra: Record<string, string> = {}) =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json", ...extra },
    });

  const fetchImpl = vi.fn(async (_url: string | URL, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    const httpMethod = (init?.method ?? "GET").toUpperCase();
    const message =
      httpMethod === "POST" && typeof init?.body === "string"
        ? (JSON.parse(init.body) as {
            id?: number;
            method?: string;
            params?: { protocolVersion?: string; name?: string };
          })
        : undefined;
    seen.push({
      httpMethod,
      rpcMethod: message?.method,
      authorization: headers.get("authorization"),
      userId: headers.get(USER_ID_HEADER),
    });

    if (httpMethod === "DELETE") return new Response(null, { status: 200 });
    if (httpMethod === "GET") {
      // The standing stream: open until the transport aborts it.
      const signal = init?.signal;
      return new Response(
        new ReadableStream({
          start(controller) {
            signal?.addEventListener("abort", () => {
              try {
                controller.close();
              } catch {
                // already closed
              }
            });
          },
        }),
        { status: 200, headers: { "content-type": "text/event-stream" } },
      );
    }
    switch (message?.method) {
      case "initialize":
        return json(
          {
            jsonrpc: "2.0",
            id: message.id,
            result: {
              protocolVersion: message.params?.protocolVersion,
              capabilities: { tools: {} },
              serverInfo: { name: "m365", version: "1.0.0" },
            },
          },
          { "mcp-session-id": SESSION_ID },
        );
      case "tools/list":
        return json({
          jsonrpc: "2.0",
          id: message.id,
          result: {
            tools: [
              {
                name: "mail_search",
                description: "Search mail",
                inputSchema: { type: "object", properties: {} },
              },
            ],
          },
        });
      case "tools/call":
        return json({
          jsonrpc: "2.0",
          id: message.id,
          result: { content: [{ type: "text", text: "ok" }] },
        });
      default:
        // notifications/initialized and the rest: accepted, no body.
        return new Response(null, { status: 202 });
    }
  });
  return { fetchImpl, seen };
}

/**
 * A mint stub with one enrolled user and any number of users who are not.
 * The enrolled user gets a token; anyone else gets what the broker throws.
 */
export function makeMint(enrolled: Record<string, string> = {}) {
  return {
    getAccessToken: vi.fn(async (userId: string) => {
      const token = enrolled[userId];
      if (token) return token;
      throw new M365BrokerError(
        "credential_missing",
        "No Microsoft 365 account is connected for your user yet.",
        ENROLL,
      );
    }),
  } as unknown as M365MintService;
}

/** The production transport and client, with the injected fetch over a fake backend. */
export function makeCreateClient(
  mint: M365MintService,
  backendFetch: typeof fetch,
) {
  return ((_serverParams: ServerParameters) => {
    const transport = new StreamableHTTPClientTransport(new URL(BACKEND_URL), {
      fetch: makeM365InjectedFetch(
        mint,
        backendFetch as unknown as Parameters<typeof makeM365InjectedFetch>[1],
      ),
    });
    const client = new Client(
      { name: "metamcp-client", version: "2.0.0" },
      { capabilities: {} },
    );
    return { client, transport };
  }) as typeof createMetaMcpClient;
}
