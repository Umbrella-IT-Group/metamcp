/**
 * The fixture is the backend the gateway fronts during a conformance run. The
 * suite calls tools by fixed name and expects fixed content, so each tool has to
 * return exactly what its scenario text demands, and the sampling and
 * elicitation tools must be request-bound (they ride the in-flight call's own
 * response stream) so they can never hang waiting on a stream that is not open.
 *
 * The real SDK client talks to the real SDK server over a loopback socket.
 * `sleep` is injected as a no-op, so no test waits on a timer.
 *
 * Oracles: the @modelcontextprotocol/conformance 0.1.16 scenario text (the
 * exact tool names, content shapes and strings below are copied from its
 * `dist/index.js`), and SDK 1.32.0 `shared/protocol.js` (a request sent through
 * `extra.sendRequest` carries `relatedRequestId`, so it rides the POST response
 * that is already open; a client with no handler answers MethodNotFound).
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  CreateMessageRequestSchema,
  ElicitRequestSchema,
  LoggingMessageNotificationSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { createFixtureServer } from "./fixture-server";
import {
  createFixtureHandlers,
  FIXTURE_TOOL_NAMES,
  FIXTURE_TOOLS,
} from "./fixture-tools";

// Copied from the scenario text, not derived from the code under test.
const EXPECTED_TOOLS = [
  "test_simple_text",
  "test_image_content",
  "test_audio_content",
  "test_embedded_resource",
  "test_multiple_content_types",
  "test_error_handling",
  "test_tool_with_logging",
  "test_tool_with_progress",
  "test_sampling",
  "test_elicitation",
  "test_elicitation_sep1034_defaults",
  "test_elicitation_sep1330_enums",
  "json_schema_2020_12_tool",
];

let server: ReturnType<typeof createFixtureServer>;
let port: number;
const clients: Client[] = [];

async function connect(withHandlers: boolean): Promise<Client> {
  const client = new Client(
    { name: "fixture-test", version: "0.0.0" },
    { capabilities: withHandlers ? { sampling: {}, elicitation: {} } : {} },
  );
  if (withHandlers) {
    client.setRequestHandler(CreateMessageRequestSchema, async () => ({
      role: "assistant",
      content: { type: "text", text: "from the client" },
      model: "test-model",
      stopReason: "endTurn",
    }));
    client.setRequestHandler(ElicitRequestSchema, async () => ({
      action: "accept",
      content: { username: "testuser", email: "test@example.com" },
    }));
  }
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`)),
  );
  clients.push(client);
  return client;
}

beforeEach(async () => {
  server = createFixtureServer({ sleep: async () => undefined });
  port = await server.listen(0, "127.0.0.1");
});

afterEach(async () => {
  for (const c of clients.splice(0)) await c.close();
  await server.close();
});

const textOf = (r: unknown) =>
  (r as { content?: Array<{ type: string; text?: string }> }).content?.[0]
    ?.text;

describe("tool table", () => {
  it("is exactly the set of tools the 0.1.16 scenarios call, each with a description and a schema", () => {
    expect([...FIXTURE_TOOL_NAMES].sort()).toEqual([...EXPECTED_TOOLS].sort());
    expect(FIXTURE_TOOLS.map((t) => t.name)).toEqual([...FIXTURE_TOOL_NAMES]);
    for (const t of FIXTURE_TOOLS) {
      expect(t.description.trim().length, t.name).toBeGreaterThan(0);
      expect(typeof t.inputSchema, t.name).toBe("object");
    }
  });

  it("lists over the wire with the same names and keeps the raw JSON Schema 2020-12 keywords", async () => {
    const client = await connect(true);
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual([...EXPECTED_TOOLS].sort());
    const schemaTool = tools.find((t) => t.name === "json_schema_2020_12_tool");
    const schema = schemaTool?.inputSchema as Record<string, unknown>;
    expect(schema.$schema).toBe("https://json-schema.org/draft/2020-12/schema");
    expect((schema.$defs as Record<string, unknown>).address).toBeDefined();
    expect(schema.additionalProperties).toBe(false);
    expect(
      (schema.properties as { address: Record<string, unknown> }).address.$ref,
    ).toBe("#/$defs/address");
  });
});

describe("content shapes", () => {
  it("returns the exact content each scenario requires", async () => {
    const client = await connect(true);
    const call = (name: string) => client.callTool({ name, arguments: {} });

    expect(await call("test_simple_text")).toMatchObject({
      content: [
        { type: "text", text: "This is a simple text response for testing." },
      ],
    });

    const image = (await call("test_image_content")).content as Array<
      Record<string, string>
    >;
    expect(image[0]).toMatchObject({ type: "image", mimeType: "image/png" });
    expect(image[0].data.length).toBeGreaterThan(0);

    const audio = (await call("test_audio_content")).content as Array<
      Record<string, string>
    >;
    expect(audio[0]).toMatchObject({ type: "audio", mimeType: "audio/wav" });
    expect(audio[0].data.length).toBeGreaterThan(0);

    expect(await call("test_embedded_resource")).toMatchObject({
      content: [
        {
          type: "resource",
          resource: {
            uri: "test://embedded-resource",
            mimeType: "text/plain",
            text: "This is an embedded resource content.",
          },
        },
      ],
    });

    const mixed = (await call("test_multiple_content_types")).content as Array<
      Record<string, unknown>
    >;
    expect(mixed.map((c) => c.type)).toEqual(["text", "image", "resource"]);
    expect(mixed[0].text).toBe("Multiple content types test:");
    expect(mixed[2].resource).toEqual({
      uri: "test://mixed-content-resource",
      mimeType: "application/json",
      text: '{"test":"data","value":123}',
    });

    expect(await call("test_error_handling")).toMatchObject({
      isError: true,
      content: [
        {
          type: "text",
          text: "This tool intentionally returns an error for testing",
        },
      ],
    });
  });

  it("answers an unknown tool as an error result, not a crash", async () => {
    const client = await connect(true);
    const r = await client.callTool({ name: "no_such_tool", arguments: {} });
    expect(r.isError).toBe(true);
  });
});

describe("progress and logging", () => {
  it("sends 0, 50 and 100 of 100 progress notifications only when the request carries a token", async () => {
    const client = await connect(true);
    const seen: Array<{ progress: number; total?: number }> = [];
    await client.callTool(
      { name: "test_tool_with_progress", arguments: {} },
      undefined,
      {
        onprogress: (p) => seen.push(p),
      },
    );
    expect(seen.map((p) => p.progress)).toEqual([0, 50, 100]);
    expect(seen.every((p) => p.total === 100)).toBe(true);

    // No token: the handler must stay silent.
    const sent: unknown[] = [];
    const handlers = createFixtureHandlers({ sleep: async () => undefined });
    await handlers.callTool(
      "test_tool_with_progress",
      {},
      {
        sendNotification: async (n) => void sent.push(n),
        sendRequest: async () => ({}),
      },
    );
    expect(sent).toEqual([]);
  });

  it("sends three info log messages with the scenario's wording", async () => {
    const client = await connect(true);
    const messages: string[] = [];
    client.setNotificationHandler(LoggingMessageNotificationSchema, (n) => {
      messages.push(String(n.params.data));
    });
    await client.callTool({ name: "test_tool_with_logging", arguments: {} });
    expect(messages).toEqual([
      "Tool execution started",
      "Tool processing data",
      "Tool execution completed",
    ]);
  });
});

describe("sampling and elicitation", () => {
  it("round-trips through a client that supports them", async () => {
    const client = await connect(true);
    expect(
      textOf(
        await client.callTool({
          name: "test_sampling",
          arguments: { prompt: "hi" },
        }),
      ),
    ).toBe("LLM response: from the client");
    expect(
      textOf(
        await client.callTool({
          name: "test_elicitation",
          arguments: { message: "who?" },
        }),
      ),
    ).toBe(
      'User response: action=accept, content={"username":"testuser","email":"test@example.com"}',
    );
    for (const name of [
      "test_elicitation_sep1034_defaults",
      "test_elicitation_sep1330_enums",
    ]) {
      expect(
        textOf(await client.callTool({ name, arguments: {} })),
        name,
      ).toMatch(/^Elicitation completed: action=accept, content=\{/);
    }
  });

  it("returns a fixed error result, promptly, when the client has no handler (MethodNotFound)", async () => {
    const client = await connect(false);
    const expected: Record<string, string> = {
      test_sampling: "Sampling is not available through this gateway.",
      test_elicitation: "Elicitation is not available through this gateway.",
      test_elicitation_sep1034_defaults:
        "Elicitation (defaults schema) is not available through this gateway.",
      test_elicitation_sep1330_enums:
        "Elicitation (enum schema) is not available through this gateway.",
    };
    for (const [name, text] of Object.entries(expected)) {
      const r = await client.callTool({
        name,
        arguments: { prompt: "p", message: "m" },
      });
      expect(r.isError, name).toBe(true);
      expect(textOf(r), name).toBe(text);
    }
  });
});
