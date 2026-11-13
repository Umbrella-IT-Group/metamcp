/**
 * The tools the conformance fixture backend serves. Every name, argument and
 * returned string is copied from the scenario text in
 * @modelcontextprotocol/conformance 0.1.16 (`dist/index.js`), because the suite
 * calls tools by fixed name and checks fixed content. The smoke test and the
 * tests derive their expected names from this one table.
 *
 * Sampling and elicitation go through `extra.sendRequest`, never through the
 * server-level `createMessage` / `elicitInput`. A request sent through `extra`
 * is bound to the in-flight call and rides that call's own response stream. The
 * server-level calls carry no related request id, so the SDK routes them to the
 * standalone GET stream and silently drops them when none is open: the caller
 * would then wait out the 60 s default timeout. `elicitInput` additionally
 * throws locally when the client declared no elicitation capability, which the
 * gateway's backend client never does, so it could never flip to passing.
 * These tools exist so the four baseline entries that depend on them can pass
 * the day the gateway relays such requests.
 */
import {
  type CallToolResult,
  CreateMessageResultSchema,
  ElicitResultSchema,
  type ServerNotification,
  type ServerRequest,
} from "@modelcontextprotocol/sdk/types.js";

export interface FixtureTool {
  name: string;
  description: string;
  inputSchema: { type: "object"; [key: string]: unknown };
}

const emptyObject = { type: "object", properties: {} } as const;

// 1x1 PNG and a header-only WAV: the scenarios only check type, data and mimeType.
const PNG_BASE64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
const WAV_BASE64 =
  "UklGRiQAAABXQVZFZm10IBAAAAABAAEAQB8AAIA+AAACABAAZGF0YQAAAAA=";

const JSON_SCHEMA_2020_12 = "https://json-schema.org/draft/2020-12/schema";

export const FIXTURE_TOOLS: readonly FixtureTool[] = [
  {
    name: "test_simple_text",
    description: "Returns a fixed text response.",
    inputSchema: { ...emptyObject },
  },
  {
    name: "test_image_content",
    description: "Returns a 1x1 PNG as image content.",
    inputSchema: { ...emptyObject },
  },
  {
    name: "test_audio_content",
    description: "Returns a minimal WAV as audio content.",
    inputSchema: { ...emptyObject },
  },
  {
    name: "test_embedded_resource",
    description: "Returns an embedded text resource.",
    inputSchema: { ...emptyObject },
  },
  {
    name: "test_multiple_content_types",
    description: "Returns text, image and an embedded resource together.",
    inputSchema: { ...emptyObject },
  },
  {
    name: "test_error_handling",
    description: "Always returns an error result (isError true).",
    inputSchema: { ...emptyObject },
  },
  {
    name: "test_tool_with_logging",
    description: "Sends three info log notifications while it runs.",
    inputSchema: { ...emptyObject },
  },
  {
    name: "test_tool_with_progress",
    description:
      "Reports 0, 50 and 100 of 100 progress when given a progress token.",
    inputSchema: { ...emptyObject },
  },
  {
    name: "test_sampling",
    description:
      "Asks the client to sample an LLM response for the given prompt.",
    inputSchema: {
      type: "object",
      properties: {
        prompt: { type: "string", description: "Prompt to sample" },
      },
      required: ["prompt"],
    },
  },
  {
    name: "test_elicitation",
    description: "Asks the client for a username and email.",
    inputSchema: {
      type: "object",
      properties: {
        message: { type: "string", description: "Message to show" },
      },
      required: ["message"],
    },
  },
  {
    name: "test_elicitation_sep1034_defaults",
    description: "Elicits input using a schema that carries default values.",
    inputSchema: { ...emptyObject },
  },
  {
    name: "test_elicitation_sep1330_enums",
    description: "Elicits input using every enum schema variant.",
    inputSchema: { ...emptyObject },
  },
  {
    name: "json_schema_2020_12_tool",
    description: "Tool with JSON Schema 2020-12 features",
    inputSchema: {
      $schema: JSON_SCHEMA_2020_12,
      type: "object",
      $defs: {
        address: {
          type: "object",
          properties: { street: { type: "string" }, city: { type: "string" } },
        },
      },
      properties: {
        name: { type: "string" },
        address: { $ref: "#/$defs/address" },
      },
      additionalProperties: false,
    },
  },
];

export const FIXTURE_TOOL_NAMES: readonly string[] = FIXTURE_TOOLS.map(
  (tool) => tool.name,
);

/** The slice of the SDK's request-handler `extra` the handlers use. */
export interface ToolExtra {
  _meta?: { progressToken?: string | number };
  sendNotification(notification: ServerNotification): Promise<void>;
  sendRequest(
    request: ServerRequest,
    schema: typeof CreateMessageResultSchema | typeof ElicitResultSchema,
    options?: { timeout?: number },
  ): Promise<unknown>;
}

export interface FixtureHandlers {
  callTool(
    name: string,
    args: Record<string, unknown> | undefined,
    extra: ToolExtra,
  ): Promise<CallToolResult>;
}

const REQUEST_TIMEOUT_MS = 10_000;

const text = (value: string): CallToolResult => ({
  content: [{ type: "text", text: value }],
});

const unavailable = (what: string): CallToolResult => ({
  isError: true,
  content: [
    { type: "text", text: `${what} is not available through this gateway.` },
  ],
});

const DEFAULTS_SCHEMA = {
  type: "object",
  properties: {
    name: { type: "string", default: "John Doe" },
    age: { type: "integer", default: 30 },
    score: { type: "number", default: 95.5 },
    status: {
      type: "string",
      enum: ["active", "inactive", "pending"],
      default: "active",
    },
    verified: { type: "boolean", default: true },
  },
};

const ENUMS_SCHEMA = {
  type: "object",
  properties: {
    untitledSingle: { type: "string", enum: ["option1", "option2", "option3"] },
    titledSingle: {
      type: "string",
      oneOf: [
        { const: "value1", title: "First Option" },
        { const: "value2", title: "Second Option" },
        { const: "value3", title: "Third Option" },
      ],
    },
    legacyEnum: {
      type: "string",
      enum: ["opt1", "opt2", "opt3"],
      enumNames: ["Option One", "Option Two", "Option Three"],
    },
    untitledMulti: {
      type: "array",
      items: { type: "string", enum: ["option1", "option2", "option3"] },
    },
    titledMulti: {
      type: "array",
      items: {
        anyOf: [
          { const: "value1", title: "First Choice" },
          { const: "value2", title: "Second Choice" },
          { const: "value3", title: "Third Choice" },
        ],
      },
    },
  },
};

export function createFixtureHandlers(deps: {
  sleep?: (ms: number) => Promise<void>;
}): FixtureHandlers {
  const sleep =
    deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));

  async function elicit(
    extra: ToolExtra,
    message: string,
    requestedSchema: Record<string, unknown>,
    label: string,
    format: (action: string, content: unknown) => string,
  ): Promise<CallToolResult> {
    try {
      const request = {
        method: "elicitation/create",
        params: { message, requestedSchema },
      } as unknown as ServerRequest;
      const result = (await extra.sendRequest(request, ElicitResultSchema, {
        timeout: REQUEST_TIMEOUT_MS,
      })) as { action: string; content?: unknown };
      return text(format(result.action, result.content));
    } catch {
      // Always the case through the gateway: its backend client answers
      // MethodNotFound. A fixed text keeps the failing-check snapshot stable.
      return unavailable(label);
    }
  }

  return {
    async callTool(name, args, extra) {
      switch (name) {
        case "test_simple_text":
          return text("This is a simple text response for testing.");

        case "test_image_content":
          return {
            content: [
              { type: "image", data: PNG_BASE64, mimeType: "image/png" },
            ],
          };

        case "test_audio_content":
          return {
            content: [
              { type: "audio", data: WAV_BASE64, mimeType: "audio/wav" },
            ],
          };

        case "test_embedded_resource":
          return {
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
          };

        case "test_multiple_content_types":
          return {
            content: [
              { type: "text", text: "Multiple content types test:" },
              { type: "image", data: PNG_BASE64, mimeType: "image/png" },
              {
                type: "resource",
                resource: {
                  uri: "test://mixed-content-resource",
                  mimeType: "application/json",
                  text: '{"test":"data","value":123}',
                },
              },
            ],
          };

        case "test_error_handling":
          return {
            isError: true,
            content: [
              {
                type: "text",
                text: "This tool intentionally returns an error for testing",
              },
            ],
          };

        case "test_tool_with_logging": {
          const log = (data: string) =>
            extra.sendNotification({
              method: "notifications/message",
              params: { level: "info", data },
            });
          await log("Tool execution started");
          await sleep(50);
          await log("Tool processing data");
          await sleep(50);
          await log("Tool execution completed");
          return text("Logging test completed");
        }

        case "test_tool_with_progress": {
          const token = extra._meta?.progressToken;
          const report = async (progress: number) => {
            if (token === undefined) return;
            await extra.sendNotification({
              method: "notifications/progress",
              params: { progressToken: token, progress, total: 100 },
            });
          };
          await report(0);
          await sleep(50);
          await report(50);
          await sleep(50);
          await report(100);
          return text("Progress test completed");
        }

        case "test_sampling": {
          const prompt = typeof args?.prompt === "string" ? args.prompt : "";
          try {
            const request = {
              method: "sampling/createMessage",
              params: {
                messages: [
                  { role: "user", content: { type: "text", text: prompt } },
                ],
                maxTokens: 100,
              },
            } as unknown as ServerRequest;
            const result = (await extra.sendRequest(
              request,
              CreateMessageResultSchema,
              {
                timeout: REQUEST_TIMEOUT_MS,
              },
            )) as { content: { type: string; text?: string } };
            const reply =
              result.content.type === "text"
                ? (result.content.text ?? "")
                : JSON.stringify(result.content);
            return text(`LLM response: ${reply}`);
          } catch {
            return unavailable("Sampling");
          }
        }

        case "test_elicitation":
          return elicit(
            extra,
            typeof args?.message === "string" ? args.message : "",
            {
              type: "object",
              properties: {
                username: { type: "string", description: "User's response" },
                email: { type: "string", description: "User's email address" },
              },
              required: ["username", "email"],
            },
            "Elicitation",
            (action, content) =>
              `User response: action=${action}, content=${JSON.stringify(content)}`,
          );

        case "test_elicitation_sep1034_defaults":
          return elicit(
            extra,
            "Please confirm your details",
            DEFAULTS_SCHEMA,
            "Elicitation (defaults schema)",
            (action, content) =>
              `Elicitation completed: action=${action}, content=${JSON.stringify(content)}`,
          );

        case "test_elicitation_sep1330_enums":
          return elicit(
            extra,
            "Please choose your options",
            ENUMS_SCHEMA,
            "Elicitation (enum schema)",
            (action, content) =>
              `Elicitation completed: action=${action}, content=${JSON.stringify(content)}`,
          );

        case "json_schema_2020_12_tool":
          return text("ok");

        default:
          return {
            isError: true,
            content: [{ type: "text", text: `Unknown tool: ${name}` }],
          };
      }
    },
  };
}
