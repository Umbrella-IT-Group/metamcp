// Stub: an empty tool table, committed first so the tests fail on assertions
// rather than on a missing import. Replaced by the real implementation in the
// next commit.

export interface FixtureTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

export const FIXTURE_TOOLS: readonly FixtureTool[] = [];

export const FIXTURE_TOOL_NAMES: readonly string[] = [];

export interface ToolExtra {
  _meta?: { progressToken?: string | number };
  sendNotification(notification: {
    method: string;
    params?: Record<string, unknown>;
  }): Promise<void>;
  sendRequest(
    request: { method: string; params?: Record<string, unknown> },
    schema: unknown,
    options?: { timeout?: number },
  ): Promise<unknown>;
}

export interface ToolResult {
  isError?: boolean;
  content: Array<Record<string, unknown>>;
}

export interface FixtureHandlers {
  callTool(
    name: string,
    args: Record<string, unknown> | undefined,
    extra: ToolExtra,
  ): Promise<ToolResult>;
}

export function createFixtureHandlers(_deps: {
  sleep?: (ms: number) => Promise<void>;
}): FixtureHandlers {
  return {
    async callTool(name) {
      return {
        isError: true,
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
      };
    },
  };
}
