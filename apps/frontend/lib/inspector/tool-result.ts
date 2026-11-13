// Skeleton: the final exported API with bodies that reproduce how the
// inspector read a tool call before this change (any answer that did not throw
// was a success). It exists so the tests can be run red first.

export type ExecutionStatus =
  | "running"
  | "success"
  | "tool_error"
  | "protocol_error"
  | "stopped";

export type ContentBlock =
  | { kind: "text"; text: string; prettyJson?: string }
  | { kind: "image"; mimeType: string; bytes: number; dataUrl: string | null }
  | { kind: "audio"; mimeType: string; bytes: number }
  | {
      kind: "resource_link";
      uri: string;
      name?: string;
      mimeType?: string;
      description?: string;
    }
  | {
      kind: "resource";
      uri: string;
      mimeType?: string;
      text?: string;
      bytes?: number;
    }
  | { kind: "unknown"; type: string; raw: string };

export interface ClassifiedResult {
  status: "success" | "tool_error";
  errorText: string | null;
  structured: Record<string, unknown> | null;
  blocks: ContentBlock[];
}

export interface ClassifiedFailure {
  status: "protocol_error" | "stopped";
  message: string;
  code?: number;
  data?: unknown;
  outcomeUnknown: boolean;
}

export interface ToolExecutionRecord {
  id: number;
  toolName: string;
  args: Record<string, unknown>;
  startedAt: number;
  status: ExecutionStatus;
  result?: unknown;
  failure?: ClassifiedFailure;
  durationMs?: number;
}

export const HIGHLIGHT_LIMIT = 100_000;
export const JSON_BLOCK_LIMIT = 200_000;

export function classifyCallResult(_result: unknown): ClassifiedResult {
  return { status: "success", errorText: null, structured: null, blocks: [] };
}

export function classifyCallFailure(
  error: unknown,
  _options: { stoppedByUser: boolean },
): ClassifiedFailure {
  return {
    status: "protocol_error",
    message: error instanceof Error ? error.message : String(error),
    outcomeUnknown: false,
  };
}

export function imageDataUrl(mimeType: unknown, data: unknown): string | null {
  if (typeof mimeType !== "string" || typeof data !== "string") return null;
  return `data:${mimeType};base64,${data}`;
}

export function stringifyForDisplay(value: unknown): string {
  return JSON.stringify(value, null, 2);
}
