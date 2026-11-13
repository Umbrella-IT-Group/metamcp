import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";

/**
 * How the Inspector reads the outcome of a tools/call, as plain data.
 *
 * Two different things can go wrong, and the old page called both "success"
 * unless the request threw:
 *
 *   - A tool error: the call reached the tool (or the gateway answered for it)
 *     and the result says `isError: true`. MCP specification, server/tools,
 *     "Error Handling": a tool's own failure is reported inside the result so
 *     a caller can see it, not as a protocol error. The gateway answers a
 *     retired tool name, a filter denial and an unenrolled Microsoft 365 user
 *     this way, so each of those used to show a green success.
 *   - A failed request: a protocol error, a timeout, a closed connection, or
 *     the person stopping the wait.
 *
 * Everything the server sends is untrusted text. Nothing here builds markup;
 * the view renders these values as text nodes, and the only thing turned into
 * a URL is a raster image from a fixed allowlist (see imageDataUrl).
 */

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
  /** For a tool error: its text blocks joined, or a fixed sentence. */
  errorText: string | null;
  structured: Record<string, unknown> | null;
  blocks: ContentBlock[];
}

export interface ClassifiedFailure {
  status: "protocol_error" | "stopped";
  message: string;
  code?: number;
  data?: unknown;
  /**
   * True when the request ended without an answer, so the backend may still
   * have done the work: for a write, read the target before trying again.
   */
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

/** Above this many characters a result is shown in a plain block, not highlighted. */
export const HIGHLIGHT_LIMIT = 100_000;
/** Text longer than this is not parsed to look for JSON. */
export const JSON_BLOCK_LIMIT = 200_000;

const GENERIC_ERROR_TEXT = "An error occurred";

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const asString = (value: unknown): string | undefined =>
  typeof value === "string" ? value : undefined;

/** Decoded size of a base64 string. */
function base64Bytes(data: string): number {
  const compact = data.replace(/\s/g, "");
  const padding = compact.endsWith("==") ? 2 : compact.endsWith("=") ? 1 : 0;
  return Math.max(0, Math.floor((compact.length * 3) / 4) - padding);
}

function prettyJsonOf(text: string): string | undefined {
  if (text.length > JSON_BLOCK_LIMIT) return undefined;
  const first = text.trimStart()[0];
  if (first !== "{" && first !== "[") return undefined;
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return undefined;
  }
}

function rawOf(value: unknown): string {
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}

function toBlock(entry: unknown): ContentBlock {
  if (!isRecord(entry)) {
    return { kind: "unknown", type: "unknown", raw: rawOf(entry) };
  }
  switch (entry.type) {
    case "text": {
      const text = asString(entry.text) ?? "";
      const prettyJson = prettyJsonOf(text);
      return prettyJson === undefined
        ? { kind: "text", text }
        : { kind: "text", text, prettyJson };
    }
    case "image": {
      const mimeType = asString(entry.mimeType) ?? "";
      const data = asString(entry.data) ?? "";
      return {
        kind: "image",
        mimeType,
        bytes: base64Bytes(data),
        dataUrl: imageDataUrl(mimeType, data),
      };
    }
    case "audio":
      return {
        kind: "audio",
        mimeType: asString(entry.mimeType) ?? "",
        bytes: base64Bytes(asString(entry.data) ?? ""),
      };
    case "resource_link": {
      const block: ContentBlock = {
        kind: "resource_link",
        uri: asString(entry.uri) ?? "",
      };
      const name = asString(entry.name);
      if (name !== undefined) block.name = name;
      const mimeType = asString(entry.mimeType);
      if (mimeType !== undefined) block.mimeType = mimeType;
      const description = asString(entry.description);
      if (description !== undefined) block.description = description;
      return block;
    }
    case "resource": {
      const resource = isRecord(entry.resource) ? entry.resource : {};
      const block: ContentBlock = {
        kind: "resource",
        uri: asString(resource.uri) ?? "",
      };
      const mimeType = asString(resource.mimeType);
      if (mimeType !== undefined) block.mimeType = mimeType;
      const text = asString(resource.text);
      if (text !== undefined) block.text = text;
      const blob = asString(resource.blob);
      if (blob !== undefined) block.bytes = base64Bytes(blob);
      return block;
    }
    default:
      return {
        kind: "unknown",
        type: asString(entry.type) ?? "unknown",
        raw: rawOf(entry),
      };
  }
}

/**
 * Reads a tools/call result. `isError` must be exactly true to be an error
 * (MCP "isError": if not set, assumed false). The pre-2025 `toolResult` shape
 * and anything unrecognised read as success with no blocks; the raw view still
 * shows all of it.
 */
export function classifyCallResult(result: unknown): ClassifiedResult {
  const body = isRecord(result) ? result : {};
  const blocks = Array.isArray(body.content) ? body.content.map(toBlock) : [];
  const structured = isRecord(body.structuredContent)
    ? body.structuredContent
    : null;

  if (body.isError !== true) {
    return { status: "success", errorText: null, structured, blocks };
  }

  const texts = blocks.flatMap((block) =>
    block.kind === "text" && block.text !== "" ? [block.text] : [],
  );
  return {
    status: "tool_error",
    errorText: texts.length > 0 ? texts.join("\n") : GENERIC_ERROR_TEXT,
    structured,
    blocks,
  };
}

/**
 * Reads a request that ended without a result.
 *
 * `stoppedByUser` is passed in because the SDK reports an aborted request as
 * McpError(RequestTimeout), the same code a real timeout carries (SDK
 * shared/protocol.js, request(): cancel()). Only the page knows who ended the
 * wait.
 */
export function classifyCallFailure(
  error: unknown,
  options: { stoppedByUser: boolean },
): ClassifiedFailure {
  const message = error instanceof Error ? error.message : String(error);
  const failure: ClassifiedFailure = {
    status: options.stoppedByUser ? "stopped" : "protocol_error",
    message,
    outcomeUnknown: options.stoppedByUser,
  };
  if (error instanceof McpError) {
    failure.code = error.code;
    if (error.data !== undefined) failure.data = error.data;
    if (
      error.code === ErrorCode.RequestTimeout ||
      error.code === ErrorCode.ConnectionClosed
    ) {
      failure.outcomeUnknown = true;
    }
  }
  return failure;
}

const IMAGE_TYPES = new Set([
  "image/png",
  "image/jpeg",
  "image/gif",
  "image/webp",
]);
const BASE64_TEXT = /^[A-Za-z0-9+/=\s]*$/;

/**
 * A data: URL for an image block, only for the four raster types and only
 * when the data is plain base64 text. SVG and HTML (and any type this does not
 * name) are never turned into a URL: an SVG can carry script, and the page
 * shows those as a text line with the type and size instead.
 */
export function imageDataUrl(mimeType: unknown, data: unknown): string | null {
  if (typeof mimeType !== "string" || !IMAGE_TYPES.has(mimeType)) return null;
  if (typeof data !== "string" || !BASE64_TEXT.test(data)) return null;
  const compact = data.replace(/\s/g, "");
  if (compact === "") return null;
  return `data:${mimeType};base64,${compact}`;
}

/** Pretty JSON for display and copy; never throws on a circular or odd value. */
export function stringifyForDisplay(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2) ?? String(value);
  } catch {
    return String(value);
  }
}
