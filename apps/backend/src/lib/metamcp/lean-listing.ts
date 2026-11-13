import type {
  CallToolRequest,
  CallToolResult,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";

/**
 * Inert stub of the lean listing module: every symbol the tests import exists
 * and answers nothing, so the tests fail on their assertions and not on a
 * missing import. Replaced by the implementation in the next commit.
 */

export const SEARCH_TOOL = "search_tools";
export const DESCRIBE_TOOL = "describe_tool";
export const CALL_TOOL = "call_tool";
export const CALL_WRITE_TOOL = "call_write_tool";
export const LEAN_META_TOOL_NAMES = [
  SEARCH_TOOL,
  DESCRIBE_TOOL,
  CALL_TOOL,
  CALL_WRITE_TOOL,
] as const;
export const LEAN_CATALOG_TTL_MS = 1000;
export const CALL_TOOL_ROUTING_ANSWER = "";

export interface LeanListing {
  readonly tools: readonly Tool[];
  readonly unavailable: number;
}

export type SearchDetail = "names" | "descriptions" | "schemas";
export interface SearchArgs {
  readonly query: string;
  readonly queryTruncated: boolean;
  readonly detail: SearchDetail;
  readonly limit: number;
}
export interface DescribeArgs {
  readonly names: readonly string[];
  readonly includeOutputSchema: boolean;
}
export type LeanRoute =
  | { readonly kind: "passthrough" }
  | { readonly kind: "answer"; readonly result: CallToolResult }
  | { readonly kind: "search"; readonly args: SearchArgs }
  | { readonly kind: "describe"; readonly args: DescribeArgs }
  | {
      readonly kind: "call";
      readonly via: "call_tool" | "call_write_tool";
      readonly name: string;
      readonly request: CallToolRequest;
    };
export interface RankedTool {
  readonly tool: Tool;
  readonly score: number;
}

export function isLeanMetaToolName(_name: string): boolean {
  return false;
}
export function leanMetaTools(): readonly Tool[] {
  return [];
}
export function hintFlags(_tool: Tool): {
  read_only: boolean;
  destructive: boolean;
} {
  return { read_only: false, destructive: false };
}
export function runsWith(_tool: Tool): "call_tool" | "call_write_tool" {
  return "call_tool";
}
export function classifyCallTarget(
  _listing: LeanListing,
  _name: string,
): { readOnly: boolean } {
  return { readOnly: true };
}
export function tokenize(_text: string): string[] {
  return [];
}
export function tokenizeQuery(_text: string): string[] {
  return [];
}
export function rankTools(
  _tools: readonly Tool[],
  _query: string,
): RankedTool[] {
  return [];
}
export function toolError(text: string): CallToolResult {
  return { isError: true, content: [{ type: "text", text }] };
}
export function routeLeanCall(_request: CallToolRequest): LeanRoute {
  return { kind: "passthrough" };
}
export function runSearch(
  _listing: LeanListing,
  _args: SearchArgs,
): CallToolResult {
  return { content: [{ type: "text", text: "{}" }] };
}
export function runDescribe(
  _listing: LeanListing,
  _args: DescribeArgs,
): CallToolResult {
  return { content: [{ type: "text", text: "{}" }] };
}

export class LeanCatalog {
  constructor(
    readonly options: {
      load: () => Promise<LeanListing>;
      now: () => number;
      ttlMs: number;
    },
  ) {}
  get(): Promise<LeanListing> {
    return Promise.resolve({ tools: [], unavailable: 0 });
  }
  invalidate(): void {}
}
