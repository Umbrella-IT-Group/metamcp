import {
  type CallToolRequest,
  type CallToolResult,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";

import {
  CALL_TOOL,
  CALL_TOOL_CATALOG_UNAVAILABLE_ANSWER,
  CALL_TOOL_ROUTING_ANSWER,
  CATALOG_UNAVAILABLE_ANSWER,
  classifyCallTarget,
  type LeanCatalog,
  type LeanListing,
  routeLeanCall,
  runDescribe,
  runSearch,
  toolError,
} from "./lean-listing";

/**
 * What the `tools/call` handler of a lean session does before the middleware
 * chain: answer a meta call from the catalog, or hand back the request the
 * chain should run.
 *
 * `answer` is a final result. `request` is the call to run through
 * `callToolWithMiddleware`: the rewritten real-name request for a call meta
 * tool, or `undefined` for a direct real-name call, which runs as sent. The
 * prelude never executes a tool itself, so the chain stays the only way
 * anything runs.
 */
export interface LeanPreludeResult {
  answer?: CallToolResult;
  request?: CallToolRequest;
}

export type LeanPrelude = (
  incoming: CallToolRequest,
) => Promise<LeanPreludeResult>;

/**
 * Kept apart from `lean-listing.ts` so that module stays pure: this one reads
 * the real listing through the catalog and logs. The log line is a count and
 * a duration only, never the query, a tool name or a server name, and it
 * avoids the words the log-based panels count as failures in an info line.
 */
export function createLeanPrelude(options: {
  catalog: LeanCatalog;
  log: (level: "info" | "warn", message: string) => void;
  elapsedMs?: () => number;
}): LeanPrelude {
  const clock = options.elapsedMs ?? (() => performance.now());

  /**
   * The catalog, or `undefined` when the namespace's servers cannot be read.
   * That one condition (the listing's own retryable "backend unavailable"
   * error) is a tool error the model can act on; anything else is a defect and
   * propagates exactly as a failing `tools/list` would.
   */
  const readCatalog = async (): Promise<LeanListing | undefined> => {
    try {
      return await options.catalog.get();
    } catch (error) {
      if (error instanceof McpError) return undefined;
      throw error;
    }
  };

  return async (incoming) => {
    const started = clock();
    const route = routeLeanCall(incoming);
    switch (route.kind) {
      case "passthrough":
        return {};
      case "answer":
        options.log(
          "warn",
          `lean listing: ${incoming.params.name} arguments refused`,
        );
        return { answer: route.result };
      case "search":
      case "describe": {
        const listing = await readCatalog();
        if (listing === undefined) {
          options.log(
            "warn",
            `lean listing: ${incoming.params.name} could not read the catalog`,
          );
          return { answer: toolError(CATALOG_UNAVAILABLE_ANSWER) };
        }
        const answer =
          route.kind === "search"
            ? runSearch(listing, route.args)
            : runDescribe(listing, route.args);
        options.log(
          "info",
          route.kind === "search"
            ? `lean listing: search_tools over ${listing.tools.length} tools (${Math.round(clock() - started)}ms)`
            : `lean listing: describe_tool for ${route.args.names.length} names (${Math.round(clock() - started)}ms)`,
        );
        return { answer };
      }
      case "call": {
        if (route.via !== CALL_TOOL) return { request: route.request };
        // `call_tool` is the read-only door. Whether this name belongs behind
        // it is a question about its hints, so it needs the listing.
        const listing = await readCatalog();
        if (listing === undefined) {
          options.log(
            "warn",
            "lean listing: call_tool could not read the catalog",
          );
          return { answer: toolError(CALL_TOOL_CATALOG_UNAVAILABLE_ANSWER) };
        }
        if (!classifyCallTarget(listing, route.name).readOnly) {
          options.log(
            "info",
            "lean listing: call_tool pointed a tool at call_write_tool",
          );
          return { answer: toolError(CALL_TOOL_ROUTING_ANSWER) };
        }
        return { request: route.request };
      }
    }
  };
}
