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
  listedTargetOf,
  routeLeanCall,
  runDescribe,
  runSearch,
  toolError,
} from "./lean-listing";
import type { ReverifyResult } from "./metamcp-middleware/classified-target.functional";

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
 *
 * `classifiedTarget` accompanies the request of a `call_tool` call and of no
 * other call: the original full name of the tool the read-only verdict was
 * given for. The caller puts it on a per-call clone of the handler context
 * (`ClassifiedCallContext`), and the chain refuses the call if the name resolves
 * to another tool when it runs. It is part of the result, not state on the
 * prelude, so concurrent calls cannot share it. The backend UUID and the
 * snapshot's validity check travel with it; dispatch checks both immediately
 * before sending, including after any asynchronous routing or recovery.
 *
 * `reverifyClassifiedTarget` travels with them, on a `call_tool` call only. A
 * catalog invalidation (a backend reconnect, an override change) revokes the
 * validity check without saying anything about the tool, and a revoked verdict
 * is refused unless the chain can look again: it calls this, once per check
 * point, to read a fresh listing and learn whether the very tool the verdict
 * was given for still stands as read-only. It returns data and changes
 * nothing, so a call that gave up waiting leaves no trace.
 */
export interface LeanPreludeResult {
  answer?: CallToolResult;
  request?: CallToolRequest;
  classifiedTarget?: string;
  classifiedServerUuid?: string;
  classifiedTargetIsCurrent?: () => boolean;
  reverifyClassifiedTarget?: () => Promise<ReverifyResult>;
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
        // The verdict is about the tool this name stood for in the snapshot.
        // A verdict that cannot name its tool is not given: fail closed to the
        // routing answer, which is true (call_write_tool runs it) and runs
        // nothing here.
        const classifiedTarget = listedTargetOf(listing, route.name);
        const classifiedServerUuid =
          classifiedTarget === undefined
            ? undefined
            : listing.serverUuids?.get(classifiedTarget);
        if (
          classifiedTarget === undefined ||
          classifiedServerUuid === undefined ||
          listing.isCurrent === undefined
        ) {
          options.log(
            "warn",
            "lean listing: call_tool found no recorded tool for a read-only name",
          );
          return { answer: toolError(CALL_TOOL_ROUTING_ANSWER) };
        }
        // The verdict does not survive an invalidation on trust: the backend
        // behind the name may be a redeployed one whose tool now carries other
        // hints. It can be given again, from a fresh listing and only then:
        // for the SAME name the client asked by (through the same override
        // resolution as above), standing for the SAME full tool on the SAME
        // backend, read-only by the FRESH hints, in a listing that is itself
        // still current. Anything missing or different is a change: nothing
        // here widens what the verdict covered.
        const requestedName = route.name;
        const reverifyClassifiedTarget = async (): Promise<ReverifyResult> => {
          // The catalog's own load (single-flight with a concurrent search).
          // Its error contract is the first read's: the listing's retryable
          // error is an unavailable catalog, anything else is a defect and
          // propagates rather than passing for one.
          const fresh = await readCatalog();
          if (fresh === undefined) return { kind: "unavailable" };
          if (
            listedTargetOf(fresh, requestedName) !== classifiedTarget ||
            fresh.serverUuids?.get(classifiedTarget) !== classifiedServerUuid ||
            !classifyCallTarget(fresh, requestedName).readOnly ||
            fresh.isCurrent === undefined ||
            !fresh.isCurrent()
          ) {
            return { kind: "changed" };
          }
          // That listing's OWN validity check, captured before it loaded. One
          // taken now would bless hints a late or invalidated load carries.
          return { kind: "current", isCurrent: fresh.isCurrent };
        };
        return {
          request: route.request,
          classifiedTarget,
          classifiedServerUuid,
          classifiedTargetIsCurrent: listing.isCurrent,
          reverifyClassifiedTarget,
        };
      }
    }
  };
}
