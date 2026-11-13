import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { ToolListingMode } from "@repo/zod-types";
import { z } from "zod";

/**
 * Per-endpoint presentation (migration 0044), the pure half: what a session is
 * shown at `initialize` and in `tools/list`, how that is decided, and how the
 * part of it that changes behaviour is pinned for lazy recovery.
 *
 * Pure and database-free on purpose: `metamcp-proxy.ts` imports this module,
 * and the proxy's own test suites mock no database. The row read lives in
 * `endpoint-presentation-resolver.ts`.
 *
 * NO ROW MEANS TODAY'S BEHAVIOUR, exactly. Every function here maps the absent
 * or all-default input to `undefined`, and everything downstream treats
 * `undefined` as "do nothing", so a default session takes the same code path it
 * took before this module existed.
 */

/**
 * What one session presents. Resolved once per session at `initialize` (the
 * router knows the endpoint; the proxy knows only the namespace) and handed to
 * the proxy constructor, so a long-lived session never changes shape under its
 * client when an administrator edits the settings.
 */
export interface SessionPresentation {
  /** `serverInfo.title`. Never the server `name`, which routing depends on. */
  readonly title?: string;
  /** The `initialize` result's `instructions`. */
  readonly instructions?: string;
  /** Which tool listing the session serves. */
  readonly toolListing: ToolListingMode;
  /** Leave `outputSchema` out of `tools/list` results. */
  readonly omitOutputSchemas: boolean;
}

/**
 * `MCP_ENDPOINT_PRESENTATION=off` (or `false`, `0`, in any case) turns the
 * whole feature off: every session is served exactly as if no endpoint had a
 * row, whatever is stored and whatever a persisted session pinned. It is the
 * emergency lever; clearing the settings in the admin panel is the graceful
 * one and leaves running sessions alone.
 *
 * Read at call time, so a test can set `process.env`. In production the
 * environment only changes with a restart, so it behaves as boot configuration.
 * Same parsing as `toolsListRenotifyEnabled`.
 */
export function presentationEnabled(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  const raw = (env.MCP_ENDPOINT_PRESENTATION ?? "true").trim().toLowerCase();
  return !["false", "off", "0"].includes(raw);
}

/**
 * `MCP_LEAN_LISTING=off` (or `false`, `0`, in any case) turns the lean tool
 * listing off while leaving title, instructions and the output-schema trim
 * alone: a stored or pinned `lean` is then served as the full listing (see
 * `effectivePresentation`), and so is a lean session that recovers after the
 * restart. It is the emergency lever for the lean path; unticking lean in the
 * admin panel is the graceful one and leaves running lean sessions alone.
 *
 * A client that is still holding the lean tool list when this is switched off
 * has four meta tools the gateway no longer answers (`Invalid tool name
 * format`) until it reconnects, and a client that does not honour
 * re-initialization needs a manual reconnect.
 *
 * Read at call time and parsed like `presentationEnabled`.
 */
export function leanListingEnabled(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  const raw = (env.MCP_LEAN_LISTING ?? "true").trim().toLowerCase();
  return !["false", "off", "0"].includes(raw);
}

/**
 * The paragraph a lean endpoint always starts its `instructions` with, because
 * four bare meta tools with no context perform worse than a short workflow
 * description. The administrator's own text, if any, follows after a blank
 * line (see `buildServerMetadata`).
 *
 * LENGTH. Some clients are reported to keep only about 2 KiB of server
 * instructions (unverified), so this paragraph plus the blank line plus the
 * longest administrator text (`ENDPOINT_INSTRUCTIONS_MAX`) must stay under
 * 2048 characters or the tail of the administrator's text is the part that
 * gets cut. A test pins the sum. (The header of migration 0044 quotes the
 * length of an earlier, shorter wording of this paragraph; the bound it
 * justifies is the one pinned here.)
 */
export const LEAN_INSTRUCTIONS =
  "This endpoint lists its tools on demand. Use search_tools with a few words describing the task to find tool names, describe_tool to read a tool's input schema, description, safety hints (read-only or destructive) and which tool runs it, then call_tool for a tool marked read-only or call_write_tool for any other tool, passing the full tool name and its arguments. A tool can also be called directly by its full name.";

/**
 * The presentation a session is actually served, or `undefined` for "none".
 *
 * Applied at every entry (the router's resolver, the pin reader, and again by
 * `createServer` itself), so no path, the admin Inspector and tests included,
 * can bypass the kill switch. Applying it twice gives the same answer.
 */
export function effectivePresentation(
  input: SessionPresentation | undefined,
  env: NodeJS.ProcessEnv = process.env,
): SessionPresentation | undefined {
  if (input === undefined || !presentationEnabled(env)) return undefined;
  // A `lean` that this process does not serve (MCP_LEAN_LISTING is off, or the
  // row came from an image that serves it and this one was rolled back past
  // that) is coerced here rather than refused, so the row reads as an ordinary
  // full listing and no lean text is ever emitted. Title, instructions and the
  // trim are unaffected: the lean switch is narrower than the master one.
  const toolListing: ToolListingMode =
    input.toolListing === "lean" && leanListingEnabled(env) ? "lean" : "full";
  const title = input.title === "" ? undefined : input.title;
  const instructions =
    input.instructions === "" ? undefined : input.instructions;
  if (
    title === undefined &&
    instructions === undefined &&
    toolListing === "full" &&
    !input.omitOutputSchemas
  ) {
    return undefined;
  }
  return {
    ...(title !== undefined ? { title } : {}),
    ...(instructions !== undefined ? { instructions } : {}),
    toolListing,
    omitOutputSchemas: input.omitOutputSchemas,
  };
}

/**
 * `serverInfo` and `instructions` for the SDK `Server` constructor.
 *
 * The constructor is the only clean carrier: the SDK reads `instructions` once,
 * there, and keeps `serverInfo` as given; both are private afterwards, and
 * re-registering `initialize` would also have to replicate the SDK's private
 * client-capability bookkeeping.
 *
 * `name` NEVER varies. The self-reference guard (`isSameServerInstance` and
 * the backend-name check in `createServer`) compares it, so an editable name
 * would let a setting change which backends the gateway treats as itself. The
 * title is a separate, display-only field. A default session gets exactly
 * `{ name, version }`, with no `title` key at all.
 */
export function buildServerMetadata(
  namespaceUuid: string,
  presentation: SessionPresentation | undefined,
): {
  serverInfo: { name: string; version: string; title?: string };
  instructions?: string;
} {
  // A lean session's instructions begin with the workflow paragraph, then the
  // administrator's text after a blank line. Only a lean session served by this
  // process gets the paragraph: `presentation` has been through
  // `effectivePresentation`, which turns `lean` into `full` when it is off.
  const instructions =
    presentation?.toolListing === "lean"
      ? presentation.instructions !== undefined
        ? `${LEAN_INSTRUCTIONS}\n\n${presentation.instructions}`
        : LEAN_INSTRUCTIONS
      : presentation?.instructions;
  return {
    serverInfo: {
      name: `metamcp-unified-${namespaceUuid}`,
      version: "1.0.0",
      ...(presentation?.title !== undefined
        ? { title: presentation.title }
        : {}),
    },
    ...(instructions !== undefined ? { instructions } : {}),
  };
}

/**
 * A copy of a listed tool without its `outputSchema`; the argument is not
 * modified. `tools/list` results are shared objects (the override and filter
 * middleware keep their own caches), so trimming in place would trim what the
 * next session on the namespace sees.
 */
export function withoutOutputSchema(tool: Tool): Tool {
  const { outputSchema: _dropped, ...rest } = tool;
  return rest;
}

/**
 * What a session persists in `mcp_sessions.init_params` so lazy recovery can
 * restore it. Only the behavioural bits are pinned: a recovered session skips
 * `initialize` entirely, so its title and instructions are never sent again
 * and there is nothing to restore for them. A default session persists `{}`,
 * exactly what it persisted before this module existed.
 */
export function presentationToInitParams(
  presentation: SessionPresentation | undefined,
): Record<string, unknown> {
  if (presentation === undefined) return {};
  return {
    presentation: {
      v: 1,
      lean: presentation.toolListing === "lean",
      omit: presentation.omitOutputSchemas,
    },
  };
}

// Strict on purpose: a pin with a field this reader does not know was written
// by a newer build, and guessing at it is worse than serving the default.
const PresentationPinSchema = z.strictObject({
  v: z.literal(1),
  lean: z.boolean(),
  omit: z.boolean(),
});

/**
 * The presentation a persisted session pinned, or `undefined` for "none".
 *
 * Defensive by construction: `init_params` is a jsonb column that nothing but
 * this module writes today, but a row can predate the feature (`{}`), come from
 * a newer or older build, or be edited by hand. Anything that is not exactly a
 * version 1 pin reads as no pin, which recovers the session as the ordinary
 * full listing: the safe direction.
 *
 * Only the pin is read, never the endpoint's current settings: a session
 * recovers as it was created, whatever an administrator has changed since. The
 * kill switch still wins over a pin.
 */
export function presentationFromInitParams(
  raw: unknown,
  env: NodeJS.ProcessEnv = process.env,
): SessionPresentation | undefined {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return undefined;
  }
  // Own property only: `presentation` must not be read off a prototype.
  if (!Object.prototype.hasOwnProperty.call(raw, "presentation")) {
    return undefined;
  }
  const pin = PresentationPinSchema.safeParse(
    (raw as Record<string, unknown>).presentation,
  );
  if (!pin.success) return undefined;
  return effectivePresentation(
    {
      toolListing: pin.data.lean ? "lean" : "full",
      omitOutputSchemas: pin.data.omit,
    },
    env,
  );
}
