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
 * Does this build serve a lean tool listing? Not in this release, so a stored
 * or pinned `lean` is always served as the full listing (see
 * `effectivePresentation`). The release that serves lean replaces this body
 * with its own switch; the callers do not change.
 */
export function leanListingEnabled(
  _env: NodeJS.ProcessEnv = process.env,
): boolean {
  return false;
}

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
  // A `lean` that this build does not serve is coerced here rather than
  // refused, so such a row (an image rolled back past the release that serves
  // lean, or a row written by hand) reads as an ordinary full listing and no
  // lean text is ever emitted.
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
  return {
    serverInfo: {
      name: `metamcp-unified-${namespaceUuid}`,
      version: "1.0.0",
      ...(presentation?.title !== undefined
        ? { title: presentation.title }
        : {}),
    },
    ...(presentation?.instructions !== undefined
      ? { instructions: presentation.instructions }
      : {}),
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

/** Inert stub: the workflow paragraph arrives with the implementation. */
export const LEAN_INSTRUCTIONS = "";
