import { z } from "zod";

/**
 * Per-endpoint presentation settings (migration 0044): the title and the
 * instructions paragraph a client receives at `initialize`, an output-schema
 * trim for `tools/list`, and a tool listing mode.
 *
 * WHO WRITES THIS. Only a human administrator, through a browser session:
 * the text reaches models, which is the same class of act as a tool override,
 * so no admin-plane key of either scope can call these procedures (they are in
 * neither procedure set in `packages/trpc/src/trpc.ts`).
 */

/**
 * Bounds, mirrored by CHECK constraints in migration 0044. The app is the
 * stricter layer: zod counts UTF-16 code units (`String.length`), Postgres
 * counts code points, so any value the app accepts is also accepted by the
 * database and a CHECK is never the first thing to refuse a request.
 *
 * 1500 for the instructions leaves room for the lean-listing paragraph that a
 * later release prepends on a lean endpoint, keeping the combined text under
 * the 2 KiB some clients are reported to keep (unverified), so the tail of an
 * administrator's text is not the part that gets cut.
 */
export const ENDPOINT_TITLE_MAX = 80;
export const ENDPOINT_INSTRUCTIONS_MAX = 1500;

/**
 * Tool listing modes. BOTH values are accepted by every RESPONSE schema from
 * the first release, so a stored `lean` row can never fail output validation
 * (an image rolled back past the release that serves it, or a row inserted by
 * hand). Only the SET request is narrower, see below.
 */
export const ToolListingModeSchema = z.enum(["full", "lean"]);
export type ToolListingMode = z.infer<typeof ToolListingModeSchema>;

/**
 * The one canonical form of an administrator-entered text: CRLF and CR become
 * LF, surrounding whitespace is trimmed, and empty becomes null (no text).
 * Applied by the request schemas, by the implementation again (it can be
 * called without them) and by the admin panel, so a value is compared, bounded
 * and stored in exactly one shape.
 */
export function normalizePresentationText(
  value: string | null | undefined,
): string | null {
  if (value === null || value === undefined) return null;
  const normalized = value.replace(/\r\n?/g, "\n").trim();
  return normalized === "" ? null : normalized;
}

/** Why a normalized text was refused. A closed set so callers can map it to copy. */
export type PresentationTextProblem =
  | "too_long"
  | "newline"
  | "control"
  | "format";

/**
 * C0 controls other than TAB and LF, DEL and the C1 controls: characters that
 * render as nothing, move a cursor, or are read as terminal escapes. TAB and LF
 * stay legal in a multi-line text. CR cannot survive normalization, so a CR
 * here means the caller skipped it, and is refused rather than passed through.
 */
// eslint-disable-next-line no-control-regex -- the control ranges are the point
const CONTROL_MULTILINE = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F]/;
/**
 * A single-line text allows no C0 control at all, TAB included. LF and CR are
 * in the range too, though `presentationTextProblem` reports them as a
 * newline first.
 */
// eslint-disable-next-line no-control-regex -- the control ranges are the point
const CONTROL_SINGLE_LINE = /[\u0000-\u001F\u007F-\u009F]/;
/**
 * Unicode format characters (category Cf): bidirectional overrides and
 * isolates, zero-width spaces and joiners, the soft hyphen, tag characters and
 * the byte-order mark. They change how text reads, or hide text altogether,
 * without being visible, which is the wrong property in a string that is
 * handed to a model as guidance.
 */
const FORMAT_CHARACTER = /\p{Cf}/u;

/**
 * The first rule a NORMALIZED text breaks, or null. `max` counts UTF-16 code
 * units, the same unit as `String.length` and zod's `.max()`.
 */
export function presentationTextProblem(
  normalized: string,
  options: { max: number; singleLine: boolean },
): PresentationTextProblem | null {
  // Unicode line and paragraph separators also break a display title across
  // lines, although they are neither C0/C1 controls nor format characters.
  if (options.singleLine && /[\n\r\u2028\u2029]/.test(normalized))
    return "newline";
  const control = options.singleLine ? CONTROL_SINGLE_LINE : CONTROL_MULTILINE;
  if (control.test(normalized)) return "control";
  if (FORMAT_CHARACTER.test(normalized)) return "format";
  if (normalized.length > options.max) return "too_long";
  return null;
}

/** Fixed messages: they name the rule and never echo the submitted text. */
function presentationTextMessage(
  problem: PresentationTextProblem,
  max: number,
): string {
  switch (problem) {
    case "too_long":
      return `Must be ${max} characters or fewer.`;
    case "newline":
      return "Must be a single line.";
    case "control":
      return "Must not contain control characters.";
    case "format":
      return "Must not contain invisible or text-direction characters.";
  }
}

/**
 * A nullable administrator text. Normalized first, then bounded, so a value
 * with a trailing newline or CRLF line ends is judged as it will be stored.
 * The parsed value is the normalized one.
 */
const presentationText = (max: number, singleLine: boolean) =>
  z
    .string()
    .nullable()
    .transform((value) => normalizePresentationText(value))
    .pipe(
      z
        .string()
        .nullable()
        .superRefine((value, ctx) => {
          if (value === null) return;
          const problem = presentationTextProblem(value, { max, singleLine });
          if (problem !== null) {
            ctx.addIssue({
              code: "custom",
              message: presentationTextMessage(problem, max),
            });
          }
        }),
    );

export const EndpointTitleSchema = presentationText(ENDPOINT_TITLE_MAX, true);
export const EndpointInstructionsSchema = presentationText(
  ENDPOINT_INSTRUCTIONS_MAX,
  false,
);

export const EndpointPresentationSchema = z.object({
  endpoint_uuid: z.string(),
  title: z.string().nullable(),
  instructions: z.string().nullable(),
  tool_listing: ToolListingModeSchema,
  omit_output_schemas: z.boolean(),
  // Null when no row exists (every setting at its default).
  updated_at: z.string().nullable(),
});

export const GetEndpointPresentationRequestSchema = z.object({
  endpoint_uuid: z.string().uuid(),
});

/**
 * A full replacement, not a patch: the panel always holds the whole state, so
 * a field that is not sent is not "left alone", and the request can never carry
 * half of an earlier edit forward.
 *
 * `tool_listing` is the literal `full` in this release so nothing can be
 * stored that the gateway does not serve; the read side still accepts both
 * modes (see ToolListingModeSchema). A release that serves `lean` widens this
 * one line.
 */
export const SetEndpointPresentationRequestSchema = z.object({
  endpoint_uuid: z.string().uuid(),
  title: EndpointTitleSchema,
  instructions: EndpointInstructionsSchema,
  tool_listing: z.literal("full"),
  omit_output_schemas: z.boolean(),
});

/**
 * What the gateway will actually do with the stored settings. `effective`
 * reports the process-level kill switches so the panel can say so when a saved
 * setting would not take effect, instead of showing a setting that silently
 * does nothing.
 */
export const EndpointPresentationEffectiveSchema = z.object({
  presentation_enabled: z.boolean(),
  lean_enabled: z.boolean(),
});

export const GetEndpointPresentationResponseSchema = z.object({
  success: z.boolean(),
  data: EndpointPresentationSchema.extend({
    effective: EndpointPresentationEffectiveSchema,
  }).optional(),
  message: z.string().optional(),
});

export const SetEndpointPresentationResponseSchema = z.object({
  success: z.boolean(),
  data: EndpointPresentationSchema.optional(),
  message: z.string().optional(),
});

export type EndpointPresentation = z.infer<typeof EndpointPresentationSchema>;
export type GetEndpointPresentationRequest = z.infer<
  typeof GetEndpointPresentationRequestSchema
>;
export type SetEndpointPresentationRequest = z.input<
  typeof SetEndpointPresentationRequestSchema
>;
export type GetEndpointPresentationResponse = z.infer<
  typeof GetEndpointPresentationResponseSchema
>;
export type SetEndpointPresentationResponse = z.infer<
  typeof SetEndpointPresentationResponseSchema
>;
