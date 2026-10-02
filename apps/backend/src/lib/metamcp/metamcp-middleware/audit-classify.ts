/**
 * Classify a proxied tool result for `tool_call_audit`: did the call fail, in
 * which class, and (when the tool said) with which code.
 *
 * WHY THIS EXISTS. An MCP tool failure can arrive two ways. A protocol-level
 * failure sets `isError: true` on the result, and the audit middleware already
 * recorded that as `success=false`. But nearly every tool in this fleet reports
 * its own refusals in-band, as an ordinary result whose body is a structured
 * envelope (`{error: true, code, message, ...}` or `{error: "<code>"}`), with
 * `isError` unset. Those rows were recorded `success=true`, so the audit
 * undercounted failure by an order of magnitude and a refused call looked like
 * a working one. This file reads the envelope and says so.
 *
 * NO WIRE CHANGE. This is a pure function over a result that has already been
 * produced. It never modifies, wraps or replaces what the client receives; the
 * middleware that calls it returns the very same object. A fault here must
 * therefore degrade to "recorded as before", and the caller guards that.
 *
 * Rows are write-once (migration 0032): a misclassified row cannot be updated
 * and stays for the 30-day window plus retention. That is why the in-band rule
 * is TOP-LEVEL ONLY, conservative, calibrated against real results, and carries
 * a kill switch (`TOOL_AUDIT_INBAND_CLASSIFY=off` disables the in-band step
 * only; isError, unknown-tool and retired handling keep working).
 *
 * VERDICT ORDER, first match wins:
 *   1. A result the retired-tool redirect produced (process-local marker, so a
 *      backend cannot spoof it with text)        -> failed, `tool_retired`.
 *   2. `isError === true`                         -> failed, `unknown_tool`
 *      when the text says no such tool, else `tool_error`.
 *   3. The in-band rule below                     -> failed, `inband_error`.
 *   4. Anything else                              -> success.
 *
 * THE IN-BAND RULE (top level of the unwrapped envelope, own properties only).
 * Let `e` be `envelope.error`. The call failed when ANY of:
 *   - `e === true`
 *   - `e` is a string with a non-blank value
 *   - `e` is a plain object with at least one own key
 *   - `envelope.error_code` is a string with a non-blank value (a standalone
 *     `{error_code: "invalid_input", ...}` refusal; Sol review 2026-10-02)
 *   - `envelope.status === "failed"` or `"partial"`, or `envelope.partial === true`
 *     (the batch-envelope vocabulary: a batch whose items were refused or not
 *     all dispatched, which carries no top-level `error`)
 * NOT a failure: `error` absent, null, false, "", 0 or any number (a count of
 * errored items is a tally, not a refusal), an array, or an empty object. A
 * tool's success result may carry `error: null` (Ninja does, on every
 * dispatch), and that must stay a success.
 * Nested keys are never inspected: a section that degraded inside an otherwise
 * good result (`patches: {error: ...}`), a vendor write's `read_back: {ok:
 * false, error: ...}` and per-item failures inside a list are not top-level
 * failures of the call. Residual false negatives (a refusal carried only by
 * `ok: false`, `warning` or `note`) are accepted and documented.
 *
 * ENVELOPE EXTRACTION. FastMCP wraps every non-object return annotation as
 * `structuredContent: {result: <value>}` with `_meta.fastmcp.wrap_result`, and
 * every `X | ErrorModel` union is non-object, so most tools' envelopes sit one
 * level down under `result`. The rule unwraps that, O(1), with no parsing.
 * Only when there is no structured content does it fall back to parsing the
 * first text block, size-capped, and only when that text starts with `{`.
 *
 * ERROR DETAIL is the tool's own failure code token, never free text: see
 * {@link codeToken}. It rides a separate column so `error_code` stays a small,
 * GROUP BY friendly class vocabulary.
 *
 * PURE and import-light (no database, no filesystem), so the audit
 * middleware's static graph stays DB-free.
 */

import { looksLikeUnknownTool } from "../unknown-tool";
import { isRetiredToolResult } from "./retired-tool-marker";

/** The class vocabulary stored in `tool_call_audit.error_code` for results. */
export type AuditErrorClass =
  | "tool_retired"
  | "unknown_tool"
  | "tool_error"
  | "inband_error";

export interface CallVerdict {
  failed: boolean;
  errorCode?: AuditErrorClass;
  /** The tool's own failure code token, or a fixed marker. Never free text. */
  errorDetail?: string;
}

/** A text block larger than this is not parsed when there is no structuredContent. */
export const INBAND_TEXT_MAX_CHARS = 32768;
/** A stored `error_detail` token is at most this long; longer is dropped. */
export const ERROR_DETAIL_MAX = 48;
/** Fixed markers for a failure that carries no code token of its own. */
export const DETAIL_VALIDATION = "validation";
export const DETAIL_STATUS_FAILED = "status_failed";
export const DETAIL_PARTIAL = "partial";

/**
 * Kill switch for the in-band step. `TOOL_AUDIT_INBAND_CLASSIFY` set to `off`,
 * `false` or `0` (any case, whitespace ignored) disables it; default on. Read
 * per call so an operator hot-patching a container needs no restart hook.
 */
export function inbandEnabled(): boolean {
  const raw = process.env.TOOL_AUDIT_INBAND_CLASSIFY?.trim().toLowerCase();
  return raw !== "off" && raw !== "false" && raw !== "0";
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") return false;
  if (Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function own(object: Record<string, unknown>, key: string): unknown {
  return Object.prototype.hasOwnProperty.call(object, key)
    ? object[key]
    : undefined;
}

// A whole-string code: lowercase snake_case, at most ERROR_DETAIL_MAX chars.
const WHOLE_TOKEN = new RegExp(`^[a-z][a-z0-9_]{0,${ERROR_DETAIL_MAX - 1}}$`);
// The LEADING token of a longer string. It must be followed by the end of the
// string, a space, "(" or ":". That accepts "ninja_error (status=500): boom" and
// "unexpected_error: x" and rejects "device_not_found,bad" and a snake-cased
// word glued to punctuation. The run is BOUNDED to ERROR_DETAIL_MAX characters
// in the pattern itself: a longer run is dropped anyway, and the old unbounded
// `[a-z0-9_]*_[a-z0-9_]*` backtracked quadratically on a long `a_a_a_...!`
// (32 KB took 0.9 s, 128 KB 13 s of blocked event loop), and structuredContent
// is not size-capped. The "at least one underscore" rule (a plain word such as
// "provide" starts a sentence, it is not a code) is a plain includes() check in
// codeToken, not part of the pattern. Because the lookahead characters are not
// word characters, the match is always the whole run, never a prefix of it.
const LEADING_TOKEN = new RegExp(
  `^([a-z][a-z0-9_]{0,${ERROR_DETAIL_MAX - 1}})(?=$|[ (:])`,
);
const FOUR_DIGITS = /\d{4}/;

/**
 * Reduce a failure code field to a safe token, or null.
 *
 * The column is never fed free text: the value must be a string that is, or
 * starts with, a lowercase snake_case token no longer than ERROR_DETAIL_MAX
 * with no run of four or more digits (which is an id leaking into a code).
 * Sentences ("provide query or entity_id"), mixed case, punctuation, newlines,
 * numbers and objects all yield null, and the class alone then says
 * `inband_error`. Never throws.
 */
export function codeToken(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (trimmed.length === 0) return null;

  let token: string | null = null;
  if (WHOLE_TOKEN.test(trimmed)) {
    token = trimmed;
  } else {
    const match = LEADING_TOKEN.exec(trimmed);
    if (match?.[1].includes("_")) token = match[1];
  }

  if (token === null) return null;
  if (token.length > ERROR_DETAIL_MAX) return null;
  if (FOUR_DIGITS.test(token)) return null;
  return token;
}

/**
 * The tool's envelope object, or null when the result carries none.
 *
 * Structured content wins and is never parsed. A wrapped payload
 * (`_meta.fastmcp.wrap_result === true`, or a sole `result` key) is unwrapped:
 * an object inside is the envelope; a list or scalar inside is a payload that
 * can never be an error. With no structured content, the first text block is
 * parsed, but only when it is within INBAND_TEXT_MAX_CHARS and starts with `{`
 * (so a large list or prose body costs nothing), and only a plain object is
 * accepted; a text body that is only `{"result": ...}` is unwrapped like the
 * structured form, because FastMCP writes the same wrapped JSON into both. No
 * other block is parsed.
 */
export function extractEnvelope(
  result: unknown,
): Record<string, unknown> | null {
  if (!isPlainObject(result)) return null;

  const structured = own(result, "structuredContent");
  if (isPlainObject(structured)) {
    const meta = own(result, "_meta");
    const fastmcp = isPlainObject(meta) ? own(meta, "fastmcp") : undefined;
    const flagged =
      isPlainObject(fastmcp) && own(fastmcp, "wrap_result") === true;
    const soleResult =
      Object.prototype.hasOwnProperty.call(structured, "result") &&
      Object.keys(structured).length === 1;
    if (flagged || soleResult) {
      const inner = own(structured, "result");
      return isPlainObject(inner) ? inner : null;
    }
    return structured;
  }

  const content = own(result, "content");
  if (!Array.isArray(content) || content.length === 0) return null;
  const first: unknown = content[0];
  if (!isPlainObject(first) || own(first, "type") !== "text") return null;
  const text = own(first, "text");
  if (typeof text !== "string") return null;
  if (text.length > INBAND_TEXT_MAX_CHARS) return null;
  if (text.trimStart().charAt(0) !== "{") return null;
  try {
    const parsed: unknown = JSON.parse(text);
    if (!isPlainObject(parsed)) return null;
    // FastMCP writes the SAME wrapped JSON into the text block that it puts in
    // structuredContent, so a text body that is only `{"result": ...}` is the
    // wrapper too. Same rule as above, so the two paths cannot disagree.
    if (
      Object.keys(parsed).length === 1 &&
      Object.prototype.hasOwnProperty.call(parsed, "result")
    ) {
      const inner = parsed.result;
      return isPlainObject(inner) ? inner : null;
    }
    return parsed;
  } catch {
    return null;
  }
}

/** First non-null code token an envelope offers, in a fixed precedence. */
function envelopeCodeToken(envelope: Record<string, unknown>): string | null {
  const error = own(envelope, "error");
  return (
    codeToken(own(envelope, "code")) ??
    codeToken(own(envelope, "error_code")) ??
    (isPlainObject(error) ? codeToken(own(error, "code")) : null) ??
    (typeof error === "string" ? codeToken(error) : null)
  );
}

interface InbandFinding {
  detail?: string;
}

/**
 * Apply the in-band rule to an envelope. Returns null when the call did not
 * fail, otherwise the failure with its detail token when one exists. Exported
 * for the table-driven tests; callers use {@link classifyCallResult}.
 */
export function inbandFailure(
  envelope: Record<string, unknown>,
): InbandFinding | null {
  const error = own(envelope, "error");
  const errorFlag =
    error === true ||
    (typeof error === "string" && error.trim() !== "") ||
    (isPlainObject(error) && Object.keys(error).length > 0);

  const errorCode = own(envelope, "error_code");
  const errorCodeFlag =
    typeof errorCode === "string" && errorCode.trim() !== "";

  const status = own(envelope, "status");
  const statusFailed = status === "failed";
  const statusPartial =
    status === "partial" || own(envelope, "partial") === true;

  if (!errorFlag && !errorCodeFlag && !statusFailed && !statusPartial) {
    return null;
  }

  const token = envelopeCodeToken(envelope);
  if (token !== null) return { detail: token };
  // A marker only when the error key itself said nothing: an error with no
  // token stays class-only, as the design records.
  if (errorFlag || errorCodeFlag) return {};
  return { detail: statusFailed ? DETAIL_STATUS_FAILED : DETAIL_PARTIAL };
}

/** The first text block's text, capped, or "" when there is none. */
function firstText(result: Record<string, unknown>, max: number): string {
  const content = own(result, "content");
  if (!Array.isArray(content) || content.length === 0) return "";
  const first: unknown = content[0];
  if (!isPlainObject(first) || own(first, "type") !== "text") return "";
  const text = own(first, "text");
  return typeof text === "string" ? text.slice(0, max) : "";
}

// FastMCP / pydantic argument refusals: "1 validation error for call[search]"
// and the SDK's "Input validation error: ...". Matched on the first 80 chars.
const VALIDATION_REFUSAL =
  /^\s*(?:MCP error -?\d+:\s*)?(?:\d+ validation errors? for call\[|Input validation error:)/;

/**
 * Classify one tool result. See the module header for the verdict order and the
 * in-band rule. Total over any input except a hostile object whose property
 * reads throw; the audit middleware guards the call for that case.
 */
export function classifyCallResult(result: unknown): CallVerdict {
  if (isRetiredToolResult(result)) {
    return { failed: true, errorCode: "tool_retired" };
  }
  if (!isPlainObject(result)) {
    return { failed: false };
  }

  if (own(result, "isError") === true) {
    const text = firstText(result, 512);
    if (looksLikeUnknownTool(text)) {
      return { failed: true, errorCode: "unknown_tool" };
    }
    const envelope = extractEnvelope(result);
    const token = envelope ? envelopeCodeToken(envelope) : null;
    if (token !== null) {
      return { failed: true, errorCode: "tool_error", errorDetail: token };
    }
    if (VALIDATION_REFUSAL.test(text.slice(0, 80))) {
      return {
        failed: true,
        errorCode: "tool_error",
        errorDetail: DETAIL_VALIDATION,
      };
    }
    return { failed: true, errorCode: "tool_error" };
  }

  if (inbandEnabled()) {
    const envelope = extractEnvelope(result);
    if (envelope) {
      const finding = inbandFailure(envelope);
      if (finding) {
        return {
          failed: true,
          errorCode: "inband_error",
          ...(finding.detail !== undefined && { errorDetail: finding.detail }),
        };
      }
    }
  }

  return { failed: false };
}
