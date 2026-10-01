/**
 * Synthetic result bodies for the audit classifier, one row per shape seen in a
 * replay over real tool results. They carry only the KEY SETS and status
 * vocabulary of those results, never a real value, client name or payload.
 *
 * Each row is a complete CallToolResult as the gateway sees it (content plus,
 * for FastMCP backends, structuredContent), with the verdict the classifier
 * must return. The table is the contract: adding a tool whose envelope looks
 * different means adding a row here first.
 */

import type { AuditErrorClass } from "./audit-classify";

export interface ClassifierFixture {
  name: string;
  result: unknown;
  expected: {
    failed: boolean;
    errorCode?: AuditErrorClass;
    errorDetail?: string;
  };
}

const text = (body: unknown) => ({
  type: "text" as const,
  text: typeof body === "string" ? body : JSON.stringify(body),
});

/** A FastMCP object-returning tool: structuredContent is the dict itself. */
const objectResult = (body: Record<string, unknown>) => ({
  content: [text(body)],
  structuredContent: body,
});

/** A FastMCP union-returning tool: structuredContent wraps under `result`. */
const wrappedResult = (body: unknown) => ({
  content: [text(body)],
  structuredContent: { result: body },
  _meta: { fastmcp: { wrap_result: true } },
});

/** A text-only backend: no structuredContent at all. */
const textResult = (body: unknown) => ({ content: [text(body)] });

const FAIL = (errorDetail?: string): ClassifierFixture["expected"] => ({
  failed: true,
  errorCode: "inband_error",
  ...(errorDetail !== undefined && { errorDetail }),
});
const OK: ClassifierFixture["expected"] = { failed: false };

export const CLASSIFIER_FIXTURES: ClassifierFixture[] = [
  // ---- S1: error:true with a code (the shared gateway_auth.error() shape) ----
  {
    name: "S1 object envelope, invalid_input",
    result: objectResult({
      error: true,
      code: "invalid_input",
      message: "m",
      context: { field: "mode" },
    }),
    expected: FAIL("invalid_input"),
  },
  {
    name: "S1 wrapped union, not_found",
    result: wrappedResult({ error: true, code: "not_found", message: "m" }),
    expected: FAIL("not_found"),
  },
  {
    name: "S1 wrapped union without the _meta flag (sole result key)",
    result: {
      content: [text({ error: true, code: "not_found" })],
      structuredContent: { result: { error: true, code: "not_found" } },
    },
    expected: FAIL("not_found"),
  },
  {
    name: "S1 upstream graph error code",
    result: wrappedResult({
      error: true,
      code: "graph_upstream_error",
      message: "m",
    }),
    expected: FAIL("graph_upstream_error"),
  },
  {
    name: "S1 refusal that names a scope",
    result: objectResult({
      error: true,
      code: "scope_ambiguous",
      message: "m",
      context: { candidates: [] },
    }),
    expected: FAIL("scope_ambiguous"),
  },
  {
    name: "S1 text-only backend",
    result: textResult({ error: true, code: "invalid_request", message: "m" }),
    expected: FAIL("invalid_request"),
  },
  {
    name: "S1 error:true with no code at all",
    result: objectResult({ error: true, message: "m" }),
    expected: FAIL(),
  },

  // ---- S2: error:'<code>' string ----
  {
    name: "S2 string code (boolean twin of not_found)",
    result: objectResult({ error: "not_found", message: "m" }),
    expected: FAIL("not_found"),
  },
  {
    name: "S2 session_not_open",
    result: objectResult({ error: "session_not_open", session_id: "s" }),
    expected: FAIL("session_not_open"),
  },
  {
    name: "S2 sentence with a sibling error_code",
    result: objectResult({
      error: "no client matches that name",
      error_code: "client_ambiguous",
    }),
    expected: FAIL("client_ambiguous"),
  },
  {
    name: "S2 sentence with no code",
    result: objectResult({ error: "provide query or entity_id" }),
    expected: FAIL(),
  },
  {
    name: "S2 leading token followed by a colon",
    result: objectResult({ error: "unexpected_error: it broke" }),
    expected: FAIL("unexpected_error"),
  },
  {
    name: "S2b status failed with a code-and-sentence error",
    result: objectResult({
      action: "run_script",
      status: "failed",
      error: "ninja_error (status=500): boom",
    }),
    expected: FAIL("ninja_error"),
  },

  // ---- S3: error object ----
  {
    name: "S3 error object with a code",
    result: objectResult({
      error: { code: "invalid_request", message: "m" },
    }),
    expected: FAIL("invalid_request"),
  },
  {
    name: "S3 error object with no code",
    result: objectResult({ error: { message: "m" } }),
    expected: FAIL(),
  },

  // ---- Batch envelopes (status vocabulary, no top-level error) ----
  {
    name: "batch: status failed with no error key",
    result: objectResult({
      action: "run_script",
      status: "failed",
      batch: { requested: 2, fired: 0, refused: 2 },
      items: [],
    }),
    expected: FAIL("status_failed"),
  },
  {
    name: "batch: status partial",
    result: objectResult({
      action: "run_script",
      status: "partial",
      batch: { requested: 3, fired: 2, refused: 1 },
      items: [],
    }),
    expected: FAIL("partial"),
  },
  {
    name: "batch: partial true with success false (checklist shape)",
    result: wrappedResult({
      success: false,
      partial: true,
      applied: [1],
      failed: [{ id: 2, code: "not_found" }],
    }),
    expected: FAIL("partial"),
  },
  {
    name: "batch: partial true carrying a code",
    result: objectResult({ partial: true, code: "partial_failure" }),
    expected: FAIL("partial_failure"),
  },
  {
    name: "batch: status failed with error null still fails on status",
    result: objectResult({ status: "failed", error: null }),
    expected: FAIL("status_failed"),
  },
  {
    name: "batch: dispatched is a success",
    result: objectResult({
      action: "run_script",
      status: "dispatched",
      batch: { requested: 2, fired: 2 },
      error: null,
    }),
    expected: OK,
  },
  {
    name: "batch: await_run completed is a success even with failing runs inside",
    result: objectResult({
      action: "await_run",
      status: "completed",
      batch: { requested: 2, completed: 2, by_result: { FAILURE: 1 } },
      runs: [{ status: "completed", activity_result: "FAILURE" }],
    }),
    expected: OK,
  },
  {
    name: "batch: partial false is a success",
    result: objectResult({ partial: false, applied: [1, 2] }),
    expected: OK,
  },

  // ---- Successes that must NOT misfire ----
  {
    name: "ninja dispatch success carries error null",
    result: objectResult({
      status: "succeeded",
      result: {},
      error: null,
      action: "run_script",
    }),
    expected: OK,
  },
  {
    name: "ordinary object result, no error key",
    result: objectResult({ tickets: [], total: 0 }),
    expected: OK,
  },
  {
    name: "wrapped list payload",
    result: wrappedResult([{ id: 1 }, { id: 2 }]),
    expected: OK,
  },
  {
    name: "wrapped scalar payload",
    result: wrappedResult("a plain string"),
    expected: OK,
  },
  {
    name: "wrapped number payload",
    result: wrappedResult(7),
    expected: OK,
  },
  {
    name: "error false",
    result: objectResult({ error: false, ok: true }),
    expected: OK,
  },
  {
    name: "error empty string",
    result: objectResult({ error: "" }),
    expected: OK,
  },
  {
    name: "error blank string",
    result: objectResult({ error: "   " }),
    expected: OK,
  },
  {
    name: "error zero",
    result: objectResult({ error: 0 }),
    expected: OK,
  },
  {
    name: "error as a tally",
    result: objectResult({ error: 3, total: 10 }),
    expected: OK,
  },
  {
    name: "error empty array",
    result: objectResult({ error: [] }),
    expected: OK,
  },
  {
    name: "error empty object",
    result: objectResult({ error: {} }),
    expected: OK,
  },
  {
    name: "sms-style success with no error key",
    result: objectResult({
      messages: [{ from: "x", body: "y" }],
      count: 1,
    }),
    expected: OK,
  },

  // ---- Nested errors that must NOT count ----
  {
    name: "briefing section degraded inside a good result",
    result: objectResult({
      device: { name: "d1" },
      patches: { error: "patches_unavailable", message: "m" },
    }),
    expected: OK,
  },
  {
    name: "wrapped result with a nested error deeper down",
    result: wrappedResult({ sections: { x: { error: true } } }),
    expected: OK,
  },
  {
    name: "vendor write with a failed read-back sub-object",
    result: objectResult({
      ok: true,
      read_back: { ok: false, error: { code: "x" } },
    }),
    expected: OK,
  },
  {
    name: "per-item failures inside a list",
    result: objectResult({
      results: [{ id: 1, error: true }, { id: 2 }],
    }),
    expected: OK,
  },
  {
    name: "documented false negative: top-level ok:false with no error",
    result: objectResult({ ok: false, authenticated: false }),
    expected: OK,
  },

  // ---- Edge shapes ----
  {
    name: "non-object text body",
    result: textResult("plain prose, not json"),
    expected: OK,
  },
  {
    name: "text body that is a JSON list",
    result: textResult([{ error: true }]),
    expected: OK,
  },
  {
    name: "no content at all",
    result: { content: [] },
    expected: OK,
  },
];
