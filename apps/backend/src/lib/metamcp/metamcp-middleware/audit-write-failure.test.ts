/**
 * A failed tool_call_audit insert must be visible (#241).
 *
 * Before the report existed, `persist()` swallowed the rejection with an empty
 * catch, so a schema mismatch, a constraint or a dropped connection lost audit
 * rows with no trace and a gap read as "nobody called this". These cases force
 * the recorder to fail and read the log and the counter, never the code.
 *
 * Transport-level fake: the recorder is the repository's `record`, the only
 * thing the middleware hands the row to. Date is faked (not the timers) so the
 * one-line-a-minute window is driven without a real wait.
 */
import { CallToolRequest } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import logger from "@/utils/logger";

import {
  reportToolCallAuditDrop,
  resetToolCallAuditFailureReportingForTesting,
  toolCallAuditFailureCount,
} from "./audit-write-failure";
import {
  createAuditingMiddleware,
  setAuditRecorderForTesting,
} from "./auditing.functional";
import { MetaMCPHandlerContext } from "./functional-middleware";

const context: MetaMCPHandlerContext = {
  namespaceUuid: "ns-123",
  sessionId: "sess-456",
  clientName: "example connector",
  requestId: "req-aaaa",
};

/** Text that must never reach a log line: an argument value and a row value. */
const SECRET_ARGUMENT = "hunter2-argument-value";
const SECRET_ROW_VALUE = "row-value-from-failing-insert";

const makeRequest = (name = "autotask__search"): CallToolRequest =>
  ({
    method: "tools/call",
    params: { name, arguments: { note: SECRET_ARGUMENT } },
  }) as CallToolRequest;

const okHandler = vi.fn().mockResolvedValue({ content: [] });

/** What node-postgres and Drizzle produce for a failed insert. */
function insertFailure(): Error {
  const pgError = Object.assign(
    new Error(
      `duplicate key value violates unique constraint (${SECRET_ROW_VALUE})`,
    ),
    {
      code: "23505",
      constraint: "tool_call_audit_pkey",
      table: "tool_call_audit",
      detail: `Key (id)=(${SECRET_ROW_VALUE}) already exists.`,
      severity: "ERROR",
    },
  );
  class DrizzleQueryError extends Error {
    params = [SECRET_ARGUMENT, SECRET_ROW_VALUE];
    query = "insert into tool_call_audit values ($1, $2)";
  }
  const error = new DrizzleQueryError(
    `Failed query: insert into tool_call_audit values ($1, $2)\nparams: ${SECRET_ARGUMENT},${SECRET_ROW_VALUE}`,
  );
  (error as { cause?: unknown }).cause = pgError;
  return error;
}

// Flush the fire-and-forget persist() chain (resolveRecorder().then(...)).
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

const callOnce = async (name?: string) => {
  const wrapped = createAuditingMiddleware()(okHandler);
  const result = await wrapped(makeRequest(name), context);
  await flush();
  return result;
};

let warn: ReturnType<typeof vi.spyOn>;

/** Everything the WARN spy was handed, as one string. */
const warned = () => JSON.stringify(warn.mock.calls);

beforeEach(() => {
  // Date only: the flush above needs real timers. The reporter throttles to one
  // line a minute PROCESS-WIDE, so each case starts from a fresh window.
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2026-11-19T12:00:00Z"));
  resetToolCallAuditFailureReportingForTesting();
  warn = vi.spyOn(logger, "warn").mockImplementation(() => undefined);
});

afterEach(() => {
  setAuditRecorderForTesting(null);
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.clearAllMocks();
});

describe("a rejected audit insert is reported (#241)", () => {
  it("logs one WARN naming server, tool and cause, counts the row and leaves the call alone", async () => {
    setAuditRecorderForTesting(vi.fn().mockRejectedValue(insertFailure()));

    const result = await callOnce();

    expect(result).toEqual({ content: [] });
    expect(toolCallAuditFailureCount()).toBe(1);
    expect(warn).toHaveBeenCalledTimes(1);
    const line = String(warn.mock.calls[0][0]);
    expect(line).toContain("[tool-call-audit]");
    expect(line).toContain("1 audit row(s) lost since startup");
    expect(line).toContain("server=autotask");
    expect(line).toContain("tool=search");
    // The class and the database's identifiers are what a responder needs.
    expect(line).toContain("DrizzleQueryError");
    expect(line).toContain("code=23505");
    expect(line).toContain("constraint=tool_call_audit_pkey");
  });

  it("puts no argument text, row value, query text or error message in the line", async () => {
    setAuditRecorderForTesting(vi.fn().mockRejectedValue(insertFailure()));

    await callOnce();

    expect(warn).toHaveBeenCalledTimes(1);
    const text = warned();
    expect(text).not.toContain(SECRET_ARGUMENT);
    expect(text).not.toContain(SECRET_ROW_VALUE);
    expect(text).not.toContain("insert into");
    expect(text).not.toContain("Failed query");
    expect(text).not.toContain("duplicate key");
  });

  it("is a WARN, not an ERROR: a lost row is a degraded record, not a failed request", async () => {
    const error = vi.spyOn(logger, "error").mockImplementation(() => undefined);
    setAuditRecorderForTesting(vi.fn().mockRejectedValue(insertFailure()));

    await callOnce();

    expect(warn).toHaveBeenCalledTimes(1);
    expect(error).not.toHaveBeenCalled();
  });

  it("reports a recorder that throws synchronously as well as one that rejects", async () => {
    setAuditRecorderForTesting(() => {
      throw new Error("sync boom");
    });

    await callOnce();

    expect(toolCallAuditFailureCount()).toBe(1);
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it("reports the row of a call that threw, not only one that returned", async () => {
    setAuditRecorderForTesting(vi.fn().mockRejectedValue(insertFailure()));
    const wrapped = createAuditingMiddleware()(
      vi.fn().mockRejectedValue(new Error("backend down")),
    );

    await expect(wrapped(makeRequest(), context)).rejects.toThrow(
      "backend down",
    );
    await flush();

    expect(toolCallAuditFailureCount()).toBe(1);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toContain("tool=search");
  });

  it("says nothing and counts nothing for a write that succeeds", async () => {
    setAuditRecorderForTesting(vi.fn().mockResolvedValue(undefined));

    await callOnce();

    expect(toolCallAuditFailureCount()).toBe(0);
    expect(warn).not.toHaveBeenCalled();
  });

  it("says nothing when there is no sink at all (no database in this process)", async () => {
    setAuditRecorderForTesting(null);

    await callOnce();

    expect(toolCallAuditFailureCount()).toBe(0);
    expect(warn).not.toHaveBeenCalled();
  });
});

describe("a burst of failures is counted in full and logged once a minute", () => {
  it("counts every drop, logs the first, and logs the running total after the window", async () => {
    setAuditRecorderForTesting(vi.fn().mockRejectedValue(insertFailure()));

    for (let i = 0; i < 25; i += 1) {
      await callOnce();
    }

    expect(toolCallAuditFailureCount()).toBe(25);
    expect(warn).toHaveBeenCalledTimes(1);

    vi.setSystemTime(new Date("2026-11-19T12:00:59Z"));
    await callOnce();
    expect(warn).toHaveBeenCalledTimes(1);

    vi.setSystemTime(new Date("2026-11-19T12:01:00Z"));
    await callOnce();
    expect(warn).toHaveBeenCalledTimes(2);
    // A running total since startup, not a per-window delta.
    expect(String(warn.mock.calls[1][0])).toContain(
      "27 audit row(s) lost since startup",
    );
  });

  it("does not let the very first failure vanish when the clock reads the epoch", async () => {
    vi.setSystemTime(new Date(0));
    setAuditRecorderForTesting(vi.fn().mockRejectedValue(insertFailure()));

    await callOnce();

    expect(warn).toHaveBeenCalledTimes(1);
  });
});

describe("the report itself can never break the audit path", () => {
  it("keeps counting and rejects nothing when the logger throws", async () => {
    warn.mockImplementation(() => {
      throw new Error("log sink closed");
    });
    setAuditRecorderForTesting(vi.fn().mockRejectedValue(insertFailure()));

    // An unhandled rejection from the detached chain fails the run.
    const result = await callOnce();

    expect(result).toEqual({ content: [] });
    expect(toolCallAuditFailureCount()).toBe(1);
  });

  it("survives an error value whose properties throw when read", () => {
    const hostile = new Proxy(
      {},
      {
        get() {
          throw new Error("trap");
        },
        getPrototypeOf() {
          throw new Error("trap");
        },
      },
    );

    expect(() =>
      reportToolCallAuditDrop(
        { server_name: "autotask", tool_name: "search" },
        hostile,
      ),
    ).not.toThrow();
    expect(toolCallAuditFailureCount()).toBe(1);
    expect(String(warn.mock.calls[0][0])).toContain("summary unavailable");
  });

  it("bounds and cleans a caller-supplied tool name so it cannot forge a log line", async () => {
    setAuditRecorderForTesting(vi.fn().mockRejectedValue(insertFailure()));

    await callOnce(`autotask__bad\n[forged] ${"x".repeat(400)}`);

    expect(warn).toHaveBeenCalledTimes(1);
    const line = String(warn.mock.calls[0][0]);
    expect(line).not.toContain("\n");
    expect(line).toContain("tool=bad?[forged] xxx");
    expect(line.length).toBeLessThan(600);
  });
});
