/**
 * A lost audit row is reported on the WARN line, and that line must not copy
 * the row it failed to write.
 *
 * Drizzle wraps a failed query in a DrizzleQueryError whose message is
 * "Failed query: <sql>\nparams: <bound values>" and which also carries the
 * bound values on `.params`. An audit row's bound values are the event: actor
 * labels, user agents, request detail, and administrator-authored text such
 * as endpoint instructions. Logging the raw error therefore copies the event
 * into the container log on exactly the path where the durable copy failed.
 * The report keeps what an operator needs to diagnose the failure (the error
 * class and the database's own error code and constraint) and nothing else.
 */

import { format } from "node:util";

import { DrizzleQueryError } from "drizzle-orm/errors";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { loggerMock } = vi.hoisted(() => ({
  loggerMock: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

const { emit, resetAuditFailureReportingForTesting, setAuditSinkForTesting } =
  await import("./audit-emitter");

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

const SECRET = "Instructions only an administrator wrote";

function postgresCause(): Error {
  // The shape node-postgres gives a server-side error: a message that can
  // quote values, a detail that does quote them, and stable identifiers.
  return Object.assign(
    new Error(`value too long for type character varying: ${SECRET}`),
    {
      code: "22001",
      constraint: "endpoint_presentation_instructions_len",
      detail: `Failing row contains (${SECRET}).`,
    },
  );
}

function loggedText(): string {
  return [
    ...loggerMock.warn.mock.calls,
    ...loggerMock.error.mock.calls,
    ...loggerMock.info.mock.calls,
    ...loggerMock.debug.mock.calls,
  ]
    .map((args) => format(...args))
    .join("\n");
}

beforeEach(() => {
  vi.clearAllMocks();
  resetAuditFailureReportingForTesting();
  setAuditSinkForTesting(undefined);
});

describe("audit write failure report", () => {
  it("keeps bound values, the query text and the database detail out of the log", async () => {
    setAuditSinkForTesting(async () => {
      throw new DrizzleQueryError(
        'insert into "audit_log" ("action", "detail") values ($1, $2)',
        ["endpoint.presentation.set", JSON.stringify({ instructions: SECRET })],
        postgresCause(),
      );
    });

    emit({
      actor_type: "user",
      action: "endpoint.presentation.set",
      outcome: "success",
    });
    await flush();

    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    const logged = loggedText();
    expect(logged).not.toContain(SECRET);
    expect(logged).not.toContain('insert into "audit_log"');
    expect(logged).not.toContain("Failing row contains");
  });

  it("still names the error class and the database code and constraint", async () => {
    setAuditSinkForTesting(async () => {
      throw new DrizzleQueryError(
        'insert into "audit_log" ("detail") values ($1)',
        [SECRET],
        postgresCause(),
      );
    });

    emit({
      actor_type: "user",
      action: "endpoint.presentation.set",
      outcome: "success",
    });
    await flush();

    const logged = loggedText();
    expect(logged).toContain("DrizzleQueryError");
    expect(logged).toContain("22001");
    expect(logged).toContain("endpoint_presentation_instructions_len");
    expect(logged).toContain("audit row(s) lost since startup");
  });

  it("keeps a server error's message out even without a Drizzle wrapper", async () => {
    // A Postgres server error can quote the offending value in its message
    // ("invalid input syntax for type uuid: ..."); a five-character SQLSTATE
    // marks it as query-bearing whatever wraps it.
    setAuditSinkForTesting(async () => {
      throw postgresCause();
    });

    emit({
      actor_type: "user",
      action: "endpoint.presentation.set",
      outcome: "success",
    });
    await flush();

    const logged = loggedText();
    expect(logged).not.toContain(SECRET);
    expect(logged).toContain("22001");
  });

  it("keeps a connection failure's own message, which is the diagnosis", async () => {
    setAuditSinkForTesting(async () => {
      throw Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:5432"), {
        code: "ECONNREFUSED",
      });
    });

    emit({
      actor_type: "user",
      action: "endpoint.presentation.set",
      outcome: "success",
    });
    await flush();

    const logged = loggedText();
    expect(logged).toContain("code=ECONNREFUSED");
    expect(logged).toContain("connect ECONNREFUSED 127.0.0.1:5432");
  });
});
