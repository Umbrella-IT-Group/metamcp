/**
 * The admin read and write of an endpoint's presentation settings, below the
 * router: what is stored, what is refused, what is audited.
 *
 * Oracles. The ownership rule is `endpoints.update`'s (the endpoint's owner, or
 * anyone for a public endpoint). The "no row means defaults" rule and the
 * audit detail are the design's (C.4); the audit hash is recomputed here with
 * node:crypto rather than read back from the module. The text bounds are the
 * shared request schema's, asserted again at the write boundary because
 * `set` is callable without the router.
 */
import { createHash } from "node:crypto";
import { format } from "node:util";

import { GetEndpointPresentationResponseSchema } from "@repo/zod-types";
import { DrizzleQueryError } from "drizzle-orm/errors";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { findEndpointMock, findRowMock, upsertMock, deleteMock, loggerMock } =
  vi.hoisted(() => ({
    findEndpointMock: vi.fn(),
    findRowMock: vi.fn(),
    upsertMock: vi.fn(),
    deleteMock: vi.fn(),
    loggerMock: {
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
  }));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));
vi.mock("../db/repositories/endpoints.repo", () => ({
  endpointsRepository: { findByUuid: findEndpointMock },
}));
vi.mock("../db/repositories/endpoint-presentation.repo", () => ({
  endpointPresentationRepository: {
    findByEndpointUuid: findRowMock,
    upsert: upsertMock,
    deleteByEndpointUuid: deleteMock,
  },
}));

const { endpointPresentationImplementations: impl } = await import(
  "./endpoint-presentation.impl"
);
const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");

type AuditRow = {
  action: string;
  outcome: string;
  target_type?: string | null;
  target_id?: string | null;
  detail?: Record<string, unknown>;
};

const ENDPOINT_UUID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const ADMIN = "admin-1";
const ACTOR = {
  actor_id: ADMIN,
  actor_label: "admin@example.invalid",
  actor_ip: "203.0.113.9",
  actor_user_agent: "Mozilla/5.0",
  request_id: "req-1",
};
const ENDPOINT = { uuid: ENDPOINT_UUID, name: "desk", user_id: null };

const SAVED_SWITCH = process.env.MCP_ENDPOINT_PRESENTATION;
const SAVED_LEAN_SWITCH = process.env.MCP_LEAN_LISTING;

let audit: AuditRow[];
/** The audit sink runs on a promise chain; a macrotask drains it. */
const settle = () => new Promise<void>((resolve) => setImmediate(resolve));

const request = (over: Record<string, unknown> = {}) => ({
  endpoint_uuid: ENDPOINT_UUID,
  title: null,
  instructions: null,
  tool_listing: "full" as const,
  omit_output_schemas: false,
  ...over,
});

const storedRow = (over: Record<string, unknown> = {}) => ({
  endpoint_uuid: ENDPOINT_UUID,
  title: null,
  instructions: null,
  tool_listing: "full",
  omit_output_schemas: false,
  updated_at: new Date("2026-11-12T10:00:00.000Z"),
  ...over,
});

beforeEach(() => {
  vi.clearAllMocks();
  delete process.env.MCP_ENDPOINT_PRESENTATION;
  delete process.env.MCP_LEAN_LISTING;
  audit = [];
  setAuditSinkForTesting(async (event) => {
    audit.push(event as AuditRow);
  });
  findEndpointMock.mockResolvedValue(ENDPOINT);
  findRowMock.mockResolvedValue(undefined);
  upsertMock.mockImplementation(async (input: Record<string, unknown>) =>
    storedRow(input),
  );
  deleteMock.mockResolvedValue(true);
});

afterEach(() => {
  setAuditSinkForTesting(undefined);
  if (SAVED_SWITCH === undefined) delete process.env.MCP_ENDPOINT_PRESENTATION;
  else process.env.MCP_ENDPOINT_PRESENTATION = SAVED_SWITCH;
  if (SAVED_LEAN_SWITCH === undefined) delete process.env.MCP_LEAN_LISTING;
  else process.env.MCP_LEAN_LISTING = SAVED_LEAN_SWITCH;
});

describe("get", () => {
  it("an endpoint with no row reads as all defaults with no update time", async () => {
    const answer = await impl.get({ endpoint_uuid: ENDPOINT_UUID }, ADMIN);

    expect(answer).toEqual({
      success: true,
      data: {
        endpoint_uuid: ENDPOINT_UUID,
        title: null,
        instructions: null,
        tool_listing: "full",
        omit_output_schemas: false,
        updated_at: null,
        effective: { presentation_enabled: true, lean_enabled: true },
      },
    });
  });

  it("returns the stored row, the update time as ISO 8601", async () => {
    findRowMock.mockResolvedValue(
      storedRow({
        title: "Desk",
        instructions: "Be brief.",
        omit_output_schemas: true,
      }),
    );

    const answer = await impl.get({ endpoint_uuid: ENDPOINT_UUID }, ADMIN);

    expect(answer.data).toMatchObject({
      title: "Desk",
      instructions: "Be brief.",
      omit_output_schemas: true,
      updated_at: "2026-11-12T10:00:00.000Z",
    });
  });

  it("reports what the kill switch makes of a stored setting", async () => {
    process.env.MCP_ENDPOINT_PRESENTATION = "off";
    findRowMock.mockResolvedValue(storedRow({ title: "Desk" }));

    const answer = await impl.get({ endpoint_uuid: ENDPOINT_UUID }, ADMIN);

    expect(answer.data?.effective).toEqual({
      presentation_enabled: false,
      lean_enabled: true,
    });
  });

  it("reports the lean switch on its own, so the panel can say a saved lean listing is not applied", async () => {
    process.env.MCP_LEAN_LISTING = "off";
    findRowMock.mockResolvedValue(storedRow({ tool_listing: "lean" }));

    const answer = await impl.get({ endpoint_uuid: ENDPOINT_UUID }, ADMIN);

    expect(answer.data?.tool_listing).toBe("lean");
    expect(answer.data?.effective).toEqual({
      presentation_enabled: true,
      lean_enabled: false,
    });
  });

  it("a stored lean row reads back and still satisfies the response schema", async () => {
    findRowMock.mockResolvedValue(storedRow({ tool_listing: "lean" }));

    const answer = await impl.get({ endpoint_uuid: ENDPOINT_UUID }, ADMIN);

    expect(answer.data?.tool_listing).toBe("lean");
    expect(
      GetEndpointPresentationResponseSchema.safeParse(answer).success,
    ).toBe(true);
  });

  it("answers Endpoint not found for an unknown endpoint", async () => {
    findEndpointMock.mockResolvedValue(undefined);
    expect(await impl.get({ endpoint_uuid: ENDPOINT_UUID }, ADMIN)).toEqual({
      success: false,
      message: "Endpoint not found",
    });
    expect(findRowMock).not.toHaveBeenCalled();
  });

  it("refuses a private endpoint owned by someone else, and reads no row", async () => {
    findEndpointMock.mockResolvedValue({
      ...ENDPOINT,
      user_id: "someone-else",
    });
    const answer = await impl.get({ endpoint_uuid: ENDPOINT_UUID }, ADMIN);
    expect(answer.success).toBe(false);
    expect(answer.message).toMatch(/Access denied/);
    expect(findRowMock).not.toHaveBeenCalled();
  });

  it("allows the owner of a private endpoint", async () => {
    findEndpointMock.mockResolvedValue({ ...ENDPOINT, user_id: ADMIN });
    expect(
      (await impl.get({ endpoint_uuid: ENDPOINT_UUID }, ADMIN)).success,
    ).toBe(true);
  });

  it("a database failure is a fixed failure message, not an exception", async () => {
    findRowMock.mockRejectedValue(new Error("connection refused: db-internal"));
    const answer = await impl.get({ endpoint_uuid: ENDPOINT_UUID }, ADMIN);
    expect(answer).toEqual({
      success: false,
      message: "Failed to read endpoint presentation",
    });
  });
});

describe("set", () => {
  it("normalizes both texts before storing them", async () => {
    await impl.set(
      request({ title: "  Desk  ", instructions: "step one\r\nstep two\r\n" }),
      ADMIN,
      ACTOR,
    );

    expect(upsertMock).toHaveBeenCalledWith({
      endpoint_uuid: ENDPOINT_UUID,
      title: "Desk",
      instructions: "step one\nstep two",
      tool_listing: "full",
      omit_output_schemas: false,
    });
  });

  it("returns the stored state, update time included", async () => {
    const answer = await impl.set(
      request({ title: "Desk", omit_output_schemas: true }),
      ADMIN,
      ACTOR,
    );

    expect(answer).toEqual({
      success: true,
      data: {
        endpoint_uuid: ENDPOINT_UUID,
        title: "Desk",
        instructions: null,
        tool_listing: "full",
        omit_output_schemas: true,
        updated_at: "2026-11-12T10:00:00.000Z",
      },
    });
  });

  it("setting everything back to default deletes the row instead of storing defaults", async () => {
    findRowMock.mockResolvedValue(storedRow({ title: "Desk" }));

    const answer = await impl.set(request(), ADMIN, ACTOR);

    expect(deleteMock).toHaveBeenCalledWith(ENDPOINT_UUID);
    expect(upsertMock).not.toHaveBeenCalled();
    expect(answer).toEqual({
      success: true,
      data: {
        endpoint_uuid: ENDPOINT_UUID,
        title: null,
        instructions: null,
        tool_listing: "full",
        omit_output_schemas: false,
        updated_at: null,
      },
    });
  });

  it("an empty text counts as default: whitespace-only texts delete the row too", async () => {
    await impl.set(
      request({ title: "   ", instructions: "\r\n\t" }),
      ADMIN,
      ACTOR,
    );
    expect(deleteMock).toHaveBeenCalledTimes(1);
    expect(upsertMock).not.toHaveBeenCalled();
  });

  it("clears a stored lean row when saved with the full listing", async () => {
    findRowMock.mockResolvedValue(storedRow({ tool_listing: "lean" }));

    await impl.set(request(), ADMIN, ACTOR);

    expect(deleteMock).toHaveBeenCalledWith(ENDPOINT_UUID);
  });

  it("audits the change: action, target, lengths, hash, and the bounded previous and new text", async () => {
    findRowMock.mockResolvedValue(
      storedRow({
        title: "Old title",
        instructions: "Old instructions",
        omit_output_schemas: false,
      }),
    );
    const instructions = "Prefer read-only tools.";

    await impl.set(
      request({
        title: "New title",
        instructions,
        omit_output_schemas: true,
      }),
      ADMIN,
      ACTOR,
    );
    await settle();

    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      action: "endpoint.presentation.set",
      outcome: "success",
      target_type: "endpoint",
      target_id: ENDPOINT_UUID,
    });
    expect(audit[0].detail).toEqual({
      name: "desk",
      tool_listing: "full",
      omit_output_schemas: true,
      title: "New title",
      instructions,
      instructions_length: instructions.length,
      // Recomputed here, not read back from the module.
      instructions_sha256_prefix: createHash("sha256")
        .update(instructions)
        .digest("hex")
        .slice(0, 16),
      previous: {
        tool_listing: "full",
        omit_output_schemas: false,
        title: "Old title",
        instructions: "Old instructions",
      },
    });
  });

  it("audits a first save against defaults, and a clear against the previous text", async () => {
    await impl.set(request({ title: "Desk" }), ADMIN, ACTOR);
    await settle();
    expect(audit[0].detail?.previous).toEqual({
      tool_listing: "full",
      omit_output_schemas: false,
      title: null,
      instructions: null,
    });

    findRowMock.mockResolvedValue(storedRow({ title: "Desk" }));
    await impl.set(request(), ADMIN, ACTOR);
    await settle();
    expect(audit[1].detail).toMatchObject({
      title: null,
      instructions: null,
      instructions_length: 0,
      instructions_sha256_prefix: null,
      previous: { title: "Desk" },
    });
  });

  it("emits nothing when the endpoint is unknown or not the caller's", async () => {
    findEndpointMock.mockResolvedValue(undefined);
    expect(
      (await impl.set(request({ title: "Desk" }), ADMIN, ACTOR)).message,
    ).toBe("Endpoint not found");

    findEndpointMock.mockResolvedValue({
      ...ENDPOINT,
      user_id: "someone-else",
    });
    const refused = await impl.set(request({ title: "Desk" }), ADMIN, ACTOR);
    await settle();

    expect(refused.success).toBe(false);
    expect(refused.message).toMatch(/Access denied/);
    expect(audit).toEqual([]);
    expect(upsertMock).not.toHaveBeenCalled();
    expect(deleteMock).not.toHaveBeenCalled();
  });

  it("allows a public endpoint to any administrator, and a private one to its owner", async () => {
    expect(
      (await impl.set(request({ title: "A" }), "another-admin", ACTOR)).success,
    ).toBe(true);
    findEndpointMock.mockResolvedValue({ ...ENDPOINT, user_id: ADMIN });
    expect(
      (await impl.set(request({ title: "B" }), ADMIN, ACTOR)).success,
    ).toBe(true);
  });

  it.each([
    ["a title over 80 characters", { title: "t".repeat(81) }],
    ["instructions over 1500 characters", { instructions: "i".repeat(1501) }],
    ["a newline in the title", { title: "a\nb" }],
    ["a control character", { instructions: "a\u0007b" }],
    ["a bidi override", { instructions: "a‮b" }],
    ["a listing mode that does not exist", { tool_listing: "everything" }],
  ])(
    "refuses %s at the write boundary: nothing written, nothing audited",
    async (_label, over) => {
      const answer = await impl.set(request(over) as never, ADMIN, ACTOR);
      await settle();

      expect(answer.success).toBe(false);
      expect(upsertMock).not.toHaveBeenCalled();
      expect(deleteMock).not.toHaveBeenCalled();
      expect(audit).toEqual([]);
    },
  );

  it("saves a lean listing, and audits the mode with the one it replaced", async () => {
    findRowMock.mockResolvedValue(storedRow({ title: "Desk" }));

    const answer = await impl.set(
      request({ title: "Desk", tool_listing: "lean" }),
      ADMIN,
      ACTOR,
    );
    await settle();

    expect(answer.success).toBe(true);
    expect(upsertMock).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Desk", tool_listing: "lean" }),
    );
    expect(answer.data?.tool_listing).toBe("lean");
    expect(audit).toHaveLength(1);
    expect(audit[0]?.detail).toMatchObject({
      tool_listing: "lean",
      previous: { tool_listing: "full" },
    });
  });

  it("a database failure is a fixed failure message and no audit row", async () => {
    upsertMock.mockRejectedValue(new Error("connection refused: db-internal"));

    const answer = await impl.set(request({ title: "Desk" }), ADMIN, ACTOR);
    await settle();

    expect(answer).toEqual({
      success: false,
      message: "Failed to save endpoint presentation",
    });
    expect(audit).toEqual([]);
  });

  it("never writes administrator text to a log line", async () => {
    // Drizzle includes bound values in both the message and the error's
    // enumerable params. A plain Error("boom") cannot expose this leak.
    upsertMock.mockRejectedValue(
      new DrizzleQueryError(
        "insert into endpoint_presentation (title, instructions) values ($1, $2)",
        ["Secret title", "Secret instructions"],
        new Error("connection refused"),
      ),
    );
    await impl.set(
      request({ title: "Secret title", instructions: "Secret instructions" }),
      ADMIN,
      ACTOR,
    );
    const logged = [
      ...loggerMock.error.mock.calls,
      ...loggerMock.warn.mock.calls,
      ...loggerMock.info.mock.calls,
    ]
      .map((args) => format(...args))
      .join("\n");
    expect(loggerMock.error).toHaveBeenCalledTimes(1);
    expect(logged).not.toContain("Secret title");
    expect(logged).not.toContain("Secret instructions");
  });
});
