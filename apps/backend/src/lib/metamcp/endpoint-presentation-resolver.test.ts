/**
 * The resolver that reads an endpoint's presentation row at `initialize`.
 * Presentation is cosmetic, so the contract that matters here is that the
 * resolver never throws and fails open to "no presentation": a database error,
 * a missing endpoint or a disabled feature all give `undefined`, and the
 * disabled feature reads nothing at all. The router suites cover the same
 * contract through a real `initialize`; this file pins the resolver on its own,
 * including the arguments that need no HTTP request to construct.
 *
 * Oracle: the design (C.4: returns undefined when the endpoint is missing or
 * the switch is off, with no DB read; any failure logs one WARN and returns
 * undefined; it never throws).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { findMock, loggerMock } = vi.hoisted(() => ({
  findMock: vi.fn(),
  loggerMock: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));
vi.mock("../../db/repositories/endpoint-presentation.repo", () => ({
  endpointPresentationRepository: { findByEndpointUuid: findMock },
}));

import { resolveSessionPresentation } from "./endpoint-presentation-resolver";

const SAVED_SWITCH = process.env.MCP_ENDPOINT_PRESENTATION;
const row = (over: Record<string, unknown> = {}) => ({
  endpoint_uuid: "uuid-1",
  title: null,
  instructions: null,
  tool_listing: "full",
  omit_output_schemas: false,
  updated_at: new Date(0),
  ...over,
});

beforeEach(() => {
  vi.clearAllMocks();
  delete process.env.MCP_ENDPOINT_PRESENTATION;
});

afterEach(() => {
  if (SAVED_SWITCH === undefined) delete process.env.MCP_ENDPOINT_PRESENTATION;
  else process.env.MCP_ENDPOINT_PRESENTATION = SAVED_SWITCH;
});

describe("resolveSessionPresentation", () => {
  it("reads nothing for an unknown endpoint", async () => {
    expect(await resolveSessionPresentation(undefined)).toBeUndefined();
    expect(await resolveSessionPresentation("")).toBeUndefined();
    expect(findMock).not.toHaveBeenCalled();
  });

  it("reads nothing when the kill switch is off", async () => {
    process.env.MCP_ENDPOINT_PRESENTATION = "off";
    findMock.mockResolvedValue(row({ title: "Desk" }));

    expect(await resolveSessionPresentation("uuid-1")).toBeUndefined();
    expect(findMock).not.toHaveBeenCalled();
  });

  it("is undefined for an endpoint with no row", async () => {
    findMock.mockResolvedValue(undefined);
    expect(await resolveSessionPresentation("uuid-1")).toBeUndefined();
    expect(findMock).toHaveBeenCalledWith("uuid-1");
  });

  it("maps a row, leaving out the texts that are null", async () => {
    findMock.mockResolvedValue(
      row({ title: "Desk", omit_output_schemas: true }),
    );

    expect(await resolveSessionPresentation("uuid-1")).toEqual({
      title: "Desk",
      toolListing: "full",
      omitOutputSchemas: true,
    });
  });

  it("is undefined for a row that is all defaults", async () => {
    findMock.mockResolvedValue(row());
    expect(await resolveSessionPresentation("uuid-1")).toBeUndefined();
  });

  it("never throws: a read failure gives undefined and exactly one WARN naming no setting", async () => {
    findMock.mockRejectedValue(new Error("connection refused"));

    await expect(resolveSessionPresentation("uuid-1")).resolves.toBeUndefined();

    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(String(loggerMock.warn.mock.calls[0][0])).toBe(
      "Endpoint presentation could not be read; serving this session with the default presentation.",
    );
  });
});
