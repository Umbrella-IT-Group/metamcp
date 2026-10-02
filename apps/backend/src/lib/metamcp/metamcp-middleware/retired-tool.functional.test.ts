import {
  CallToolRequest,
  CallToolResult,
  ErrorCode,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it, vi } from "vitest";

import logger from "@/utils/logger";

import { M365BrokerError } from "../../m365/errors";
import type { RetiredEntry } from "../retired-tools";
import { classifyCallResult } from "./audit-classify";
import { MetaMCPHandlerContext } from "./functional-middleware";
import { createRetiredToolMiddleware } from "./retired-tool.functional";
import { isRetiredToolResult } from "./retired-tool-marker";

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

const context: MetaMCPHandlerContext = {
  namespaceUuid: "ns-1",
  sessionId: "sess-1",
};

const request = (name: string): CallToolRequest =>
  ({
    method: "tools/call",
    params: { name, arguments: {} },
  }) as CallToolRequest;

const NOTE_ENTRY: RetiredEntry = {
  since: "2026-09-02",
  replacement: "autotask__ticket_manage",
  args: { mode: "note_add" },
  hint: "pass ticket and note",
};

const MAP: Record<string, RetiredEntry> = {
  autotask__add_note: NOTE_ENTRY,
  "retired-server__lookup": {
    since: "2026-09-28",
    replacement: "registry__universal_lookup",
  },
};

const makeLookup = () => vi.fn(async (name: string) => MAP[name] ?? null);

const errText = (text: string): CallToolResult => ({
  isError: true,
  content: [{ type: "text", text }],
});

afterEach(() => vi.clearAllMocks());

describe("retired-tool middleware: zero cost off the failure path", () => {
  it("a successful call is returned unchanged, with no lookup", async () => {
    const lookup = makeLookup();
    const result: CallToolResult = { content: [{ type: "text", text: "ok" }] };
    const wrapped = createRetiredToolMiddleware({ lookup })(async () => result);

    await expect(wrapped(request("autotask__search"), context)).resolves.toBe(
      result,
    );
    expect(lookup).not.toHaveBeenCalled();
  });

  it("SAFETY: a name that IS in the map but whose call succeeds returns the real result", async () => {
    // A re-introduced or wrongly listed name must never be shadowed.
    const lookup = makeLookup();
    const real: CallToolResult = {
      content: [{ type: "text", text: "a real answer" }],
    };
    const wrapped = createRetiredToolMiddleware({ lookup })(async () => real);

    await expect(wrapped(request("autotask__add_note"), context)).resolves.toBe(
      real,
    );
    expect(lookup).not.toHaveBeenCalled();
  });

  it("a failure that is not an unknown tool is rethrown or returned untouched, with no lookup", async () => {
    const lookup = makeLookup();
    const timeout = new McpError(ErrorCode.RequestTimeout, "Request timed out");
    const notConnected = new Error("Not connected");
    // The proxy's outer handler turns this into an enrollment prompt; the
    // redirect must leave it to travel up untouched.
    const broker = new M365BrokerError(
      "credential_missing",
      "no stored grant for this user",
    );
    const inactive = errText(
      'Access denied to tool "autotask__add_note": Tool has been marked as inactive',
    );
    const validation = errText(
      "1 validation error for call[add_note]\n  mode\n    Input should be 'x'",
    );

    for (const failure of [timeout, notConnected, broker]) {
      const wrapped = createRetiredToolMiddleware({ lookup })(async () => {
        throw failure;
      });
      await expect(
        wrapped(request("autotask__add_note"), context),
      ).rejects.toBe(failure);
    }
    for (const result of [inactive, validation]) {
      const wrapped = createRetiredToolMiddleware({ lookup })(
        async () => result,
      );
      await expect(
        wrapped(request("autotask__add_note"), context),
      ).resolves.toBe(result);
    }
    expect(lookup).not.toHaveBeenCalled();
  });

  it("an unlisted name that fails as unknown keeps its bare failure", async () => {
    const lookup = makeLookup();
    const thrown = new Error("Unknown tool: autotask__never_existed");
    const wrapped = createRetiredToolMiddleware({ lookup })(async () => {
      throw thrown;
    });

    await expect(
      wrapped(request("autotask__never_existed"), context),
    ).rejects.toBe(thrown);
    expect(lookup).toHaveBeenCalledWith("autotask__never_existed");

    const returned = errText("Unknown tool: 'never_existed'");
    const wrapped2 = createRetiredToolMiddleware({ lookup })(
      async () => returned,
    );
    await expect(
      wrapped2(request("autotask__never_existed"), context),
    ).resolves.toBe(returned);
  });

  it.each([
    "Unknown tool: internal_helper",
    "Tool internal_helper not found",
    'Access denied to tool "other__add_note": server could not be resolved',
    "Unknown tool operation is disabled",
  ])(
    "does not retire a live tool for a different failure: %s",
    async (message) => {
      const lookup = makeLookup();
      const result = errText(message);
      const returned = createRetiredToolMiddleware({ lookup })(
        async () => result,
      );
      await expect(
        returned(request("autotask__add_note"), context),
      ).resolves.toBe(result);

      const error = new Error(message);
      const thrown = createRetiredToolMiddleware({ lookup })(async () => {
        throw error;
      });
      await expect(thrown(request("autotask__add_note"), context)).rejects.toBe(
        error,
      );
      expect(lookup).not.toHaveBeenCalled();
    },
  );
});

describe("retired-tool middleware: the redirect", () => {
  const redirectOf = async (
    name: string,
    run: () => Promise<CallToolResult>,
  ): Promise<CallToolResult> => {
    const wrapped = createRetiredToolMiddleware({ lookup: makeLookup() })(run);
    return wrapped(request(name), context);
  };

  const unknownTextForms: Array<[string, () => Promise<CallToolResult>]> = [
    [
      "a thrown gateway error",
      async () => {
        throw new Error("Unknown tool: autotask__add_note");
      },
    ],
    [
      "a thrown OpenAPI-quoted error",
      async () => {
        throw new Error('Unknown tool: "autotask__add_note"');
      },
    ],
    [
      "a thrown SDK-wrapped error",
      async () => {
        throw new McpError(
          ErrorCode.InvalidParams,
          "Unknown tool: autotask__add_note",
        );
      },
    ],
    [
      "a FastMCP isError answer",
      async () => errText("Unknown tool: 'add_note'"),
    ],
    [
      "a TypeScript-SDK isError answer",
      async () => errText("Tool add_note not found"),
    ],
    [
      "the filter's unresolved-server denial",
      async () =>
        errText(
          'Access denied to tool "autotask__add_note": server could not be resolved',
        ),
    ],
  ];

  it.each(unknownTextForms)("%s becomes the redirect", async (_label, run) => {
    const result = await redirectOf("autotask__add_note", run);

    expect(result.isError).toBe(true);
    // No structuredContent: a client validating it against a cached output
    // schema would turn this message into a validation failure.
    expect(result).not.toHaveProperty("structuredContent");
    expect(result.content).toHaveLength(1);
    const block = result.content[0];
    expect(block.type).toBe("text");
    const envelope = JSON.parse((block as { text: string }).text);
    expect(envelope).toMatchObject({
      error: true,
      code: "tool_retired",
      context: {
        retired: "autotask__add_note",
        since: "2026-09-02",
        replacement: "autotask__ticket_manage",
        replacement_call: 'autotask__ticket_manage(mode="note_add")',
      },
    });
    expect(envelope.message).toContain("Use autotask__ticket_manage");
  });

  it("registers the redirect so the audit records tool_retired", async () => {
    const result = await redirectOf("autotask__add_note", async () => {
      throw new Error("Unknown tool: autotask__add_note");
    });

    expect(isRetiredToolResult(result)).toBe(true);
    expect(classifyCallResult(result)).toEqual({
      failed: true,
      errorCode: "tool_retired",
    });
  });

  it("answers for a server that no longer exists", async () => {
    const result = await redirectOf("retired-server__lookup", async () =>
      errText(
        'Access denied to tool "retired-server__lookup": server could not be resolved',
      ),
    );
    const envelope = JSON.parse((result.content[0] as { text: string }).text);
    expect(envelope.context.replacement).toBe("registry__universal_lookup");
  });

  it("looks the name up exactly as the caller sent it", async () => {
    const lookup = makeLookup();
    const wrapped = createRetiredToolMiddleware({ lookup })(async () => {
      throw new Error("Unknown tool: autotask__add_note");
    });
    await wrapped(request("autotask__add_note"), context);
    expect(lookup).toHaveBeenCalledTimes(1);
    expect(lookup).toHaveBeenCalledWith("autotask__add_note");
  });

  it("a fault in the lookup falls back to today's answer and warns", async () => {
    const lookup = vi.fn().mockRejectedValue(new Error("disk went away"));
    const thrown = new Error("Unknown tool: autotask__add_note");
    const wrapped = createRetiredToolMiddleware({ lookup })(async () => {
      throw thrown;
    });

    await expect(wrapped(request("autotask__add_note"), context)).rejects.toBe(
      thrown,
    );
    expect(vi.mocked(logger.warn)).toHaveBeenCalledTimes(1);
  });

  it("does not treat a result it cannot read as unknown-tool", async () => {
    const lookup = makeLookup();
    const hostile = new Proxy(
      {},
      {
        get(_target, property) {
          if (property === "then") return undefined;
          throw new Error("hostile");
        },
      },
    ) as unknown as CallToolResult;
    const wrapped = createRetiredToolMiddleware({ lookup })(
      async () => hostile,
    );

    await expect(wrapped(request("autotask__add_note"), context)).resolves.toBe(
      hostile,
    );
    expect(lookup).not.toHaveBeenCalled();
  });

  it("is the same behavior for a returned isError whose first block is not text", async () => {
    const lookup = makeLookup();
    const odd: CallToolResult = {
      isError: true,
      content: [{ type: "image", data: "x", mimeType: "image/png" }],
    };
    const wrapped = createRetiredToolMiddleware({ lookup })(async () => odd);
    await expect(wrapped(request("autotask__add_note"), context)).resolves.toBe(
      odd,
    );
    expect(lookup).not.toHaveBeenCalled();
  });

  it("rethrows the identical opaque failure when its message cannot be read", async () => {
    const lookup = makeLookup();
    const failure = {
      get message() {
        throw new Error("private-fault-data");
      },
    };
    const wrapped = createRetiredToolMiddleware({ lookup })(async () => {
      throw failure;
    });
    await expect(wrapped(request("autotask__add_note"), context)).rejects.toBe(
      failure,
    );
    expect(lookup).not.toHaveBeenCalled();
  });
});
