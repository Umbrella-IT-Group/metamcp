/**
 * The two request variants of `mcpServers.update`, through the real router:
 *
 *  - the full variant is what every caller has always sent (a type plus a URL
 *    or a command, and the rest) and is unchanged;
 *  - the metadata-only variant (`metadata_only: true`, a name and/or a
 *    description, the change reason and run id) is strict: a connection field,
 *    an owner or any unknown key rejects the whole request. It is never
 *    dropped and the rest applied, and a request that carries the marker can
 *    never be taken for the full variant with the marker stripped.
 *
 * A request the schema refuses never reaches the implementation.
 */
import { createMcpServersRouter } from "@repo/trpc";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

const okImpl = <T>(value: T) => vi.fn(async () => value);
const impls = {
  create: okImpl({ success: true }),
  list: okImpl({ success: true, data: [] }),
  listAll: okImpl({ success: true, data: [] }),
  bulkImport: okImpl({ success: true, imported: 0 }),
  get: okImpl({ success: true }),
  delete: okImpl({ success: true }),
  update: okImpl({ success: true }),
  reconnect: okImpl({ success: true }),
  resetErrors: okImpl({
    reset: [],
    recovery: { status: "not_needed", servers: [] },
  }),
};
const router = () => createMcpServersRouter(impls as never);
const admin = {
  user: { id: "admin-1", role: "admin" },
  session: { id: "s" },
};

const UUID = "11111111-1111-4111-8111-111111111111";

beforeEach(() => vi.clearAllMocks());

describe("the metadata-only variant", () => {
  it.each([
    ["a name", { name: "renamed" }],
    ["a description", { description: "what it does" }],
    ["both", { name: "renamed", description: "what it does" }],
    [
      "a name with the change context",
      { name: "renamed", reason: "tidy the name", run_id: "run-1" },
    ],
  ])(
    "accepts %s and hands the implementation exactly that",
    async (_label, extra) => {
      const request = { uuid: UUID, metadata_only: true, ...extra };

      await expect(
        router()
          .createCaller(admin)
          .update(request as never),
      ).resolves.toEqual({ success: true });

      expect(impls.update).toHaveBeenCalledTimes(1);
      const handed = impls.update.mock.calls[0] as unknown as unknown[];
      expect(handed[0]).toEqual(request);
    },
  );

  it.each([
    ["a URL", { url: "https://vendor.internal/mcp" }],
    ["a type", { type: "STREAMABLE_HTTP" }],
    ["a command", { command: "/bin/true" }],
    ["arguments", { args: ["--x"] }],
    ["an environment", { env: { TOKEN: "x" } }],
    ["headers", { headers: { Authorization: "x" } }],
    ["a bearer token", { bearerToken: "x" }],
    ["a clear-bearer flag", { clearBearerToken: true }],
    ["an owner", { user_id: null }],
    ["an unknown key", { somethingElse: 1 }],
  ])("rejects a request that also carries %s, whole", async (_label, extra) => {
    await expect(
      router()
        .createCaller(admin)
        .update({
          uuid: UUID,
          metadata_only: true,
          name: "renamed",
          ...extra,
        } as never),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });

    expect(impls.update).not.toHaveBeenCalled();
  });

  it.each([
    ["neither a name nor a description", {}],
    ["a name with a space", { name: "a b" }],
    ["a name with consecutive underscores", { name: "a__b" }],
    ["an empty name", { name: "" }],
  ])("rejects %s", async (_label, extra) => {
    await expect(
      router()
        .createCaller(admin)
        .update({ uuid: UUID, metadata_only: true, ...extra } as never),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });

    expect(impls.update).not.toHaveBeenCalled();
  });

  it.each([
    ["false", false],
    ["the string true", "true"],
    ["1", 1],
  ])(
    "rejects a marker that is %s, so it is not read as the full variant",
    async (_label, marker) => {
      await expect(
        router()
          .createCaller(admin)
          .update({
            uuid: UUID,
            metadata_only: marker,
            name: "renamed",
            type: "STREAMABLE_HTTP",
            url: "https://vendor.internal/mcp",
          } as never),
      ).rejects.toMatchObject({ code: "BAD_REQUEST" });

      expect(impls.update).not.toHaveBeenCalled();
    },
  );

  it("rejects a full variant that also carries the marker, instead of stripping it", async () => {
    await expect(
      router()
        .createCaller(admin)
        .update({
          uuid: UUID,
          metadata_only: true,
          name: "renamed",
          type: "STREAMABLE_HTTP",
          url: "https://vendor.internal/mcp",
        } as never),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });

    expect(impls.update).not.toHaveBeenCalled();
  });
});

describe("the full variant", () => {
  it("is accepted as it always was", async () => {
    const request = {
      uuid: UUID,
      name: "vendor",
      type: "STREAMABLE_HTTP",
      url: "https://vendor.internal/mcp",
      description: "a vendor",
    };

    await expect(
      router()
        .createCaller(admin)
        .update(request as never),
    ).resolves.toEqual({ success: true });

    expect(impls.update).toHaveBeenCalledTimes(1);
  });

  it("still needs its type, and its URL or command", async () => {
    await expect(
      router()
        .createCaller(admin)
        .update({ uuid: UUID, name: "vendor" } as never),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    await expect(
      router()
        .createCaller(admin)
        .update({
          uuid: UUID,
          name: "vendor",
          type: "STREAMABLE_HTTP",
        } as never),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });

    expect(impls.update).not.toHaveBeenCalled();
  });
});
