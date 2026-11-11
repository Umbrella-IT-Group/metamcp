/**
 * How a server update treats the stored bearer token and headers
 * (planServerUpdate). A URL change must replace or clear each stored
 * credential, or it is refused; a same-URL save keeps the established
 * blank-means-keep contract. The repository applies this against the row it
 * holds under FOR UPDATE (mcp-servers.credential-retention.integration
 * .test.ts runs that against Postgres).
 */
import { randomBytes } from "node:crypto";

import { UpdateMcpServerRequestSchema } from "@repo/zod-types";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import { BEARER_ENVELOPE_PREFIX } from "@/lib/metamcp/server-bearer-crypto";

import {
  CLEAR_AND_REPLACE_BEARER_CONFLICT,
  planServerUpdate,
  ServerCredentialRetentionError,
  URL_CHANGE_NEEDS_BEARER_DECISION,
  URL_CHANGE_NEEDS_HEADERS_DECISION,
} from "./mcp-server-update-plan";

const OLD_URL = "http://mcp-vendor:3000/mcp";
const NEW_URL = "http://mcp-vendor-next:3000/mcp";

const stored = (
  overrides: Partial<{
    url: string | null;
    bearerToken: string | null;
    headers: Record<string, string> | null;
  }> = {},
) => ({
  url: OLD_URL,
  bearerToken: "enc:v1:stored-ciphertext",
  headers: { "x-api-key": "stored-header-value" },
  ...overrides,
});

const refusal = (run: () => unknown): string => {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(ServerCredentialRetentionError);
    return (error as Error).message;
  }
  throw new Error("expected a refusal");
};

beforeEach(() => {
  process.env.M365_TOKEN_KEK = randomBytes(32).toString("base64");
  delete process.env.M365_KEK_ID;
});

describe("a same-URL update keeps the established contract", () => {
  it.each([
    ["a blank bearer", { bearerToken: "" }],
    ["an omitted bearer", {}],
  ])(
    "%s keeps the stored bearer (the key is not in the SET)",
    (_label, extra) => {
      const set = planServerUpdate(stored(), {
        name: "vendor",
        url: OLD_URL,
        ...extra,
      });
      expect(set).not.toHaveProperty("bearerToken");
      expect(set).not.toHaveProperty("clearBearerToken");
      expect(set.name).toBe("vendor");
    },
  );

  it("omitted headers keep the stored headers", () => {
    const set = planServerUpdate(stored(), { url: OLD_URL });
    expect(set).not.toHaveProperty("headers");
  });

  it("a URL that differs only in what URL parsing normalizes is the same address", () => {
    const set = planServerUpdate(stored(), {
      url: "HTTP://MCP-VENDOR:3000/mcp",
    });
    expect(set).not.toHaveProperty("bearerToken");
  });

  it("an omitted URL is not a URL change", () => {
    expect(() =>
      planServerUpdate(stored(), { description: "renamed" }),
    ).not.toThrow();
  });

  it("the sync's routine payload (name, type, url, user_id, description) is accepted and keeps both", () => {
    const set = planServerUpdate(stored(), {
      name: "vendor",
      type: "STREAMABLE_HTTP",
      url: OLD_URL,
      user_id: null,
      description: "Vendor tools",
    });
    expect(set).not.toHaveProperty("bearerToken");
    expect(set).not.toHaveProperty("headers");
  });

  it("a new bearer replaces the stored one, encrypted", () => {
    const set = planServerUpdate(stored(), {
      url: OLD_URL,
      bearerToken: "replacement-bearer",
    });
    expect(set.bearerToken?.startsWith(BEARER_ENVELOPE_PREFIX)).toBe(true);
    expect(set.bearerToken).not.toContain("replacement-bearer");
  });

  it("clearBearerToken clears it", () => {
    const set = planServerUpdate(stored(), {
      url: OLD_URL,
      clearBearerToken: true,
    });
    expect(set.bearerToken).toBeNull();
    expect(set).not.toHaveProperty("clearBearerToken");
  });
});

describe("a URL-changing update decides what happens to stored credentials", () => {
  it.each([
    ["a blank bearer", { bearerToken: "" }],
    ["an omitted bearer", {}],
  ])("with %s and a stored bearer, it is refused", (_label, extra) => {
    expect(
      refusal(() =>
        planServerUpdate(stored(), { url: NEW_URL, headers: {}, ...extra }),
      ),
    ).toBe(URL_CHANGE_NEEDS_BEARER_DECISION);
  });

  it("with a replacement bearer, it is accepted and the bearer replaced", () => {
    const set = planServerUpdate(stored(), {
      url: NEW_URL,
      bearerToken: "bearer-for-the-new-address",
      headers: {},
    });
    expect(set.url).toBe(NEW_URL);
    expect(set.bearerToken?.startsWith(BEARER_ENVELOPE_PREFIX)).toBe(true);
  });

  it("with clearBearerToken, it is accepted and the bearer cleared", () => {
    const set = planServerUpdate(stored(), {
      url: NEW_URL,
      clearBearerToken: true,
      headers: {},
    });
    expect(set.bearerToken).toBeNull();
  });

  it("with stored headers and no headers sent, it is refused", () => {
    expect(
      refusal(() =>
        planServerUpdate(stored(), {
          url: NEW_URL,
          bearerToken: "bearer-for-the-new-address",
        }),
      ),
    ).toBe(URL_CHANGE_NEEDS_HEADERS_DECISION);
  });

  it("with the headers sent again, or an empty set, it is accepted", () => {
    expect(
      planServerUpdate(stored(), {
        url: NEW_URL,
        clearBearerToken: true,
        headers: { "x-api-key": "stored-header-value" },
      }).headers,
    ).toEqual({ "x-api-key": "stored-header-value" });
    expect(
      planServerUpdate(stored(), {
        url: NEW_URL,
        clearBearerToken: true,
        headers: {},
      }).headers,
    ).toEqual({});
  });

  it("with nothing stored, it needs no decision", () => {
    expect(() =>
      planServerUpdate(stored({ bearerToken: null, headers: {} }), {
        url: NEW_URL,
      }),
    ).not.toThrow();
    expect(() =>
      planServerUpdate(stored({ bearerToken: null, headers: null }), {
        url: NEW_URL,
      }),
    ).not.toThrow();
  });

  it("clearing the URL counts as a change, and so does setting one where none was", () => {
    expect(refusal(() => planServerUpdate(stored(), { url: "" }))).toBe(
      URL_CHANGE_NEEDS_BEARER_DECISION,
    );
    expect(
      refusal(() =>
        planServerUpdate(stored({ url: null }), { url: NEW_URL, headers: {} }),
      ),
    ).toBe(URL_CHANGE_NEEDS_BEARER_DECISION);
  });

  it("the refusal names no stored value", () => {
    const message = refusal(() => planServerUpdate(stored(), { url: NEW_URL }));
    expect(message).not.toContain("stored-ciphertext");
    expect(message).not.toContain("stored-header-value");
    expect(message).not.toContain(NEW_URL);
  });
});

describe("clearing and replacing in one update is contradictory", () => {
  it("the planner refuses it", () => {
    expect(
      refusal(() =>
        planServerUpdate(stored(), {
          url: OLD_URL,
          clearBearerToken: true,
          bearerToken: "replacement",
        }),
      ),
    ).toBe(CLEAR_AND_REPLACE_BEARER_CONFLICT);
  });

  it("the request schema refuses it before the impl runs", () => {
    const base = {
      uuid: "11111111-1111-4111-8111-111111111111",
      name: "vendor",
      type: "STREAMABLE_HTTP",
      url: OLD_URL,
    };
    expect(
      UpdateMcpServerRequestSchema.safeParse({
        ...base,
        clearBearerToken: true,
        bearerToken: "replacement",
      }).success,
    ).toBe(false);
    expect(
      UpdateMcpServerRequestSchema.safeParse({
        ...base,
        clearBearerToken: true,
      }).success,
    ).toBe(true);
    expect(
      UpdateMcpServerRequestSchema.safeParse({
        ...base,
        clearBearerToken: false,
        bearerToken: "replacement",
      }).success,
    ).toBe(true);
  });
});
