/**
 * The `oauth` tRPC procedures keep the `issuer` stamp on the upstream OAuth
 * credentials they store and return (GHSA-6qxp-vccf-f47h).
 *
 * MCP SDK 1.31 binds a stored client registration and refresh token to the
 * authorization server they came from by stamping `issuer` on them, and
 * refuses to present a value stamped for a different server. The Inspector
 * stores those values through `oauth.upsert` and reads them back through
 * `oauth.get`; while the shared schemas lacked `issuer`, zod stripped it on
 * the way in and every stored credential read back unbound.
 *
 * Driven through the REAL router from @repo/trpc (its input and output
 * schemas are the thing under test) over the real implementation and
 * serializer. The repository is an in-memory stand-in with the same merge
 * semantics, because its barrel reaches db/index, which needs a live
 * DATABASE_URL; the column itself is jsonb and stores whatever object it is
 * given.
 */

import { createOAuthRouter } from "@repo/trpc";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const { rows, upsertCalls } = vi.hoisted(() => ({
  rows: new Map<string, Record<string, unknown>>(),
  upsertCalls: [] as Array<Record<string, unknown>>,
}));

vi.mock("../db/repositories", () => ({
  oauthSessionsRepository: {
    findByMcpServerUuid: async (uuid: string) => rows.get(uuid),
    upsert: async (input: Record<string, unknown>) => {
      upsertCalls.push(structuredClone(input));
      const uuid = input.mcp_server_uuid as string;
      const row = rows.get(uuid) ?? {
        uuid: "00000000-0000-4000-8000-000000000001",
        mcp_server_uuid: uuid,
        client_information: {},
        tokens: null,
        code_verifier: null,
        created_at: new Date("2026-10-08T00:00:00Z"),
        updated_at: new Date("2026-10-08T00:00:00Z"),
      };
      for (const key of ["client_information", "tokens", "code_verifier"]) {
        if (input[key]) row[key] = input[key];
      }
      rows.set(uuid, row);
      return row;
    },
  },
}));

import { oauthImplementations } from "./oauth.impl";

const SERVER_UUID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
const ISSUER = "https://as.example.test";

const caller = createOAuthRouter(oauthImplementations).createCaller({
  user: { id: "admin-1", role: "admin" },
  session: { id: "session-1" },
} as never);

beforeEach(() => {
  rows.clear();
  upsertCalls.length = 0;
});

describe("oauth.upsert / oauth.get keep the issuer stamp", () => {
  it("stores the stamp on client information and tokens", async () => {
    const result = await caller.upsert({
      mcp_server_uuid: SERVER_UUID,
      client_information: {
        client_id: "client-1",
        client_secret: "secret-1",
        issuer: ISSUER,
      },
      tokens: {
        access_token: "access-1",
        token_type: "Bearer",
        refresh_token: "refresh-1",
        issuer: ISSUER,
      },
    });

    expect(result.success).toBe(true);
    expect(upsertCalls).toEqual([
      {
        mcp_server_uuid: SERVER_UUID,
        client_information: {
          client_id: "client-1",
          client_secret: "secret-1",
          issuer: ISSUER,
        },
        tokens: {
          access_token: "access-1",
          token_type: "Bearer",
          refresh_token: "refresh-1",
          issuer: ISSUER,
        },
      },
    ]);
  });

  it("returns the stamp from both the upsert response and a later get", async () => {
    const upserted = await caller.upsert({
      mcp_server_uuid: SERVER_UUID,
      client_information: { client_id: "client-1", issuer: ISSUER },
      tokens: {
        access_token: "access-1",
        token_type: "Bearer",
        refresh_token: "refresh-1",
        issuer: ISSUER,
      },
    });
    const fetched = await caller.get({ mcp_server_uuid: SERVER_UUID });

    for (const result of [upserted, fetched]) {
      if (!result.success) throw new Error("expected a stored session");
      expect(result.data.client_information?.issuer).toBe(ISSUER);
      expect(result.data.tokens?.issuer).toBe(ISSUER);
    }
  });

  it("still accepts and returns a row stored before the stamp existed", async () => {
    // Rows written before SDK 1.31 have no issuer. They must stay readable
    // (the Inspector refuses to present them to an authorization server, see
    // apps/frontend/lib/oauth-provider) rather than fail the output schema.
    await caller.upsert({
      mcp_server_uuid: SERVER_UUID,
      client_information: { client_id: "client-legacy" },
      tokens: { access_token: "access-legacy", token_type: "Bearer" },
    });
    const fetched = await caller.get({ mcp_server_uuid: SERVER_UUID });

    if (!fetched.success) throw new Error("expected a stored session");
    expect(fetched.data.client_information).toEqual({
      client_id: "client-legacy",
    });
    expect(fetched.data.tokens).toEqual({
      access_token: "access-legacy",
      token_type: "Bearer",
    });
  });
});
