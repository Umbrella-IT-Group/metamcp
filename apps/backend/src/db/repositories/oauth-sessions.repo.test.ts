/**
 * Unit tests for the `oauth_sessions` repository upsert contract.
 *
 * These run against an in-memory fake keyed by mcp_server_uuid that mimics
 * `INSERT ... ON CONFLICT (mcp_server_uuid) DO UPDATE SET ...` and the
 * `UPDATE ... WHERE mcp_server_uuid = ?` used by clearExpectedState. They pin:
 *   - the upsert is a SINGLE atomic statement (no SELECT-then-INSERT race);
 *   - concurrent callers for one server converge on ONE row instead of the
 *     loser crashing on the unique constraint;
 *   - the conditional spread never clears a column a partial update omits;
 *   - expected_state (CSRF nonce) is written on upsert and cleared via the
 *     dedicated NULL-write path.
 * They do NOT exercise the postgres engine; the ON CONFLICT + NULL semantics
 * themselves are a drizzle/postgres contract validated at deploy.
 */

import type {
  OAuthClientInformation,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import { beforeEach, describe, expect, it, vi } from "vitest";

const valuesCalls: Record<string, unknown>[] = [];
const onConflictSetCalls: Record<string, unknown>[] = [];
const onConflictTargetCalls: unknown[] = [];
const updateSetCalls: Record<string, unknown>[] = [];

// In-memory store keyed by mcp_server_uuid.
const store = new Map<string, Record<string, unknown>>();

vi.mock("../index", () => ({
  db: {
    insert: () => ({
      values: (values: Record<string, unknown>) => {
        valuesCalls.push(values);
        return {
          onConflictDoUpdate: ({
            target,
            set,
          }: {
            target: unknown;
            set: Record<string, unknown>;
          }) => {
            onConflictTargetCalls.push(target);
            onConflictSetCalls.push(set);
            return {
              returning: async () => {
                const key = values.mcp_server_uuid as string;
                const now = new Date();
                const existing = store.get(key);
                if (existing) {
                  // ON CONFLICT DO UPDATE: merge only the keys present in `set`.
                  // Drop the sql`NOW()` updated_at the fake can't execute.
                  const { updated_at: _ignored, ...applicable } = set;
                  const updated = {
                    ...existing,
                    ...applicable,
                    updated_at: now,
                  };
                  store.set(key, updated);
                  return [updated];
                }
                const row = {
                  uuid: `uuid-${store.size}`,
                  mcp_server_uuid: values.mcp_server_uuid,
                  client_information: values.client_information ?? {},
                  tokens: values.tokens ?? null,
                  code_verifier: values.code_verifier ?? null,
                  expected_state: values.expected_state ?? null,
                  created_at: now,
                  updated_at: now,
                };
                store.set(key, row);
                return [row];
              },
            };
          },
        };
      },
    }),
    // Only clearExpectedState reaches update() in these tests. The WHERE clause
    // is a real drizzle `eq(...)` object we can't introspect from the fake, so
    // we apply the SET to every stored row — tests operate on a single server.
    update: () => ({
      set: (set: Record<string, unknown>) => {
        updateSetCalls.push(set);
        return {
          where: () => ({
            returning: async () => {
              const now = new Date();
              const { updated_at: _ignored, ...applicable } = set;
              const rows: Record<string, unknown>[] = [];
              for (const [key, row] of store) {
                const updated = { ...row, ...applicable, updated_at: now };
                store.set(key, updated);
                rows.push(updated);
              }
              return rows;
            },
          }),
        };
      },
    }),
  },
}));

// schema.ts imports @repo/zod-types (a workspace package) plus every table;
// stub only the columns the repo touches so the import graph stays satisfiable.
vi.mock("../schema", () => ({
  oauthSessionsTable: {
    mcp_server_uuid: { name: "mcp_server_uuid" },
    client_information: { name: "client_information" },
    tokens: { name: "tokens" },
    code_verifier: { name: "code_verifier" },
    expected_state: { name: "expected_state" },
    updated_at: { name: "updated_at" },
  },
}));

const { OAuthSessionsRepository } = await import("./oauth-sessions.repo");

describe("OAuthSessionsRepository.upsert", () => {
  const repo = new OAuthSessionsRepository();
  const serverId = "00000000-0000-0000-0000-000000000001";

  beforeEach(() => {
    store.clear();
    valuesCalls.length = 0;
    onConflictSetCalls.length = 0;
    onConflictTargetCalls.length = 0;
    updateSetCalls.length = 0;
  });

  it("uses a single ON CONFLICT statement (not check-then-insert)", async () => {
    await repo.upsert({
      mcp_server_uuid: serverId,
      client_information: { client_id: "client-A" } as OAuthClientInformation,
    });

    // Exactly one insert chain per call: this is what makes the upsert atomic
    // and removes the SELECT-then-INSERT race window.
    expect(valuesCalls).toHaveLength(1);
    expect(onConflictSetCalls).toHaveLength(1);
    expect(onConflictTargetCalls[0]).toBeDefined();
  });

  it("concurrent upserts for one server converge on a single row, no throw", async () => {
    // The racy SELECT-then-INSERT crashed the loser with a unique-constraint
    // violation. The atomic ON CONFLICT path must let every concurrent caller
    // resolve against the same row.
    const results = await Promise.all([
      repo.upsert({
        mcp_server_uuid: serverId,
        client_information: { client_id: "A" } as OAuthClientInformation,
      }),
      repo.upsert({
        mcp_server_uuid: serverId,
        tokens: { access_token: "t", token_type: "Bearer" } as OAuthTokens,
      }),
      repo.upsert({
        mcp_server_uuid: serverId,
        code_verifier: "verifier",
      }),
    ]);

    expect(results).toHaveLength(3);
    for (const row of results) {
      expect(row.mcp_server_uuid).toBe(serverId);
    }
    expect(store.size).toBe(1);
  });

  it("partial upsert with only tokens does not write code_verifier into the SET", async () => {
    await repo.upsert({
      mcp_server_uuid: serverId,
      tokens: { access_token: "tok", token_type: "Bearer" } as OAuthTokens,
    });

    const set = onConflictSetCalls[0];
    expect(set).toHaveProperty("tokens");
    expect(set).not.toHaveProperty("code_verifier");
    expect(set).not.toHaveProperty("client_information");
    expect(set).not.toHaveProperty("expected_state");
  });

  it("partial upsert with only code_verifier does not clear existing tokens", async () => {
    await repo.upsert({
      mcp_server_uuid: serverId,
      tokens: { access_token: "tok", token_type: "Bearer" } as OAuthTokens,
    });
    const second = await repo.upsert({
      mcp_server_uuid: serverId,
      code_verifier: "the-verifier",
    });

    expect(second.tokens).toEqual({
      access_token: "tok",
      token_type: "Bearer",
    });
    expect(second.code_verifier).toBe("the-verifier");

    const setOnSecond = onConflictSetCalls[1];
    expect(setOnSecond).toHaveProperty("code_verifier");
    expect(setOnSecond).not.toHaveProperty("tokens");
  });

  it("writes expected_state on upsert and does not touch it on an unrelated update", async () => {
    const withState = await repo.upsert({
      mcp_server_uuid: serverId,
      expected_state: "csrf-nonce",
    });
    expect(withState.expected_state).toBe("csrf-nonce");
    expect(onConflictSetCalls[0]).toHaveProperty(
      "expected_state",
      "csrf-nonce",
    );

    // A later tokens-only upsert must leave expected_state intact (the guard
    // that keeps the CSRF nonce alive until validation clears it).
    const afterTokens = await repo.upsert({
      mcp_server_uuid: serverId,
      tokens: { access_token: "x", token_type: "Bearer" } as OAuthTokens,
    });
    expect(afterTokens.expected_state).toBe("csrf-nonce");
    expect(onConflictSetCalls[1]).not.toHaveProperty("expected_state");
  });
});

describe("OAuthSessionsRepository.clearExpectedState", () => {
  const repo = new OAuthSessionsRepository();
  const serverId = "00000000-0000-0000-0000-000000000002";

  beforeEach(() => {
    store.clear();
    updateSetCalls.length = 0;
  });

  it("writes NULL to expected_state via an UPDATE (not the truthy-spread path)", async () => {
    await repo.upsert({
      mcp_server_uuid: serverId,
      expected_state: "to-be-cleared",
    });

    const cleared = await repo.clearExpectedState(serverId);

    expect(cleared?.expected_state).toBeNull();
    // The SET must explicitly carry expected_state: null — the upsert spread
    // could never produce this (a null value is elided by its `&&` guard).
    expect(updateSetCalls[0]).toHaveProperty("expected_state", null);
  });

  it("returns undefined when no row exists for the server", async () => {
    const result = await repo.clearExpectedState(
      "00000000-0000-0000-0000-0000000000ff",
    );
    expect(result).toBeUndefined();
  });
});
