/**
 * Endpoint presentation settings on the real /trpc stack, against a REAL
 * Postgres: the real router module with its middleware, the real createContext
 * and admin-plane bearer resolver, the real implementation and repository, and
 * the real audit writer (fixture: admin-plane-integration-fixture.ts). Only the
 * MCP connection pools are stubbed.
 *
 * What it proves, each a statement about a real database or the real auth
 * stack that a mocked repository could not make:
 *  - a human administrator's `set` persists, upserts on a second save, bumps
 *    the update time and records an `endpoint.presentation.set` audit row that
 *    carries the text, bounded;
 *  - a member, an operator-scope key and a sync-scope key are all refused with
 *    403, no row appears, and a key's refusal leaves an `rbac.denied` row
 *    naming the key and the procedure;
 *  - a private endpoint owned by someone else is refused;
 *  - an out-of-bound or control-character text is refused with no row;
 *  - saving every setting back to default deletes the row, and an endpoint
 *    with no row reads as defaults with no update time;
 *  - a `lean` listing saves, reads back as lean and is audited, a `lean` row
 *    written outside the app reads back without an error, and saving the full
 *    listing clears it.
 * The migration itself (its bounds, defaults, cascade and idempotence) is
 * src/db/repositories/endpoint-presentation-migration.integration.test.ts.
 *
 * Opt-in via TEST_DATABASE_URL, pointed at a disposable, migrated database:
 *
 *   cd apps/backend
 *   DATABASE_URL=<url> npx drizzle-kit migrate
 *   TEST_DATABASE_URL=<url> npx vitest run \
 *     src/trpc/endpoint-presentation.integration.test.ts
 */

import { createHash } from "node:crypto";

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { createFixture, type Fixture } from "./admin-plane-integration-fixture";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

const quiet = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
vi.mock("@/utils/logger", () => ({ default: quiet }));
vi.mock("../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    ensureIdleSessionForNewServer: vi.fn().mockResolvedValue(undefined),
    cleanupIdleSession: vi.fn().mockResolvedValue(undefined),
    invalidateIdleSession: vi.fn().mockResolvedValue(undefined),
    invalidateServerConnection: vi.fn().mockResolvedValue(undefined),
  },
}));
vi.mock("../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {
    ensureIdleServerForNewNamespace: vi.fn().mockResolvedValue(undefined),
    cleanupIdleServer: vi.fn().mockResolvedValue(undefined),
    invalidateIdleServer: vi.fn().mockResolvedValue(undefined),
    invalidateIdleServers: vi.fn().mockResolvedValue(undefined),
    invalidateOpenApiSessions: vi.fn().mockResolvedValue(undefined),
  },
}));

type SetResponse = {
  success: boolean;
  message?: string;
  data?: {
    endpoint_uuid: string;
    title: string | null;
    instructions: string | null;
    tool_listing: string;
    omit_output_schemas: boolean;
    updated_at: string | null;
  };
};
type GetResponse = SetResponse & {
  data?: SetResponse["data"] & {
    effective: { presentation_enabled: boolean; lean_enabled: boolean };
  };
};

describeIfDb(
  "endpoint presentation on the real /trpc stack (real Postgres)",
  () => {
    let fx: Fixture;

    const rowFor = async (endpointUuid: string) =>
      (
        await fx.suiteLock.query(
          `SELECT title, instructions, tool_listing, omit_output_schemas, updated_at
           FROM endpoint_presentation WHERE endpoint_uuid = $1`,
          [endpointUuid],
        )
      ).rows;

    const set = (
      endpointUuid: string,
      over: Record<string, unknown> = {},
      options: { cookie?: string; key?: string } = { cookie: fx.ownerCookie },
    ) =>
      fx.trpc(
        "frontend.endpointPresentation.set",
        {
          endpoint_uuid: endpointUuid,
          title: null,
          instructions: null,
          tool_listing: "full",
          omit_output_schemas: false,
          ...over,
        },
        "mutation",
        options,
      );

    const get = (
      endpointUuid: string,
      options: { cookie?: string; key?: string } = { cookie: fx.ownerCookie },
    ) =>
      fx.trpc(
        "frontend.endpointPresentation.get",
        { endpoint_uuid: endpointUuid },
        "query",
        options,
      );

    beforeAll(async () => {
      fx = await createFixture(TEST_DATABASE_URL as string, "itpres");
    }, 180_000);

    afterAll(async () => {
      await fx?.close();
    });

    describe("a human administrator", () => {
      it("sets, persists and audits, with the text in the audit detail", async () => {
        const uuid = await fx.endpoint({ name: "pres-set" });
        const instructions =
          "Prefer read-only tools.\nAsk before changing data.";

        const reply = await set(uuid, {
          title: "  Helpdesk desk  ",
          instructions: `${instructions}\r\n`,
          omit_output_schemas: true,
        });

        expect(reply.status).toBe(200);
        const body = reply.data as SetResponse;
        expect(body.success).toBe(true);
        expect(body.data).toMatchObject({
          endpoint_uuid: uuid,
          title: "Helpdesk desk",
          instructions,
          tool_listing: "full",
          omit_output_schemas: true,
        });
        expect(await rowFor(uuid)).toMatchObject([
          {
            title: "Helpdesk desk",
            instructions,
            tool_listing: "full",
            omit_output_schemas: true,
          },
        ]);

        const rows = await fx.auditEventually(
          `action = 'endpoint.presentation.set' AND target_id = $1`,
          [uuid],
        );
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({
          actor_type: "user",
          actor_id: fx.ownerId,
          target_type: "endpoint",
          outcome: "success",
        });
        expect(rows[0].detail).toMatchObject({
          title: "Helpdesk desk",
          instructions,
          instructions_length: instructions.length,
          instructions_sha256_prefix: createHash("sha256")
            .update(instructions)
            .digest("hex")
            .slice(0, 16),
          omit_output_schemas: true,
          previous: {
            title: null,
            instructions: null,
            tool_listing: "full",
            omit_output_schemas: false,
          },
        });
      });

      it("a second save replaces the settings and moves the update time forward", async () => {
        const uuid = await fx.endpoint({ name: "pres-upsert" });
        const first = (await set(uuid, { title: "First" })).data as SetResponse;
        const second = (
          await set(uuid, { title: "Second", omit_output_schemas: true })
        ).data as SetResponse;

        expect(second.data?.title).toBe("Second");
        expect(await rowFor(uuid)).toHaveLength(1);
        expect(Date.parse(second.data?.updated_at as string)).toBeGreaterThan(
          Date.parse(first.data?.updated_at as string),
        );

        const audited = await fx.auditEventually(
          `action = 'endpoint.presentation.set' AND target_id = $1 AND detail->>'title' = 'Second'`,
          [uuid],
        );
        expect(audited[0].detail).toMatchObject({
          previous: { title: "First" },
        });
      });

      it("an endpoint with no row reads as defaults with no update time", async () => {
        const uuid = await fx.endpoint({ name: "pres-defaults" });

        const reply = await get(uuid);

        expect(reply.status).toBe(200);
        expect((reply.data as GetResponse).data).toEqual({
          endpoint_uuid: uuid,
          title: null,
          instructions: null,
          tool_listing: "full",
          omit_output_schemas: false,
          updated_at: null,
          effective: { presentation_enabled: true, lean_enabled: true },
        });
      });

      it("saving every setting back to default deletes the row", async () => {
        const uuid = await fx.endpoint({ name: "pres-clear" });
        await set(uuid, { title: "Temporary", omit_output_schemas: true });
        expect(await rowFor(uuid)).toHaveLength(1);

        const reply = await set(uuid);

        expect((reply.data as SetResponse).success).toBe(true);
        expect(await rowFor(uuid)).toEqual([]);
        const read = (await get(uuid)).data as GetResponse;
        expect(read.data?.updated_at).toBeNull();
        const audited = await fx.auditEventually(
          `action = 'endpoint.presentation.set' AND target_id = $1 AND detail->>'title' IS NULL`,
          [uuid],
        );
        expect(audited[0].detail).toMatchObject({
          previous: { title: "Temporary", omit_output_schemas: true },
        });
      });

      it("saves a lean listing, reads it back as lean and audits the mode", async () => {
        const uuid = await fx.endpoint({ name: "pres-lean-save" });

        const saved = await set(uuid, {
          tool_listing: "lean",
          title: "Lean desk",
        });

        expect((saved.data as SetResponse).success).toBe(true);
        expect((saved.data as SetResponse).data?.tool_listing).toBe("lean");
        const rows = await rowFor(uuid);
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({ tool_listing: "lean" });
        const read = (await get(uuid)).data as GetResponse;
        expect(read.data?.tool_listing).toBe("lean");
        const audited = await fx.auditEventually(
          `action = 'endpoint.presentation.set' AND target_id = $1 AND detail->>'tool_listing' = 'lean'`,
          [uuid],
        );
        expect(audited[0].detail).toMatchObject({
          previous: { tool_listing: "full" },
        });
      });

      it("a lean row alone is not a row of defaults, so clearing the title keeps it", async () => {
        const uuid = await fx.endpoint({ name: "pres-lean-keep" });
        await set(uuid, { tool_listing: "lean", title: "Lean desk" });

        await set(uuid, { tool_listing: "lean" });

        const rows = await rowFor(uuid);
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({ tool_listing: "lean", title: null });
      });

      it("reads a lean row written outside the app without an error, and saving the full listing clears it", async () => {
        const uuid = await fx.endpoint({ name: "pres-lean" });
        await fx.suiteLock.query(
          `INSERT INTO endpoint_presentation (endpoint_uuid, tool_listing) VALUES ($1, 'lean')`,
          [uuid],
        );

        const read = await get(uuid);
        expect(read.status).toBe(200);
        expect((read.data as GetResponse).data?.tool_listing).toBe("lean");

        const cleared = await set(uuid);
        expect((cleared.data as SetResponse).success).toBe(true);
        expect(await rowFor(uuid)).toEqual([]);
      });

      it("is refused the settings of a private endpoint owned by someone else", async () => {
        const uuid = await fx.endpoint({
          name: "pres-private",
          userId: fx.otherMemberId,
        });

        const written = await set(uuid, { title: "Not mine" });
        const read = await get(uuid);

        expect((written.data as SetResponse).success).toBe(false);
        expect((written.data as SetResponse).message).toMatch(/Access denied/);
        expect((read.data as GetResponse).success).toBe(false);
        expect(await rowFor(uuid)).toEqual([]);
        expect(
          await fx.auditNow(
            `action = 'endpoint.presentation.set' AND target_id = $1`,
            [uuid],
          ),
        ).toEqual([]);
      });

      it("is told an unknown endpoint is not found", async () => {
        const reply = await set("00000000-0000-4000-8000-000000000000", {
          title: "Nowhere",
        });
        expect((reply.data as SetResponse).message).toBe("Endpoint not found");
      });

      it.each([
        ["a title over 80 characters", { title: "t".repeat(81) }],
        ["a newline in the title", { title: "a\nb" }],
        [
          "instructions over 1500 characters",
          { instructions: "i".repeat(1501) },
        ],
        ["a control character", { instructions: "a\u0007b" }],
        ["a text-direction override", { title: "a‮b" }],
        ["a listing mode that does not exist", { tool_listing: "everything" }],
      ])("refuses %s with 400 and writes no row", async (_label, over) => {
        const uuid = await fx.endpoint({ name: `pres-bad-${_label.length}` });

        const reply = await set(uuid, over);

        expect(reply.status).toBe(400);
        expect(reply.code).toBe("BAD_REQUEST");
        expect(await rowFor(uuid)).toEqual([]);
      });

      it("accepts the boundary values", async () => {
        const uuid = await fx.endpoint({ name: "pres-bounds" });
        const reply = await set(uuid, {
          title: "t".repeat(80),
          instructions: "i".repeat(1500),
        });
        expect((reply.data as SetResponse).success).toBe(true);
      });
    });

    describe("everyone else", () => {
      it("a member is refused reading and writing, and no row appears", async () => {
        const uuid = await fx.endpoint({ name: "pres-member" });

        const written = await set(
          uuid,
          { title: "Member edit" },
          { cookie: fx.memberCookie },
        );
        const read = await get(uuid, { cookie: fx.memberCookie });

        expect(written.status).toBe(403);
        expect(written.code).toBe("FORBIDDEN");
        expect(read.status).toBe(403);
        expect(await rowFor(uuid)).toEqual([]);
      });

      it.each([
        ["operator", () => fx.operator],
        ["sync", () => fx.sync],
      ])(
        "a %s-scope admin-plane key is refused with 403, leaves an rbac.denied row, and writes nothing",
        async (scope, key) => {
          const uuid = await fx.endpoint({ name: `pres-key-${scope}` });
          const { key: bearer, uuid: keyUuid } = key();

          const written = await set(
            uuid,
            { title: "Key edit" },
            { key: bearer },
          );
          const read = await get(uuid, { key: bearer });

          expect(written.status).toBe(403);
          expect(written.code).toBe("FORBIDDEN");
          expect(read.status).toBe(403);
          expect(await rowFor(uuid)).toEqual([]);

          for (const procedure of [
            "frontend.endpointPresentation.set",
            "frontend.endpointPresentation.get",
          ]) {
            const denied = await fx.auditEventually(
              `action = 'rbac.denied' AND target_id = $1 AND actor_id = $2`,
              [procedure, keyUuid],
            );
            expect(denied.length).toBeGreaterThanOrEqual(1);
            expect(denied[0]).toMatchObject({ actor_type: "api_key" });
            expect(denied[0].detail).toMatchObject({
              admin_plane: { key_uuid: keyUuid, scope },
            });
          }
          expect(
            await fx.auditNow(
              `action = 'endpoint.presentation.set' AND target_id = $1`,
              [uuid],
            ),
          ).toEqual([]);
        },
      );
    });
  },
);
