/**
 * Who may read and write an endpoint's presentation settings: a human
 * administrator's browser session, and nobody else.
 *
 * The title and the instructions reach models, so authorship is a human
 * administrator's act, the same posture as tool overrides. Neither procedure is
 * in an admin-plane procedure set, so an admin-plane API key of either scope is
 * refused by the scope middleware before the implementation runs, and a member
 * is refused by `adminProcedure`.
 *
 * Driven through the REAL app router (createAppRouter) and its real procedure
 * builders, with a recording stub for the implementation, as
 * admin-plane-scope.test.ts does: what is under test is who reaches the
 * implementation, not what it does. The Postgres-backed twin over the real
 * /trpc stack is endpoint-presentation.integration.test.ts.
 *
 * Oracle: the design's rule (C.8: human administrator session only, in neither
 * set) and the standing refusal sentence the scope middleware answers with.
 */
import {
  ADMIN_PLANE_FORBIDDEN_MESSAGE,
  ADMIN_PLANE_OPERATOR_PROCEDURES,
  ADMIN_PLANE_SYNC_PROCEDURES,
  assertAdminPlaneProcedureAllowed,
  createAppRouter,
  setTrpcAuditSink,
  type TrpcDenialEvent,
} from "@repo/trpc";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const KEY_UUID = "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b";
const OWNER_ID = "owner-admin-1";
const ENDPOINT_UUID = "11111111-1111-4111-8111-111111111111";

const PROCEDURES = [
  "frontend.endpointPresentation.get",
  "frontend.endpointPresentation.set",
] as const;

const INPUTS: Record<(typeof PROCEDURES)[number], unknown> = {
  "frontend.endpointPresentation.get": { endpoint_uuid: ENDPOINT_UUID },
  "frontend.endpointPresentation.set": {
    endpoint_uuid: ENDPOINT_UUID,
    title: "Desk",
    instructions: null,
    tool_listing: "full",
    omit_output_schemas: true,
  },
};

const owner = { id: OWNER_ID, role: "admin", email: "owner@example.test" };
const adminPlaneCtx = (scope: "sync" | "operator") => ({
  user: owner,
  session: { id: "synthetic-session" },
  authOrigin: {
    kind: "admin_plane" as const,
    key_uuid: KEY_UUID,
    owner_user_id: OWNER_ID,
    scope,
  },
  audit: { actor_ip: "203.0.113.5", actor_user_agent: "ci", request_id: "r1" },
});
const humanAdminCtx = { user: owner, session: { id: "browser-session" } };
const memberCtx = {
  user: { id: "member-1", role: "member", email: "member@example.test" },
  session: { id: "member-session" },
};

let reached: Array<{ method: string; args: unknown[] }> = [];
const implementation = {
  get: async (...args: unknown[]) => {
    reached.push({ method: "get", args });
    return { success: true, data: undefined };
  },
  set: async (...args: unknown[]) => {
    reached.push({ method: "set", args });
    return { success: true, data: undefined };
  },
};
/** Every other router's methods are stubs that fail the test if they run. */
const unused = new Proxy(
  {},
  {
    get: (_target, prop) =>
      typeof prop === "string"
        ? async () => {
            throw new Error(`unexpected call to ${prop}`);
          }
        : undefined,
  },
);

const appRouter = createAppRouter({
  frontend: {
    mcpServers: unused,
    namespaces: unused,
    endpoints: unused,
    oauth: unused,
    oauthClients: unused,
    oauthTokens: unused,
    users: unused,
    tools: unused,
    apiKeys: unused,
    config: unused,
    logs: unused,
    accessGroups: unused,
    endpointPresentation: implementation,
  } as unknown as Parameters<typeof createAppRouter>[0]["frontend"],
});

const ALL_PROCEDURES = Object.keys(
  (appRouter as unknown as { _def: { procedures: Record<string, unknown> } })
    ._def.procedures,
);

async function call(ctx: object, path: string, input: unknown) {
  const caller = appRouter.createCaller(ctx as never) as unknown as Record<
    string,
    unknown
  >;
  const fn = path
    .split(".")
    .reduce<unknown>(
      (node, key) => (node as Record<string, unknown>)[key],
      caller,
    ) as (input: unknown) => Promise<unknown>;
  try {
    await fn(input);
    return { error: null as { code?: string; message?: string } | null };
  } catch (error) {
    return { error: error as { code?: string; message?: string } };
  }
}

let denials: TrpcDenialEvent[] = [];
beforeEach(() => {
  reached = [];
  denials = [];
  setTrpcAuditSink((event) => {
    denials.push(event);
  });
});
afterEach(() => {
  setTrpcAuditSink(null);
});

describe("the procedures exist and are in neither admin-plane set", () => {
  it.each(PROCEDURES)("%s is a procedure of the app router", (path) => {
    expect(ALL_PROCEDURES).toContain(path);
  });

  it.each(PROCEDURES)("%s is in neither admin-plane procedure set", (path) => {
    expect(ADMIN_PLANE_SYNC_PROCEDURES.has(path)).toBe(false);
    expect(ADMIN_PLANE_OPERATOR_PROCEDURES.has(path)).toBe(false);
  });

  it.each(PROCEDURES)(
    "%s is refused by the scope check for a key of either scope, with the standing message",
    (path) => {
      for (const scope of ["sync", "operator"] as const) {
        expect(() =>
          assertAdminPlaneProcedureAllowed(
            adminPlaneCtx(scope),
            path,
            path.endsWith(".get") ? "query" : "mutation",
          ),
        ).toThrowError(ADMIN_PLANE_FORBIDDEN_MESSAGE);
      }
    },
  );
});

describe("through the real router", () => {
  it.each(PROCEDURES)(
    "%s is refused to an admin-plane key of either scope before the implementation runs",
    async (path) => {
      for (const scope of ["sync", "operator"] as const) {
        const result = await call(adminPlaneCtx(scope), path, INPUTS[path]);
        expect(result.error?.code).toBe("FORBIDDEN");
        expect(result.error?.message).toBe(ADMIN_PLANE_FORBIDDEN_MESSAGE);
      }
      expect(reached).toEqual([]);
      expect(denials).toHaveLength(2);
      expect(denials.map((d) => d.path)).toEqual([path, path]);
    },
  );

  it.each(PROCEDURES)(
    "%s is refused to a member, who is not an administrator",
    async (path) => {
      const result = await call(memberCtx, path, INPUTS[path]);
      expect(result.error?.code).toBe("FORBIDDEN");
      expect(reached).toEqual([]);
    },
  );

  it.each(PROCEDURES)("%s needs a session at all", async (path) => {
    const result = await call({}, path, INPUTS[path]);
    expect(result.error?.code).toBe("UNAUTHORIZED");
    expect(reached).toEqual([]);
  });

  it("a human administrator reaches both, and the writer is handed the session user and the audit actor", async () => {
    for (const path of PROCEDURES) {
      const result = await call(humanAdminCtx, path, INPUTS[path]);
      expect(result.error).toBeNull();
    }
    expect(reached.map((r) => r.method)).toEqual(["get", "set"]);
    const [, setCall] = reached;
    expect(setCall.args[1]).toBe(OWNER_ID);
    expect(setCall.args[2]).toMatchObject({ actor_id: OWNER_ID });
    expect(
      (setCall.args[2] as { admin_plane?: unknown }).admin_plane,
    ).toBeUndefined();
  });

  it("an invalid input never reaches the implementation", async () => {
    const result = await call(
      humanAdminCtx,
      "frontend.endpointPresentation.set",
      {
        ...(INPUTS["frontend.endpointPresentation.set"] as object),
        title: "a\nb",
      },
    );
    expect(result.error?.code).toBe("BAD_REQUEST");
    expect(reached).toEqual([]);
  });
});
