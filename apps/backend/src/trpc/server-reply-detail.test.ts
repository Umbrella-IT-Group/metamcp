/**
 * Which detail level of a stored server's connection each caller's reply
 * carries is decided by the router from the verified request context, and
 * handed to the implementation as an explicit argument (full for a person
 * signed in as an administrator, names only for an admin-plane key of either
 * scope, nothing for a member). Drives the real app router with recording
 * implementations, through a real tRPC caller, so the wiring is what is under
 * test: a router that handed the implementation the owner's role instead of
 * the verified caller kind would give an admin-plane key the full connection
 * (its owner is an administrator), and every implementation suite would still
 * pass.
 *
 * Also pinned: the contract's marker list and version, and that
 * `serverDetailLevelOf` fails closed.
 */
import {
  ADMIN_PLANE_OPERATOR_CONTRACT_VERSION,
  ADMIN_PLANE_OPERATOR_MARKERS,
  createAppRouter,
  serverDetailLevelOf,
} from "@repo/trpc";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

const calls: Array<{ path: string; args: unknown[] }> = [];
const stub = (router: string) =>
  new Proxy(
    {},
    {
      get: (_target, prop) =>
        typeof prop === "string"
          ? async (...args: unknown[]) => {
              calls.push({ path: `${router}.${prop}`, args });
              return {};
            }
          : undefined,
    },
  );
const ROUTERS = [
  "mcpServers",
  "namespaces",
  "endpoints",
  "oauth",
  "oauthClients",
  "oauthTokens",
  "users",
  "tools",
  "apiKeys",
  "config",
  "logs",
  "accessGroups",
  "endpointPresentation",
  "audit",
];
const appRouter = createAppRouter({
  frontend: Object.fromEntries(
    ROUTERS.map((name) => [name, stub(name)]),
  ) as never,
});

const KEY_UUID = "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b";
const ownerSession = {
  user: { id: "owner-1", role: "admin", email: "o@example.test" },
  session: { id: "s" },
};
const keyCtx = (scope: "sync" | "operator") => ({
  ...ownerSession,
  authOrigin: {
    kind: "admin_plane" as const,
    key_uuid: KEY_UUID,
    owner_user_id: "owner-1",
    scope,
  },
});
const memberCtx = {
  user: { id: "member-1", role: "member" },
  session: { id: "s" },
};

type Caller = Record<
  string,
  Record<string, (input?: unknown) => Promise<unknown>>
>;

/** The level argument each procedure's implementation received, or null when it was not reached. */
async function levelFor(
  ctx: object,
  router: "mcpServers" | "namespaces",
  procedure: string,
  input?: unknown,
): Promise<unknown> {
  calls.length = 0;
  const caller = (
    appRouter.createCaller(ctx as never) as unknown as {
      frontend: Caller;
    }
  ).frontend;
  try {
    await caller[router][procedure](input);
  } catch {
    // The stub answers {}, which fails the output schema after the
    // implementation ran; a refusal never reaches it.
  }
  const reached = calls.find(
    (entry) => entry.path === `${router}.${procedure}`,
  );
  if (!reached) return null;
  return reached.args[reached.args.length - 1];
}

const UUID = "33333333-3333-4333-8333-333333333333";

describe("the detail level of server replies, by caller", () => {
  it.each([
    ["a person signed in as an administrator", ownerSession, "full"],
    ["a sync-scope admin-plane key", keyCtx("sync"), "names_only"],
    ["an operator-scope admin-plane key", keyCtx("operator"), "names_only"],
    ["a member", memberCtx, "redacted"],
  ])("mcpServers.list for %s", async (_who, ctx, expected) => {
    expect(await levelFor(ctx, "mcpServers", "list")).toBe(expected);
  });

  it.each([
    ["a person signed in as an administrator", ownerSession, "full"],
    ["a sync-scope admin-plane key", keyCtx("sync"), "names_only"],
    ["an operator-scope admin-plane key", keyCtx("operator"), "names_only"],
    ["a member", memberCtx, "redacted"],
  ])("namespaces.get for %s", async (_who, ctx, expected) => {
    expect(await levelFor(ctx, "namespaces", "get", { uuid: UUID })).toBe(
      expected,
    );
  });

  it("gives a person signed in as an administrator the full connection on the human-only reads", async () => {
    expect(await levelFor(ownerSession, "mcpServers", "listAll")).toBe("full");
    expect(
      await levelFor(ownerSession, "mcpServers", "get", { uuid: UUID }),
    ).toBe("full");
  });

  it.each(["sync", "operator"] as const)(
    "never reaches the human-only reads for a %s-scope key, so no level is handed over",
    async (scope) => {
      expect(await levelFor(keyCtx(scope), "mcpServers", "listAll")).toBeNull();
      expect(
        await levelFor(keyCtx(scope), "mcpServers", "get", { uuid: UUID }),
      ).toBeNull();
    },
  );

  it("takes the level from the verified origin, not from the owner's role", async () => {
    // The same owner, an administrator, with and without the origin the
    // backend sets only for a key row it verified.
    const { authOrigin: _origin, ...person } = keyCtx("operator");
    expect(await levelFor(person, "mcpServers", "list")).toBe("full");
    expect(await levelFor(keyCtx("operator"), "mcpServers", "list")).toBe(
      "names_only",
    );
  });
});

describe("serverDetailLevelOf", () => {
  it("fails closed on a context it cannot read", () => {
    const hostile = {
      get authOrigin(): never {
        throw new Error("exotic");
      },
    };
    expect(serverDetailLevelOf(hostile as never)).toBe("redacted");
    expect(serverDetailLevelOf(undefined)).toBe("redacted");
    expect(serverDetailLevelOf(null)).toBe("redacted");
    expect(serverDetailLevelOf({} as never)).toBe("redacted");
  });

  it("does not read a role of administrator as full for an admin-plane origin", () => {
    expect(serverDetailLevelOf(keyCtx("sync") as never)).toBe("names_only");
  });
});

describe("the capabilities markers and contract", () => {
  it("lists exactly the two markers 2A adds, sorted, and leaves the contract at 3", () => {
    expect([...ADMIN_PLANE_OPERATOR_MARKERS]).toEqual([
      "server-reads-redacted-v1",
      "server-update-metadata-only-v1",
    ]);
    expect(ADMIN_PLANE_OPERATOR_CONTRACT_VERSION).toBe(3);
  });
});
