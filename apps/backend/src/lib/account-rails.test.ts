/**
 * The account rails (lib/account-rails) without a database: which account
 * changes an admin-plane key may make, and the last-enabled-administrator rule
 * every caller is held to. The row locks they are judged under are pinned
 * against Postgres in trpc/admin-plane-rails.integration.test.ts.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const { ownsMock } = vi.hoisted(() => ({ ownsMock: vi.fn() }));
vi.mock("../db/repositories/admin-plane-locks", () => ({
  ownsActiveAdminPlaneKey: ownsMock,
}));

const { ACCOUNT_RAIL_REFUSALS, assertAccountChangeAllowed } = await import(
  "./account-rails"
);
const { AdminRuleRefusal } = await import("./audit/admin-write");

const human = {
  actor_id: "admin-1",
  actor_label: null,
  actor_ip: null,
  actor_user_agent: null,
  request_id: null,
};
const key = {
  ...human,
  admin_plane: {
    key_uuid: "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b",
    owner_user_id: "admin-1",
    scope: "operator" as const,
  },
};
const member = { id: "m-1", role: "member", disabled: false };
const admin = { id: "a-2", role: "admin", disabled: false };

const judge = (
  actor: object,
  target: { id: string; role: string; disabled: boolean },
  admins: string[] | null,
  change: "disable" | "enable" | "revoke" | "delete",
) =>
  assertAccountChangeAllowed(
    {} as never,
    actor as never,
    target,
    admins,
    change,
  )
    .then(() => null)
    .catch((e) => e);

beforeEach(() => {
  ownsMock.mockReset();
  ownsMock.mockResolvedValue(false);
});

describe("an admin-plane key", () => {
  it.each(["disable", "enable", "revoke", "delete"] as const)(
    "may not %s an administrator's account",
    async (change) => {
      const refusal = await judge(key, admin, ["admin-1", "a-2"], change);
      expect(refusal).toBeInstanceOf(AdminRuleRefusal);
      expect(refusal).toMatchObject({
        code: "FORBIDDEN",
        message: ACCOUNT_RAIL_REFUSALS.protectedTarget,
      });
      expect(refusal.denial.detail).toEqual({ rule: "account_admin_target" });
    },
  );

  it("may not change the account that owns an active admin-plane key", async () => {
    ownsMock.mockResolvedValue(true);
    const refusal = await judge(key, member, ["admin-1"], "disable");
    expect(refusal).toMatchObject({ code: "FORBIDDEN" });
    expect(refusal.denial.detail).toEqual({
      rule: "account_admin_plane_owner",
    });
  });

  it("may change an ordinary member's account", async () => {
    expect(await judge(key, member, ["admin-1"], "disable")).toBeNull();
    expect(ownsMock).toHaveBeenCalledWith({}, "m-1");
  });
});

describe("every caller", () => {
  it.each(["disable", "delete"] as const)(
    "may not %s the last enabled administrator",
    async (change) => {
      const refusal = await judge(human, admin, ["a-2"], change);
      expect(refusal).toMatchObject({
        code: "CONFLICT",
        message: ACCOUNT_RAIL_REFUSALS.lastAdministrator,
      });
    },
  );

  it("may disable an administrator while another stays enabled", async () => {
    expect(await judge(human, admin, ["admin-1", "a-2"], "disable")).toBeNull();
  });

  it("is not held to it for enabling, revoking, or an already-disabled administrator", async () => {
    expect(await judge(human, admin, ["a-2"], "enable")).toBeNull();
    expect(await judge(human, admin, null, "revoke")).toBeNull();
    expect(
      await judge(human, { ...admin, disabled: true }, [], "delete"),
    ).toBeNull();
  });

  it("does not ask a person's session about admin-plane keys", async () => {
    await judge(human, member, ["admin-1"], "disable");
    expect(ownsMock).not.toHaveBeenCalled();
  });
});
