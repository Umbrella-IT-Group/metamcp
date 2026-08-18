/**
 * The access-group admin surface: what it records, and what it invalidates.
 *
 * TWO properties, and the second one is the load-bearing half.
 *
 * WHAT IT RECORDS. These grants are the authorization boundary for every OAuth
 * caller on the gateway, so "who was added to what, and when was this endpoint's
 * gate switched on" has to be answerable from `audit_log` rather than from
 * inference. Every mutation is asserted to emit, and the no-op cases (a repeat
 * add, a delete that matched nothing) are asserted NOT to — a row claiming a
 * grant that was never made is worse than no row.
 *
 * WHAT IT INVALIDATES. The middleware caches its decision per (user, endpoint)
 * for a minute. Every mutation here must drop that cache on its success path,
 * or a revoked user keeps being served for up to a minute after an operator
 * believes they cut access. Asserted against the REAL cache — the module is not
 * mocked, so these tests fail if the `invalidateEndpointAccessCache()` call is
 * ever dropped from a mutation.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const {
  listWithCountsMock,
  findByUuidMock,
  findByNameMock,
  findDetailByUuidMock,
  findGroupsForEndpointMock,
  createMock,
  updateMock,
  deleteByUuidMock,
  addMemberMock,
  removeMemberMock,
  addEndpointMock,
  removeEndpointMock,
  setEndpointRestrictedMock,
  endpointFindByUuidMock,
  endpointFindAllMock,
  userFindByIdMock,
  userFindRoleByIdMock,
  loggerMock,
} = vi.hoisted(() => ({
  listWithCountsMock: vi.fn(),
  findByUuidMock: vi.fn(),
  findByNameMock: vi.fn(),
  findDetailByUuidMock: vi.fn(),
  findGroupsForEndpointMock: vi.fn(),
  createMock: vi.fn(),
  updateMock: vi.fn(),
  deleteByUuidMock: vi.fn(),
  addMemberMock: vi.fn(),
  removeMemberMock: vi.fn(),
  addEndpointMock: vi.fn(),
  removeEndpointMock: vi.fn(),
  setEndpointRestrictedMock: vi.fn(),
  endpointFindByUuidMock: vi.fn(),
  endpointFindAllMock: vi.fn(),
  userFindByIdMock: vi.fn(),
  userFindRoleByIdMock: vi.fn(),
  loggerMock: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

vi.mock("../db/repositories/access-groups.repo", () => ({
  accessGroupsRepository: {
    listWithCounts: listWithCountsMock,
    findByUuid: findByUuidMock,
    findByName: findByNameMock,
    findDetailByUuid: findDetailByUuidMock,
    findGroupsForEndpoint: findGroupsForEndpointMock,
    create: createMock,
    update: updateMock,
    deleteByUuid: deleteByUuidMock,
    addMember: addMemberMock,
    removeMember: removeMemberMock,
    addEndpoint: addEndpointMock,
    removeEndpoint: removeEndpointMock,
    setEndpointRestricted: setEndpointRestrictedMock,
    // The gate's own query. Present because `lib/endpoint-access-control` is
    // deliberately NOT mocked in this file — the invalidation assertions below
    // drive the real cache.
    hasEndpointGrant: vi.fn().mockResolvedValue(true),
  },
}));

vi.mock("../db/repositories/endpoints.repo", () => ({
  endpointsRepository: {
    findByUuid: endpointFindByUuidMock,
    findAll: endpointFindAllMock,
  },
}));

vi.mock("../db/repositories/users.repo", () => ({
  usersRepository: {
    findById: userFindByIdMock,
    findRoleById: userFindRoleByIdMock,
  },
}));

const { accessGroupsImplementations } = await import("./access-groups.impl");
const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");
const {
  isOAuthUserAllowedOnEndpoint,
  __resetEndpointAccessCacheForTesting,
  __endpointAccessCacheSizeForTesting,
} = await import("@/lib/endpoint-access-control");

type AuditRow = {
  action: string;
  outcome: string;
  actor_type: string;
  actor_id?: string | null;
  target_type?: string | null;
  target_id?: string | null;
  detail?: Record<string, unknown>;
};

const GROUP_UUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ENDPOINT_UUID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const USER_ID = "user-alice";

const ACTOR = {
  actor_id: "admin-1",
  actor_label: "admin@example.invalid",
  actor_ip: "203.0.113.9",
  actor_user_agent: "Mozilla/5.0",
  request_id: "req-1",
};

const GROUP_ROW = {
  uuid: GROUP_UUID,
  name: "helpdesk",
  description: null,
  created_at: new Date("2026-08-01T00:00:00Z"),
};

const ENDPOINT_ROW = {
  uuid: ENDPOINT_UUID,
  name: "autotask",
  restricted: false,
  enable_oauth: true,
  enable_api_key_auth: false,
};

let rows: AuditRow[];
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

/**
 * Put one real decision in the middleware's cache, so a mutation's
 * invalidation has something to actually drop. Uses the real gate, not a stub.
 */
async function seedDecisionCache(): Promise<void> {
  __resetEndpointAccessCacheForTesting();
  userFindRoleByIdMock.mockResolvedValue("member");
  await isOAuthUserAllowedOnEndpoint(USER_ID, {
    uuid: ENDPOINT_UUID,
    restricted: true,
  });
  expect(__endpointAccessCacheSizeForTesting()).toBe(1);
}

beforeEach(() => {
  vi.clearAllMocks();
  rows = [];
  setAuditSinkForTesting(async (event) => {
    rows.push(event as AuditRow);
  });
  findByUuidMock.mockResolvedValue(GROUP_ROW);
  findByNameMock.mockResolvedValue(undefined);
  endpointFindByUuidMock.mockResolvedValue(ENDPOINT_ROW);
  userFindByIdMock.mockResolvedValue({
    id: USER_ID,
    email: "alice@example.invalid",
    name: "Alice",
  });
  userFindRoleByIdMock.mockResolvedValue("member");
  __resetEndpointAccessCacheForTesting();
});

afterEach(() => {
  setAuditSinkForTesting(undefined);
});

describe("group.create", () => {
  it("emits group.create naming the group, and returns the new row", async () => {
    createMock.mockResolvedValue({ ...GROUP_ROW, name: "helpdesk" });

    const result = await accessGroupsImplementations.create(
      { name: "helpdesk" },
      ACTOR,
    );
    await flush();

    expect(result.success).toBe(true);
    expect(result.data?.member_count).toBe(0);
    expect(rows).toHaveLength(1);
    expect(rows[0].action).toBe("group.create");
    expect(rows[0].target_type).toBe("access_group");
    expect(rows[0].target_id).toBe(GROUP_UUID);
    expect(rows[0].actor_id).toBe("admin-1");
    expect(rows[0].detail?.name).toBe("helpdesk");
  });

  it("refuses a duplicate name and writes NO row", async () => {
    findByNameMock.mockResolvedValue({ uuid: "some-other-uuid" });

    const result = await accessGroupsImplementations.create(
      { name: "helpdesk" },
      ACTOR,
    );
    await flush();

    expect(result.success).toBe(false);
    expect(result.message).toContain("already exists");
    expect(createMock).not.toHaveBeenCalled();
    expect(rows).toHaveLength(0);
  });
});

describe("group.update / group.delete", () => {
  it("update emits group.update", async () => {
    updateMock.mockResolvedValue({ ...GROUP_ROW, name: "helpdesk-tier-2" });

    const result = await accessGroupsImplementations.update(
      { uuid: GROUP_UUID, name: "helpdesk-tier-2" },
      ACTOR,
    );
    await flush();

    expect(result.success).toBe(true);
    expect(rows.map((r) => r.action)).toEqual(["group.update"]);
    expect(rows[0].detail?.name).toBe("helpdesk-tier-2");
  });

  it("update on a missing group reports the miss and writes NO row", async () => {
    updateMock.mockResolvedValue(undefined);

    const result = await accessGroupsImplementations.update(
      { uuid: GROUP_UUID, name: "helpdesk" },
      ACTOR,
    );
    await flush();

    expect(result.success).toBe(false);
    expect(rows).toHaveLength(0);
  });

  it("delete emits group.delete", async () => {
    deleteByUuidMock.mockResolvedValue(GROUP_ROW);

    const result = await accessGroupsImplementations.delete(
      { uuid: GROUP_UUID },
      ACTOR,
    );
    await flush();

    expect(result.success).toBe(true);
    expect(rows.map((r) => r.action)).toEqual(["group.delete"]);
    expect(rows[0].target_id).toBe(GROUP_UUID);
  });

  it("delete that matched nothing writes NO row", async () => {
    deleteByUuidMock.mockResolvedValue(undefined);

    const result = await accessGroupsImplementations.delete(
      { uuid: GROUP_UUID },
      ACTOR,
    );
    await flush();

    expect(result.success).toBe(false);
    expect(rows).toHaveLength(0);
  });
});

describe("membership mutations", () => {
  it("addMember emits group.member.add with the group and the account", async () => {
    addMemberMock.mockResolvedValue(true);

    const result = await accessGroupsImplementations.addMember(
      { group_uuid: GROUP_UUID, user_id: USER_ID },
      ACTOR,
    );
    await flush();

    expect(result.success).toBe(true);
    expect(rows.map((r) => r.action)).toEqual(["group.member.add"]);
    expect(rows[0].detail?.group_name).toBe("helpdesk");
    expect(rows[0].detail?.user_id).toBe(USER_ID);
    expect(rows[0].detail?.user_email).toBe("alice@example.invalid");
  });

  it("a REPEAT add succeeds but writes NO row, because nothing changed", async () => {
    addMemberMock.mockResolvedValue(false);

    const result = await accessGroupsImplementations.addMember(
      { group_uuid: GROUP_UUID, user_id: USER_ID },
      ACTOR,
    );
    await flush();

    expect(result.success).toBe(true);
    expect(rows).toHaveLength(0);
  });

  it("an unknown account is reported as such, never inserted", async () => {
    userFindByIdMock.mockResolvedValue(undefined);

    const result = await accessGroupsImplementations.addMember(
      { group_uuid: GROUP_UUID, user_id: "ghost" },
      ACTOR,
    );
    await flush();

    expect(result.success).toBe(false);
    expect(result.message).toBe("User not found");
    expect(addMemberMock).not.toHaveBeenCalled();
    expect(rows).toHaveLength(0);
  });

  it("removeMember emits group.member.remove", async () => {
    removeMemberMock.mockResolvedValue(true);

    const result = await accessGroupsImplementations.removeMember(
      { group_uuid: GROUP_UUID, user_id: USER_ID },
      ACTOR,
    );
    await flush();

    expect(result.success).toBe(true);
    expect(rows.map((r) => r.action)).toEqual(["group.member.remove"]);
  });

  it("removing a non-member reports the miss and writes NO row", async () => {
    removeMemberMock.mockResolvedValue(false);

    const result = await accessGroupsImplementations.removeMember(
      { group_uuid: GROUP_UUID, user_id: USER_ID },
      ACTOR,
    );
    await flush();

    expect(result.success).toBe(false);
    expect(rows).toHaveLength(0);
  });
});

describe("endpoint mapping mutations", () => {
  it("addEndpoint emits group.endpoint.add, recording whether the gate is on", async () => {
    addEndpointMock.mockResolvedValue(true);

    const result = await accessGroupsImplementations.addEndpoint(
      { group_uuid: GROUP_UUID, endpoint_uuid: ENDPOINT_UUID },
      ACTOR,
    );
    await flush();

    expect(result.success).toBe(true);
    expect(rows.map((r) => r.action)).toEqual(["group.endpoint.add"]);
    expect(rows[0].detail?.endpoint_name).toBe("autotask");
    // The mapping is legal and INERT while the endpoint has not opted in, and
    // a reader of this row should not have to join `endpoints` to learn that.
    expect(rows[0].detail?.endpoint_restricted).toBe(false);
  });

  it("an unknown endpoint is reported as such, never mapped", async () => {
    endpointFindByUuidMock.mockResolvedValue(undefined);

    const result = await accessGroupsImplementations.addEndpoint(
      { group_uuid: GROUP_UUID, endpoint_uuid: ENDPOINT_UUID },
      ACTOR,
    );
    await flush();

    expect(result.success).toBe(false);
    expect(result.message).toBe("Endpoint not found");
    expect(addEndpointMock).not.toHaveBeenCalled();
    expect(rows).toHaveLength(0);
  });

  it("removeEndpoint emits group.endpoint.remove", async () => {
    removeEndpointMock.mockResolvedValue(true);

    const result = await accessGroupsImplementations.removeEndpoint(
      { group_uuid: GROUP_UUID, endpoint_uuid: ENDPOINT_UUID },
      ACTOR,
    );
    await flush();

    expect(result.success).toBe(true);
    expect(rows.map((r) => r.action)).toEqual(["group.endpoint.remove"]);
  });
});

describe("endpoint.restricted.set", () => {
  it("emits both the previous and the new value", async () => {
    endpointFindByUuidMock.mockResolvedValue({
      ...ENDPOINT_ROW,
      restricted: false,
    });
    setEndpointRestrictedMock.mockResolvedValue({
      ...ENDPOINT_ROW,
      restricted: true,
    });

    const result = await accessGroupsImplementations.setEndpointRestricted(
      { endpoint_uuid: ENDPOINT_UUID, restricted: true },
      ACTOR,
    );
    await flush();

    expect(result.success).toBe(true);
    expect(rows.map((r) => r.action)).toEqual(["endpoint.restricted.set"]);
    expect(rows[0].target_type).toBe("endpoint");
    expect(rows[0].target_id).toBe(ENDPOINT_UUID);
    // "Who turned this on" needs the before as well as the after.
    expect(rows[0].detail?.previous).toBe(false);
    expect(rows[0].detail?.restricted).toBe(true);
  });

  it("an unknown endpoint writes NO row", async () => {
    endpointFindByUuidMock.mockResolvedValue(undefined);

    const result = await accessGroupsImplementations.setEndpointRestricted(
      { endpoint_uuid: ENDPOINT_UUID, restricted: true },
      ACTOR,
    );
    await flush();

    expect(result.success).toBe(false);
    expect(setEndpointRestrictedMock).not.toHaveBeenCalled();
    expect(rows).toHaveLength(0);
  });
});

describe("every mutation drops the middleware's decision cache", () => {
  /**
   * The revocation guarantee, asserted against the REAL cache rather than a
   * spy: `lib/endpoint-access-control` is deliberately not mocked in this file,
   * so dropping an `invalidateEndpointAccessCache()` call from any of these
   * turns the corresponding case red.
   */
  const cases: Array<[string, () => Promise<unknown>]> = [
    [
      "create",
      () => {
        createMock.mockResolvedValue(GROUP_ROW);
        return accessGroupsImplementations.create({ name: "x" }, ACTOR);
      },
    ],
    [
      "update",
      () => {
        updateMock.mockResolvedValue(GROUP_ROW);
        return accessGroupsImplementations.update(
          { uuid: GROUP_UUID, name: "x" },
          ACTOR,
        );
      },
    ],
    [
      "delete",
      () => {
        deleteByUuidMock.mockResolvedValue(GROUP_ROW);
        return accessGroupsImplementations.delete({ uuid: GROUP_UUID }, ACTOR);
      },
    ],
    [
      "addMember",
      () => {
        addMemberMock.mockResolvedValue(true);
        return accessGroupsImplementations.addMember(
          { group_uuid: GROUP_UUID, user_id: USER_ID },
          ACTOR,
        );
      },
    ],
    [
      "removeMember",
      () => {
        removeMemberMock.mockResolvedValue(true);
        return accessGroupsImplementations.removeMember(
          { group_uuid: GROUP_UUID, user_id: USER_ID },
          ACTOR,
        );
      },
    ],
    [
      "addEndpoint",
      () => {
        addEndpointMock.mockResolvedValue(true);
        return accessGroupsImplementations.addEndpoint(
          { group_uuid: GROUP_UUID, endpoint_uuid: ENDPOINT_UUID },
          ACTOR,
        );
      },
    ],
    [
      "removeEndpoint",
      () => {
        removeEndpointMock.mockResolvedValue(true);
        return accessGroupsImplementations.removeEndpoint(
          { group_uuid: GROUP_UUID, endpoint_uuid: ENDPOINT_UUID },
          ACTOR,
        );
      },
    ],
    [
      "setEndpointRestricted",
      () => {
        setEndpointRestrictedMock.mockResolvedValue({
          ...ENDPOINT_ROW,
          restricted: true,
        });
        return accessGroupsImplementations.setEndpointRestricted(
          { endpoint_uuid: ENDPOINT_UUID, restricted: true },
          ACTOR,
        );
      },
    ],
  ];

  it.each(cases)("%s invalidates", async (_name, run) => {
    await seedDecisionCache();
    await run();
    expect(__endpointAccessCacheSizeForTesting()).toBe(0);
  });

  it("a mutation that changed NOTHING leaves the cache alone", async () => {
    // A repeat add grants nothing, so throwing every decision on the gateway
    // away for it would be a self-inflicted stampede on a no-op.
    await seedDecisionCache();
    addMemberMock.mockResolvedValue(false);

    await accessGroupsImplementations.addMember(
      { group_uuid: GROUP_UUID, user_id: USER_ID },
      ACTOR,
    );

    expect(__endpointAccessCacheSizeForTesting()).toBe(1);
  });
});

describe("read side", () => {
  it("listEndpoints returns every endpoint, reduced to what a picker needs", async () => {
    endpointFindAllMock.mockResolvedValue([
      { ...ENDPOINT_ROW, namespace_uuid: "ns", enable_oauth: true },
      {
        uuid: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        name: "ninja",
        restricted: true,
        namespace_uuid: "ns",
        enable_oauth: false,
      },
    ]);

    const result = await accessGroupsImplementations.listEndpoints();

    expect(result.success).toBe(true);
    expect(result.data).toEqual([
      { uuid: ENDPOINT_UUID, name: "autotask", restricted: false },
      {
        uuid: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        name: "ninja",
        restricted: true,
      },
    ]);
    // The namespace binding and auth posture are NOT disclosed by this query.
    expect(JSON.stringify(result.data)).not.toContain("namespace_uuid");
    expect(JSON.stringify(result.data)).not.toContain("enable_oauth");
  });

  it("getEndpointAccess reports the gate state alongside the mapped groups", async () => {
    endpointFindByUuidMock.mockResolvedValue({
      ...ENDPOINT_ROW,
      restricted: true,
    });
    findGroupsForEndpointMock.mockResolvedValue([
      { uuid: GROUP_UUID, name: "helpdesk", member_count: 3 },
    ]);

    const result = await accessGroupsImplementations.getEndpointAccess({
      endpoint_uuid: ENDPOINT_UUID,
    });

    expect(result.success).toBe(true);
    expect(result.data?.restricted).toBe(true);
    expect(result.data?.groups).toEqual([
      { uuid: GROUP_UUID, name: "helpdesk", member_count: 3 },
    ]);
  });

  it("getEndpointAccess carries the auth toggles, so the panel can tell inert from enforcing", async () => {
    // Without these the UI can only say "restricted", which on an endpoint that
    // accepts no OAuth callers is a switch that reads as on and gates nobody.
    endpointFindByUuidMock.mockResolvedValue({
      ...ENDPOINT_ROW,
      restricted: true,
      enable_oauth: false,
      enable_api_key_auth: true,
    });
    findGroupsForEndpointMock.mockResolvedValue([]);

    const result = await accessGroupsImplementations.getEndpointAccess({
      endpoint_uuid: ENDPOINT_UUID,
    });

    expect(result.data?.enable_oauth).toBe(false);
    expect(result.data?.enable_api_key_auth).toBe(true);
  });
});
