import { describe, expect, it } from "vitest";

import {
  assertTopologyRemovalConfirmed,
  cascadeCounts,
  firstRemovalBlocker,
  hiddenDependents,
  removalBlockers,
  TOPOLOGY_REMOVAL_REFUSALS,
  type TopologyBlocker,
  topologyRemovalFingerprint,
  TopologyRemovalRefusal,
  type TopologyRemovalState,
  topologySnapshot,
  visibleDependents,
} from "./topology-removal-rules";

const UUID = "11111111-1111-4111-8111-111111111111";
const CALLER = "user-caller";

const blocker = (over: Partial<TopologyBlocker>): TopologyBlocker => ({
  rule: "server_mounted",
  kind: "namespace",
  key: "aaaaaaaa-0000-4000-8000-000000000001",
  uuid: "bbbbbbbb-0000-4000-8000-000000000001",
  name: "ns-one",
  is_active: null,
  owner_user_id: null,
  ...over,
});

const state = (
  over: Partial<TopologyRemovalState> = {},
): TopologyRemovalState => ({
  kind: "mcp_server",
  uuid: UUID,
  name: "retired",
  user_id: null,
  version: "1234",
  fields: {
    type: "STREAMABLE_HTTP",
    error_status: "ERROR",
    created_at: "2026-01-01T00:00:00.000Z",
  },
  blockers: [],
  cascades: [
    { kind: "tool", key: "t-2", version: "20" },
    { kind: "tool", key: "t-1", version: "10" },
    { kind: "oauth_session", key: "o-1", version: null },
  ],
  live_sessions: null,
  ...over,
});

describe("removalBlockers", () => {
  it("reports every rule once, in the fixed order, with target_private first", () => {
    const s = state({
      user_id: CALLER,
      blockers: [
        blocker({ rule: "server_tools_mapped", key: "m-2" }),
        blocker({ rule: "server_mounted", key: "m-1" }),
        blocker({ rule: "server_tools_mapped", key: "m-3" }),
      ],
    });
    expect(removalBlockers(s)).toEqual([
      "target_private",
      "server_mounted",
      "server_tools_mapped",
    ]);
    expect(firstRemovalBlocker(s)).toBe("target_private");
  });

  it("finds nothing for a public row with no blocker", () => {
    expect(removalBlockers(state())).toEqual([]);
    expect(firstRemovalBlocker(state())).toBeNull();
  });
});

describe("topologyRemovalFingerprint", () => {
  it("does not depend on the order the database returned the rows in", () => {
    const a = state({
      blockers: [blocker({ key: "k-1" }), blocker({ key: "k-2" })],
    });
    const b = state({
      blockers: [blocker({ key: "k-2" }), blocker({ key: "k-1" })],
      cascades: [...a.cascades].reverse(),
      fields: {
        created_at: a.fields.created_at,
        error_status: "ERROR",
        type: "STREAMABLE_HTTP",
      },
    });
    expect(topologyRemovalFingerprint(b)).toBe(topologyRemovalFingerprint(a));
    expect(topologyRemovalFingerprint(a)).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it.each([
    ["a rename", { name: "renamed" }],
    ["a same-name edit (row version)", { version: "1235" }],
    ["an owner change", { user_id: "someone" }],
    [
      "a judged field",
      {
        fields: {
          type: "SSE",
          error_status: "ERROR",
          created_at: "2026-01-01T00:00:00.000Z",
        },
      },
    ],
    ["a new blocker", { blockers: [blocker({})] }],
    [
      "an edited catalog row",
      {
        cascades: [
          { kind: "tool" as const, key: "t-1", version: "11" },
          { kind: "tool" as const, key: "t-2", version: "20" },
          { kind: "oauth_session" as const, key: "o-1", version: null },
        ],
      },
    ],
    [
      "a replaced OAuth session",
      {
        cascades: [
          { kind: "tool" as const, key: "t-1", version: "10" },
          { kind: "tool" as const, key: "t-2", version: "20" },
          { kind: "oauth_session" as const, key: "o-2", version: null },
        ],
      },
    ],
  ])("changes with %s", (_label, over) => {
    expect(topologyRemovalFingerprint(state(over))).not.toBe(
      topologyRemovalFingerprint(state()),
    );
  });

  it("does not change with persisted session churn", () => {
    expect(topologyRemovalFingerprint(state({ live_sessions: 9 }))).toBe(
      topologyRemovalFingerprint(state({ live_sessions: 0 })),
    );
  });
});

describe("visibility", () => {
  const s = state({
    blockers: [
      blocker({
        key: "m-1",
        uuid: "ns-public",
        name: "b",
        owner_user_id: null,
      }),
      blocker({
        key: "m-2",
        uuid: "ns-public",
        name: "b",
        owner_user_id: null,
      }),
      blocker({
        key: "m-3",
        uuid: "ns-mine",
        name: "a",
        owner_user_id: CALLER,
      }),
      blocker({
        key: "m-4",
        uuid: "ns-theirs",
        name: "secret",
        owner_user_id: "other",
      }),
      blocker({
        rule: "server_tools_mapped",
        key: "m-5",
        uuid: "ns-theirs",
        name: "secret",
        owner_user_id: "other",
      }),
    ],
  });

  it("names public rows and the caller's own, once per rule, and never another person's", () => {
    const visible = visibleDependents(s, CALLER);
    expect(visible.map((d) => d.uuid)).toEqual(["ns-mine", "ns-public"]);
    expect(JSON.stringify(visible)).not.toContain("secret");
  });

  it("counts another person's rows per rule", () => {
    expect(hiddenDependents(s, CALLER)).toEqual([
      { rule: "server_mounted", count: 1 },
      { rule: "server_tools_mapped", count: 1 },
    ]);
  });
});

describe("snapshot and cascades", () => {
  it("records only the kind, name, owner, the picked fields and the cascade counts", () => {
    expect(topologySnapshot(state())).toEqual({
      kind: "mcp_server",
      name: "retired",
      owner_user_id: null,
      type: "STREAMABLE_HTTP",
      error_status: "ERROR",
      created_at: "2026-01-01T00:00:00.000Z",
      cascade_tool_count: 2,
      cascade_oauth_session_count: 1,
    });
    expect(cascadeCounts(state())).toEqual([
      { kind: "tool", count: 2 },
      { kind: "oauth_session", count: 1 },
    ]);
  });
});

describe("assertTopologyRemovalConfirmed", () => {
  it("accepts the current name and fingerprint", () => {
    expect(() =>
      assertTopologyRemovalConfirmed(
        state(),
        "retired",
        topologyRemovalFingerprint(state()),
      ),
    ).not.toThrow();
  });

  it("refuses a wrong name before it looks at the fingerprint", () => {
    expect(() =>
      assertTopologyRemovalConfirmed(
        state(),
        "Retired",
        "sha256:" + "0".repeat(64),
      ),
    ).toThrow(new TopologyRemovalRefusal("confirm_name_mismatch"));
  });

  it("refuses a stale fingerprint", () => {
    const stale = topologyRemovalFingerprint(state({ version: "1" }));
    try {
      assertTopologyRemovalConfirmed(state(), "retired", stale);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(TopologyRemovalRefusal);
      expect((error as TopologyRemovalRefusal).rule).toBe("impact_changed");
      expect((error as TopologyRemovalRefusal).code).toBe("CONFLICT");
    }
  });

  it("gives every refusal a fixed sentence that names no row", () => {
    for (const { message } of Object.values(TOPOLOGY_REMOVAL_REFUSALS)) {
      expect(message).not.toMatch(/[0-9a-f]{8}-[0-9a-f]{4}/);
      expect(message.length).toBeGreaterThan(20);
    }
  });
});
