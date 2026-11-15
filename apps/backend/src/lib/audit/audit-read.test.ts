import { describe, expect, it } from "vitest";

import { projectAuditDetail } from "./audit-read";

describe("projectAuditDetail", () => {
  it("drops credential-bearing and unrecognised fields inside allowed detail objects", () => {
    const { detail, omitted } = projectAuditDetail({
      old_value: {
        name: "old server",
        bearer_token: "previous-credential",
        url: "https://backend.example/mcp?token=previous-credential",
      },
      new_value: {
        name: "new server",
        password: "next-credential",
        command: "client --secret next-credential",
      },
      snapshot: {
        name: "retired key",
        key_prefix: "sk_mt_…abcd",
        key_hash: "credential-digest",
        key: "raw-credential",
      },
      admin_plane: {
        key_uuid: "key-id",
        scope: "operator",
        session_token: "session-credential",
        unknown_field: "unexpected-value",
      },
      ip_policy: {
        mode: "enforce",
        allowed_cidrs: ["203.0.113.0/24"],
        api_key: "policy-credential",
      },
    });

    expect(detail).toEqual({
      old_value: { name: "old server" },
      new_value: { name: "new server" },
      snapshot: { name: "retired key", key_prefix: "sk_mt_…abcd" },
      admin_plane: { key_uuid: "key-id", scope: "operator" },
      ip_policy: { mode: "enforce", allowed_cidrs: ["203.0.113.0/24"] },
    });
    expect(omitted).toBe(9);
    expect(JSON.stringify(detail)).not.toContain("credential");
  });

  it("preserves safe update values and scalar configuration before-state", () => {
    expect(
      projectAuditDetail({
        old_value: {
          description: "previous description",
          require_scoped_api_key: false,
          namespace_uuid: "namespace-id",
          server_uuids: ["server-id"],
          client_max_rate: 10,
          allowed_cidrs: null,
          mode: "audit",
        },
        new_value: {
          require_scoped_api_key: true,
          allowed_cidrs: ["203.0.113.0/24"],
          mode: "enforce",
        },
      }).omitted,
    ).toBe(0);
    expect(
      projectAuditDetail({
        old_value: false,
        new_value: true,
        policy_widened: true,
      }),
    ).toEqual({
      detail: { old_value: false, new_value: true, policy_widened: true },
      omitted: 0,
    });
  });
});
