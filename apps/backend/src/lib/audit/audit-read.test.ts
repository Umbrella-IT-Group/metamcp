import { describe, expect, it, vi } from "vitest";

import { projectAuditDetail } from "./audit-read";

const readAuditLogPage = vi.fn();
vi.mock("../../db/repositories/audit-log-read.repo", () => ({
  readAuditLogPage: (...args: unknown[]) => readAuditLogPage(...args),
}));

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

describe("policy approval of a self-registration in the audit read", () => {
  // A successful oauth.dcr.register detail as the registration door writes
  // it, plus hostile extras: policy text inside the nested marker and a
  // top-level policy document no writer should ever add.
  const registrationDetail = {
    client_name: "Example Desktop Client",
    redirect_uris: ["http://localhost:53682/callback"],
    redirect_uri_count: 1,
    grant_types: ["authorization_code"],
    token_endpoint_auth_method: "none",
    has_client_secret: false,
    approval_status: "approved",
    dcr_mode: "pending",
    auto_approval: {
      entry_id: "desktop",
      policy_version: "a".repeat(64),
      allowed_cidrs: ["203.0.113.0/24"],
      client_name: "Example Desktop Client",
      document: { version: 1, entries: [] },
    },
    auto_approval_skipped: "cap",
    policy_document: '{"version":1,"entries":[]}',
  };
  const expectedDetail = {
    auto_approval: { entry_id: "desktop", policy_version: "a".repeat(64) },
    auto_approval_skipped: "cap",
  };

  it("returns only the marker's entry id and policy hash, and the cap flag", () => {
    expect(projectAuditDetail(registrationDetail)).toEqual({
      detail: expectedDetail,
      omitted: 12,
    });
  });

  it("is what audit.list returns for the row", async () => {
    const occurred = new Date("2026-01-01T00:00:00Z");
    readAuditLogPage.mockResolvedValueOnce([
      {
        uuid: "00000000-0000-4000-8000-000000000001",
        occurred_at: occurred,
        actor_type: "anonymous",
        actor_id: null,
        actor_label: null,
        actor_ip: "203.0.113.7",
        action: "oauth.dcr.register",
        target_type: "oauth_client",
        target_id: "mcp_client_example",
        outcome: "success",
        request_id: "r-1",
        http_status: 201,
        detail: registrationDetail,
      },
    ]);
    const { auditImplementations } = await import("../../trpc/audit.impl");
    const page = await auditImplementations.list({ limit: 10 } as never);
    expect(page.rows).toHaveLength(1);
    expect(page.rows[0].detail).toEqual(expectedDetail);
    expect(page.rows[0].detail_omitted).toBe(12);
    const text = JSON.stringify(page.rows[0].detail);
    expect(text).not.toContain("203.0.113.0/24");
    expect(text).not.toContain("Example Desktop Client");
    expect(text).not.toContain("entries");
  });
});
