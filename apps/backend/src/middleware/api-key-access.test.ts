/**
 * Unit tests for checkApiKeyAccess — the per-request access gate every
 * API-key-authenticated public-endpoint request funnels through (both
 * authenticateApiKey branches in api-key-oauth.middleware.ts).
 *
 * Covers the endpoint-scope semantics added by migration 0023:
 *  - a scoped key (endpoint_uuid non-NULL) works ONLY on its bound endpoint,
 *  - an unscoped key (endpoint_uuid NULL — legacy/grandfathered) keeps
 *    working on every endpoint UNLESS the endpoint opts out via
 *    require_scoped_api_key,
 *  - the pre-existing public/private ownership checks are unchanged.
 *
 * The api-keys repository module is mocked because the middleware constructs
 * one at module load and the repo's import chain reaches db/index (needs a
 * live DATABASE_URL). checkApiKeyAccess itself is a pure function.
 */

import { DatabaseEndpoint } from "@repo/zod-types";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock("../db/repositories/api-keys.repo", () => ({
  ApiKeysRepository: class {
    validateApiKey = vi.fn();
  },
}));

import {
  checkApiKeyAccess,
  resolveActsAsUserId,
} from "./api-key-oauth.middleware";

const ENDPOINT_UUID = "11111111-1111-4111-8111-111111111111";
const OTHER_ENDPOINT_UUID = "22222222-2222-4222-8222-222222222222";

const makeEndpoint = (
  overrides: Partial<DatabaseEndpoint> = {},
): DatabaseEndpoint => ({
  uuid: ENDPOINT_UUID,
  name: "autotask",
  description: null,
  namespace_uuid: "33333333-3333-4333-8333-333333333333",
  enable_api_key_auth: true,
  require_scoped_api_key: false,
  enable_max_rate: false,
  enable_client_max_rate: false,
  max_rate_seconds: null,
  max_rate: null,
  client_max_rate: null,
  client_max_rate_seconds: null,
  client_max_rate_strategy: null,
  client_max_rate_strategy_key: null,
  enable_oauth: false,
  use_query_param_auth: false,
  created_at: new Date("2026-07-01T00:00:00Z"),
  updated_at: new Date("2026-07-01T00:00:00Z"),
  user_id: null,
  ...overrides,
});

describe("checkApiKeyAccess — endpoint scope binding", () => {
  it("allows a scoped key on the endpoint it is bound to", () => {
    const result = checkApiKeyAccess(
      { user_id: null, endpoint_uuid: ENDPOINT_UUID },
      makeEndpoint(),
    );
    expect(result.allowed).toBe(true);
  });

  it("denies a scoped key on any other endpoint", () => {
    const result = checkApiKeyAccess(
      { user_id: null, endpoint_uuid: OTHER_ENDPOINT_UUID },
      makeEndpoint(),
    );
    expect(result.allowed).toBe(false);
    expect(result.message).toMatch(/scoped to a different endpoint/i);
  });

  it("scoped-mismatch denial fires even when ownership would allow (private key, own endpoint)", () => {
    // The key's owner also owns the endpoint — ownership alone would pass,
    // but the scope binding is narrower and must win.
    const result = checkApiKeyAccess(
      { user_id: "user-1", endpoint_uuid: OTHER_ENDPOINT_UUID },
      makeEndpoint({ user_id: "user-1" }),
    );
    expect(result.allowed).toBe(false);
    expect(result.message).toMatch(/scoped to a different endpoint/i);
  });

  it("a scoped key must still satisfy the ownership check on its own endpoint", () => {
    // Correctly-scoped private key, but the endpoint belongs to someone
    // else: scope passes, ownership still denies. Scope must not become an
    // ownership bypass.
    const result = checkApiKeyAccess(
      { user_id: "user-1", endpoint_uuid: ENDPOINT_UUID },
      makeEndpoint({ user_id: "other-user" }),
    );
    expect(result.allowed).toBe(false);
  });
});

describe("checkApiKeyAccess — legacy unscoped (NULL) keys", () => {
  it("allows a NULL-scope key on a normal endpoint (grandfathered behavior)", () => {
    const result = checkApiKeyAccess(
      { user_id: null, endpoint_uuid: null },
      makeEndpoint(),
    );
    expect(result.allowed).toBe(true);
  });

  it("treats an absent endpoint_uuid (pre-0023 validation shape) as unscoped", () => {
    const result = checkApiKeyAccess({ user_id: null }, makeEndpoint());
    expect(result.allowed).toBe(true);
  });

  it("denies a NULL-scope key on a require_scoped_api_key endpoint", () => {
    const result = checkApiKeyAccess(
      { user_id: null, endpoint_uuid: null },
      makeEndpoint({ require_scoped_api_key: true }),
    );
    expect(result.allowed).toBe(false);
    expect(result.message).toMatch(/requires an endpoint-scoped api key/i);
  });

  it("denies an absent-scope key on a require_scoped_api_key endpoint too", () => {
    const result = checkApiKeyAccess(
      { user_id: null },
      makeEndpoint({ require_scoped_api_key: true }),
    );
    expect(result.allowed).toBe(false);
  });

  it("allows a correctly-scoped key on a require_scoped_api_key endpoint", () => {
    const result = checkApiKeyAccess(
      { user_id: null, endpoint_uuid: ENDPOINT_UUID },
      makeEndpoint({ require_scoped_api_key: true }),
    );
    expect(result.allowed).toBe(true);
  });
});

describe("checkApiKeyAccess — pre-existing ownership checks unchanged", () => {
  it("still denies a public key on a private endpoint", () => {
    const result = checkApiKeyAccess(
      { user_id: null, endpoint_uuid: null },
      makeEndpoint({ user_id: "owner-1" }),
    );
    expect(result.allowed).toBe(false);
    expect(result.message).toMatch(/public api keys cannot access private/i);
  });

  it("still denies another user's private key on a private endpoint", () => {
    const result = checkApiKeyAccess(
      { user_id: "user-2", endpoint_uuid: null },
      makeEndpoint({ user_id: "owner-1" }),
    );
    expect(result.allowed).toBe(false);
  });

  it("still allows the owner's private key on their private endpoint", () => {
    const result = checkApiKeyAccess(
      { user_id: "owner-1", endpoint_uuid: null },
      makeEndpoint({ user_id: "owner-1" }),
    );
    expect(result.allowed).toBe(true);
  });
});

// Runtime re-check of the identity-requires-scope pairing (round-2 MEDIUM):
// mint-time is NOT the only writer of api_keys rows (psql / admin_cli are
// routine ops paths), so both authenticateApiKey branches route the stamp
// through resolveActsAsUserId — an unscoped-but-bound row must NEVER become
// a gateway-wide identity key.
describe("resolveActsAsUserId — acts-as honored only alongside an endpoint scope", () => {
  const EP = "11111111-1111-4111-8111-111111111111";

  it("an unscoped-but-bound row (direct DB write) does NOT stamp an identity", () => {
    expect(
      resolveActsAsUserId({ endpoint_uuid: null, acts_as_user_id: "alex-id" }),
    ).toBeUndefined();
    // undefined scope (row shape from a partial projection) is equally inert.
    expect(resolveActsAsUserId({ acts_as_user_id: "alex-id" })).toBeUndefined();
  });

  it("a scoped+bound row stamps the bound identity", () => {
    expect(
      resolveActsAsUserId({ endpoint_uuid: EP, acts_as_user_id: "alex-id" }),
    ).toBe("alex-id");
  });

  it("a scoped-but-unbound row stamps nothing (fail-closed default)", () => {
    expect(
      resolveActsAsUserId({ endpoint_uuid: EP, acts_as_user_id: null }),
    ).toBeUndefined();
    expect(resolveActsAsUserId({ endpoint_uuid: EP })).toBeUndefined();
  });

  it("an unscoped, unbound legacy row stamps nothing", () => {
    expect(
      resolveActsAsUserId({ endpoint_uuid: null, acts_as_user_id: null }),
    ).toBeUndefined();
  });
});
