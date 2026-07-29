/**
 * Unit tests for the consumer identity resolver's acts-as label behavior
 * (PR #85 round 2, LOW findings):
 *
 *  - DB-error honesty: when the key row cannot be read, the label is
 *    `api-key <short> (identity unresolved)` — never a bare `api-key
 *    <short>` that reads exactly like a no-identity key — and the failure
 *    is NOT cached (the next call retries and can recover).
 *  - Cache shape: the immutable BINDING (key name + acts_as_user_id) is
 *    cached per key uuid; the mutable EMAIL is looked up per call behind a
 *    60s TTL, so an email change corrects the audit label within a minute
 *    instead of surviving until process restart.
 *
 * The db module is mocked with a chain stub routed by table identity (same
 * convention as bootstrap.order.test.ts); `vi.resetModules()` re-imports
 * the resolver per test so its module-level caches start empty.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { dbMock, fixtures } = vi.hoisted(() => {
  const fixtures = {
    apiKeysRows: [] as Record<string, unknown>[],
    userRows: [] as Record<string, unknown>[],
    apiKeysError: false,
    userError: false,
    apiKeysSelectCount: 0,
    userSelectCount: 0,
  };

  const tableIs = (table: unknown, name: string) =>
    (table as { [key: symbol]: unknown })?.[Symbol.for("drizzle:Name")] ===
    name;

  const dbMock = {
    select: vi.fn(() => ({
      from: (table: unknown) => ({
        where: () => {
          if (tableIs(table, "api_keys")) {
            fixtures.apiKeysSelectCount++;
            return fixtures.apiKeysError
              ? Promise.reject(new Error("db down"))
              : Promise.resolve(fixtures.apiKeysRows);
          }
          if (tableIs(table, "users")) {
            fixtures.userSelectCount++;
            return fixtures.userError
              ? Promise.reject(new Error("db down"))
              : Promise.resolve(fixtures.userRows);
          }
          return Promise.resolve([]);
        },
      }),
    })),
  };

  return { dbMock, fixtures };
});
vi.mock("../../db/index", () => ({ db: dbMock }));

const KEY_UUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

async function freshResolver() {
  vi.resetModules();
  const mod = await import("./consumer-identity-resolver");
  return mod.resolveClientIdentity;
}

beforeEach(() => {
  vi.clearAllMocks();
  fixtures.apiKeysRows = [];
  fixtures.userRows = [];
  fixtures.apiKeysError = false;
  fixtures.userError = false;
  fixtures.apiKeysSelectCount = 0;
  fixtures.userSelectCount = 0;
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-07-29T00:00:00Z"));
});

afterEach(() => {
  vi.useRealTimers();
});

describe("resolveClientIdentity — acts-as label composition", () => {
  it("labels a bound key `name (as email)`", async () => {
    const resolve = await freshResolver();
    fixtures.apiKeysRows = [
      { name: "sever-m365", acts_as_user_id: "alex-id" },
    ];
    fixtures.userRows = [{ email: "alex@example.com" }];

    const identity = await resolve({
      authMethod: "api_key",
      apiKeyUuid: KEY_UUID,
    });

    expect(identity?.name).toBe("sever-m365 (as alex@example.com)");
  });

  it("labels an unbound key by name alone and never queries users", async () => {
    const resolve = await freshResolver();
    fixtures.apiKeysRows = [{ name: "plain-key", acts_as_user_id: null }];

    const identity = await resolve({
      authMethod: "api_key",
      apiKeyUuid: KEY_UUID,
    });

    expect(identity?.name).toBe("plain-key");
    expect(fixtures.userSelectCount).toBe(0);
  });
});

describe("resolveClientIdentity — DB-error path is honest and uncached", () => {
  it("labels the failure `api-key <short> (identity unresolved)` — never a plain no-identity label", async () => {
    const resolve = await freshResolver();
    fixtures.apiKeysError = true;

    const identity = await resolve({
      authMethod: "api_key",
      apiKeyUuid: KEY_UUID,
    });

    expect(identity?.name).toBe(
      `api-key ${KEY_UUID.slice(0, 8)} (identity unresolved)`,
    );
  });

  it("does NOT cache the failure — the next call retries and resolves the real binding", async () => {
    const resolve = await freshResolver();
    fixtures.apiKeysError = true;
    await resolve({ authMethod: "api_key", apiKeyUuid: KEY_UUID });

    fixtures.apiKeysError = false;
    fixtures.apiKeysRows = [
      { name: "sever-m365", acts_as_user_id: "alex-id" },
    ];
    fixtures.userRows = [{ email: "alex@example.com" }];

    const identity = await resolve({
      authMethod: "api_key",
      apiKeyUuid: KEY_UUID,
    });

    expect(identity?.name).toBe("sever-m365 (as alex@example.com)");
    // Two api_keys reads: the failed one plus the successful retry.
    expect(fixtures.apiKeysSelectCount).toBe(2);
  });
});

describe("resolveClientIdentity — binding cached forever, email TTL-fresh", () => {
  it("re-resolves a changed email after the TTL while never re-reading the immutable binding", async () => {
    const resolve = await freshResolver();
    fixtures.apiKeysRows = [
      { name: "sever-m365", acts_as_user_id: "alex-id" },
    ];
    fixtures.userRows = [{ email: "alex@example.com" }];

    const first = await resolve({
      authMethod: "api_key",
      apiKeyUuid: KEY_UUID,
    });
    expect(first?.name).toBe("sever-m365 (as alex@example.com)");

    // The email changes (mutable!) — pre-fix, the composed label was cached
    // under the key uuid and this change was invisible until restart.
    fixtures.userRows = [{ email: "alex@newdomain.com" }];
    vi.setSystemTime(new Date("2026-07-29T00:01:01Z")); // past the 60s TTL

    const second = await resolve({
      authMethod: "api_key",
      apiKeyUuid: KEY_UUID,
    });
    expect(second?.name).toBe("sever-m365 (as alex@newdomain.com)");
    // The binding itself was read exactly once — it is creation-time
    // immutable, so the cache never needs to revisit it.
    expect(fixtures.apiKeysSelectCount).toBe(1);
    expect(fixtures.userSelectCount).toBe(2);
  });

  it("within the TTL, repeated calls pay no extra users lookup", async () => {
    const resolve = await freshResolver();
    fixtures.apiKeysRows = [
      { name: "sever-m365", acts_as_user_id: "alex-id" },
    ];
    fixtures.userRows = [{ email: "alex@example.com" }];

    await resolve({ authMethod: "api_key", apiKeyUuid: KEY_UUID });
    vi.setSystemTime(new Date("2026-07-29T00:00:30Z")); // inside the TTL
    await resolve({ authMethod: "api_key", apiKeyUuid: KEY_UUID });

    expect(fixtures.userSelectCount).toBe(1);
  });

  it("a failed email lookup falls back to the short user id without failing resolution", async () => {
    const resolve = await freshResolver();
    fixtures.apiKeysRows = [
      { name: "sever-m365", acts_as_user_id: "alex-id-12345" },
    ];
    fixtures.userError = true;

    const identity = await resolve({
      authMethod: "api_key",
      apiKeyUuid: KEY_UUID,
    });

    expect(identity?.name).toBe("sever-m365 (as user alex-id-)");
  });
});
