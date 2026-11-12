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
    // When set, users reads are answered per queried id (see `eq` below)
    // instead of from `userRows`; ids in `userErrorIds` fail.
    usersById: null as Record<string, Record<string, unknown>> | null,
    userErrorIds: new Set<string>(),
  };

  const tableIs = (table: unknown, name: string) =>
    (table as { [key: symbol]: unknown })?.[Symbol.for("drizzle:Name")] ===
    name;

  const dbMock = {
    select: vi.fn(() => ({
      from: (table: unknown) => ({
        where: (condition?: { queriedValue?: unknown }) => {
          if (tableIs(table, "api_keys")) {
            fixtures.apiKeysSelectCount++;
            return fixtures.apiKeysError
              ? Promise.reject(new Error("db down"))
              : Promise.resolve(fixtures.apiKeysRows);
          }
          if (tableIs(table, "users")) {
            fixtures.userSelectCount++;
            if (fixtures.usersById !== null) {
              const id = String(condition?.queriedValue);
              if (fixtures.userErrorIds.has(id)) {
                return Promise.reject(new Error("db down"));
              }
              const row = fixtures.usersById[id];
              return Promise.resolve(row ? [row] : []);
            }
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
// Lets the users stub see which id a query asked for. Everything else in
// drizzle-orm is the real module.
vi.mock("drizzle-orm", async (importOriginal) => {
  const actual = await importOriginal<typeof import("drizzle-orm")>();
  return {
    ...actual,
    eq: (column: unknown, value: unknown) => ({
      queriedValue: value,
      condition: actual.eq(column as never, value),
    }),
  };
});

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
  fixtures.usersById = null;
  fixtures.userErrorIds = new Set();
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-07-29T00:00:00Z"));
});

afterEach(() => {
  vi.useRealTimers();
});

describe("resolveClientIdentity — acts-as label composition", () => {
  it("labels a bound key `name (as email)`", async () => {
    const resolve = await freshResolver();
    fixtures.apiKeysRows = [{ name: "sever-m365", acts_as_user_id: "alex-id" }];
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
    fixtures.apiKeysRows = [{ name: "sever-m365", acts_as_user_id: "alex-id" }];
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
    fixtures.apiKeysRows = [{ name: "sever-m365", acts_as_user_id: "alex-id" }];
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
    fixtures.apiKeysRows = [{ name: "sever-m365", acts_as_user_id: "alex-id" }];
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

/**
 * The account behind a request and its email. Unlike the labels above, the
 * email may be compared by a backend to decide who is asking, so it is either
 * a fresh answer for exactly the effective user or null: never stale, never
 * another account's, never a name or a short-id label.
 */
describe("resolveClientIdentity: the effective account and its email", () => {
  const OWNER = "owner-user-1";
  const BOUND = "bound-user-2";
  const SUBJECT = "oauth-user-3";

  beforeEach(() => {
    fixtures.usersById = {
      [OWNER]: { email: "owner@example.com", name: "Owner Person" },
      [BOUND]: { email: "bound@example.com", name: "Bound Person" },
      [SUBJECT]: { email: "subject@example.com", name: "Subject Person" },
    };
  });

  it("is the key owner, with the owner's email, for an unbound key", async () => {
    const resolve = await freshResolver();
    fixtures.apiKeysRows = [{ name: "plain-key", acts_as_user_id: null }];

    const identity = await resolve({
      authMethod: "api_key",
      apiKeyUuid: KEY_UUID,
      apiKeyUserId: OWNER,
    });

    expect(identity?.account).toEqual({
      userId: OWNER,
      email: "owner@example.com",
    });
  });

  it("is the acts-as user, with that user's email, never the owner's, for a bound key", async () => {
    const resolve = await freshResolver();
    fixtures.apiKeysRows = [{ name: "bound-key", acts_as_user_id: BOUND }];

    const identity = await resolve({
      authMethod: "api_key",
      apiKeyUuid: KEY_UUID,
      apiKeyUserId: OWNER,
      apiKeyActsAsUserId: BOUND,
    });

    expect(identity?.account).toEqual({
      userId: BOUND,
      email: "bound@example.com",
    });
    expect(identity?.name).toBe("bound-key (as bound@example.com)");
  });

  it.each([
    ["has no row", () => delete fixtures.usersById?.[BOUND]],
    ["cannot be read", () => fixtures.userErrorIds.add(BOUND)],
  ])(
    "gives a null email, not the owner's, when the acts-as user %s",
    async (_label, arrange) => {
      const resolve = await freshResolver();
      fixtures.apiKeysRows = [{ name: "bound-key", acts_as_user_id: BOUND }];
      arrange();

      const identity = await resolve({
        authMethod: "api_key",
        apiKeyUuid: KEY_UUID,
        apiKeyUserId: OWNER,
        apiKeyActsAsUserId: BOUND,
      });

      expect(identity?.account).toEqual({ userId: BOUND, email: null });
    },
  );

  it("is the OAuth subject, with the subject's email, for an OAuth caller", async () => {
    const resolve = await freshResolver();

    const identity = await resolve({
      authMethod: "oauth",
      oauthUserId: SUBJECT,
    });

    expect(identity?.account).toEqual({
      userId: SUBJECT,
      email: "subject@example.com",
    });
  });

  it("gives a null email, never the display name, for an account with no email", async () => {
    const resolve = await freshResolver();
    fixtures.usersById = { [SUBJECT]: { email: "", name: "Subject Person" } };

    const identity = await resolve({
      authMethod: "oauth",
      oauthUserId: SUBJECT,
    });

    expect(identity?.name).toBe("Subject Person");
    expect(identity?.account).toEqual({ userId: SUBJECT, email: null });
  });

  it("names no account for a blank acts-as binding or a key with no owner", async () => {
    const resolve = await freshResolver();
    fixtures.apiKeysRows = [{ name: "plain-key", acts_as_user_id: null }];

    const blank = await resolve({
      authMethod: "api_key",
      apiKeyUuid: KEY_UUID,
      apiKeyUserId: OWNER,
      apiKeyActsAsUserId: "",
    });
    const ownerless = await resolve({
      authMethod: "api_key",
      apiKeyUuid: KEY_UUID,
    });

    expect(blank?.account).toBeUndefined();
    expect(ownerless?.account).toBeUndefined();
  });

  it("returns null after the TTL when the read fails, never the cached email, while the label keeps its last value", async () => {
    const resolve = await freshResolver();
    fixtures.apiKeysRows = [{ name: "bound-key", acts_as_user_id: BOUND }];
    const auth = {
      authMethod: "api_key",
      apiKeyUuid: KEY_UUID,
      apiKeyUserId: OWNER,
      apiKeyActsAsUserId: BOUND,
    };

    const first = await resolve(auth);
    expect(first?.account?.email).toBe("bound@example.com");

    fixtures.userErrorIds.add(BOUND);
    vi.setSystemTime(new Date("2026-07-29T00:01:01Z")); // past the 60s TTL
    const second = await resolve(auth);

    expect(second?.account).toEqual({ userId: BOUND, email: null });
    // The display label may stay stale; the email may not.
    expect(second?.name).toBe("bound-key (as bound@example.com)");
  });

  it("does not cache a failed read: the next call reads again and recovers", async () => {
    const resolve = await freshResolver();
    fixtures.userErrorIds.add(SUBJECT);
    const failed = await resolve({ authMethod: "oauth", oauthUserId: SUBJECT });
    expect(failed?.account?.email).toBeNull();

    fixtures.userErrorIds.delete(SUBJECT);
    const recovered = await resolve({
      authMethod: "oauth",
      oauthUserId: SUBJECT,
    });
    expect(recovered?.account?.email).toBe("subject@example.com");
  });

  it("serves a cached answer inside the TTL and a changed email after it", async () => {
    const resolve = await freshResolver();
    fixtures.apiKeysRows = [{ name: "plain-key", acts_as_user_id: null }];
    const auth = {
      authMethod: "api_key",
      apiKeyUuid: KEY_UUID,
      apiKeyUserId: OWNER,
    };

    await resolve(auth);
    fixtures.usersById = {
      [OWNER]: { email: "renamed@example.com", name: "Owner Person" },
    };
    vi.setSystemTime(new Date("2026-07-29T00:00:30Z")); // inside the TTL
    const inside = await resolve(auth);
    vi.setSystemTime(new Date("2026-07-29T00:01:01Z")); // past it
    const after = await resolve(auth);

    expect(inside?.account?.email).toBe("owner@example.com");
    expect(after?.account?.email).toBe("renamed@example.com");
    expect(fixtures.userSelectCount).toBe(2);
  });

  it("reads a bound key's acts-as user once per TTL for both the label and the email", async () => {
    const resolve = await freshResolver();
    fixtures.apiKeysRows = [{ name: "bound-key", acts_as_user_id: BOUND }];

    await resolve({
      authMethod: "api_key",
      apiKeyUuid: KEY_UUID,
      apiKeyUserId: OWNER,
      apiKeyActsAsUserId: BOUND,
    });

    expect(fixtures.userSelectCount).toBe(1);
  });

  it("bounds the cache: the oldest answer is dropped once 1,000 users are held", async () => {
    const resolve = await freshResolver();
    fixtures.apiKeysRows = [{ name: "plain-key", acts_as_user_id: null }];
    fixtures.usersById = {};
    for (let i = 0; i <= 1_000; i++) {
      fixtures.usersById[`user-${i}`] = { email: `user-${i}@example.com` };
    }
    const asUser = (i: number) =>
      resolve({
        authMethod: "api_key",
        apiKeyUuid: KEY_UUID,
        apiKeyUserId: `user-${i}`,
      });

    for (let i = 0; i <= 1_000; i++) await asUser(i);
    expect(fixtures.userSelectCount).toBe(1_001);

    await asUser(1_000); // the newest answer is still held
    expect(fixtures.userSelectCount).toBe(1_001);
    await asUser(0); // the oldest was dropped, so it is read again
    expect(fixtures.userSelectCount).toBe(1_002);
  });
});
