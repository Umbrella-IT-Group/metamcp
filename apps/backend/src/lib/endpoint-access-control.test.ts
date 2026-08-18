/**
 * The decision cache and the denial throttle, tested directly.
 *
 * The middleware suite proves the GATE; this one proves the two pieces of
 * bookkeeping behind it, which are the parts that fail quietly rather than
 * loudly: a cache that outlives its TTL keeps serving a revoked user, and an
 * unbounded map on the auth path is a memory leak that only appears in
 * production.
 *
 * Time is driven with vitest's fake timers rather than by sleeping, so the TTL
 * boundary is asserted exactly instead of approximately.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { findRoleByIdMock, hasEndpointGrantMock } = vi.hoisted(() => ({
  findRoleByIdMock: vi.fn(),
  hasEndpointGrantMock: vi.fn(),
}));

vi.mock("../db/repositories/users.repo", () => ({
  usersRepository: { findRoleById: findRoleByIdMock },
}));

vi.mock("../db/repositories/access-groups.repo", () => ({
  accessGroupsRepository: { hasEndpointGrant: hasEndpointGrantMock },
}));

const {
  ACCESS_DECISION_TTL_MS,
  ACCESS_DECISION_MAX_ENTRIES,
  ACCESS_DENIAL_REPORT_INTERVAL_MS,
  ENDPOINT_ACCESS_DENIED_MESSAGE,
  isOAuthUserAllowedOnEndpoint,
  invalidateEndpointAccessCache,
  recordAccessDenial,
  __resetEndpointAccessCacheForTesting,
  __resetAccessDenialThrottleForTesting,
  __endpointAccessCacheSizeForTesting,
} = await import("./endpoint-access-control");

const ENDPOINT = { uuid: "endpoint-1", restricted: true };
const OPEN_ENDPOINT = { uuid: "endpoint-1", restricted: false };
const USER = "user-1";

beforeEach(() => {
  vi.clearAllMocks();
  __resetEndpointAccessCacheForTesting();
  __resetAccessDenialThrottleForTesting();
  findRoleByIdMock.mockResolvedValue("member");
  hasEndpointGrantMock.mockResolvedValue(false);
});

afterEach(() => {
  vi.useRealTimers();
});

describe("the refusal copy", () => {
  it("is the configured sentence, verbatim", () => {
    // Pinned here as well as in the middleware suite. This constant is product
    // copy an operator wrote; a well-meant tidy-up of the wording is a change
    // to what every refused user reads, and should have to be deliberate.
    expect(ENDPOINT_ACCESS_DENIED_MESSAGE).toBe(
      "Permission denied, this connector is not available for you. Please reach out to your administrator.",
    );
  });
});

describe("an endpoint that has not opted in", () => {
  it("is allowed without a query and without a cache entry", async () => {
    await expect(
      isOAuthUserAllowedOnEndpoint(USER, OPEN_ENDPOINT),
    ).resolves.toBe(true);

    expect(findRoleByIdMock).not.toHaveBeenCalled();
    expect(hasEndpointGrantMock).not.toHaveBeenCalled();
    expect(__endpointAccessCacheSizeForTesting()).toBe(0);
  });
});

describe("the decision", () => {
  it("admits a member", async () => {
    hasEndpointGrantMock.mockResolvedValue(true);
    await expect(isOAuthUserAllowedOnEndpoint(USER, ENDPOINT)).resolves.toBe(
      true,
    );
  });

  it("admits an administrator with no grant", async () => {
    findRoleByIdMock.mockResolvedValue("admin");
    hasEndpointGrantMock.mockResolvedValue(false);
    await expect(isOAuthUserAllowedOnEndpoint(USER, ENDPOINT)).resolves.toBe(
      true,
    );
  });

  it("refuses a member with no grant", async () => {
    await expect(isOAuthUserAllowedOnEndpoint(USER, ENDPOINT)).resolves.toBe(
      false,
    );
  });

  it("refuses an unknown account — an absent role is not an admin role", async () => {
    findRoleByIdMock.mockResolvedValue(undefined);
    await expect(isOAuthUserAllowedOnEndpoint(USER, ENDPOINT)).resolves.toBe(
      false,
    );
  });

  it("FAILS CLOSED: a database error propagates rather than admitting", async () => {
    // The middleware's own catch turns this into a 500. Serving the request
    // because a query failed would be the one unacceptable outcome on an
    // endpoint an operator explicitly switched on.
    hasEndpointGrantMock.mockRejectedValue(new Error("connection terminated"));
    await expect(isOAuthUserAllowedOnEndpoint(USER, ENDPOINT)).rejects.toThrow(
      "connection terminated",
    );
    expect(__endpointAccessCacheSizeForTesting()).toBe(0);
  });
});

describe("the decision cache", () => {
  it("answers a repeat from memory", async () => {
    hasEndpointGrantMock.mockResolvedValue(true);

    await isOAuthUserAllowedOnEndpoint(USER, ENDPOINT);
    await isOAuthUserAllowedOnEndpoint(USER, ENDPOINT);

    expect(hasEndpointGrantMock).toHaveBeenCalledTimes(1);
  });

  it("re-decides once the TTL has elapsed", async () => {
    vi.useFakeTimers();
    hasEndpointGrantMock.mockResolvedValue(true);

    await isOAuthUserAllowedOnEndpoint(USER, ENDPOINT);
    expect(hasEndpointGrantMock).toHaveBeenCalledTimes(1);

    // One millisecond short of the ceiling: still cached.
    vi.advanceTimersByTime(ACCESS_DECISION_TTL_MS - 1);
    await isOAuthUserAllowedOnEndpoint(USER, ENDPOINT);
    expect(hasEndpointGrantMock).toHaveBeenCalledTimes(1);

    // At the ceiling: gone. This is the bound that still holds when the
    // mutation happened in ANOTHER process and no invalidation reached here.
    vi.advanceTimersByTime(1);
    hasEndpointGrantMock.mockResolvedValue(false);
    await expect(isOAuthUserAllowedOnEndpoint(USER, ENDPOINT)).resolves.toBe(
      false,
    );
    expect(hasEndpointGrantMock).toHaveBeenCalledTimes(2);
  });

  it("invalidation drops an entry immediately, without waiting out the TTL", async () => {
    hasEndpointGrantMock.mockResolvedValue(true);
    await isOAuthUserAllowedOnEndpoint(USER, ENDPOINT);
    expect(__endpointAccessCacheSizeForTesting()).toBe(1);

    invalidateEndpointAccessCache();

    expect(__endpointAccessCacheSizeForTesting()).toBe(0);
    hasEndpointGrantMock.mockResolvedValue(false);
    await expect(isOAuthUserAllowedOnEndpoint(USER, ENDPOINT)).resolves.toBe(
      false,
    );
  });

  it("an invalidation landing MID-FLIGHT discards the result instead of caching it", async () => {
    // The window this closes: a decision that began before a revocation and
    // resolved after it. Stamping the generation at WRITE time would store the
    // pre-revocation `true` under the new generation, where it looks current
    // for the full TTL — invalidation defeated in exactly the case it exists
    // for, and only visible to a request that raced an admin mutation.
    let releaseGrant: (value: boolean) => void = () => {};
    hasEndpointGrantMock.mockReturnValue(
      new Promise<boolean>((resolve) => {
        releaseGrant = resolve;
      }),
    );

    const inFlight = isOAuthUserAllowedOnEndpoint(USER, ENDPOINT);

    // The admin revokes while the queries are still outstanding.
    invalidateEndpointAccessCache();
    releaseGrant(true);

    // The in-flight request keeps the answer it computed — it was authorized
    // before the revocation landed and there is nothing to un-decide.
    await expect(inFlight).resolves.toBe(true);

    // But nothing was cached, so the NEXT request re-decides against the
    // committed state rather than replaying the stale admission.
    expect(__endpointAccessCacheSizeForTesting()).toBe(0);

    hasEndpointGrantMock.mockResolvedValue(false);
    await expect(isOAuthUserAllowedOnEndpoint(USER, ENDPOINT)).resolves.toBe(
      false,
    );
    expect(hasEndpointGrantMock).toHaveBeenCalledTimes(2);
  });

  it("a decision that does NOT race an invalidation is still cached", async () => {
    // The other half of the guard: it must discard only the racing write, not
    // every write. Without this, "the cache never stores anything" would pass
    // the test above.
    hasEndpointGrantMock.mockResolvedValue(true);

    await isOAuthUserAllowedOnEndpoint(USER, ENDPOINT);

    expect(__endpointAccessCacheSizeForTesting()).toBe(1);
    await isOAuthUserAllowedOnEndpoint(USER, ENDPOINT);
    expect(hasEndpointGrantMock).toHaveBeenCalledTimes(1);
  });

  it("keys on the pair — a shared user id does not leak across endpoints", async () => {
    hasEndpointGrantMock.mockResolvedValue(true);
    await isOAuthUserAllowedOnEndpoint(USER, ENDPOINT);

    hasEndpointGrantMock.mockResolvedValue(false);
    await expect(
      isOAuthUserAllowedOnEndpoint(USER, {
        uuid: "endpoint-2",
        restricted: true,
      }),
    ).resolves.toBe(false);
    expect(__endpointAccessCacheSizeForTesting()).toBe(2);
  });

  it("a crafted user id cannot collide with another pair's key", async () => {
    // The separator is NUL, which cannot occur in a better-auth id or a uuid.
    // A `:` separator would let ("a", "b:c") and ("a:b", "c") produce the same
    // key — the classic confused-deputy shape for a cache, and here that would
    // be one user's admission answering another user's request.
    hasEndpointGrantMock.mockResolvedValue(true);
    await isOAuthUserAllowedOnEndpoint("a:b", { uuid: "c", restricted: true });

    hasEndpointGrantMock.mockResolvedValue(false);
    await expect(
      isOAuthUserAllowedOnEndpoint("a", { uuid: "b:c", restricted: true }),
    ).resolves.toBe(false);
  });

  it("is BOUNDED: overflow clears rather than growing without limit", async () => {
    hasEndpointGrantMock.mockResolvedValue(true);

    for (let i = 0; i < ACCESS_DECISION_MAX_ENTRIES; i += 1) {
      await isOAuthUserAllowedOnEndpoint(`user-${i}`, ENDPOINT);
    }
    expect(__endpointAccessCacheSizeForTesting()).toBe(
      ACCESS_DECISION_MAX_ENTRIES,
    );

    await isOAuthUserAllowedOnEndpoint("one-too-many", ENDPOINT);

    // Cleared, then the new decision written — so the map never exceeds the
    // ceiling and never has to be swept.
    expect(__endpointAccessCacheSizeForTesting()).toBe(1);
  });
});

describe("the denial throttle", () => {
  it("reports the first denial immediately", () => {
    // Detection must not have to wait out a window — the first refusal of a
    // credential is the one worth seeing soonest.
    expect(recordAccessDenial(USER, ENDPOINT.uuid)).toEqual({
      emit: true,
      suppressed: 0,
    });
  });

  it("swallows the rest of the window and COUNTS them", () => {
    vi.useFakeTimers();
    recordAccessDenial(USER, ENDPOINT.uuid);

    for (let i = 0; i < 40; i += 1) {
      expect(recordAccessDenial(USER, ENDPOINT.uuid).emit).toBe(false);
    }

    vi.advanceTimersByTime(ACCESS_DENIAL_REPORT_INTERVAL_MS);
    const next = recordAccessDenial(USER, ENDPOINT.uuid);
    expect(next.emit).toBe(true);
    // Volume survives the throttle: "denied once" and "denied 40 more times"
    // stay distinguishable even though per-attempt timestamps do not.
    expect(next.suppressed).toBe(40);
  });

  it("resets the count after a report, so the next row is not double-counting", () => {
    vi.useFakeTimers();
    recordAccessDenial(USER, ENDPOINT.uuid);
    recordAccessDenial(USER, ENDPOINT.uuid);
    vi.advanceTimersByTime(ACCESS_DENIAL_REPORT_INTERVAL_MS);
    expect(recordAccessDenial(USER, ENDPOINT.uuid).suppressed).toBe(1);

    vi.advanceTimersByTime(ACCESS_DENIAL_REPORT_INTERVAL_MS);
    expect(recordAccessDenial(USER, ENDPOINT.uuid).suppressed).toBe(0);
  });

  it("throttles per (user, endpoint), never globally", () => {
    recordAccessDenial(USER, ENDPOINT.uuid);

    // A different user on the same endpoint, and the same user on a different
    // endpoint, both still get their first row.
    expect(recordAccessDenial("user-2", ENDPOINT.uuid).emit).toBe(true);
    expect(recordAccessDenial(USER, "endpoint-2").emit).toBe(true);
  });
});
