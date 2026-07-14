import { describe, expect, it } from "vitest";

import {
  LAST_USED_THROTTLE_MS,
  shouldTouchLastUsed,
} from "./api-keys.last-used";

// The throttle decision guards the fire-and-forget last_used_at write on the
// hot public-endpoint auth path (validateApiKey). It must write when the key
// has never been used or its stamp is at least the throttle window stale, and
// skip otherwise, so the auth path stays near-write-free under load.
describe("shouldTouchLastUsed", () => {
  const now = 1_700_000_000_000;

  it("writes when the key has never been used (null / undefined)", () => {
    expect(shouldTouchLastUsed(null, now)).toBe(true);
    expect(shouldTouchLastUsed(undefined, now)).toBe(true);
  });

  it("skips when the key was used within the throttle window", () => {
    const recent = new Date(now - (LAST_USED_THROTTLE_MS - 1000));
    expect(shouldTouchLastUsed(recent, now)).toBe(false);
  });

  it("writes when the last use is older than the throttle window", () => {
    const stale = new Date(now - (LAST_USED_THROTTLE_MS + 1000));
    expect(shouldTouchLastUsed(stale, now)).toBe(true);
  });

  it("writes exactly at the window boundary (>= comparison)", () => {
    const boundary = new Date(now - LAST_USED_THROTTLE_MS);
    expect(shouldTouchLastUsed(boundary, now)).toBe(true);
  });

  it("honors a custom threshold", () => {
    const oneMinuteAgo = new Date(now - 60_000);
    expect(shouldTouchLastUsed(oneMinuteAgo, now, 30_000)).toBe(true);
    expect(shouldTouchLastUsed(oneMinuteAgo, now, 120_000)).toBe(false);
  });
});
