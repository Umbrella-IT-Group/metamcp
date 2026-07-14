import { describe, expect, it } from "vitest";

import {
  describeConnectError,
  formatConnectionAge,
  unwrapErrorCause,
} from "./connect-error";

/**
 * Build a Node-style system error (ECONNREFUSED etc.) the way undici's
 * leaf socket error looks at runtime: an Error with code/syscall/address
 * /port fields that the type system doesn't model but that exist on real
 * `connect` failures.
 */
function makeSysError(fields: {
  code: string;
  syscall?: string;
  address?: string;
  port?: number;
  message?: string;
}): Error {
  const err = new Error(
    fields.message ?? `${fields.syscall ?? "connect"} ${fields.code}`,
  );
  Object.assign(err, fields);
  return err;
}

describe("unwrapErrorCause", () => {
  it("follows undici's nested .cause chain to the leaf", () => {
    // Mirrors the real shape: TypeError('fetch failed').cause =
    // Error(...).cause = ECONNREFUSED system error.
    const leaf = makeSysError({
      code: "ECONNREFUSED",
      syscall: "connect",
      address: "172.18.0.13",
      port: 3000,
    });
    const mid = new Error("connect failure");
    (mid as Error & { cause?: unknown }).cause = leaf;
    const top = new TypeError("fetch failed");
    (top as Error & { cause?: unknown }).cause = mid;

    expect(unwrapErrorCause(top)).toBe(leaf);
  });

  it("picks the coded member out of an AggregateError", () => {
    const codeless = new Error("no code");
    const coded = makeSysError({
      code: "ECONNREFUSED",
      syscall: "connect",
      address: "::1",
      port: 3000,
    });
    const agg = new AggregateError([codeless, coded], "all dials failed");

    expect(unwrapErrorCause(agg)).toBe(coded);
  });

  it("returns a plain Error unchanged when there is no cause", () => {
    const plain = new Error("boom");
    expect(unwrapErrorCause(plain)).toBe(plain);
  });

  it("returns a non-Error throw unchanged", () => {
    expect(unwrapErrorCause("just a string")).toBe("just a string");
    expect(unwrapErrorCause(undefined)).toBeUndefined();
  });

  it("does not loop forever on a self-referential cause", () => {
    const cyclic = new Error("cyclic");
    (cyclic as Error & { cause?: unknown }).cause = cyclic;
    // Self-cause is skipped (cause === current), so it returns itself.
    expect(unwrapErrorCause(cyclic)).toBe(cyclic);

    const a = new Error("a");
    const b = new Error("b");
    (a as Error & { cause?: unknown }).cause = b;
    (b as Error & { cause?: unknown }).cause = a;
    // Two-node cycle terminates via the seen-set without throwing.
    expect(() => unwrapErrorCause(a)).not.toThrow();
  });
});

describe("describeConnectError", () => {
  it("renders syscall + code + address:port for a wrapped undici failure", () => {
    const leaf = makeSysError({
      code: "ECONNREFUSED",
      syscall: "connect",
      address: "172.18.0.13",
      port: 3000,
    });
    const top = new TypeError("fetch failed");
    (top as Error & { cause?: unknown }).cause = leaf;

    expect(describeConnectError(top)).toBe(
      "connect ECONNREFUSED 172.18.0.13:3000",
    );
  });

  it("renders code + address without a port", () => {
    const leaf = makeSysError({
      code: "EAI_AGAIN",
      syscall: "getaddrinfo",
      address: "backend",
    });
    expect(describeConnectError(leaf)).toBe("getaddrinfo EAI_AGAIN backend");
  });

  it("renders just the code when no address is attached", () => {
    const leaf = makeSysError({ code: "ECONNRESET", syscall: "read" });
    expect(describeConnectError(leaf)).toBe("read ECONNRESET");
  });

  it("falls back to the message for a codeless Error", () => {
    expect(describeConnectError(new Error("SSE stream disconnected"))).toBe(
      "SSE stream disconnected",
    );
  });

  it("stringifies a non-Error throw", () => {
    expect(describeConnectError("terminated")).toBe("terminated");
    expect(describeConnectError(42)).toBe("42");
  });
});

describe("formatConnectionAge", () => {
  it("reports never-connected for an undefined established time", () => {
    expect(formatConnectionAge(undefined)).toBe("never-connected");
  });

  it("reports seconds, minutes, hours and days", () => {
    const now = 10_000_000_000;
    expect(formatConnectionAge(now - 5_000, now)).toBe("established 5s ago");
    expect(formatConnectionAge(now - 90_000, now)).toBe("established 1m ago");
    expect(formatConnectionAge(now - 2 * 3_600_000, now)).toBe(
      "established 2h ago",
    );
    expect(formatConnectionAge(now - 3 * 86_400_000, now)).toBe(
      "established 3d ago",
    );
  });

  it("clamps a future established time to 0s rather than going negative", () => {
    const now = 1_000_000;
    expect(formatConnectionAge(now + 5_000, now)).toBe("established 0s ago");
  });
});
