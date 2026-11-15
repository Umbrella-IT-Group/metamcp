/**
 * Policy approval of matching self-registrations: the policy parser, the
 * startup latch, the boot log line, the pure matcher and the hourly budget.
 *
 * The parser and matcher cases come from the neutral conformance vectors in
 * ./dcr-auto-approval.vectors.json, so a second implementation replaying the
 * same file agrees with this one. Their expected policy hashes were computed
 * independently of this module.
 */

import { readFileSync } from "node:fs";
import path from "node:path";

import { beforeEach, describe, expect, it, vi } from "vitest";

const loggerMock = {
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
};
vi.mock("@/utils/logger", () => ({ default: loggerMock }));

const policyModule = await import("./dcr-auto-approval");
const {
  OAUTH_DCR_AUTO_APPROVE_POLICY_ENV: ENV,
  callbackMatchesEntry,
  decideDcrAutoApproval,
  dcrAutoApprovalReservationCountsForTests,
  getDcrAutoApprovalPolicy,
  initDcrAutoApproval,
  isApprovedByPolicy,
  matchDcrAutoApproval,
  parseDcrAutoApprovalPolicy,
  resetDcrAutoApprovalForTests,
  resolveDcrAutoApprovalPolicy,
  scanJsonText,
  setDcrAutoApprovalClockForTests,
} = policyModule;
const { matchClientIp } = await import("@/lib/api-key-ip-policy");

interface DocumentVector {
  name: string;
  document?: string;
  document_padded?: { base: string; pad_to_bytes: number };
  expect: "accept" | "reject";
  entries?: unknown[];
  policy_version?: string;
  reason?: string;
  at?: string;
}

interface MatchVector {
  name: string;
  policy: string;
  registration: {
    client_name: unknown;
    redirect_uris: unknown;
    [field: string]: unknown;
  };
  caller_ip: string | null;
  expect: string | null;
}

const vectors = JSON.parse(
  readFileSync(path.join(__dirname, "dcr-auto-approval.vectors.json"), "utf8"),
) as {
  policies: Record<string, string>;
  documents: DocumentVector[];
  matches: MatchVector[];
};

function rawDocument(vector: DocumentVector): string {
  if (vector.document !== undefined) return vector.document;
  if (!vector.document_padded) throw new Error(`${vector.name}: no document`);
  const { base, pad_to_bytes } = vector.document_padded;
  const padding = pad_to_bytes - Buffer.byteLength(base, "utf8");
  return base + " ".repeat(padding);
}

function policyNamed(name: string) {
  const parsed = parseDcrAutoApprovalPolicy(vectors.policies[name]);
  if (!parsed.ok) throw new Error(`vector policy ${name} did not parse`);
  return parsed.policy;
}

const documentByName = (name: string) => {
  const found = vectors.documents.find((d) => d.name === name);
  if (!found) throw new Error(`no vector named ${name}`);
  return found;
};

const TWO_FAMILIES = vectors.policies.two_families;

const DESKTOP_REGISTRATION = {
  client_name: "Example Desktop Client",
  redirect_uris: ["http://localhost:53682/callback"],
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
  token_endpoint_auth_method: "none",
  client_secret: null,
};
const INSIDE = "203.0.113.70";

beforeEach(() => {
  vi.clearAllMocks();
  resetDcrAutoApprovalForTests();
});

describe("conformance vectors: policy documents", () => {
  it("holds both accepted and refused documents", () => {
    const accepted = vectors.documents.filter((d) => d.expect === "accept");
    expect(accepted.length).toBeGreaterThan(10);
    expect(vectors.documents.length - accepted.length).toBeGreaterThan(50);
  });

  it.each(vectors.documents.map((d) => [d.name, d] as const))(
    "%s",
    (_name, vector) => {
      const result = parseDcrAutoApprovalPolicy(rawDocument(vector));
      if (vector.expect === "accept") {
        expect(result).toEqual({
          ok: true,
          policy: {
            version: 1,
            entries: vector.entries,
            hash: vector.policy_version,
          },
        });
      } else {
        expect(result).toEqual({
          ok: false,
          reason: vector.reason,
          at: vector.at ?? null,
        });
      }
    },
  );
});

describe("conformance vectors: matching", () => {
  it("holds both matching and non-matching cases", () => {
    expect(vectors.matches.filter((m) => m.expect !== null).length).toBe(23);
    expect(vectors.matches.filter((m) => m.expect === null).length).toBe(82);
  });

  it.each(vectors.matches.map((m) => [m.name, m] as const))(
    "%s",
    (_name, vector) => {
      expect(
        matchDcrAutoApproval(
          policyNamed(vector.policy),
          vector.registration,
          vector.caller_ip ?? undefined,
        ),
      ).toBe(vector.expect);
    },
  );
});

describe("policy hash", () => {
  it("is the same across key order, CIDR spelling and CIDR order", () => {
    expect(
      documentByName(
        "same policy, keys reordered, CIDRs respelled and reordered",
      ).policy_version,
    ).toBe(documentByName("two entries").policy_version);
  });

  it("changes with entry precedence", () => {
    expect(
      documentByName("same entries in the other order").policy_version,
    ).not.toBe(documentByName("two entries").policy_version);
  });

  it("is 64 lowercase hex characters", () => {
    const parsed = parseDcrAutoApprovalPolicy(TWO_FAMILIES);
    expect(parsed.ok && parsed.policy.hash).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("policy paths are already canonical URL pathnames", () => {
  it("round-trips every accepted path through the URL parser unchanged", () => {
    for (const vector of vectors.documents) {
      if (vector.expect !== "accept") continue;
      for (const entry of vector.entries as Array<{
        redirect: { host: string; path: string; port_max: number };
      }>) {
        const { host, path: p, port_max } = entry.redirect;
        expect(new URL(`http://${host}:${port_max}${p}`).pathname).toBe(p);
      }
    }
  });
});

describe("the raw-text scan behind JSON.parse", () => {
  it.each([
    ['{"a":1}', "ok"],
    ['{"a":"1.5e3","b":[1,-2,0]}', "ok"],
    ['{"a":true,"b":false,"c":null}', "ok"],
    ['{"a":{"a":1},"b":{"a":2}}', "ok"],
    ['{"a":"x\\"y","b":1}', "ok"],
    ['[{"a":1},{"a":1}]', "ok"],
    ['{"a":-0.5}', "non_integer_number"],
    ['{"a":[1,2E2]}', "non_integer_number"],
    ['{"a":1,"b":{"c":1,"c":2}}', "duplicate_key"],
    ['{"\\u0061":1,"a":2}', "duplicate_key"],
  ])("%s -> %s", (text, expected) => {
    expect(scanJsonText(text)).toBe(expected);
  });
});

describe("the reused address helper (pinned, not reimplemented)", () => {
  it("matches an IPv4-mapped caller against an IPv4 network", () => {
    expect(matchClientIp(["203.0.113.64/26"], "::ffff:203.0.113.70")).toBe(
      "in_list",
    );
  });

  it("matches an IPv4 caller against an IPv4-mapped network", () => {
    expect(matchClientIp(["::ffff:198.51.100.0/121"], "198.51.100.20")).toBe(
      "in_list",
    );
  });

  it("keeps native IPv6 and IPv4 lists apart", () => {
    expect(matchClientIp(["2001:db8:1234::/48"], "203.0.113.70")).toBe(
      "not_in_list",
    );
    expect(matchClientIp(["203.0.113.64/26"], "2001:db8:1234::1")).toBe(
      "not_in_list",
    );
  });

  it("reports the any-address exemption, which the matcher never accepts", () => {
    expect(matchClientIp(["0.0.0.0/0", "::/0"], undefined)).toBe(
      "any_ip_exemption",
    );
    const policy = policyNamed("two_families");
    policy.entries[0].allowed_cidrs = ["0.0.0.0/0", "::/0"];
    expect(
      matchDcrAutoApproval(policy, DESKTOP_REGISTRATION, undefined),
    ).toBeNull();
    expect(
      matchDcrAutoApproval(policy, DESKTOP_REGISTRATION, INSIDE),
    ).toBeNull();
  });
});

describe("callbackMatchesEntry", () => {
  const redirect = {
    host: "localhost" as const,
    path: "/callback",
    port_min: 1024,
    port_max: 65535,
  };

  it("accepts the exact shape", () => {
    expect(
      callbackMatchesEntry("http://localhost:53682/callback", redirect),
    ).toBe(true);
  });

  it.each([
    "http://localhost:53682/callback?",
    "http://localhost:53682/callback#",
    "http://localhost:53682/call\tback",
    "http:/localhost:53682/callback",
    "http://LOCALHOST:53682/callback",
  ])("refuses %j, which the URL parser alone would accept", (uri) => {
    const parsed = new URL(uri);
    expect(parsed.hostname).toBe("localhost");
    expect(parsed.pathname).toBe("/callback");
    expect(parsed.search).toBe("");
    expect(parsed.hash).toBe("");
    expect(callbackMatchesEntry(uri, redirect)).toBe(false);
  });

  it("refuses a non-string", () => {
    expect(callbackMatchesEntry(42, redirect)).toBe(false);
  });
});

describe("resolution, logging and the startup latch", () => {
  const SENTINEL_NAME = "Sentinel Name Q7Z";
  const SENTINEL_CIDR = "203.0.113.77/32";

  function sentinelPolicy(mutate: (entry: Record<string, unknown>) => void) {
    const entry: Record<string, unknown> = {
      id: "sentinel-entry",
      client_name: SENTINEL_NAME,
      redirect: {
        host: "localhost",
        path: "/sentinel-path",
        port_min: 1024,
        port_max: 65535,
      },
      allowed_cidrs: [SENTINEL_CIDR],
      max_per_hour: 5,
    };
    mutate(entry);
    return JSON.stringify({ version: 1, entries: [entry] });
  }

  function allLogText(): string {
    return [
      loggerMock.info,
      loggerMock.warn,
      loggerMock.error,
      loggerMock.debug,
    ]
      .flatMap((fn) => fn.mock.calls.flat())
      .map(String)
      .join("\n");
  }

  it("is inactive and quiet when unset", () => {
    expect(initDcrAutoApproval({})).toBeNull();
    expect(loggerMock.warn).not.toHaveBeenCalled();
    expect(loggerMock.info).toHaveBeenCalledTimes(1);
    expect(loggerMock.info.mock.calls[0][0]).toContain("inactive");
  });

  it("is inactive for a valid empty policy, and says so with its hash", () => {
    expect(initDcrAutoApproval({ [ENV]: vectors.policies.empty })).toBeNull();
    const line = loggerMock.info.mock.calls[0][0] as string;
    expect(line).toContain("inactive, 0 entries");
    expect(line).toMatch(/policy_version [0-9a-f]{64}$/);
  });

  it("logs active state, entry count and hash once, and no policy contents", () => {
    const policy = initDcrAutoApproval({ [ENV]: TWO_FAMILIES });
    expect(policy?.entries.map((e) => e.id)).toEqual(["desktop", "cli"]);
    expect(loggerMock.info).toHaveBeenCalledTimes(1);
    expect(loggerMock.info.mock.calls[0][0]).toBe(
      `[oauth] policy approval of matching registrations: active, 2 entries, policy_version ${policy?.hash}`,
    );
    const text = allLogText();
    for (const value of [
      "Example Desktop Client",
      "203.0.113.64",
      "2001:db8",
      "/callback",
      "desktop",
    ]) {
      expect(text).not.toContain(value);
    }
  });

  it.each([
    [
      "an unknown key",
      sentinelPolicy((e) => {
        e.sentinel_unknown_key_Q7Z = 1;
      }),
      "unknown_field at entries[0]",
    ],
    [
      "a CIDR with host bits (parseCidr's message would quote it)",
      sentinelPolicy((e) => {
        e.allowed_cidrs = ["203.0.113.77/24"];
      }),
      "bad_cidr at entries[0].allowed_cidrs[0]",
    ],
    [
      "a too-wide CIDR",
      sentinelPolicy((e) => {
        e.allowed_cidrs = [SENTINEL_CIDR, "::ffff:0:0/96"];
      }),
      "cidr_too_wide at entries[0].allowed_cidrs[1]",
    ],
    [
      "malformed JSON",
      `{"version":1,"entries":[{"id":"${SENTINEL_NAME}"`,
      "not_json",
    ],
  ])(
    "refuses %s with a fixed reason and no policy value in the warning",
    (_label, raw, reason) => {
      expect(initDcrAutoApproval({ [ENV]: raw })).toBeNull();
      expect(loggerMock.warn).toHaveBeenCalledTimes(1);
      const warning = loggerMock.warn.mock.calls[0][0] as string;
      expect(warning).toBe(
        `[oauth] ${ENV} refused (${reason}); policy approval is OFF and every self-registration stays pending.`,
      );
      const text = allLogText();
      for (const value of [
        SENTINEL_NAME,
        SENTINEL_CIDR,
        "203.0.113.77",
        "sentinel_unknown_key_Q7Z",
        "sentinel-entry",
        "/sentinel-path",
        "host bits",
        "Unexpected",
      ]) {
        expect(text).not.toContain(value);
      }
    },
  );

  it("never enables part of a document: one good entry beside a bad one", () => {
    const vector = documentByName("one good entry beside a bad one");
    expect(initDcrAutoApproval({ [ENV]: vector.document })).toBeNull();
    expect(getDcrAutoApprovalPolicy()).toBeNull();
    expect(
      matchDcrAutoApproval(
        getDcrAutoApprovalPolicy(),
        DESKTOP_REGISTRATION,
        INSIDE,
      ),
    ).toBeNull();
  });

  it("does not keep an earlier policy when a later one is refused", () => {
    expect(initDcrAutoApproval({ [ENV]: TWO_FAMILIES })).not.toBeNull();
    expect(initDcrAutoApproval({ [ENV]: "{" })).toBeNull();
    expect(getDcrAutoApprovalPolicy()).toBeNull();
    expect(initDcrAutoApproval({})).toBeNull();
    expect(getDcrAutoApprovalPolicy()).toBeNull();
  });

  it("serves the latched policy, not a fresh read of the environment", () => {
    const original = process.env[ENV];
    try {
      const policy = initDcrAutoApproval({ [ENV]: TWO_FAMILIES });
      process.env[ENV] = "{";
      expect(getDcrAutoApprovalPolicy()).toBe(policy);
      expect(loggerMock.warn).not.toHaveBeenCalled();
    } finally {
      if (original === undefined) delete process.env[ENV];
      else process.env[ENV] = original;
    }
  });

  it("resolves once from the process environment when never initialised", () => {
    const original = process.env[ENV];
    try {
      process.env[ENV] = TWO_FAMILIES;
      const first = getDcrAutoApprovalPolicy();
      expect(first?.entries).toHaveLength(2);
      process.env[ENV] = vectors.policies.empty;
      expect(getDcrAutoApprovalPolicy()).toBe(first);
      expect(loggerMock.info).toHaveBeenCalledTimes(1);
      resetDcrAutoApprovalForTests();
      expect(getDcrAutoApprovalPolicy()).toBeNull();
    } finally {
      if (original === undefined) delete process.env[ENV];
      else process.env[ENV] = original;
    }
  });

  it("resolves without logging (the pure step)", () => {
    const resolution = resolveDcrAutoApprovalPolicy({ [ENV]: "[]" });
    expect(resolution.policy).toBeNull();
    expect(resolution.log.level).toBe("warn");
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });
});

describe("the hourly budget", () => {
  const HOUR = 60 * 60 * 1000;
  let now = 0;

  function capPolicy(
    entries: Array<{ id: string; cidr: string; cap: number }>,
  ) {
    return JSON.stringify({
      version: 1,
      entries: entries.map((e) => ({
        id: e.id,
        client_name: "Example Desktop Client",
        redirect: {
          host: "localhost",
          path: "/callback",
          port_min: 1024,
          port_max: 65535,
        },
        allowed_cidrs: [e.cidr],
        max_per_hour: e.cap,
      })),
    });
  }

  beforeEach(() => {
    now = 1_000;
    setDcrAutoApprovalClockForTests(() => now);
  });

  it("approves up to the cap and holds the next match pending", () => {
    initDcrAutoApproval({
      [ENV]: capPolicy([{ id: "only", cidr: "203.0.113.0/24", cap: 3 }]),
    });
    const outcomes = Array.from({ length: 4 }, () =>
      decideDcrAutoApproval(DESKTOP_REGISTRATION, INSIDE),
    );
    expect(outcomes.map((o) => o.outcome)).toEqual([
      "approved",
      "approved",
      "approved",
      "cap",
    ]);
    expect(outcomes[3]).toEqual({ outcome: "cap", entryId: "only" });
    expect(outcomes[0]).toEqual({
      outcome: "approved",
      entryId: "only",
      policyVersion: getDcrAutoApprovalPolicy()?.hash,
    });
  });

  it("frees a slot at exactly one hour, not a millisecond before", () => {
    initDcrAutoApproval({
      [ENV]: capPolicy([{ id: "only", cidr: "203.0.113.0/24", cap: 1 }]),
    });
    expect(decideDcrAutoApproval(DESKTOP_REGISTRATION, INSIDE).outcome).toBe(
      "approved",
    );
    now = 1_000 + HOUR - 1;
    expect(decideDcrAutoApproval(DESKTOP_REGISTRATION, INSIDE).outcome).toBe(
      "cap",
    );
    now = 1_000 + HOUR;
    expect(decideDcrAutoApproval(DESKTOP_REGISTRATION, INSIDE).outcome).toBe(
      "approved",
    );
  });

  it("keeps each entry's budget separate", () => {
    initDcrAutoApproval({
      [ENV]: capPolicy([
        { id: "network-a", cidr: "203.0.113.0/24", cap: 1 },
        { id: "network-b", cidr: "198.51.100.0/24", cap: 1 },
      ]),
    });
    expect(decideDcrAutoApproval(DESKTOP_REGISTRATION, INSIDE)).toMatchObject({
      outcome: "approved",
      entryId: "network-a",
    });
    expect(
      decideDcrAutoApproval(DESKTOP_REGISTRATION, "198.51.100.9"),
    ).toMatchObject({ outcome: "approved", entryId: "network-b" });
    expect(decideDcrAutoApproval(DESKTOP_REGISTRATION, INSIDE)).toMatchObject({
      outcome: "cap",
      entryId: "network-a",
    });
  });

  it("never falls through to a later overlapping entry when the first is spent", () => {
    initDcrAutoApproval({
      [ENV]: capPolicy([
        { id: "first", cidr: "203.0.113.0/24", cap: 1 },
        { id: "second", cidr: "203.0.113.64/26", cap: 50 },
      ]),
    });
    expect(decideDcrAutoApproval(DESKTOP_REGISTRATION, INSIDE)).toMatchObject({
      outcome: "approved",
      entryId: "first",
    });
    expect(decideDcrAutoApproval(DESKTOP_REGISTRATION, INSIDE)).toEqual({
      outcome: "cap",
      entryId: "first",
    });
    expect(dcrAutoApprovalReservationCountsForTests()).toEqual({ first: 1 });
  });

  it("spends nothing on a registration that does not match", () => {
    initDcrAutoApproval({
      [ENV]: capPolicy([{ id: "only", cidr: "203.0.113.0/24", cap: 1 }]),
    });
    for (const [registration, ip] of [
      [{ ...DESKTOP_REGISTRATION, client_name: "Other Client" }, INSIDE],
      [DESKTOP_REGISTRATION, "198.51.100.9"],
      [DESKTOP_REGISTRATION, undefined],
    ] as const) {
      expect(decideDcrAutoApproval(registration, ip)).toEqual({
        outcome: "none",
      });
    }
    expect(dcrAutoApprovalReservationCountsForTests()).toEqual({});
    expect(decideDcrAutoApproval(DESKTOP_REGISTRATION, INSIDE).outcome).toBe(
      "approved",
    );
  });

  it("holds at most max_per_hour times per entry however long it runs", () => {
    initDcrAutoApproval({
      [ENV]: capPolicy([{ id: "only", cidr: "203.0.113.0/24", cap: 5 }]),
    });
    for (let i = 0; i < 2_000; i++) {
      now += 7_919;
      decideDcrAutoApproval(DESKTOP_REGISTRATION, INSIDE);
      expect(
        dcrAutoApprovalReservationCountsForTests().only,
      ).toBeLessThanOrEqual(5);
    }
  });

  it("starts empty after reset and after a new policy", () => {
    initDcrAutoApproval({
      [ENV]: capPolicy([{ id: "only", cidr: "203.0.113.0/24", cap: 1 }]),
    });
    decideDcrAutoApproval(DESKTOP_REGISTRATION, INSIDE);
    expect(dcrAutoApprovalReservationCountsForTests()).toEqual({ only: 1 });
    initDcrAutoApproval({
      [ENV]: capPolicy([{ id: "only", cidr: "203.0.113.0/24", cap: 1 }]),
    });
    expect(dcrAutoApprovalReservationCountsForTests()).toEqual({});
    decideDcrAutoApproval(DESKTOP_REGISTRATION, INSIDE);
    resetDcrAutoApprovalForTests();
    expect(dcrAutoApprovalReservationCountsForTests()).toEqual({});
  });

  it("decides nothing without a policy", () => {
    initDcrAutoApproval({});
    expect(decideDcrAutoApproval(DESKTOP_REGISTRATION, INSIDE)).toEqual({
      outcome: "none",
    });
  });
});

describe("isApprovedByPolicy (the list's provenance rule)", () => {
  const approvedDcr = {
    registration_source: "dcr",
    approval_status: "approved",
    approved_by: null,
  };

  it("needs the audit marker: a null approver alone proves nothing", () => {
    expect(isApprovedByPolicy(approvedDcr, true)).toBe(true);
    expect(isApprovedByPolicy(approvedDcr, false)).toBe(false);
  });

  it.each([
    ["approved by a person", { ...approvedDcr, approved_by: "admin-1" }],
    ["admin-created", { ...approvedDcr, registration_source: "admin" }],
    [
      "fetched metadata document",
      { ...approvedDcr, registration_source: "cimd" },
    ],
    ["legacy provenance", { ...approvedDcr, registration_source: null }],
    ["now pending", { ...approvedDcr, approval_status: "pending" }],
    ["now rejected", { ...approvedDcr, approval_status: "rejected" }],
  ])("is false for a row %s, even with the marker", (_label, client) => {
    expect(isApprovedByPolicy(client, true)).toBe(false);
  });
});
