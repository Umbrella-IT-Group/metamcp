/**
 * API-key IP allowlists (migration 0041): the policy module on its own.
 *
 * Pins the parts every surface shares: what a valid allowlist entry is, how a
 * client address is matched (including the any-IP exemption and the fail-closed
 * cases), the effective-policy precedence (per-key list over global, kill
 * switch over both), what each mode does, and the audit throttle that keeps a
 * stolen-key holder from flooding `audit_log`.
 *
 * Addresses are RFC 5737 / RFC 3849 documentation ranges only.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { loggerMock } = vi.hoisted(() => ({
  loggerMock: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));
vi.mock("@/utils/logger", () => ({ default: loggerMock }));

const {
  __resetIpPolicyKillSwitchWarningForTesting,
  __resetIpPolicyStateForTesting,
  ANY_IPV4_CIDR,
  ANY_IPV6_CIDR,
  applyApiKeyIpPolicy,
  IP_POLICY_AUDIT_INTERVAL_MS,
  IP_POLICY_AUDIT_PER_KEY_BUDGET,
  isAnyIpExemption,
  matchClientIp,
  normalizeCidrList,
  parseCidr,
  parseStoredGlobalPolicy,
  readMode,
  recordIpPolicyDecision,
  warnIfApiKeyIpPolicyDisabled,
} = await import("./api-key-ip-policy");
const { setAuditSinkForTesting } = await import("./audit/audit-emitter");

type AuditRow = {
  action: string;
  outcome: string;
  actor_type: string;
  actor_id?: string | null;
  actor_ip?: string | null;
  target_type?: string | null;
  target_id?: string | null;
  http_status?: number | null;
  detail?: Record<string, unknown>;
};

const KEY_UUID = "44444444-4444-4444-8444-444444444444";
const OTHER_KEY_UUID = "55555555-5555-4555-8555-555555555555";
const EXEMPTION = [ANY_IPV4_CIDR, ANY_IPV6_CIDR];

let rows: AuditRow[];
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

const check = (clientIp: string | undefined) => ({
  clientIp,
  surface: "data_plane" as const,
  audit: {
    actor_ip: clientIp ?? null,
    actor_user_agent: "n8n/1.0",
    request_id: "req-1",
  },
  target: { type: "endpoint", id: "ep-uuid", label: "autotask" },
});

beforeEach(() => {
  vi.clearAllMocks();
  vi.unstubAllEnvs();
  __resetIpPolicyStateForTesting();
  __resetIpPolicyKillSwitchWarningForTesting();
  rows = [];
  setAuditSinkForTesting(async (event) => {
    rows.push(event as AuditRow);
  });
});

afterEach(() => {
  setAuditSinkForTesting(undefined);
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

describe("parseCidr: what a valid allowlist entry is", () => {
  it.each([
    ["203.0.113.0/24", "203.0.113.0/24"],
    ["203.0.113.7", "203.0.113.7/32"],
    ["198.51.100.0/22", "198.51.100.0/22"],
    ["0.0.0.0/0", "0.0.0.0/0"],
    ["2001:DB8::/32", "2001:db8::/32"],
    ["2001:db8:0:0::1", "2001:db8::1/128"],
    ["::/0", "::/0"],
    ["  192.0.2.0/24  ", "192.0.2.0/24"],
    ["::ffff:192.0.2.0/120", "::ffff:192.0.2.0/120"],
  ])("accepts %s as %s", (raw, canonical) => {
    const parsed = parseCidr(raw);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(parsed.value.cidr).toBe(canonical);
  });

  it.each([
    ["", "empty"],
    ["not-an-ip", "not an IPv4 or IPv6"],
    ["203.0.113.05", "not an IPv4 or IPv6"],
    ["203.0.113.0/33", "invalid prefix"],
    ["2001:db8::/129", "invalid prefix"],
    ["203.0.113.0/-1", "invalid prefix"],
    ["203.0.113.0/24/1", "more than one"],
    ["fe80::1%eth0", "zone id"],
    ["203.0.113.5/24", "host bits set; write 203.0.113.0/24"],
    ["2001:db8::1/32", "host bits set; write 2001:db8::/32"],
  ])("refuses %s (%s)", (raw, fragment) => {
    const parsed = parseCidr(raw);
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) expect(parsed.error).toContain(fragment);
  });

  it("normalizeCidrList reports EVERY bad entry, dedupes canonical forms, keeps order", () => {
    expect(
      normalizeCidrList(["203.0.113.7", "203.0.113.7/32", "2001:DB8::/32"]),
    ).toEqual({ ok: true, cidrs: ["203.0.113.7/32", "2001:db8::/32"] });

    const bad = normalizeCidrList(["nope", "192.0.2.0/24", "198.51.100.1/24"]);
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.errors).toHaveLength(2);
  });

  it("refuses a list longer than the per-list ceiling", () => {
    const tooMany = Array.from({ length: 101 }, (_, i) => `192.0.2.${i}`);
    expect(normalizeCidrList(tooMany).ok).toBe(false);
  });
});

describe("matchClientIp: matching and the fail-closed cases", () => {
  const list = ["203.0.113.0/24", "2001:db8::/32"];

  it("matches IPv4 and IPv6 addresses inside the list", () => {
    expect(matchClientIp(list, "203.0.113.200")).toBe("in_list");
    expect(matchClientIp(list, "2001:db8:1::5")).toBe("in_list");
  });

  it("matches an IPv4-mapped IPv6 address against an IPv4 entry", () => {
    expect(matchClientIp(list, "::ffff:203.0.113.9")).toBe("in_list");
  });

  it("refuses an address outside the list", () => {
    expect(matchClientIp(list, "198.51.100.9")).toBe("not_in_list");
    expect(matchClientIp(list, "2001:db9::1")).toBe("not_in_list");
  });

  it("reports a missing or unparsable address (fail closed)", () => {
    expect(matchClientIp(list, undefined)).toBe("missing");
    expect(matchClientIp(list, "")).toBe("missing");
    expect(matchClientIp(list, "not-an-address")).toBe("unparsable");
  });

  it("an empty list admits nothing", () => {
    expect(matchClientIp([], "203.0.113.1")).toBe("not_in_list");
  });

  it("the any-IP exemption short-circuits BEFORE the address is parsed", () => {
    expect(isAnyIpExemption(EXEMPTION)).toBe(true);
    expect(matchClientIp(EXEMPTION, undefined)).toBe("any_ip_exemption");
    expect(matchClientIp(EXEMPTION, "garbage")).toBe("any_ip_exemption");
    expect(matchClientIp(EXEMPTION, "203.0.113.1")).toBe("any_ip_exemption");
  });

  it("a list with only ONE of the two any-IP entries is an ordinary list", () => {
    expect(isAnyIpExemption([ANY_IPV4_CIDR])).toBe(false);
    expect(matchClientIp([ANY_IPV4_CIDR], undefined)).toBe("missing");
    expect(matchClientIp([ANY_IPV4_CIDR], "2001:db8::1")).toBe("not_in_list");
  });

  it("ignores (and names once) a stored entry it cannot parse, which only narrows the list", () => {
    expect(matchClientIp(["garbage", "203.0.113.0/24"], "203.0.113.4")).toBe(
      "in_list",
    );
    expect(matchClientIp(["garbage"], "203.0.113.4")).toBe("not_in_list");
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
  });
});

describe("readMode / parseStoredGlobalPolicy: stored values", () => {
  it("unset reads as off; the three modes read as themselves", () => {
    expect(readMode(undefined)).toBe("off");
    expect(readMode(null)).toBe("off");
    expect(readMode("")).toBe("off");
    expect(readMode("audit")).toBe("audit");
    expect(readMode("enforce")).toBe("enforce");
  });

  it("an unknown mode reads as enforce (fail closed)", () => {
    expect(readMode("enforced")).toBe("enforce");
  });

  it("missing global rows are the inert default", () => {
    expect(parseStoredGlobalPolicy(undefined, undefined)).toEqual({
      mode: "off",
      cidrs: [],
      problems: [],
    });
  });

  it("reads a stored list and names every problem it had to work around", () => {
    expect(
      parseStoredGlobalPolicy("audit", JSON.stringify(["203.0.113.0/24"])),
    ).toEqual({ mode: "audit", cidrs: ["203.0.113.0/24"], problems: [] });

    const broken = parseStoredGlobalPolicy("ENFORCE!", "{not json");
    expect(broken.mode).toBe("enforce");
    expect(broken.cidrs).toEqual([]);
    expect(broken.problems).toHaveLength(2);

    const notArray = parseStoredGlobalPolicy("enforce", '{"a":1}');
    expect(notArray.cidrs).toEqual([]);
    expect(notArray.problems[0]).toContain("not a JSON array");
  });
});

describe("applyApiKeyIpPolicy: precedence and modes", () => {
  const readGlobal = vi.fn();

  beforeEach(() => {
    readGlobal.mockReset();
    readGlobal.mockResolvedValue({ mode: "off", cidrs: [] });
  });

  it("everything off (the deploy state): allows, writes nothing", async () => {
    const result = await applyApiKeyIpPolicy(
      { uuid: KEY_UUID, allowed_cidrs: null, ip_policy_mode: "off" },
      check("198.51.100.9"),
      readGlobal,
    );
    await flush();
    expect(result).toEqual({ denied: false });
    expect(rows).toHaveLength(0);
  });

  it("a key with its own list uses ITS mode and list and never reads the global policy", async () => {
    readGlobal.mockResolvedValue({ mode: "enforce", cidrs: ["192.0.2.0/24"] });

    const result = await applyApiKeyIpPolicy(
      {
        uuid: KEY_UUID,
        allowed_cidrs: ["203.0.113.0/24"],
        ip_policy_mode: "enforce",
      },
      check("203.0.113.10"),
      readGlobal,
    );

    expect(result).toEqual({ denied: false });
    expect(readGlobal).not.toHaveBeenCalled();
  });

  it("a key's own list with mode off is off even when the global mode is enforce", async () => {
    readGlobal.mockResolvedValue({ mode: "enforce", cidrs: ["192.0.2.0/24"] });

    const result = await applyApiKeyIpPolicy(
      { uuid: KEY_UUID, allowed_cidrs: [], ip_policy_mode: "off" },
      check("198.51.100.9"),
      readGlobal,
    );

    expect(result).toEqual({ denied: false });
    expect(readGlobal).not.toHaveBeenCalled();
  });

  it("a key with NO list follows the global list and mode", async () => {
    readGlobal.mockResolvedValue({ mode: "enforce", cidrs: ["192.0.2.0/24"] });

    const allowed = await applyApiKeyIpPolicy(
      { uuid: KEY_UUID, allowed_cidrs: null, ip_policy_mode: "audit" },
      check("192.0.2.44"),
      readGlobal,
    );
    const refused = await applyApiKeyIpPolicy(
      { uuid: KEY_UUID, allowed_cidrs: null, ip_policy_mode: "audit" },
      check("198.51.100.9"),
      readGlobal,
    );

    expect(allowed).toEqual({ denied: false });
    // The key's own mode (audit) is ignored: with no own list, global applies.
    expect(refused).toEqual({ denied: true });
    expect(readGlobal).toHaveBeenCalledTimes(2);
  });

  it("audit serves the request and writes one would-deny row", async () => {
    const result = await applyApiKeyIpPolicy(
      {
        uuid: KEY_UUID,
        allowed_cidrs: ["203.0.113.0/24"],
        ip_policy_mode: "audit",
      },
      check("198.51.100.9"),
      readGlobal,
    );
    await flush();

    expect(result).toEqual({ denied: false });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "apikey.ip.would_deny",
      outcome: "success",
      actor_type: "api_key",
      actor_id: KEY_UUID,
      actor_ip: "198.51.100.9",
      target_type: "endpoint",
      target_id: "ep-uuid",
      http_status: null,
    });
    expect(rows[0].detail).toMatchObject({
      reason: "api_key_ip_not_allowed",
      surface: "data_plane",
      policy_source: "key",
      mode: "audit",
      ip_status: "not_in_list",
      client_ip: "198.51.100.9",
      suppressed_since_last: 0,
    });
  });

  it("enforce refuses and writes one denied row with http 403", async () => {
    const result = await applyApiKeyIpPolicy(
      {
        uuid: KEY_UUID,
        allowed_cidrs: ["203.0.113.0/24"],
        ip_policy_mode: "enforce",
      },
      check("198.51.100.9"),
      readGlobal,
    );
    await flush();

    expect(result).toEqual({ denied: true });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "apikey.ip.denied",
      outcome: "denied",
      http_status: 403,
    });
    expect(rows[0].detail).toMatchObject({
      reason: "api_key_ip_not_allowed",
      mode: "enforce",
    });
  });

  it("enforce refuses a request with NO client address (fail closed)", async () => {
    const result = await applyApiKeyIpPolicy(
      {
        uuid: KEY_UUID,
        allowed_cidrs: ["203.0.113.0/24"],
        ip_policy_mode: "enforce",
      },
      check(undefined),
      readGlobal,
    );
    await flush();

    expect(result).toEqual({ denied: true });
    expect(rows[0].detail).toMatchObject({ ip_status: "missing" });
  });

  it("the any-IP exemption admits a request with no client address under enforce", async () => {
    const result = await applyApiKeyIpPolicy(
      { uuid: KEY_UUID, allowed_cidrs: EXEMPTION, ip_policy_mode: "enforce" },
      check(undefined),
      readGlobal,
    );
    await flush();

    expect(result).toEqual({ denied: false });
    expect(rows).toHaveLength(0);
  });

  it("the kill switch turns every check off before anything is read", async () => {
    vi.stubEnv("API_KEY_IP_POLICY_DISABLED", "true");
    readGlobal.mockResolvedValue({ mode: "enforce", cidrs: ["192.0.2.0/24"] });

    const own = await applyApiKeyIpPolicy(
      {
        uuid: KEY_UUID,
        allowed_cidrs: ["203.0.113.0/24"],
        ip_policy_mode: "enforce",
      },
      check("198.51.100.9"),
      readGlobal,
    );
    const global = await applyApiKeyIpPolicy(
      { uuid: KEY_UUID, allowed_cidrs: null, ip_policy_mode: "off" },
      check("198.51.100.9"),
      readGlobal,
    );
    await flush();

    expect(own).toEqual({ denied: false });
    expect(global).toEqual({ denied: false });
    expect(readGlobal).not.toHaveBeenCalled();
    expect(rows).toHaveLength(0);
  });

  it.each(["1", "yes", "TRUE", " true"])(
    "the kill switch is strict: %j does not disable enforcement",
    async (value) => {
      vi.stubEnv("API_KEY_IP_POLICY_DISABLED", value);
      const result = await applyApiKeyIpPolicy(
        {
          uuid: KEY_UUID,
          allowed_cidrs: ["203.0.113.0/24"],
          ip_policy_mode: "enforce",
        },
        check("198.51.100.9"),
        readGlobal,
      );
      expect(result).toEqual({ denied: true });
    },
  );

  it("logs the kill switch once at boot, and only when it is set", () => {
    warnIfApiKeyIpPolicyDisabled();
    expect(loggerMock.warn).not.toHaveBeenCalled();

    __resetIpPolicyKillSwitchWarningForTesting();
    vi.stubEnv("API_KEY_IP_POLICY_DISABLED", "true");
    warnIfApiKeyIpPolicyDisabled();
    warnIfApiKeyIpPolicyDisabled();
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(loggerMock.warn.mock.calls[0][0]).toContain(
      "API_KEY_IP_POLICY_DISABLED=true",
    );
  });
});

describe("audit throttle: a stolen-key holder cannot flood audit_log", () => {
  const enforceOwnList = {
    uuid: KEY_UUID,
    allowed_cidrs: ["203.0.113.0/24"],
    ip_policy_mode: "enforce",
  };
  const readGlobal = vi.fn().mockResolvedValue({ mode: "off", cidrs: [] });

  it("writes ONE row per key and address per window, however many requests", async () => {
    for (let i = 0; i < 50; i += 1) {
      const result = await applyApiKeyIpPolicy(
        enforceOwnList,
        check("198.51.100.9"),
        readGlobal,
      );
      // Every request is still refused: the throttle limits ROWS, not denials.
      expect(result).toEqual({ denied: true });
    }
    await flush();

    expect(rows).toHaveLength(1);
  });

  it("carries the suppressed count on the next row after the window", () => {
    const t0 = 1_000_000;
    expect(
      recordIpPolicyDecision("deny", KEY_UUID, "198.51.100.9", t0),
    ).toEqual({ emit: true, suppressed: 0, keySuppressed: 0 });
    for (let i = 1; i <= 7; i += 1) {
      expect(
        recordIpPolicyDecision("deny", KEY_UUID, "198.51.100.9", t0 + i).emit,
      ).toBe(false);
    }
    const next = recordIpPolicyDecision(
      "deny",
      KEY_UUID,
      "198.51.100.9",
      t0 + IP_POLICY_AUDIT_INTERVAL_MS,
    );
    expect(next).toEqual({ emit: true, suppressed: 7, keySuppressed: 0 });
  });

  it("throttles per key and per address independently", () => {
    const t0 = 2_000_000;
    expect(
      recordIpPolicyDecision("deny", KEY_UUID, "198.51.100.1", t0).emit,
    ).toBe(true);
    expect(
      recordIpPolicyDecision("deny", KEY_UUID, "198.51.100.2", t0).emit,
    ).toBe(true);
    expect(
      recordIpPolicyDecision("deny", OTHER_KEY_UUID, "198.51.100.1", t0).emit,
    ).toBe(true);
    // Would-deny and deny are separate streams, so a flip from audit to
    // enforce mid-window still writes the first denial.
    expect(
      recordIpPolicyDecision("would_deny", KEY_UUID, "198.51.100.1", t0).emit,
    ).toBe(true);
  });

  it("caps rows per key per window even when the holder rotates addresses", () => {
    const t0 = 3_000_000;
    let emitted = 0;
    for (let i = 0; i < 500; i += 1) {
      const ip = `2001:db8::${i.toString(16)}`;
      if (recordIpPolicyDecision("deny", KEY_UUID, ip, t0 + i).emit)
        emitted += 1;
    }
    expect(emitted).toBe(IP_POLICY_AUDIT_PER_KEY_BUDGET);

    // The overflow is counted and rides the key's first row of the next window.
    const next = recordIpPolicyDecision(
      "deny",
      KEY_UUID,
      "2001:db8::ffff",
      t0 + IP_POLICY_AUDIT_INTERVAL_MS + 500,
    );
    expect(next.emit).toBe(true);
    expect(next.keySuppressed).toBe(500 - IP_POLICY_AUDIT_PER_KEY_BUDGET);
  });
});
