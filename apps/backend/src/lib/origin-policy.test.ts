/**
 * The Origin policy: which `Origin` values pass, how a refusal is described,
 * and how much of it may be written down.
 *
 * Oracles. Origin comparison follows WHATWG URL origin serialization and
 * RFC 6454 sections 4 and 7 (an origin is scheme, host and port; the literal
 * `null` is the serialization of an opaque origin and is never a match).
 * The boundaries of the volume bounds are the numbers the design fixes: one
 * record per key per 60 s, 60 events and 20 audit rows per fixed hour. The
 * default mode follows the operator direction of 2026-11-12: shipping the
 * guard must not change what a legitimate consumer sees.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { loggerMock } = vi.hoisted(() => ({
  loggerMock: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));
vi.mock("@/utils/logger", () => ({ default: loggerMock }));

import {
  __resetOriginPolicyStateForTesting,
  clampMethod,
  classifyRoute,
  currentOriginPolicyMode,
  decideAuditRow,
  decideOriginReport,
  describeOrigin,
  describeSecFetchSite,
  endpointNameFromPath,
  evaluateOrigin,
  formatOriginEventMessage,
  isLivenessRequest,
  logOriginPolicyBootState,
  ORIGIN_DESCRIPTION_MAX,
  ORIGIN_REFUSAL_BODY,
  originReportKey,
  quoteBoundedHeader,
  resolveOriginPolicyMode,
  statusClass,
} from "./origin-policy";

const APP = "https://gateway.example.test";
const EXTRA = "https://partner.example.test";
const ALLOWED = "https://connector.example.test";

beforeEach(() => {
  vi.clearAllMocks();
  __resetOriginPolicyStateForTesting();
  vi.stubEnv("APP_URL", APP);
  vi.stubEnv("EXTRA_TRUSTED_ORIGINS", EXTRA);
  vi.stubEnv("MCP_ALLOWED_ORIGINS", ALLOWED);
  vi.stubEnv("MCP_ORIGIN_POLICY", undefined);
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.useRealTimers();
});

describe("evaluateOrigin", () => {
  it.each([
    ["undefined", undefined],
    ["an empty value", ""],
    ["whitespace only", "   "],
  ])("treats %s as absent", (_label, header) => {
    expect(evaluateOrigin(header)).toEqual({ kind: "absent" });
  });

  it.each([
    ["APP_URL", APP],
    ["APP_URL, upper case", "HTTPS://GATEWAY.EXAMPLE.TEST"],
    ["APP_URL, explicit default port", "https://gateway.example.test:443"],
    [
      "APP_URL, trailing path (parsed as an origin, not compared as text)",
      `${APP}/x`,
    ],
    ["an EXTRA_TRUSTED_ORIGINS entry", EXTRA],
    ["an MCP_ALLOWED_ORIGINS entry", ALLOWED],
    [
      "an MCP_ALLOWED_ORIGINS entry, upper case",
      "HTTPS://CONNECTOR.EXAMPLE.TEST",
    ],
  ])("allows %s", (_label, header) => {
    expect(evaluateOrigin(header)).toEqual({ kind: "allowed" });
  });

  it.each([
    ["another host", "https://evil.example.test"],
    ["another port", "https://gateway.example.test:8443"],
    ["http instead of https", "http://gateway.example.test"],
    [
      "a longer host ending in the trusted one",
      "https://gateway.example.test.evil.example",
    ],
    ["a userinfo lookalike", "https://gateway.example.test@evil.example"],
    ["the literal null", "null"],
    [
      "a browser-extension origin",
      "moz-extension://11111111-2222-3333-4444-555555555555",
    ],
    ["a file origin", "file://"],
    ["a data URL", "data:text/html,x"],
    [
      "two origins in one header",
      "https://gateway.example.test, https://partner.example.test",
    ],
    [
      "another port of an MCP_ALLOWED_ORIGINS entry",
      "https://connector.example.test:8080",
    ],
    ["garbage", "not a url"],
  ])("refuses %s", (_label, header) => {
    expect(evaluateOrigin(header).kind).toBe("refused");
  });

  it("refuses a value that is not a string, rather than throwing", () => {
    expect(evaluateOrigin([APP])).toEqual({
      kind: "refused",
      described: "(unparseable)",
    });
    expect(evaluateOrigin({})).toMatchObject({ kind: "refused" });
  });

  it("allows loopback only while APP_URL is loopback", () => {
    expect(evaluateOrigin("http://localhost:3000").kind).toBe("refused");

    vi.stubEnv("APP_URL", "http://localhost:12008");
    expect(evaluateOrigin("http://localhost:3000")).toEqual({
      kind: "allowed",
    });
    expect(evaluateOrigin("http://127.0.0.1:5173")).toEqual({
      kind: "allowed",
    });
  });

  it("ignores an exotic-scheme entry in MCP_ALLOWED_ORIGINS instead of trusting every opaque origin", () => {
    // Every non-special scheme serialises to the same opaque origin, "null".
    // If one entry were normalised to it, the entry would trust the literal
    // `null` and every other extension or packaged-app origin as well.
    vi.stubEnv(
      "MCP_ALLOWED_ORIGINS",
      `moz-extension://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee,${ALLOWED}`,
    );

    expect(evaluateOrigin("null").kind).toBe("refused");
    expect(
      evaluateOrigin("moz-extension://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        .kind,
    ).toBe("refused");
    expect(
      evaluateOrigin("moz-extension://ffffffff-ffff-ffff-ffff-ffffffffffff")
        .kind,
    ).toBe("refused");
    expect(evaluateOrigin(ALLOWED)).toEqual({ kind: "allowed" });
  });

  it("grants nothing from MCP_ALLOWED_ORIGINS when it is unset", () => {
    vi.stubEnv("MCP_ALLOWED_ORIGINS", undefined);
    expect(evaluateOrigin(ALLOWED).kind).toBe("refused");
  });

  it("returns a bounded description of a refusal, never the raw header", () => {
    const refusal = evaluateOrigin(
      "https://evil.example.test/path?token=secret",
    );

    expect(refusal).toEqual({
      kind: "refused",
      described: "https://evil.example.test",
    });
  });
});

describe("resolveOriginPolicyMode", () => {
  it("defaults to audit, with no warning (the default must not change consumer behaviour)", () => {
    expect(resolveOriginPolicyMode({})).toEqual({
      mode: "audit",
      warning: null,
    });
  });

  it.each(["off", "audit", "enforce"] as const)(
    "resolves %s as given",
    (mode) => {
      expect(resolveOriginPolicyMode({ MCP_ORIGIN_POLICY: mode })).toEqual({
        mode,
        warning: null,
      });
    },
  );

  it.each([
    ["a misspelling", "enforced"],
    ["a different case", "Enforce"],
    ["a padded value", " audit"],
    ["an empty value", ""],
    ["an unrelated word", "strict"],
  ])(
    "resolves %s to audit, never to off or enforce, and says so",
    (_label, value) => {
      const resolution = resolveOriginPolicyMode({ MCP_ORIGIN_POLICY: value });

      expect(resolution.mode).toBe("audit");
      expect(resolution.warning).toContain("MCP_ORIGIN_POLICY");
      expect(resolution.warning).toContain(JSON.stringify(value));
    },
  );

  it("bounds the echoed value in the warning", () => {
    const { warning } = resolveOriginPolicyMode({
      MCP_ORIGIN_POLICY: "x".repeat(500),
    });

    expect(warning?.length).toBeLessThan(400);
  });

  it("reports a bad value on the request path as an ERROR, once per process", () => {
    vi.stubEnv("MCP_ORIGIN_POLICY", "enforced");

    for (let i = 0; i < 5; i += 1) {
      expect(currentOriginPolicyMode()).toBe("audit");
    }

    expect(loggerMock.error).toHaveBeenCalledTimes(1);
    expect(String(loggerMock.error.mock.calls[0][0])).toContain('"enforced"');
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });
});

describe("describeOrigin", () => {
  it("records a valid http(s) origin as the origin this process parsed", () => {
    expect(describeOrigin("HTTPS://Evil.Example.Test:443/a?b#c")).toBe(
      "https://evil.example.test",
    );
    expect(describeOrigin("http://evil.example.test:8080")).toBe(
      "http://evil.example.test:8080",
    );
  });

  it("records null as null, a non-http scheme as its scheme, and the rest as unparseable", () => {
    expect(describeOrigin("null")).toBe("null");
    expect(describeOrigin("moz-extension://aaaa-bbbb")).toBe(
      "(scheme moz-extension)",
    );
    expect(describeOrigin("file://")).toBe("(scheme file)");
    expect(describeOrigin("not a url")).toBe("(unparseable)");
    expect(describeOrigin(undefined)).toBe("(unparseable)");
  });

  it("never lets CR or LF into a description", () => {
    const described = describeOrigin("https://evil.test\r\nX-Injected: 1");

    expect(described).toBe("(unparseable)");
    expect(describeOrigin("https://evil.test\r\n.example")).not.toMatch(
      /[\r\n]/,
    );
  });

  it("bounds a very long host to the description limit", () => {
    const described = describeOrigin(
      `https://${"a".repeat(5000)}.example.test`,
    );

    expect(described.length).toBeLessThanOrEqual(ORIGIN_DESCRIPTION_MAX);
  });
});

describe("quoteBoundedHeader", () => {
  it("quotes the value as one JSON string", () => {
    expect(quoteBoundedHeader('Agent/1.0 "x"', 160)).toBe(
      '"Agent/1.0 \\"x\\""',
    );
  });

  it("replaces control and non-ASCII characters so a log line cannot be split", () => {
    const quoted = quoteBoundedHeader(
      `a\r\nb\u0000c${String.fromCharCode(0x2028)}d${String.fromCharCode(0xe9)}`,
      160,
    );

    expect(quoted).toBe('"a??b?c?d?"');
    expect(quoted).not.toMatch(/[\r\n]/);
    expect(quoted).not.toContain(String.fromCharCode(0x2028));
  });

  it("cuts the value at the limit before quoting", () => {
    expect(quoteBoundedHeader("x".repeat(1000), 160)).toBe(
      `"${"x".repeat(160)}"`,
    );
  });
});

describe("describeSecFetchSite", () => {
  it.each(["same-origin", "same-site", "cross-site", "none"])(
    "passes the defined value %s",
    (value) => {
      expect(describeSecFetchSite(value)).toBe(value);
    },
  );

  it("clamps anything else to other and reports a missing header as absent", () => {
    expect(describeSecFetchSite("https://evil.test")).toBe("other");
    expect(describeSecFetchSite("")).toBe("other");
    expect(describeSecFetchSite(undefined)).toBe("absent");
  });
});

describe("route and request classification", () => {
  it.each([
    ["/ep/mcp", "mcp"],
    ["/ep/MCP", "mcp"],
    ["/ep/sse", "sse"],
    ["/ep/message", "message"],
    ["/ep/api/openapi.json", "api"],
    ["/ep/api/some_tool", "api"],
    ["/ep/admin/reset-errors", "admin"],
    ["/ep", "other"],
    ["/", "other"],
    ["/ep/unknown", "other"],
  ])("classifies %s as %s", (route, family) => {
    expect(classifyRoute(route)).toBe(family);
  });

  it("takes the endpoint name from the first segment and clamps it", () => {
    expect(endpointNameFromPath("/my-endpoint/mcp")).toBe("my-endpoint");
    expect(endpointNameFromPath("/")).toBeNull();
    expect(endpointNameFromPath(`/${"e".repeat(400)}/mcp`)?.length).toBe(128);
  });

  it("clamps a method outside the standard set", () => {
    expect(clampMethod("POST")).toBe("POST");
    expect(clampMethod("BREW")).toBe("OTHER");
  });

  it.each([
    ["GET", "/", true],
    ["HEAD", "/", true],
    ["GET", "/health", true],
    ["HEAD", "/health/sessions", true],
    ["GET", "/health/sessions", true],
    // An endpoint may be named `health`: this is its data plane, not liveness.
    ["GET", "/health/mcp", false],
    ["POST", "/health/mcp", false],
    ["GET", "/health/sse", false],
    ["POST", "/health", false],
    ["DELETE", "/", false],
    ["GET", "/healthz", false],
    ["GET", "/ep/mcp", false],
  ])("isLivenessRequest(%s %s) is %s", (method, route, expected) => {
    expect(isLivenessRequest(method, route)).toBe(expected);
  });

  it.each([
    [200, "served"],
    [399, "served"],
    [400, "denied"],
    [401, "denied"],
    [499, "denied"],
    [500, "error"],
    [503, "error"],
  ] as const)("statusClass(%i) is %s", (status, expected) => {
    expect(statusClass(status)).toBe(expected);
  });
});

describe("the refusal body", () => {
  it("is the SDK's JSON-RPC error shape with no id and names no origin", () => {
    expect(JSON.stringify(ORIGIN_REFUSAL_BODY)).toBe(
      '{"jsonrpc":"2.0","error":{"code":-32000,"message":"Origin not allowed"},"id":null}',
    );
  });
});

describe("decideOriginReport", () => {
  const START = new Date("2026-11-12T12:00:00.000Z");
  const key = (
    described: string,
    over: Partial<Parameters<typeof originReportKey>[0]> = {},
  ) =>
    originReportKey({
      mode: "audit",
      described,
      route: "mcp",
      method: "POST",
      eventClass: "served",
      credentialPresent: false,
      ...over,
    });

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(START);
  });

  it("reports the first refusal and collapses repeats within 60 s, counting them", () => {
    expect(decideOriginReport(key("https://a.test"), "served")).toEqual({
      report: true,
      suppressed: 0,
      droppedByCeiling: 0,
    });

    for (let i = 0; i < 3; i += 1) {
      vi.advanceTimersByTime(10_000);
      expect(decideOriginReport(key("https://a.test"), "served").report).toBe(
        false,
      );
    }

    // 30 s in; the window ends at exactly 60 s, so 59 s is still inside it.
    vi.advanceTimersByTime(29_000);
    expect(decideOriginReport(key("https://a.test"), "served").report).toBe(
      false,
    );

    vi.advanceTimersByTime(1_000);
    expect(decideOriginReport(key("https://a.test"), "served")).toEqual({
      report: true,
      suppressed: 4,
      droppedByCeiling: 0,
    });
  });

  it("keeps keys that differ in origin, credential, class, method or mode apart", () => {
    const base = key("https://a.test");
    expect(decideOriginReport(base, "served").report).toBe(true);

    for (const other of [
      key("https://b.test"),
      key("https://a.test", { credentialPresent: true }),
      key("https://a.test", { eventClass: "denied" }),
      key("https://a.test", { method: "GET" }),
      key("https://a.test", { mode: "enforce" }),
      key("https://a.test", { route: "sse" }),
    ]) {
      expect(decideOriginReport(other, "other").report, other).toBe(true);
    }
    expect(decideOriginReport(base, "served").report).toBe(false);
  });

  it("stops at 60 events an hour in the other bucket while the served bucket still reports", () => {
    for (let i = 0; i < 60; i += 1) {
      expect(
        decideOriginReport(
          key(`https://flood-${i}.test`, { eventClass: "denied" }),
          "other",
        ).report,
      ).toBe(true);
    }
    expect(
      decideOriginReport(
        key("https://flood-60.test", { eventClass: "denied" }),
        "other",
      ),
    ).toMatchObject({
      report: false,
    });
    expect(
      decideOriginReport(
        key("https://flood-61.test", { eventClass: "denied" }),
        "other",
      ).report,
    ).toBe(false);

    // Reserved: a genuine served event is not crowded out by the flood.
    expect(decideOriginReport(key("https://real.test"), "served").report).toBe(
      true,
    );
  });

  it("carries the dropped count on the next reported event of the bucket and warns once per window", () => {
    for (let i = 0; i < 60; i += 1) {
      decideOriginReport(key(`https://flood-${i}.test`), "other");
    }
    for (let i = 60; i < 65; i += 1) {
      decideOriginReport(key(`https://flood-${i}.test`), "other");
    }

    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(String(loggerMock.warn.mock.calls[0][0])).toContain(
      "hourly ceiling",
    );

    // A new hour opens a new window; the count is owed to its first record.
    vi.advanceTimersByTime(60 * 60 * 1000);
    expect(decideOriginReport(key("https://later.test"), "other")).toEqual({
      report: true,
      suppressed: 0,
      droppedByCeiling: 5,
    });
    // ...and is paid once.
    expect(
      decideOriginReport(key("https://later-2.test"), "other").droppedByCeiling,
    ).toBe(0);
  });

  it("writes a second warning when a later window hits the ceiling again", () => {
    for (let i = 0; i < 61; i += 1) {
      decideOriginReport(key(`https://first-window-${i}.test`), "other");
    }
    vi.advanceTimersByTime(60 * 60 * 1000);
    for (let i = 0; i < 61; i += 1) {
      decideOriginReport(key(`https://second-window-${i}.test`), "other");
    }

    expect(loggerMock.warn).toHaveBeenCalledTimes(2);
  });

  it("keeps what a key swallowed when its record is dropped by the ceiling", () => {
    const victim = key("https://victim.test");
    expect(decideOriginReport(victim, "other").report).toBe(true);
    decideOriginReport(victim, "other");
    decideOriginReport(victim, "other");
    for (let i = 0; i < 59; i += 1) {
      decideOriginReport(key(`https://fill-${i}.test`), "other");
    }

    // The victim's window ends while the hour's budget is spent.
    vi.advanceTimersByTime(61_000);
    expect(decideOriginReport(victim, "other").report).toBe(false);

    vi.advanceTimersByTime(60 * 60 * 1000);
    expect(decideOriginReport(victim, "other")).toMatchObject({
      report: true,
      suppressed: 2,
      droppedByCeiling: 1,
    });
  });

  it("clears its key table when 1,000 distinct keys have been seen", () => {
    const first = key("https://first.test");
    decideOriginReport(first, "served");
    expect(decideOriginReport(first, "served").report).toBe(false);

    // Distinct keys in the served bucket reach its ceiling, and the table
    // clears when the 1,001st key arrives.
    for (let i = 0; i < 1_000; i += 1) {
      decideOriginReport(key(`https://k-${i}.test`), "served");
    }

    // The cleared key is new again, so the table cannot grow without bound.
    expect(decideOriginReport(first, "served")).toMatchObject({
      suppressed: 0,
    });
  });
});

describe("decideAuditRow", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-11-12T12:00:00.000Z"));
  });

  const key = (i: number) =>
    originReportKey({
      mode: "enforce",
      described: `https://o-${i}.test`,
      route: "mcp",
      method: "POST",
      eventClass: "refused",
      credentialPresent: false,
    });

  it("refuses the 21st row in a window and resets after an hour, carrying the count", () => {
    for (let i = 0; i < 20; i += 1) {
      expect(decideAuditRow(key(i)).report).toBe(true);
    }
    for (let i = 20; i < 100; i += 1) {
      expect(decideAuditRow(key(i)).report).toBe(false);
    }

    vi.advanceTimersByTime(60 * 60 * 1000);
    expect(decideAuditRow(key(500))).toEqual({
      report: true,
      suppressed: 0,
      droppedByCeiling: 80,
    });
  });

  it("is independent of the event bucket's budget", () => {
    for (let i = 0; i < 60; i += 1) {
      decideOriginReport(key(i), "other");
    }
    expect(decideOriginReport(key(60), "other").report).toBe(false);

    expect(decideAuditRow(key(60)).report).toBe(true);
  });
});

describe("formatOriginEventMessage", () => {
  const base = {
    mode: "audit" as const,
    origin: "https://x.example",
    route: "mcp" as const,
    method: "POST",
    eventClass: "served" as const,
    status: 200,
    credentialPresent: true,
    secFetchSite: "cross-site" as const,
    userAgent: "claude-mcp/1.0",
    suppressed: 0,
    droppedByCeiling: 0,
  };

  it("words an audit event with the status it was served", () => {
    expect(formatOriginEventMessage(base)).toBe(
      'origin-policy audit: Origin "https://x.example", POST mcp, served (200), credential present, ' +
        "sec-fetch-site cross-site; would be refused under MCP_ORIGIN_POLICY=enforce; " +
        'ua "claude-mcp/1.0"',
    );
  });

  it("words an enforce refusal and carries both counts", () => {
    expect(
      formatOriginEventMessage({
        ...base,
        mode: "enforce",
        eventClass: "refused",
        status: 403,
        credentialPresent: false,
        suppressed: 3,
        droppedByCeiling: 2,
        userAgent: undefined,
      }),
    ).toBe(
      'origin-policy enforce: refused Origin "https://x.example", POST mcp, 403, credential absent, ' +
        "sec-fetch-site cross-site; 3 similar request(s) suppressed since the last event; " +
        "2 dropped by the hourly ceiling; ua absent",
    );
  });

  it("quotes a hostile User-Agent and Origin so neither can forge a field or split the line", () => {
    const message = formatOriginEventMessage({
      ...base,
      origin: 'https://evil.test";x=1',
      userAgent: 'x"; credential absent; ua "forged\r\nINJECTED',
    });

    expect(message).not.toMatch(/[\r\n]/);
    expect(message).toContain('Origin "https://evil.test\\";x=1"');
    expect(message).toContain(
      'ua "x\\"; credential absent; ua \\"forged??INJECTED"',
    );
    // The one real credential field is still the only unquoted one.
    expect(message.match(/credential (present|absent)/g)).toEqual([
      "credential present",
      "credential absent",
    ]);
  });

  it("stays under the history sink's message cap with a hostile origin and agent", () => {
    const message = formatOriginEventMessage({
      ...base,
      origin: describeOrigin(`https://${'"'.repeat(300)}.example.test`),
      userAgent: '"'.repeat(1000),
      suppressed: 999_999_999_999,
      droppedByCeiling: 999_999_999_999,
    });

    // Every quote in both values really was escaped, or this proves nothing.
    expect(message.match(/\\"/g)?.length).toBeGreaterThan(300);

    // GATEWAY_EVENT_MESSAGE_MAX is 1024. The user agent is last, so a cut
    // there costs the least useful part.
    expect(message.length).toBeLessThanOrEqual(1024);
  });
});

describe("logOriginPolicyBootState", () => {
  it("logs one info line for audit and names the allowed-origin count", () => {
    logOriginPolicyBootState();
    logOriginPolicyBootState();

    expect(loggerMock.info).toHaveBeenCalledTimes(1);
    const line = String(loggerMock.info.mock.calls[0][0]);
    expect(line).toContain("[origin-policy] MCP_ORIGIN_POLICY=audit");
    expect(line).toContain("MCP_ALLOWED_ORIGINS: 1 origin(s)");
    expect(loggerMock.error).not.toHaveBeenCalled();
  });

  it("says how many MCP_ALLOWED_ORIGINS entries were ignored", () => {
    vi.stubEnv(
      "MCP_ALLOWED_ORIGINS",
      `${ALLOWED},moz-extension://aaaa,not-an-origin, ,`,
    );

    logOriginPolicyBootState();

    expect(String(loggerMock.info.mock.calls[0][0])).toContain(
      "1 origin(s), 2 ignored",
    );
  });

  it("warns for off", () => {
    vi.stubEnv("MCP_ORIGIN_POLICY", "off");

    logOriginPolicyBootState();

    expect(String(loggerMock.warn.mock.calls[0][0])).toContain(
      "MCP_ORIGIN_POLICY=off",
    );
  });

  it("logs an ERROR for an unrecognised value and still runs as audit", () => {
    vi.stubEnv("MCP_ORIGIN_POLICY", "enforced");

    logOriginPolicyBootState();

    expect(loggerMock.error).toHaveBeenCalledTimes(1);
    expect(String(loggerMock.error.mock.calls[0][0])).toContain('"enforced"');
    expect(String(loggerMock.info.mock.calls[0][0])).toContain(
      "MCP_ORIGIN_POLICY=audit",
    );
  });

  it("warns when enforce has no usable APP_URL, because nothing would be trusted", () => {
    vi.stubEnv("MCP_ORIGIN_POLICY", "enforce");
    vi.stubEnv("APP_URL", undefined);

    logOriginPolicyBootState();

    expect(String(loggerMock.info.mock.calls[0][0])).toContain(
      "MCP_ORIGIN_POLICY=enforce",
    );
    expect(String(loggerMock.warn.mock.calls[0][0])).toContain("APP_URL");
  });

  it("does not warn about APP_URL when enforce has one", () => {
    vi.stubEnv("MCP_ORIGIN_POLICY", "enforce");

    logOriginPolicyBootState();

    expect(loggerMock.warn).not.toHaveBeenCalled();
  });
});

/**
 * The boot line is worth nothing if the boot never prints it. `index.ts` starts
 * the server at import, so the wiring is pinned against its source, the
 * technique `stdio-policy.test.ts` uses.
 */
describe("boot wiring", () => {
  const INDEX = readFileSync(
    path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../index.ts"),
    "utf8",
  );

  it("index.ts calls logOriginPolicyBootState() before the server listens", () => {
    const call = INDEX.indexOf("\n  logOriginPolicyBootState();");
    const listen = INDEX.indexOf("app.listen(12009");

    expect(INDEX).toContain(
      'import { logOriginPolicyBootState } from "./lib/origin-policy";',
    );
    expect(call).toBeGreaterThan(-1);
    expect(listen).toBeGreaterThan(call);
  });
});
