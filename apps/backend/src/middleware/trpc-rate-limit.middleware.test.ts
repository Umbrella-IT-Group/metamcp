/**
 * The `/trpc` request cap, and specifically the two ways it could be wrong.
 *
 * It could fail to limit — `/trpc` had no limiter at all, and every anonymous
 * `protectedProcedure` call writes an `authn.denied` row to an append-only
 * table, so an unbounded caller is an unbounded writer.
 *
 * Or it could limit the wrong thing, which is the worse failure and the one
 * this file exists for. Keying on `req.ip` would put every caller in ONE
 * bucket, because this fork deliberately leaves express `trust proxy` unset
 * and the backend sits behind an in-container rewrite — the first busy admin
 * would then lock out the whole organisation. The keying assertions below are
 * the regression guard for that.
 *
 * Or it could be written, exported and never MOUNTED, in which case every
 * assertion here still passes while nothing is limited at all. The last
 * describe reads `routers/trpc.ts` to close that.
 */

import { readFileSync } from "node:fs";
import path from "node:path";

import express from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AuthRateLimiter } from "@/lib/auth-rate-limiter";

const { loggerMock } = vi.hoisted(() => ({
  loggerMock: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

// Imported dynamically, as in the other audit suites, so the logger mock above
// is in place before the module under test resolves its own import of it.
const {
  createTrpcRateLimitMiddleware,
  resetTrpcRefusalReportingForTesting,
  TRPC_RATE_LIMIT_MAX,
  TRPC_RATE_LIMIT_WINDOW_MS,
} = await import("./trpc-rate-limit.middleware");

/** A caller as the middleware sees it: only `auditClientIp` is consulted. */
function request(fields: {
  auditClientIp?: string;
  ip?: string;
}): express.Request {
  return {
    ...fields,
    socket: { remoteAddress: "127.0.0.1" },
  } as unknown as express.Request;
}

interface Result {
  passed: boolean;
  statusCode: number | undefined;
  body: unknown;
  headers: Record<string, string>;
}

function call(
  middleware: ReturnType<typeof createTrpcRateLimitMiddleware>,
  req: express.Request,
): Result {
  const result: Result = {
    passed: false,
    statusCode: undefined,
    body: undefined,
    headers: {},
  };
  const res = {
    status(code: number) {
      result.statusCode = code;
      return res;
    },
    json(payload: unknown) {
      result.body = payload;
      return res;
    },
    set(name: string, value: string) {
      result.headers[name] = value;
      return res;
    },
  };
  middleware(req, res as unknown as express.Response, () => {
    result.passed = true;
  });
  return result;
}

beforeEach(() => {
  vi.clearAllMocks();
  // The refusal reporter throttles to one line a minute PROCESS-WIDE, so
  // without this every case after the first would observe silence for the
  // wrong reason and assert nothing.
  resetTrpcRefusalReportingForTesting();
});

describe("trpc rate limit — refusing a flood", () => {
  it("blocks an anonymous flood once the budget is spent", () => {
    // A small injected budget stands in for the real 600; driving 600 real
    // calls would test the loop, not the middleware.
    const middleware = createTrpcRateLimitMiddleware(
      new AuthRateLimiter(3, 60_000),
    );
    const flooder = () => request({ auditClientIp: "203.0.113.7" });

    expect(call(middleware, flooder()).passed).toBe(true);
    expect(call(middleware, flooder()).passed).toBe(true);
    expect(call(middleware, flooder()).passed).toBe(true);

    const refused = call(middleware, flooder());
    expect(refused.passed).toBe(false);
    expect(refused.statusCode).toBe(429);
    expect(refused.body).toMatchObject({ error: "Too many requests" });
  });

  it("tells a well-behaved client when to come back", () => {
    const middleware = createTrpcRateLimitMiddleware(
      new AuthRateLimiter(1, 60_000),
    );
    call(middleware, request({ auditClientIp: "203.0.113.7" }));

    const refused = call(middleware, request({ auditClientIp: "203.0.113.7" }));

    expect(refused.headers["Retry-After"]).toBe("60");
  });

  it("lets the caller back in once the window rolls over", () => {
    vi.useFakeTimers();
    try {
      const middleware = createTrpcRateLimitMiddleware(
        new AuthRateLimiter(1, 60_000),
      );
      const caller = () => request({ auditClientIp: "203.0.113.7" });

      expect(call(middleware, caller()).passed).toBe(true);
      expect(call(middleware, caller()).passed).toBe(false);

      vi.advanceTimersByTime(60_001);

      expect(call(middleware, caller()).passed).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("trpc rate limit — NOT throttling legitimate use", () => {
  /**
   * The failure this guards against is an outage caused by the control meant
   * to prevent one. Both existing identifiers in lib/auth-rate-limiter key on
   * `req.ip`, which behind the in-container rewrite is the same loopback
   * address for every caller — one shared organisation-wide bucket. Reusing
   * that key here would mean one busy admin refusing the whole company.
   */
  it("gives each client IP its own budget, so one caller cannot spend another's", () => {
    const middleware = createTrpcRateLimitMiddleware(
      new AuthRateLimiter(2, 60_000),
    );

    // One caller burns their whole budget.
    call(middleware, request({ auditClientIp: "203.0.113.7" }));
    call(middleware, request({ auditClientIp: "203.0.113.7" }));
    expect(
      call(middleware, request({ auditClientIp: "203.0.113.7" })).passed,
    ).toBe(false);

    // A different admin is unaffected.
    expect(
      call(middleware, request({ auditClientIp: "198.51.100.4" })).passed,
    ).toBe(true);
  });

  it("ignores req.ip entirely — that key is the shared-bucket trap", () => {
    const middleware = createTrpcRateLimitMiddleware(
      new AuthRateLimiter(1, 60_000),
    );

    // Same loopback `req.ip` for both, as production actually presents them;
    // only CF-Connecting-IP differs. If the middleware keyed on req.ip the
    // second call would be refused.
    call(
      middleware,
      request({ auditClientIp: "203.0.113.7", ip: "127.0.0.1" }),
    );

    expect(
      call(
        middleware,
        request({ auditClientIp: "198.51.100.4", ip: "127.0.0.1" }),
      ).passed,
    ).toBe(true);
  });

  it("exempts the no-CF-IP class rather than collapsing it into one bucket", () => {
    // Direct-to-origin and local development have no CF-Connecting-IP. Sharing
    // one "unknown" key would let any one of them refuse all the others —
    // exactly the outage this limiter is keyed to avoid.
    const middleware = createTrpcRateLimitMiddleware(
      new AuthRateLimiter(1, 60_000),
    );

    for (let i = 0; i < 25; i += 1) {
      expect(call(middleware, request({ ip: "127.0.0.1" })).passed).toBe(true);
    }
  });

  it("sets the shipped budget far above a real UI burst", () => {
    // The frontend uses httpBatchLink, so a dashboard's many procedure calls
    // collapse into few HTTP requests. A limiter that trips on normal admin
    // use is a limiter someone deletes.
    const middleware = createTrpcRateLimitMiddleware();
    const admin = () => request({ auditClientIp: "203.0.113.9" });

    for (let i = 0; i < 200; i += 1) {
      expect(call(middleware, admin()).passed).toBe(true);
    }
    expect(TRPC_RATE_LIMIT_MAX).toBeGreaterThanOrEqual(600);
    expect(TRPC_RATE_LIMIT_WINDOW_MS).toBe(60_000);
  });
});

/**
 * A refusal nobody can see is indistinguishable from no limiter at all.
 *
 * The 429 path writes no audit row on purpose — a row per refusal on the path
 * whose write volume is being limited moves the amplifier one layer up instead
 * of closing it. That makes the log the only place a flood can surface, so
 * these pin that it does surface, and that it surfaces as one line rather than
 * as the flood itself.
 */
describe("trpc rate limit — a refusal is visible to an operator", () => {
  it("says nothing while requests are being served", () => {
    const middleware = createTrpcRateLimitMiddleware(
      new AuthRateLimiter(2, 60_000),
    );

    call(middleware, request({ auditClientIp: "203.0.113.7" }));
    call(middleware, request({ auditClientIp: "203.0.113.7" }));

    expect(loggerMock.warn).not.toHaveBeenCalled();
  });

  it("warns on the FIRST refusal, naming the caller and the count", () => {
    const middleware = createTrpcRateLimitMiddleware(
      new AuthRateLimiter(1, 60_000),
    );
    call(middleware, request({ auditClientIp: "203.0.113.7" }));

    call(middleware, request({ auditClientIp: "203.0.113.7" }));

    // Immediately, not after a window: detection must not wait out the
    // throttle, which is why the first line necessarily reads 1.
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(loggerMock.warn.mock.calls[0]?.[0]).toContain(
      "1 request(s) refused",
    );
    // The IP is what makes the line actionable, and it is quoted because it
    // came out of a header.
    expect(loggerMock.warn.mock.calls[0]?.[0]).toContain('"203.0.113.7"');
    // WARN and nothing louder. A refused request is this control working; an
    // alert that pages on it is an alert someone turns off.
    expect(loggerMock.error).not.toHaveBeenCalled();
    expect(loggerMock.debug).not.toHaveBeenCalled();
  });

  it("throttles a flood to ONE line, then carries the FULL total forward", () => {
    // Only Date is faked; nothing here awaits a timer.
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      // The limiter window is deliberately an hour, far longer than the
      // one-minute report window, so advancing the clock past the report
      // throttle does not also refill the budget and turn the next call into
      // a pass.
      const middleware = createTrpcRateLimitMiddleware(
        new AuthRateLimiter(1, 60 * 60_000),
      );
      const flooder = () => request({ auditClientIp: "203.0.113.7" });
      call(middleware, flooder());

      for (let i = 0; i < 50; i += 1) {
        expect(call(middleware, flooder()).statusCode).toBe(429);
      }

      // Fifty refusals, one line — a flood that logs per refusal buries its
      // own cause.
      expect(loggerMock.warn).toHaveBeenCalledTimes(1);
      expect(loggerMock.warn.mock.calls[0]?.[0]).toContain(
        "1 request(s) refused",
      );

      vi.setSystemTime(Date.now() + 61_000);
      call(middleware, flooder());

      expect(loggerMock.warn).toHaveBeenCalledTimes(2);
      // 51, not 1. This is the assertion that pins the counter as a running
      // total: a per-window delta would have stranded the 50 the first line
      // could not carry, and stranded loss is silent loss.
      expect(loggerMock.warn.mock.calls[1]?.[0]).toContain(
        "51 request(s) refused",
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("cannot have a log line forged through the IP it names", () => {
    // `auditClientIp` is a header value. Interpolated raw, an embedded newline
    // writes whole log entries of the attacker's choosing — the same defect
    // this fork already fixed on the mcp-proxy connect line.
    const middleware = createTrpcRateLimitMiddleware(
      new AuthRateLimiter(1, 60_000),
    );
    const forged = "203.0.113.7\n2026-01-01 INFO all clear";
    call(middleware, request({ auditClientIp: forged }));

    call(middleware, request({ auditClientIp: forged }));

    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(loggerMock.warn.mock.calls[0]?.[0]).not.toContain("\n");
  });
});

/**
 * The limiter is MOUNTED, and mounted where the comments say it is.
 *
 * Everything above calls the middleware directly, so `routers/trpc.ts` could
 * drop `trpcRouter.use(trpcRateLimitMiddleware)` — or replace it with a
 * statement that merely references the export — and this whole suite would
 * stay green and the build would stay typecheck-clean while `/trpc` went back
 * to having no limiter at all.
 *
 * Read from SOURCE rather than driven over a socket because mounting the real
 * `routers/trpc.ts` drags the entire procedure tree, every `*.impl` and the MCP
 * server pool into the import graph. Same technique, and the same reason, as
 * the repo-wide `cors()` drift guard at the end of
 * `routers/cors-policy.test.ts`. What it proves is the wiring and its ORDER;
 * the behaviour is proved by the cases above.
 */
describe("trpc rate limit — mounted on the router", () => {
  const TRPC_ROUTER_SOURCE = readFileSync(
    path.resolve(import.meta.dirname, "../routers/trpc.ts"),
    "utf8",
  );

  it("finds the router source it is meant to be guarding", () => {
    // A moved file or a renamed router would otherwise make every assertion
    // below pass without checking anything.
    expect(TRPC_ROUTER_SOURCE).toContain("const trpcRouter = express.Router()");
    expect(TRPC_ROUTER_SOURCE).toContain(
      "middleware/trpc-rate-limit.middleware",
    );
  });

  it("mounts the middleware on the router", () => {
    expect(TRPC_ROUTER_SOURCE).toMatch(
      /trpcRouter\.use\(\s*trpcRateLimitMiddleware\s*\)/,
    );
  });

  it("mounts it after cors and before the tRPC handler", () => {
    const cors = TRPC_ROUTER_SOURCE.indexOf("cors({");
    const limiter = TRPC_ROUTER_SOURCE.search(
      /trpcRouter\.use\(\s*trpcRateLimitMiddleware\s*\)/,
    );
    const handler = TRPC_ROUTER_SOURCE.indexOf("createExpressMiddleware");

    expect(cors).toBeGreaterThan(-1);
    expect(handler).toBeGreaterThan(-1);
    // AFTER cors: the cors package answers and ENDS a preflight itself, so
    // preflights stay out of the budget, and a 429 carries the CORS headers the
    // browser needs to surface it as a 429 rather than an opaque network
    // failure.
    expect(limiter).toBeGreaterThan(cors);
    // BEFORE the handler: a request refused after the tRPC handler has run has
    // already written the audit rows this limiter exists to bound.
    expect(limiter).toBeLessThan(handler);
  });
});
