/**
 * The relay names the path better-auth ROUTED ON, not the one express parsed.
 *
 * `routers/auth-relay` rebuilds every `/api/auth` request as a web `Request`
 * with `new URL(req.url, ...)` and hands that to `auth.handler`. The WHATWG
 * parser behind that constructor resolves dot segments — percent-encoded ones
 * included — and reads a backslash as a slash. Express's `req.path` does
 * neither. So the two disagree on exactly the inputs an attacker chooses, and
 * `lib/audit/auth-relay-audit` compares its path EXACTLY: pass it `req.path`
 * and every respelling of `sign-in/email` is judged by better-auth and
 * recorded nowhere.
 *
 * That silence is the failure this file exists to prevent. `auth.login.failure`
 * is the one event in the auth plane with no database-hook equivalent — a
 * refused sign-in mints no session, so nothing else in the app notices it —
 * which makes it the whole credential-stuffing and account-enumeration signal.
 * `auth.login.success` through the same spelling is worse still: an
 * authenticated session with no row saying who opened it.
 *
 * WHY RAW SOCKET WRITES. `fetch` resolves dot segments in the client before a
 * byte goes out, so a test that used it would send the canonical path and pass
 * against the broken code. The request line has to be written verbatim for the
 * server to see the spelling under test at all.
 *
 * Companion to `middleware/auth-signin-rate-limit.middleware.test.ts`, which
 * pins the same respellings against the LIMITER. Both halves are needed: one
 * bounds the attempts, this one records them.
 */

import http from "node:http";
import net from "node:net";

import express from "express";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

const { loggerMock, authHandler } = vi.hoisted(() => ({
  loggerMock: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
  authHandler: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));
vi.mock("../auth", () => ({ auth: { handler: authHandler } }));

const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");
const { authApiRelay } = await import("./auth-relay");

const CANONICAL = "/api/auth/sign-in/email";
const ATTEMPTED_EMAIL = "victim@example.invalid";

/**
 * Every spelling here is one the relay RESOLVES to the credential path, which
 * is why recording it is not over-matching: better-auth checked a password in
 * each case. Each assertion below proves that resolution rather than assuming
 * it, so a future better-auth or Node change that stopped resolving one of
 * these would fail loudly instead of leaving a test that guards nothing.
 *
 * The EMPTY-SEGMENT entries are here because `..` consumes an empty segment
 * exactly as it consumes a named one. Any normaliser downstream of this that
 * squeezes `//` to `/` before resolving loses that segment and stops agreeing
 * with the relay, so the spelling has to be pinned on both sides.
 */
const RESPELLINGS = [
  "/api/auth/x/../sign-in/email",
  "/api/auth/./sign-in/email",
  "/api/auth/x/%2e%2e/sign-in/email",
  "/api/auth/x/%2E%2E/sign-in/email",
  "/api/auth/x/y/../../sign-in/email",
  "/api/auth\\sign-in/email",
  "/api/auth//../sign-in/email",
  "/api/auth//%2e%2e/sign-in/email",
];

type AuditRow = {
  action: string;
  outcome: string;
  actor_label?: string | null;
  http_status?: number | null;
};

let rows: AuditRow[];
let server: http.Server;
let port: number;

/** Drain the detached promise chain `emit()` schedules. */
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

/**
 * One request whose path is written to the socket verbatim — see WHY RAW
 * SOCKET WRITES above. Resolves once the server has closed the connection,
 * so the relay has already emitted by the time the caller flushes.
 */
function rawSignInAttempt(rawPath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1", () => {
      const body = JSON.stringify({
        email: ATTEMPTED_EMAIL,
        password: "hunter2-do-not-log-me",
      });
      socket.write(
        `POST ${rawPath} HTTP/1.1\r\n` +
          `Host: localhost\r\n` +
          `Content-Type: application/json\r\n` +
          `Content-Length: ${Buffer.byteLength(body)}\r\n` +
          `Connection: close\r\n\r\n${body}`,
      );
    });
    let received = "";
    socket.on("data", (chunk) => (received += chunk.toString()));
    socket.on("end", () => resolve(received));
    socket.on("error", reject);
  });
}

/** The pathname better-auth was routed on for the most recent call. */
function pathHandlerSaw(): string {
  const call = authHandler.mock.calls.at(-1);
  return new URL((call?.[0] as Request).url).pathname;
}

beforeAll(async () => {
  const app = express();
  // The relay reads `req.body` for the attempted address; in the real server
  // `lib/global-body-parser` has already run by this point.
  app.use(express.json());
  app.use(authApiRelay);

  server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = (server.address() as net.AddressInfo).port;
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
});

beforeEach(() => {
  vi.clearAllMocks();
  rows = [];
  setAuditSinkForTesting(async (event) => {
    rows.push(event as AuditRow);
  });
  authHandler.mockImplementation(
    async () =>
      new Response(JSON.stringify({ message: "Invalid email or password" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      }),
  );
});

afterEach(() => {
  setAuditSinkForTesting(undefined);
});

describe("auth relay audit — the path the emitter is given", () => {
  it("records the canonical credential path", async () => {
    await rawSignInAttempt(CANONICAL);
    await flush();

    expect(pathHandlerSaw()).toBe(CANONICAL);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "auth.login.failure",
      outcome: "failure",
      actor_label: ATTEMPTED_EMAIL,
      http_status: 401,
    });
  });

  it.each(RESPELLINGS)(
    "records a failed attempt spelled %s, which the relay resolves",
    async (spelling) => {
      await rawSignInAttempt(spelling);
      await flush();

      // First: this spelling really does reach better-auth as the credential
      // path. Without this the next assertion could pass for the wrong reason.
      expect(pathHandlerSaw()).toBe(CANONICAL);

      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        action: "auth.login.failure",
        outcome: "failure",
        actor_label: ATTEMPTED_EMAIL,
        http_status: 401,
      });
    },
  );

  it("records a SUCCESSFUL sign-in through a respelled path", async () => {
    // The worst case of the two: a session opened with nothing saying who
    // opened it. `databaseHooks.session.create.after` catches the session, but
    // only this row carries the HTTP verdict and the caller attribution.
    authHandler.mockImplementation(
      async () =>
        new Response(
          JSON.stringify({
            redirect: false,
            token: "st_super_secret_session_token_value",
            user: { id: "user-42", email: "person@example.invalid" },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    );

    await rawSignInAttempt("/api/auth/x/../sign-in/email");
    await flush();

    expect(pathHandlerSaw()).toBe(CANONICAL);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "auth.login.success",
      outcome: "success",
      http_status: 200,
    });
    // The success body carries the SESSION TOKEN; it must not reach the table.
    expect(JSON.stringify(rows)).not.toContain(
      "st_super_secret_session_token_value",
    );
  });

  it("still writes nothing for an /api/auth path that is not a credential verdict", async () => {
    // The resolution must not become a licence to over-match: `get-session`
    // carries no password, and a row per session read would bury the signal in
    // a table that cannot be pruned.
    await rawSignInAttempt("/api/auth/x/../get-session");
    await flush();

    expect(pathHandlerSaw()).toBe("/api/auth/get-session");
    expect(rows).toHaveLength(0);
  });
});
