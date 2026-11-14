/**
 * The Inspector session registry (inspector-sessions.ts): which signed-in user
 * opened each Inspector session, which server row it was opened from, and the
 * pending opens a row change has to reach.
 *
 * The registry is module state shared by the two Inspector routers and the
 * server mutations, so every case here uses session ids and row uuids of its
 * own and leaves nothing bound behind it.
 */
import type express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { loggerMock } = vi.hoisted(() => ({
  loggerMock: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));
vi.mock("@/utils/logger", () => ({ default: loggerMock }));

import {
  beginInspectorOpen,
  bindInspectorSession,
  callerUserId,
  closeInspectorSessionsForServer,
  finishInspectorOpen,
  forgetInspectorSession,
  inspectorOpensPending,
  inspectorSessionBelongsToCaller,
  isInspectorOpenUsable,
} from "./inspector-sessions";

/** A request carrying the session user `betterAuthMcpMiddleware` would set. */
const as = (user: unknown) => ({ user }) as unknown as express.Request;
const USER_A = as({ id: "user-a", role: "admin" });
const USER_B = as({ id: "user-b", role: "admin" });

let counter = 0;
/** A session id and two row uuids no other case uses. */
const fresh = () => {
  counter += 1;
  return {
    session: `session-${counter}`,
    rowA: `row-a-${counter}`,
    rowB: `row-b-${counter}`,
  };
};

/** Every id this case bound, forgotten after it so no case sees another's. */
const bound: string[] = [];
const bind = (
  sessionId: string,
  req: express.Request,
  close: () => unknown,
  serverUuid?: string,
  openToken?: ReturnType<typeof beginInspectorOpen>,
) => {
  bound.push(sessionId);
  return bindInspectorSession(sessionId, req, close, serverUuid, openToken);
};

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  for (const sessionId of bound.splice(0)) forgetInspectorSession(sessionId);
});

describe("callerUserId", () => {
  it("is the signed-in user's id when it is a non-empty string", () => {
    expect(callerUserId(USER_A)).toBe("user-a");
  });

  it.each([
    ["no user", undefined],
    ["a user with no id", { role: "admin" }],
    ["an empty id", { id: "" }],
    ["a numeric id", { id: 7 }],
    ["an object id", { id: { toString: () => "user-a" } }],
  ])("is undefined for %s", (_label, user) => {
    expect(callerUserId(as(user))).toBeUndefined();
  });
});

describe("session ownership", () => {
  it("a session belongs to the user who opened it and to nobody else", () => {
    const { session } = fresh();
    expect(bind(session, USER_A, vi.fn())).toBe(true);

    expect(inspectorSessionBelongsToCaller(session, USER_A)).toBe(true);
    expect(inspectorSessionBelongsToCaller(session, as({ id: "user-a" }))).toBe(
      true,
    );
    expect(inspectorSessionBelongsToCaller(session, USER_B)).toBe(false);
  });

  it.each([
    ["no user", undefined],
    ["an empty id", { id: "" }],
    ["a numeric id", { id: 7 }],
  ])("a request with %s owns no session", (_label, user) => {
    const { session } = fresh();
    bind(session, USER_A, vi.fn());

    expect(inspectorSessionBelongsToCaller(session, as(user))).toBe(false);
  });

  it.each([
    ["an id nobody was given", "never-issued"],
    ["an empty id", ""],
    ["a number", 7],
    ["an array", ["session"]],
    ["undefined", undefined],
  ])("%s belongs to nobody", (_label, sessionId) => {
    expect(inspectorSessionBelongsToCaller(sessionId, USER_A)).toBe(false);
  });

  it.each([
    ["no user", undefined],
    ["an empty id", { id: "" }],
    ["a numeric id", { id: 7 }],
  ])("binding with %s registers nothing", async (_label, user) => {
    const { session, rowA } = fresh();
    const close = vi.fn();

    expect(bind(session, as(user), close, rowA)).toBe(false);

    expect(inspectorSessionBelongsToCaller(session, as(user))).toBe(false);
    expect(inspectorSessionBelongsToCaller(session, USER_A)).toBe(false);
    expect(await closeInspectorSessionsForServer(rowA)).toBe(0);
    expect(close).not.toHaveBeenCalled();
  });

  it("a forgotten session belongs to nobody, its opener included", () => {
    const { session } = fresh();
    bind(session, USER_A, vi.fn());

    forgetInspectorSession(session);

    expect(inspectorSessionBelongsToCaller(session, USER_A)).toBe(false);
  });

  it("a fresh login of the same account keeps the session; another account does not", () => {
    // The owner is the account id, not a login session or a cookie.
    const { session } = fresh();
    bind(
      session,
      as({ id: "user-a", role: "admin", sessionId: "login-1" }),
      vi.fn(),
    );

    expect(
      inspectorSessionBelongsToCaller(
        session,
        as({ id: "user-a", role: "admin", sessionId: "login-2" }),
      ),
    ).toBe(true);
    expect(
      inspectorSessionBelongsToCaller(
        session,
        as({ id: "user-b", role: "admin", sessionId: "login-1" }),
      ),
    ).toBe(false);
  });
});

describe("closeInspectorSessionsForServer", () => {
  it("closes every session of that row, and none of another row or of no row", async () => {
    const { session, rowA, rowB } = fresh();
    const closeA1 = vi.fn();
    const closeA2 = vi.fn();
    const closeB = vi.fn();
    const closeNoRow = vi.fn();
    bind(`${session}-a1`, USER_A, closeA1, rowA);
    bind(`${session}-a2`, USER_B, closeA2, rowA);
    bind(`${session}-b`, USER_A, closeB, rowB);
    bind(`${session}-none`, USER_A, closeNoRow);

    expect(await closeInspectorSessionsForServer(rowA)).toBe(2);

    expect(closeA1).toHaveBeenCalledTimes(1);
    expect(closeA2).toHaveBeenCalledTimes(1);
    expect(closeB).not.toHaveBeenCalled();
    expect(closeNoRow).not.toHaveBeenCalled();
    expect(inspectorSessionBelongsToCaller(`${session}-a1`, USER_A)).toBe(
      false,
    );
    expect(inspectorSessionBelongsToCaller(`${session}-a2`, USER_B)).toBe(
      false,
    );
    expect(inspectorSessionBelongsToCaller(`${session}-b`, USER_A)).toBe(true);
    expect(inspectorSessionBelongsToCaller(`${session}-none`, USER_A)).toBe(
      true,
    );
  });

  it("repeated and overlapping closes run each close once", async () => {
    const { session, rowA } = fresh();
    let release: () => void = () => {};
    const slow = new Promise<void>((resolve) => {
      release = resolve;
    });
    const close1 = vi.fn(() => slow);
    const close2 = vi.fn(() => slow);
    bind(`${session}-1`, USER_A, close1, rowA);
    bind(`${session}-2`, USER_A, close2, rowA);

    const first = closeInspectorSessionsForServer(rowA);
    const second = closeInspectorSessionsForServer(rowA);
    release();

    expect(await first).toBe(2);
    expect(await second).toBe(0);
    expect(await closeInspectorSessionsForServer(rowA)).toBe(0);
    expect(close1).toHaveBeenCalledTimes(1);
    expect(close2).toHaveBeenCalledTimes(1);
  });

  it("a close that re-enters the registry is not run twice", async () => {
    const { session, rowA } = fresh();
    const close = vi.fn(async () => {
      forgetInspectorSession(session);
      await closeInspectorSessionsForServer(rowA);
    });
    bind(session, USER_A, close, rowA);

    expect(await closeInspectorSessionsForServer(rowA)).toBe(1);
    expect(close).toHaveBeenCalledTimes(1);
  });

  it("a close that throws or rejects detaches every entry, runs the others and does not throw", async () => {
    const { session, rowA } = fresh();
    const detail = `https://vendor.example.test/mcp?token=${session}`;
    const throwing = vi.fn(() => {
      throw new Error(`close failed for ${detail}`);
    });
    const rejecting = vi.fn(async () => {
      throw new Error(`close rejected for ${detail}`);
    });
    const fine = vi.fn(async () => undefined);
    bind(`${session}-throws`, USER_A, throwing, rowA);
    bind(`${session}-rejects`, USER_A, rejecting, rowA);
    bind(`${session}-fine`, USER_A, fine, rowA);

    await expect(closeInspectorSessionsForServer(rowA)).resolves.toBe(3);

    expect(throwing).toHaveBeenCalledTimes(1);
    expect(rejecting).toHaveBeenCalledTimes(1);
    expect(fine).toHaveBeenCalledTimes(1);
    for (const suffix of ["throws", "rejects", "fine"]) {
      expect(
        inspectorSessionBelongsToCaller(`${session}-${suffix}`, USER_A),
      ).toBe(false);
    }
    expect(await closeInspectorSessionsForServer(rowA)).toBe(0);

    // Two failures, each logged with a fixed label and the error class only.
    expect(loggerMock.error).toHaveBeenCalledTimes(2);
    const logged = JSON.stringify(loggerMock.error.mock.calls);
    expect(logged).not.toContain(session);
    expect(logged).not.toContain("vendor.example.test");
    expect(logged).not.toContain("close failed");
    expect(logged).not.toContain("close rejected");
  });

  it("returns 0 and touches nothing for a row with no sessions", async () => {
    const { session, rowA, rowB } = fresh();
    const close = vi.fn();
    bind(session, USER_A, close, rowB);

    expect(await closeInspectorSessionsForServer(rowA)).toBe(0);
    expect(close).not.toHaveBeenCalled();
  });
});

describe("pending opens", () => {
  it("a row change marks a pending open even when no session is bound yet", async () => {
    const { session, rowA, rowB } = fresh();
    const open = beginInspectorOpen();
    try {
      expect(await closeInspectorSessionsForServer(rowA)).toBe(0);

      expect(isInspectorOpenUsable(open, rowA)).toBe(false);
      expect(isInspectorOpenUsable(open, rowB)).toBe(true);
      const close = vi.fn();
      expect(bind(session, USER_A, close, rowA, open)).toBe(false);
      expect(inspectorSessionBelongsToCaller(session, USER_A)).toBe(false);
      expect(close).not.toHaveBeenCalled();
    } finally {
      finishInspectorOpen(open);
    }
  });

  it("a change to another row leaves the open usable (control)", async () => {
    const { session, rowA, rowB } = fresh();
    const open = beginInspectorOpen();
    try {
      await closeInspectorSessionsForServer(rowB);

      expect(bind(session, USER_A, vi.fn(), rowA, open)).toBe(true);
      expect(inspectorSessionBelongsToCaller(session, USER_A)).toBe(true);
    } finally {
      finishInspectorOpen(open);
    }
  });

  it("an open with no row is not refused by a row change", async () => {
    const { session, rowA } = fresh();
    const open = beginInspectorOpen();
    try {
      await closeInspectorSessionsForServer(rowA);

      expect(bind(session, USER_A, vi.fn(), undefined, open)).toBe(true);
    } finally {
      finishInspectorOpen(open);
    }
  });

  it("an open begun after the row change is not affected by it", async () => {
    const { session, rowA } = fresh();
    await closeInspectorSessionsForServer(rowA);
    const open = beginInspectorOpen();
    try {
      expect(bind(session, USER_A, vi.fn(), rowA, open)).toBe(true);
    } finally {
      finishInspectorOpen(open);
    }
  });

  it("a released open cannot register a session", () => {
    const { session, rowA } = fresh();
    const open = beginInspectorOpen();
    finishInspectorOpen(open);

    expect(isInspectorOpenUsable(open)).toBe(false);
    expect(bind(session, USER_A, vi.fn(), rowA, open)).toBe(false);
    expect(bind(`${session}-no-row`, USER_A, vi.fn(), undefined, open)).toBe(
      false,
    );
    expect(inspectorSessionBelongsToCaller(session, USER_A)).toBe(false);
  });

  it("a pending open is counted until it is released, and releasing twice is harmless", () => {
    const before = inspectorOpensPending();
    const first = beginInspectorOpen();
    const second = beginInspectorOpen();
    expect(inspectorOpensPending()).toBe(before + 2);

    finishInspectorOpen(first);
    finishInspectorOpen(first);
    expect(inspectorOpensPending()).toBe(before + 1);

    finishInspectorOpen(second);
    expect(inspectorOpensPending()).toBe(before);
  });
});
