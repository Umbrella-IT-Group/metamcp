/**
 * Log hygiene: the age-based session cleanup used to join every expired
 * session id into a single info line, re-leaking the ids the round-1 payload
 * sweep stripped from the HTTP responses. The count belongs at info; the ids
 * drop to debug. Dormant in production (session lifetime is null there), but the
 * timer fires the moment an operator sets a finite lifetime.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const { getSessionLifetimeMock } = vi.hoisted(() => ({
  getSessionLifetimeMock: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// config.service reaches @/db transitively; the manager's TTL path is the one
// under test, so drive getSessionLifetime directly.
vi.mock("@/db", () => ({ db: {}, pool: { on: vi.fn() } }));
vi.mock("./config.service", () => ({
  configService: { getSessionLifetime: getSessionLifetimeMock },
}));

import logger from "@/utils/logger";

import { SessionLifetimeManagerImpl } from "./session-lifetime-manager";

const BINDING = {
  namespaceUuid: "ns-A",
  endpointName: "ep-A",
  identity: { method: "api_key", credentialId: "key-A" },
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("SessionLifetimeManagerImpl.cleanupExpiredSessions -- session ids stay out of the info log", () => {
  it("logs a COUNT at info and the ids only at debug", async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
      getSessionLifetimeMock.mockResolvedValue(1000);

      const mgr = new SessionLifetimeManagerImpl<{ id: string }>("Streamable");
      mgr.addSession("sess-secret-aaa", { id: "a" }, BINDING as never);
      mgr.addSession("sess-secret-bbb", { id: "b" }, BINDING as never);

      // Advance past the 1s lifetime so both sessions are expired.
      vi.setSystemTime(new Date("2026-01-01T00:00:02Z"));
      const cleaned: string[] = [];
      await mgr.cleanupExpiredSessions(async (id) => {
        cleaned.push(id);
      });

      expect(cleaned.sort()).toEqual(["sess-secret-aaa", "sess-secret-bbb"]);

      const infoLines = vi
        .mocked(logger.info)
        .mock.calls.map((c) => String(c[0]));
      const cleanupLine = infoLines.find((l) =>
        l.includes("expired Streamable sessions"),
      );
      expect(cleanupLine).toBeDefined();
      expect(cleanupLine).toContain("2 expired");
      expect(cleanupLine).not.toContain("sess-secret");

      const debugLines = vi
        .mocked(logger.debug)
        .mock.calls.map((c) => String(c[0]));
      const idLine = debugLines.find((l) =>
        l.includes("Expired Streamable session ids"),
      );
      expect(idLine).toBeDefined();
      expect(idLine).toContain("sess-secret-aaa");
      expect(idLine).toContain("sess-secret-bbb");
    } finally {
      vi.useRealTimers();
    }
  });
});
