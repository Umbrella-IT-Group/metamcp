/**
 * The history view's pagination, tested where it is testable.
 *
 * The component around these functions is React state plumbing; the decisions
 * that can be silently wrong live here. A cursor read from the wrong source
 * either strands the "load older" button on a list that has more rows, or
 * offers it on a list that does not — and the failure looks like a complete
 * result either way.
 */

import type { GatewayEvent, GatewayEventCursor } from "@repo/zod-types";
import { describe, expect, it } from "vitest";

import { activeCursor, joinPages } from "./gateway-event-paging";

const cursor = (uuid: string): GatewayEventCursor => ({
  occurredAt: "2026-08-17T12:00:00.000Z",
  uuid,
});

const event = (uuid: string): GatewayEvent => ({
  uuid,
  occurredAt: "2026-08-17T12:00:00.000Z",
  category: "connection",
  level: "warn",
  serverUuid: null,
  serverName: "example-backend",
  clientName: null,
  sessionId: null,
  message: `event ${uuid}`,
  metadata: null,
});

describe("activeCursor", () => {
  it("follows the first page while nothing has been paged in", () => {
    expect(activeCursor(cursor("first"), null, 0)).toEqual(cursor("first"));
  });

  it("follows the last fetched page once paging has started", () => {
    // The first page's cursor is stale the moment a second page exists, and a
    // background refetch keeps refreshing it — reading it here would hand
    // "load older" a cursor pointing back into rows already on screen.
    expect(activeCursor(cursor("first"), cursor("third"), 2)).toEqual(
      cursor("third"),
    );
  });

  it("ends the run when the last fetched page had no successor", () => {
    expect(activeCursor(cursor("first"), null, 2)).toBeNull();
  });

  it("treats an absent first-page cursor as the end", () => {
    expect(activeCursor(undefined, null, 0)).toBeNull();
    expect(activeCursor(null, null, 0)).toBeNull();
  });
});

describe("joinPages", () => {
  it("keeps the first page ahead of everything loaded after it", () => {
    const joined = joinPages(
      [event("a"), event("b")],
      [[event("c")], [event("d"), event("e")]],
    );

    expect(joined.map((e) => e.uuid)).toEqual(["a", "b", "c", "d", "e"]);
  });

  it("survives a first page that has not arrived yet", () => {
    expect(joinPages(undefined, [])).toEqual([]);
    expect(joinPages(undefined, [[event("a")]]).map((e) => e.uuid)).toEqual([
      "a",
    ]);
  });
});
