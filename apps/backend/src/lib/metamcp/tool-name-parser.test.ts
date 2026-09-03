/**
 * Tool name parsing and the cross-server routing-collision guard.
 *
 * The routing maps in the proxy are keyed on the fully-qualified tool name, and
 * before the guard a second server producing a name already owned by a
 * DIFFERENT server would overwrite the route last-writer-wins, silently sending
 * a call to the wrong backend. `registerToolRoute` is the pure decision behind
 * the guard; these pin that a same-name-different-server pair is a collision
 * (the duplicate is dropped, the first owner kept) while a re-list of the same
 * server is not.
 */
import { describe, expect, it } from "vitest";

import {
  parseToolName,
  registerToolRoute,
  ToolRouteOwner,
} from "./tool-name-parser";

describe("parseToolName", () => {
  it("splits on the first double underscore", () => {
    expect(parseToolName("Server__tool")).toEqual({
      serverName: "Server",
      originalToolName: "tool",
    });
  });

  it("keeps nested prefixes in the forwarded tool name", () => {
    expect(parseToolName("Parent__Child__my_tool")).toEqual({
      serverName: "Parent",
      originalToolName: "Child__my_tool",
    });
  });

  it("returns null when there is no separator", () => {
    expect(parseToolName("noseparator")).toBeNull();
  });
});

describe("registerToolRoute: cross-server collision guard", () => {
  it("registers a tool name the first time it is seen", () => {
    const owners = new Map<string, ToolRouteOwner>();
    const outcome = registerToolRoute(
      "Srv__tool",
      { uuid: "uuid-a", name: "Srv" },
      owners,
    );
    expect(outcome.registered).toBe(true);
    expect(owners.get("Srv__tool")).toEqual({ uuid: "uuid-a", name: "Srv" });
  });

  it("reports a collision when a DIFFERENT server produces the same name", () => {
    const owners = new Map<string, ToolRouteOwner>();
    registerToolRoute("Srv__tool", { uuid: "uuid-a", name: "Srv" }, owners);

    // "Srv " and "Srv" both sanitize to "Srv", so this second server collides.
    const outcome = registerToolRoute(
      "Srv__tool",
      { uuid: "uuid-b", name: "Srv " },
      owners,
    );

    expect(outcome.registered).toBe(false);
    expect(outcome.collidedWith).toEqual({ uuid: "uuid-a", name: "Srv" });
    // The first owner is kept; the duplicate never overwrites the route.
    expect(owners.get("Srv__tool")).toEqual({ uuid: "uuid-a", name: "Srv" });
  });

  it("does not treat a re-list of the SAME server as a collision", () => {
    const owners = new Map<string, ToolRouteOwner>();
    registerToolRoute("Srv__tool", { uuid: "uuid-a", name: "Srv" }, owners);

    const outcome = registerToolRoute(
      "Srv__tool",
      { uuid: "uuid-a", name: "Srv" },
      owners,
    );

    expect(outcome.registered).toBe(true);
    expect(outcome.collidedWith).toBeUndefined();
  });

  it("does not collide two different tool names from the same server", () => {
    const owners = new Map<string, ToolRouteOwner>();
    const a = registerToolRoute(
      "Srv__toolA",
      { uuid: "uuid-a", name: "Srv" },
      owners,
    );
    const b = registerToolRoute(
      "Srv__toolB",
      { uuid: "uuid-a", name: "Srv" },
      owners,
    );
    expect(a.registered).toBe(true);
    expect(b.registered).toBe(true);
    expect(owners.size).toBe(2);
  });
});
