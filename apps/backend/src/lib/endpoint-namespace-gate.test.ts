/**
 * The endpoint namespace gate's judgement, without a database
 * (lib/endpoint-namespace-gate): the full truth table for create, move and
 * opening an endpoint, for a person's session and an admin-plane key, with
 * every "never refused" row as a negative control. The locks, the locked
 * re-read and the writers that call these are pinned against Postgres in
 * trpc/admin-plane-rails.integration.test.ts.
 */
import { describe, expect, it } from "vitest";

import {
  ENDPOINT_GATE_REFUSALS,
  judgeEndpointCreate,
  judgeEndpointMove,
  judgeEndpointUnrestrict,
} from "./endpoint-namespace-gate";

const create = (over: Partial<Parameters<typeof judgeEndpointCreate>[0]>) =>
  judgeEndpointCreate({
    restricted: false,
    isPublic: true,
    adminPlane: false,
    restrictedSibling: false,
    gatedSibling: false,
    ...over,
  });
const move = (over: Partial<Parameters<typeof judgeEndpointMove>[0]>) =>
  judgeEndpointMove({
    restricted: false,
    isPublic: true,
    adminPlane: false,
    restrictedSibling: false,
    gatedSibling: false,
    ...over,
  });
const open = (over: Partial<Parameters<typeof judgeEndpointUnrestrict>[0]>) =>
  judgeEndpointUnrestrict({
    adminPlane: false,
    restrictedSibling: false,
    rollbackEligible: false,
    ...over,
  });

describe("create", () => {
  it.each([false, true])(
    "refuses an unrestricted endpoint over a namespace with a restricted one, for any writer (admin-plane %s)",
    (adminPlane) => {
      expect(
        create({ restrictedSibling: true, gatedSibling: true, adminPlane }),
      ).toBe("namespace_restricted_create_open");
    },
  );

  it("counts a private endpoint as a route like a public one", () => {
    expect(
      create({ isPublic: false, restrictedSibling: true, gatedSibling: true }),
    ).toBe("namespace_restricted_create_open");
  });

  it.each([false, true])(
    "allows a restricted endpoint over such a namespace (admin-plane %s)",
    (adminPlane) => {
      expect(
        create({
          restricted: true,
          restrictedSibling: true,
          gatedSibling: true,
          adminPlane,
        }),
      ).toBeNull();
    },
  );

  it("allows an open endpoint over a namespace nothing restricts", () => {
    expect(create({})).toBeNull();
    expect(create({ adminPlane: true })).toBeNull();
  });

  it("keeps the admin-plane publish rule: a public open endpoint over a namespace a private endpoint serves", () => {
    expect(create({ adminPlane: true, gatedSibling: true })).toBe(
      "admin_plane_publish",
    );
    // Not for a person, and not for a private or restricted new endpoint.
    expect(create({ gatedSibling: true })).toBeNull();
    expect(
      create({ adminPlane: true, gatedSibling: true, isPublic: false }),
    ).toBeNull();
    expect(
      create({ adminPlane: true, gatedSibling: true, restricted: true }),
    ).toBeNull();
  });
});

describe("move", () => {
  it.each([
    [false, false],
    [true, false],
    [false, true],
    [true, true],
  ])(
    "refuses moving any endpoint onto a namespace a restricted endpoint guards (restricted %s, admin-plane %s)",
    (restricted, adminPlane) => {
      expect(move({ restricted, adminPlane, restrictedSibling: true })).toBe(
        "namespace_restricted_move",
      );
    },
  );

  it("allows a move onto a namespace nothing restricts", () => {
    expect(move({})).toBeNull();
    expect(move({ restricted: true, adminPlane: true })).toBeNull();
  });

  it("keeps the admin-plane publish rule for a public open endpoint", () => {
    expect(move({ adminPlane: true, gatedSibling: true })).toBe(
      "admin_plane_publish",
    );
    expect(move({ gatedSibling: true })).toBeNull();
    expect(
      move({ adminPlane: true, gatedSibling: true, restricted: true }),
    ).toBeNull();
  });
});

describe("opening an endpoint", () => {
  it.each([false, true])(
    "refuses while another endpoint over the namespace stays restricted (admin-plane %s)",
    (adminPlane) => {
      expect(
        open({ adminPlane, restrictedSibling: true, rollbackEligible: true }),
      ).toBe("namespace_restricted_unrestrict");
    },
  );

  it("lets a person open the last restricted endpoint over a namespace", () => {
    expect(open({})).toBeNull();
  });

  it("lets an admin-plane key open it only to roll back its own current restriction", () => {
    expect(open({ adminPlane: true, rollbackEligible: true })).toBeNull();
    expect(open({ adminPlane: true, rollbackEligible: false })).toBe(
      "admin_plane_unrestrict",
    );
  });
});

describe("the refusals", () => {
  it("are coded, fixed and name nothing", () => {
    for (const [rule, refusal] of Object.entries(ENDPOINT_GATE_REFUSALS)) {
      expect(["CONFLICT", "FORBIDDEN"]).toContain(refusal.code);
      expect(refusal.message.length).toBeGreaterThan(20);
      // No em or en dash in a sentence a caller reads.
      expect({ rule, dash: /[\u2013\u2014]/.test(refusal.message) }).toEqual({
        rule,
        dash: false,
      });
    }
    expect(ENDPOINT_GATE_REFUSALS.admin_plane_unrestrict.code).toBe(
      "FORBIDDEN",
    );
    // A different sentence from the scope refusal, so tooling never reads it
    // as "this procedure is not available".
    expect(ENDPOINT_GATE_REFUSALS.admin_plane_unrestrict.message).not.toBe(
      "This procedure is not available to an admin-plane API key.",
    );
  });
});
