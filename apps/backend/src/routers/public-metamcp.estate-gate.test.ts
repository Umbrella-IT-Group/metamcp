/**
 * `GET /metamcp/` — the unauthenticated estate listing.
 *
 * The handler returned every endpoint's name, description, namespace and all
 * four URL forms (mcp / sse / api / openapi.json) to any caller who could
 * reach the host: a directory of the whole integration estate, and a ready
 * target list for the auth-gated MCP legs. It is the same topology disclosure
 * `/health/upstream` was gated for (`servers[]` there), served by a second
 * door. Neither can 401 — probes hit both — so both answer 200 and withhold.
 *
 * These drive the REAL router composition over a real socket, mirroring
 * `mcp-proxy.admin-gate.test.ts`. Mocked seams:
 *  - `../lib/health-upstream`, so an admin/non-admin caller can be simulated
 *    without better-auth or a database. The gate's own fail-closed behavior
 *    is exhaustively tested in `lib/health-upstream.test.ts`; what is under
 *    test here is that this route consults it and withholds when it says no.
 *  - the endpoints repository — asserting it stays UNCALLED for an anonymous
 *    request is half the point: the gate runs before the query, so the public
 *    path no longer reaches postgres at all.
 *  - the four sub-routers, replaced by empty routers, so importing this
 *    module does not drag in the MCP transports, the pool, or `@/db`.
 */
import type { Server } from "node:http";

import express from "express";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

const h = vi.hoisted(() => ({
  isAdminHealthRequest: vi.fn<() => Promise<boolean>>(),
  findAllWithNamespaces: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({
  default: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock("../lib/health-upstream", () => ({
  isAdminHealthRequest: h.isAdminHealthRequest,
}));

vi.mock("../db/repositories/endpoints.repo", () => ({
  endpointsRepository: { findAllWithNamespaces: h.findAllWithNamespaces },
}));

// Empty stand-ins: `publicEndpointsRouter.use()`s them ahead of the "/" route,
// and an empty router just falls through to it.
vi.mock("./public-metamcp/openapi", async () => ({
  openApiRouter: (await import("express")).Router(),
}));
vi.mock("./public-metamcp/admin", async () => ({
  default: (await import("express")).Router(),
}));
vi.mock("./public-metamcp/sse", async () => ({
  default: (await import("express")).Router(),
}));
vi.mock("./public-metamcp/streamable-http", async () => ({
  default: (await import("express")).Router(),
}));

import publicEndpointsRouter, {
  buildPublicEndpointsBody,
} from "./public-metamcp";

/** Two endpoints in the shape `findAllWithNamespaces` returns. */
const ESTATE = [
  {
    name: "autotask",
    description: "Autotask PSA tools",
    namespace: { name: "umbrella-internal" },
  },
  {
    name: "m365",
    description: null,
    namespace: { name: "umbrella-internal" },
  },
];

/** `Response.json()` is typed `unknown`; every body here is an object. */
const readJson = async (response: Response): Promise<Record<string, unknown>> =>
  (await response.json()) as Record<string, unknown>;

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  const app = express();
  app.use("/metamcp", publicEndpointsRouter);
  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (typeof address === "object" && address) {
    baseUrl = `http://127.0.0.1:${address.port}`;
  }
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
});

beforeEach(() => {
  vi.clearAllMocks();
  h.isAdminHealthRequest.mockResolvedValue(false);
  h.findAllWithNamespaces.mockResolvedValue(ESTATE);
});

describe("GET /metamcp/ — estate listing is admin-only", () => {
  it("gives an anonymous caller the banner and no endpoints key", async () => {
    const response = await fetch(`${baseUrl}/metamcp/`);
    const body = await readJson(response);

    // 200, not 401: a liveness probe on this path must keep working.
    expect(response.status).toBe(200);
    expect(Object.keys(body).sort()).toEqual([
      "description",
      "service",
      "version",
    ]);
    expect(body).not.toHaveProperty("endpoints");
  });

  it("leaks no endpoint name, namespace or URL form to an anonymous caller", async () => {
    const response = await fetch(`${baseUrl}/metamcp/`);
    const serialised = JSON.stringify(await readJson(response));

    for (const secret of [
      "autotask",
      "m365",
      "umbrella-internal",
      "openapi.json",
    ]) {
      expect(serialised).not.toContain(secret);
    }
  });

  it("does not even query the database for an anonymous caller", async () => {
    await fetch(`${baseUrl}/metamcp/`);

    expect(h.isAdminHealthRequest).toHaveBeenCalledTimes(1);
    expect(h.findAllWithNamespaces).not.toHaveBeenCalled();
  });

  it("gives an admin the full listing with all four URL forms", async () => {
    h.isAdminHealthRequest.mockResolvedValue(true);

    const response = await fetch(`${baseUrl}/metamcp/`);
    const body = await readJson(response);

    expect(response.status).toBe(200);
    expect(body.service).toBe("public-endpoints");
    expect(body.endpoints).toEqual([
      {
        name: "autotask",
        description: "Autotask PSA tools",
        namespace: "umbrella-internal",
        endpoints: {
          mcp: "/metamcp/autotask/mcp",
          sse: "/metamcp/autotask/sse",
          api: "/metamcp/autotask/api",
          openapi: "/metamcp/autotask/api/openapi.json",
        },
      },
      {
        name: "m365",
        description: null,
        namespace: "umbrella-internal",
        endpoints: {
          mcp: "/metamcp/m365/mcp",
          sse: "/metamcp/m365/sse",
          api: "/metamcp/m365/api",
          openapi: "/metamcp/m365/api/openapi.json",
        },
      },
    ]);
  });

  it("still answers 500 with a constant when the query fails for an admin", async () => {
    h.isAdminHealthRequest.mockResolvedValue(true);
    h.findAllWithNamespaces.mockRejectedValue(
      new Error('connect ECONNREFUSED postgres-internal:5432 db "metamcp"'),
    );

    const response = await fetch(`${baseUrl}/metamcp/`);
    const body = await readJson(response);

    expect(response.status).toBe(500);
    expect(body).toEqual({
      error: "Internal server error",
      message: "Failed to list endpoints",
    });
    expect(JSON.stringify(body)).not.toContain("postgres-internal");
  });
});

describe("buildPublicEndpointsBody", () => {
  it("omits the endpoints key entirely when the listing is withheld", () => {
    // Additive, not redacted: a field added to the listing later cannot leak
    // by someone forgetting to add it to a delete-list.
    expect(buildPublicEndpointsBody(null)).toEqual({
      service: "public-endpoints",
      version: "1.0.0",
      description: "Public MetaMCP endpoints",
    });
  });

  it("attaches the listing on top of the same banner", () => {
    const listing = [
      {
        name: "autotask",
        description: null,
        namespace: "ns",
        endpoints: {
          mcp: "/metamcp/autotask/mcp",
          sse: "/metamcp/autotask/sse",
          api: "/metamcp/autotask/api",
          openapi: "/metamcp/autotask/api/openapi.json",
        },
      },
    ];

    const body = buildPublicEndpointsBody(listing);

    expect(body.endpoints).toEqual(listing);
    expect(body.service).toBe("public-endpoints");
  });
});
