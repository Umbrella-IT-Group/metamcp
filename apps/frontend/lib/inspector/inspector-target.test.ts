/**
 * Which connection the Inspector page opens is tool-call routing: a wrong
 * namespace is a different set of tools, and a gateway target for a member is
 * a surface the route refuses. These tests pin the resolver, the connection
 * settings, the reconnect key, the tabs and the honest label of an endpoint
 * (a preview of its namespace).
 *
 * Oracles: the route the backend mounts (read from its source below), the
 * page's pre-change mapping for a server (copied verbatim as `legacyOptions`),
 * and the resolver's own contract (exact uuid, admin only).
 */
import { readFileSync } from "node:fs";
import path from "node:path";

import { type McpServer, McpServerTypeEnum } from "@repo/zod-types";
import { describe, expect, it } from "vitest";

import { getTranslation, type Translations } from "@/lib/i18n";
import { buildInspectorConnectionKey } from "@/lib/inspector-connection-key";

import {
  buildInspectorTargetKey,
  describeTarget,
  inspectorConnectionOptions,
  type ResolvableEndpoint,
  type ResolvableNamespace,
  resolveInspectorTarget,
  type TargetLists,
  targetName,
  visibleTabs,
} from "./inspector-target";

const FRONTEND = path.join(__dirname, "..", "..");
const BACKEND_SRC = path.join(FRONTEND, "..", "backend", "src");

const dictionary = {
  inspector: JSON.parse(
    readFileSync(
      path.join(FRONTEND, "public", "locales", "en", "inspector.json"),
      "utf8",
    ),
  ),
} as unknown as Translations;
const t = (key: string, params?: Record<string, string | number>) =>
  getTranslation(dictionary, key, params);

function server(overrides: Partial<McpServer> = {}): McpServer {
  return {
    uuid: "11111111-1111-4111-8111-111111111111",
    name: "alpha",
    description: "first server",
    type: "STDIO",
    command: "npx",
    args: ["-y", "@scope/pkg"],
    env: { TOKEN: "t0" },
    url: null,
    created_at: "2026-10-01T00:00:00.000Z",
    bearerToken: null,
    headers: {},
    user_id: null,
    error_status: "NONE",
    ...overrides,
  };
}

const NS_A: ResolvableNamespace = {
  uuid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  name: "ns-helpdesk",
};
const NS_B: ResolvableNamespace = {
  uuid: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  name: "ns-billing",
};
const EP_1: ResolvableEndpoint = {
  uuid: "e1e1e1e1-e1e1-4e1e-8e1e-e1e1e1e1e1e1",
  name: "helpdesk-public",
  namespace_uuid: NS_A.uuid,
  namespace: { name: NS_A.name },
};
const EP_2: ResolvableEndpoint = {
  uuid: "e2e2e2e2-e2e2-4e2e-8e2e-e2e2e2e2e2e2",
  name: "billing-public",
  namespace_uuid: NS_B.uuid,
  namespace: { name: NS_B.name },
};
const SERVER = server();

const LISTS: TargetLists = {
  servers: [SERVER],
  namespaces: [NS_A, NS_B],
  endpoints: [EP_1, EP_2],
};

describe("resolveInspectorTarget", () => {
  it("resolves each endpoint to its own namespace", () => {
    const first = resolveInspectorTarget({ endpoint: EP_1.uuid }, LISTS, {
      isAdmin: true,
    });
    const second = resolveInspectorTarget({ endpoint: EP_2.uuid }, LISTS, {
      isAdmin: true,
    });
    expect(first).toEqual({
      kind: "endpoint",
      endpointUuid: EP_1.uuid,
      endpointName: EP_1.name,
      namespaceUuid: NS_A.uuid,
      namespaceName: NS_A.name,
    });
    expect(second).toMatchObject({
      kind: "endpoint",
      namespaceUuid: NS_B.uuid,
      namespaceName: NS_B.name,
    });
  });

  it("resolves a namespace and a server by exact uuid", () => {
    expect(
      resolveInspectorTarget({ namespace: NS_B.uuid }, LISTS, {
        isAdmin: true,
      }),
    ).toEqual({
      kind: "namespace",
      namespaceUuid: NS_B.uuid,
      label: NS_B.name,
    });
    expect(
      resolveInspectorTarget({ server: SERVER.uuid }, LISTS, {
        isAdmin: false,
      }),
    ).toEqual({ kind: "server", server: SERVER });
  });

  it("never falls back to another target for a value it cannot find", () => {
    const unknown = [
      "00000000-0000-4000-8000-000000000000",
      // Not an exact match: a different case of a real uuid.
      NS_A.uuid.toUpperCase(),
      // Things a person or a crafted link could put in the parameter.
      "../../mcp-proxy/server/stdio",
      `${NS_A.uuid}/../${NS_B.uuid}`,
      `${NS_A.uuid}?includeInactiveServers=true`,
      "/etc/passwd",
      "__proto__",
      "constructor",
    ];
    for (const value of unknown) {
      for (const param of ["server", "namespace", "endpoint"] as const) {
        expect(
          resolveInspectorTarget({ [param]: value }, LISTS, { isAdmin: true }),
          `${param}=${value}`,
        ).toEqual({ kind: "none" });
      }
    }
  });

  it("is none when no parameter is set", () => {
    expect(resolveInspectorTarget({}, LISTS, { isAdmin: true })).toEqual({
      kind: "none",
    });
    expect(
      resolveInspectorTarget(
        { server: null, namespace: "", endpoint: undefined },
        LISTS,
        { isAdmin: true },
      ),
    ).toEqual({ kind: "none" });
  });

  it("lets only the first parameter present decide: server, then namespace, then endpoint", () => {
    const all = {
      server: SERVER.uuid,
      namespace: NS_A.uuid,
      endpoint: EP_2.uuid,
    };
    expect(resolveInspectorTarget(all, LISTS, { isAdmin: true }).kind).toBe(
      "server",
    );
    expect(
      resolveInspectorTarget(
        { namespace: NS_A.uuid, endpoint: EP_2.uuid },
        LISTS,
        { isAdmin: true },
      ),
    ).toMatchObject({ kind: "namespace", namespaceUuid: NS_A.uuid });

    // A present parameter that does not resolve ends the search: the later
    // parameters are not tried.
    expect(
      resolveInspectorTarget(
        { server: "not-a-server", namespace: NS_A.uuid },
        LISTS,
        { isAdmin: true },
      ),
    ).toEqual({ kind: "none" });
    expect(
      resolveInspectorTarget(
        { namespace: "not-a-namespace", endpoint: EP_1.uuid },
        LISTS,
        { isAdmin: true },
      ),
    ).toEqual({ kind: "none" });
  });

  it("gives a member no gateway target, even for a uuid that exists", () => {
    expect(
      resolveInspectorTarget({ namespace: NS_A.uuid }, LISTS, {
        isAdmin: false,
      }),
    ).toEqual({ kind: "none" });
    expect(
      resolveInspectorTarget({ endpoint: EP_1.uuid }, LISTS, {
        isAdmin: false,
      }),
    ).toEqual({ kind: "none" });
  });

  it("gives an administrator no gateway target from empty lists", () => {
    // The lists are what an administrator loaded; before they load, or when
    // the listing fails, there is nothing to resolve against.
    const empty: TargetLists = { servers: [], namespaces: [], endpoints: [] };
    expect(
      resolveInspectorTarget({ namespace: NS_A.uuid }, empty, {
        isAdmin: true,
      }),
    ).toEqual({ kind: "none" });
  });
});

// The pre-change page mapping (mcp-inspector/page.tsx, the useConnection call
// before targets existed), kept as the oracle for a server target.
function legacyOptions(selectedServer: McpServer | undefined) {
  return {
    mcpServerUuid: selectedServer?.uuid ?? "",
    transportType: selectedServer?.type || McpServerTypeEnum.enum.STDIO,
    command: selectedServer?.command || "",
    args: selectedServer?.args?.join(" ") || "",
    url: selectedServer?.url || "",
    bearerToken: selectedServer?.bearerToken || undefined,
  };
}

describe("inspectorConnectionOptions", () => {
  it("maps a server exactly as the page always did", () => {
    const servers = [
      SERVER,
      server({
        command: null,
        args: undefined,
        type: "SSE",
        url: "https://x.test",
      }),
      server({ command: "", args: [], bearerToken: "secret" }),
      server({ type: "STREAMABLE_HTTP", url: "https://x.test/mcp", args: [] }),
    ];
    for (const entry of servers) {
      const { targetEnabled, ...options } = inspectorConnectionOptions({
        kind: "server",
        server: entry,
      });
      expect(targetEnabled).toBe(true);
      expect(options).toEqual(legacyOptions(entry));
    }
  });

  it("is the admin namespace route for a namespace, as a signed-in session", () => {
    const options = inspectorConnectionOptions({
      kind: "namespace",
      namespaceUuid: NS_A.uuid,
      label: NS_A.name,
    });
    expect(options).toEqual({
      mcpServerUuid: NS_A.uuid,
      transportType: "SSE",
      command: "",
      args: "",
      url: `/mcp-proxy/metamcp/${NS_A.uuid}/sse`,
      isMetaMCP: true,
      includeInactiveServers: false,
      targetEnabled: true,
    });
    // No credential of any kind: the route authenticates the session cookie.
    expect(options).not.toHaveProperty("bearerToken");
  });

  it("matches the route the backend serves", () => {
    // /mcp-proxy is mounted in index.ts, /metamcp under it in mcp-proxy.ts,
    // and the stream is GET /:uuid/sse in mcp-proxy/metamcp.ts.
    const index = readFileSync(path.join(BACKEND_SRC, "index.ts"), "utf8");
    const proxy = readFileSync(
      path.join(BACKEND_SRC, "routers", "mcp-proxy.ts"),
      "utf8",
    );
    const route = readFileSync(
      path.join(BACKEND_SRC, "routers", "mcp-proxy", "metamcp.ts"),
      "utf8",
    );
    expect(index).toContain('app.use("/mcp-proxy", mcpProxyRouter)');
    expect(proxy).toContain('mcpProxyRouter.use("/metamcp", metamcpRoutes)');
    expect(route).toContain('metamcpRouter.get("/:uuid/sse"');

    const { url } = inspectorConnectionOptions({
      kind: "namespace",
      namespaceUuid: NS_A.uuid,
      label: NS_A.name,
    });
    expect(url).toBe(
      "/mcp-proxy/metamcp/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/sse",
    );
  });

  it("connects an endpoint to its namespace and puts neither the endpoint's uuid nor its name in the address", () => {
    const target = resolveInspectorTarget({ endpoint: EP_2.uuid }, LISTS, {
      isAdmin: true,
    });
    const options = inspectorConnectionOptions(target);
    expect(options.url).toBe(`/mcp-proxy/metamcp/${NS_B.uuid}/sse`);
    expect(options.mcpServerUuid).toBe(NS_B.uuid);
    expect(options.isMetaMCP).toBe(true);
    expect(options.url).not.toContain(EP_2.uuid);
    expect(options.url).not.toContain(EP_2.name);
    expect(JSON.stringify(options)).not.toContain(EP_2.uuid);
    expect(JSON.stringify(options)).not.toContain(EP_2.name);
  });

  it("escapes the namespace uuid in the address", () => {
    const options = inspectorConnectionOptions({
      kind: "namespace",
      namespaceUuid: "a/b?c#d",
      label: "odd",
    });
    expect(options.url).toBe("/mcp-proxy/metamcp/a%2Fb%3Fc%23d/sse");
  });

  it("includes inactive servers only when asked", () => {
    const namespace = {
      kind: "namespace" as const,
      namespaceUuid: NS_A.uuid,
      label: NS_A.name,
    };
    expect(inspectorConnectionOptions(namespace).includeInactiveServers).toBe(
      false,
    );
    expect(
      inspectorConnectionOptions(namespace, true).includeInactiveServers,
    ).toBe(true);
  });

  it("is disabled, with nothing to connect to, for no target", () => {
    expect(inspectorConnectionOptions({ kind: "none" })).toEqual({
      mcpServerUuid: "",
      transportType: "STDIO",
      command: "",
      args: "",
      url: "",
      targetEnabled: false,
    });
  });
});

describe("buildInspectorTargetKey", () => {
  const namespaceA = {
    kind: "namespace" as const,
    namespaceUuid: NS_A.uuid,
    label: NS_A.name,
  };

  it("keeps a server's key byte for byte", () => {
    for (const entry of [
      SERVER,
      server({ env: { B: "2", A: "1" }, headers: { Y: "2", X: "1" } }),
      server({ command: null, args: undefined, url: "https://x.test" }),
    ]) {
      expect(buildInspectorTargetKey({ kind: "server", server: entry })).toBe(
        buildInspectorConnectionKey(entry),
      );
    }
  });

  it("changes with the namespace and with the inactive flag", () => {
    const base = buildInspectorTargetKey(namespaceA);
    expect(
      buildInspectorTargetKey({
        kind: "namespace",
        namespaceUuid: NS_B.uuid,
        label: NS_B.name,
      }),
    ).not.toBe(base);
    expect(buildInspectorTargetKey(namespaceA, true)).not.toBe(base);
    expect(buildInspectorTargetKey(namespaceA, false)).toBe(base);
  });

  it("treats an endpoint and its own namespace as one connection", () => {
    const endpoint = resolveInspectorTarget({ endpoint: EP_1.uuid }, LISTS, {
      isAdmin: true,
    });
    expect(buildInspectorTargetKey(endpoint)).toBe(
      buildInspectorTargetKey(namespaceA),
    );
    const other = resolveInspectorTarget({ endpoint: EP_2.uuid }, LISTS, {
      isAdmin: true,
    });
    expect(buildInspectorTargetKey(other)).not.toBe(
      buildInspectorTargetKey(namespaceA),
    );
  });

  it("never gives a server, a gateway target and no target the same key", () => {
    const keys = [
      buildInspectorTargetKey({ kind: "server", server: SERVER }),
      buildInspectorTargetKey(namespaceA),
      buildInspectorTargetKey({ kind: "none" }),
    ];
    expect(new Set(keys).size).toBe(3);
  });
});

describe("visibleTabs", () => {
  it("shows a server the six tabs it always had, and Server info", () => {
    expect(visibleTabs("server")).toEqual([
      "tools",
      "resources",
      "prompts",
      "ping",
      "roots",
      "sampling",
      "serverInfo",
    ]);
  });

  it("shows a gateway target Tools, Ping and Server info, never Resources or Prompts", () => {
    // The gateway serves tools only: prompts and resources answer empty
    // lists locally (gateway-capabilities.ts), and roots and sampling are
    // features of the Inspector as a client that the gateway does not use.
    for (const kind of ["namespace", "endpoint"] as const) {
      expect(visibleTabs(kind)).toEqual(["tools", "ping", "serverInfo"]);
    }
  });
});

describe("how an endpoint target is described", () => {
  const endpoint = resolveInspectorTarget({ endpoint: EP_1.uuid }, LISTS, {
    isAdmin: true,
  });

  it("labels an endpoint as a preview of its namespace", () => {
    const label = describeTarget(endpoint, t);
    expect(label).toBe("helpdesk-public (preview of namespace ns-helpdesk)");
  });

  it("labels a namespace as a namespace and a server by its name", () => {
    expect(
      describeTarget(
        resolveInspectorTarget({ namespace: NS_A.uuid }, LISTS, {
          isAdmin: true,
        }),
        t,
      ),
    ).toBe("ns-helpdesk (namespace)");
    expect(describeTarget({ kind: "server", server: SERVER }, t)).toBe("alpha");
    expect(describeTarget({ kind: "none" }, t)).toBe("");
  });

  it("names a log or file after the target the user picked", () => {
    expect(targetName(endpoint)).toBe("helpdesk-public");
    expect(targetName({ kind: "server", server: SERVER })).toBe("alpha");
  });
});
