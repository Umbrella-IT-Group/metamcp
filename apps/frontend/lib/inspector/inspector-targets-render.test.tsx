/**
 * What the target, server-info and traffic surfaces show, and what they must
 * never do with text a server controls.
 *
 * Oracles: the Content Security Policy in lib/security-headers.ts
 * (script nonce only, frame-src none, no media-src), the plan's scope
 * statement for an endpoint target (a preview of its namespace: nothing
 * configured on the endpoint is applied), and the contract that the traffic
 * log is not saved by the server while tool calls remain audited there.
 */
import { readFileSync } from "node:fs";
import path from "node:path";

import * as React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { InspectorServerInfo } from "@/app/[locale]/(sidebar)/mcp-inspector/components/inspector-server-info";
import { InspectorTargetNotice } from "@/app/[locale]/(sidebar)/mcp-inspector/components/inspector-target-notice";
import {
  MessageBody,
  RpcTrafficPanelView,
} from "@/app/[locale]/(sidebar)/mcp-inspector/components/rpc-traffic-panel";
import { getTranslation, type Translations } from "@/lib/i18n";

import type { InspectorTarget } from "./inspector-target";
import type { RpcTrafficEntry } from "./rpc-traffic/types";
import type { InspectorServerInfo as ServerInfo } from "./server-info";

const FRONTEND = path.join(__dirname, "..", "..");
const INSPECTOR_DIR = "app/[locale]/(sidebar)/mcp-inspector";

const read = (relative: string) =>
  readFileSync(path.join(FRONTEND, relative), "utf8");

const dictionary = {
  inspector: JSON.parse(read("public/locales/en/inspector.json")),
} as unknown as Translations;
const t = (key: string, params?: Record<string, string | number>) =>
  getTranslation(dictionary, key, params);

beforeEach(() => {
  // Next supplies the automatic JSX runtime; this Vitest config emits classic
  // JSX. Supply its React binding without changing the app's build config.
  vi.stubGlobal("React", React);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const HOSTILE = "<img src=x onerror=alert(1)>";
const HOSTILE_ESCAPED = "&lt;img src=x onerror=alert(1)&gt;";

// The files this change owns that show server-controlled text. Explicit, like
// the list in inspector-render-safety.test.tsx, because other inspector
// components (the prompts tab plays audio) legitimately use markup this scan
// forbids here.
const SCANNED_FILES = [
  `${INSPECTOR_DIR}/page.tsx`,
  `${INSPECTOR_DIR}/components/inspector.tsx`,
  `${INSPECTOR_DIR}/components/inspector-server-info.tsx`,
  `${INSPECTOR_DIR}/components/inspector-target-notice.tsx`,
  `${INSPECTOR_DIR}/components/rpc-traffic-panel.tsx`,
];

describe("no markup sinks in the files this change owns", () => {
  const FORBIDDEN = [
    "dangerouslySetInnerHTML",
    "document.write",
    "innerHTML",
    "insertAdjacentHTML",
    "<iframe",
    "<audio",
    "srcDoc",
  ];

  it.each(SCANNED_FILES)("%s", (file) => {
    const source = read(file);
    for (const sink of FORBIDDEN) {
      expect(source, `${file} contains ${sink}`).not.toContain(sink);
    }
  });

  it("builds no link and no picture from server text", () => {
    for (const file of SCANNED_FILES) {
      const source = read(file);
      expect(source, file).not.toMatch(/<a[\s>]/);
      expect(source, file).not.toMatch(/\bhref=/);
      expect(source, file).not.toMatch(/<img[\s>]/);
    }
  });

  it("stores the log nowhere: no browser storage, no network call", () => {
    for (const file of [
      `${INSPECTOR_DIR}/components/rpc-traffic-panel.tsx`,
      "lib/inspector/rpc-traffic/store.ts",
      "lib/inspector/rpc-traffic/view.ts",
      "lib/inspector/rpc-traffic/transport-tap.ts",
    ]) {
      const source = read(file);
      expect(source, file).not.toMatch(
        /localStorage|sessionStorage|indexedDB|\bfetch\(|XMLHttpRequest|sendBeacon/,
      );
    }
  });
});

// The connection hook is shared with the server and namespace detail pages.
// The tap only works if it is on the transport before the SDK starts it, and
// the log must exist only where a page asks for one.
describe("the connection hook", () => {
  const source = read("hooks/useConnection.ts");

  it("connects through connectWithTraffic and nowhere else", () => {
    expect(source).not.toMatch(/\bclient\.connect\(/);
    expect(source.match(/connectWithTraffic\(/g)).toHaveLength(1);
  });

  it("keeps no log unless a page asks for one", () => {
    expect(source).toContain("captureTraffic = false");
    for (const page of [
      "app/[locale]/(sidebar)/namespaces/[uuid]/page.tsx",
      "app/[locale]/(sidebar)/mcp-servers/[uuid]/page.tsx",
    ]) {
      expect(read(page), page).not.toContain("captureTraffic");
    }
    expect(read(`${INSPECTOR_DIR}/page.tsx`)).toContain("captureTraffic: true");
  });

  it("no longer keeps a request history nothing reads", () => {
    expect(source).not.toContain("requestHistory");
    expect(source).not.toContain("pushHistory");
  });
});

// A member's session is refused by the whole /mcp-proxy route, and the
// administrator-only listings would be refused too. The page must not even
// ask: both listings are enabled only for a confirmed administrator.
describe("the page's gateway target lists", () => {
  const source = read(`${INSPECTOR_DIR}/page.tsx`);

  it("asks for namespaces and endpoints only as an administrator", () => {
    for (const procedure of ["namespaces", "endpoints"]) {
      expect(source).toMatch(
        new RegExp(
          `frontend\\.${procedure}\\.listAll\\.useQuery\\(undefined,\\s*\\{\\s*enabled: isAdmin,?\\s*\\}\\)`,
        ),
      );
    }
  });

  it("starts as not an administrator and stays one only on an answer of admin", () => {
    expect(source).toContain("useState(false)");
    expect(source).toMatch(/setIsAdmin\(role === "admin"\)/);
    expect(source).toMatch(/\.catch\(\(\) => \{[^}]*setIsAdmin\(false\)/);
  });
});

const entry = (
  id: string,
  overrides: Partial<RpcTrafficEntry> & Pick<RpcTrafficEntry, "message">,
): RpcTrafficEntry => ({
  id,
  direction: "receive",
  timestamp: "2026-11-12T12:00:00.000Z",
  bytes: JSON.stringify(overrides.message).length,
  ...overrides,
});

const panel = (entries: RpcTrafficEntry[]) =>
  renderToStaticMarkup(
    React.createElement(RpcTrafficPanelView, {
      entries,
      onClear: () => {},
      onDownload: () => {},
      onCopyMessage: () => {},
      t,
    }),
  );

describe("the traffic panel", () => {
  it("leaves params and results out of a download by default", () => {
    const html = panel([]);
    const checkbox =
      html.match(/<button[^>]*id="traffic-omit-bodies"[^>]*>/)?.[0] ?? "";
    expect(checkbox).toContain('role="checkbox"');
    expect(checkbox).toContain('aria-checked="true"');
    expect(checkbox).toContain('data-state="checked"');
    expect(html).toContain("Leave out params and results");
  });

  it("says the log is not saved by the server, and does not say tool calls are unaudited", () => {
    const html = panel([]);
    expect(html).toContain("This log is not saved by the server");
    expect(html).toContain(
      "it holds tool arguments and results exactly as exchanged",
    );
    expect(html).toContain(
      "Tool calls are still recorded in the gateway&#x27;s audit log.",
    );
    expect(html).not.toContain("Nothing is stored");
    expect(html).not.toMatch(/not audited|no audit|unaudited/i);
  });

  it("shows an empty log as empty", () => {
    const html = panel([]);
    expect(html).toContain("No messages yet");
    expect(html).toContain("0 of 0 messages");
  });

  it("shows a row with its direction, method, id, pair, merge count and size", () => {
    const html = panel([
      entry("rpc-1", {
        direction: "send",
        message: { jsonrpc: "2.0", id: 4, method: "tools/call" },
        timestamp: "2026-11-12T12:00:00.000Z",
      }),
      entry("rpc-2", {
        message: { jsonrpc: "2.0", id: 4, result: {} },
        timestamp: "2026-11-12T12:00:00.250Z",
      }),
      entry("rpc-3", {
        message: {
          jsonrpc: "2.0",
          method: "notifications/progress",
          params: { progressToken: "t", progress: 3 },
        },
        repeatCount: 3,
      }),
    ]);
    expect(html).toContain("3 of 3 messages");
    expect(html).toContain('data-direction="send"');
    expect(html).toContain('data-direction="receive"');
    expect(html).toContain("tools/call");
    expect(html).toContain("#4");
    // The response is named for the request it answers, and both rows carry
    // the pair's latency and outcome.
    expect(html).toContain("response: tools/call");
    expect(html.match(/250ms/g)).toHaveLength(2);
    expect(html).toContain(">x3<");
  });

  it("shows a failed connection as a transport error row, with the reason", () => {
    const html = panel([
      entry("rpc-1", {
        message: {
          transportEvent: "error",
          error: "SSE error: Non-200 status code (403)",
        },
      }),
    ]);
    expect(html).toContain("Transport error");
    expect(html).toContain("SSE error: Non-200 status code (403)");
  });

  it("shows server text as text, never as markup", () => {
    const html = panel([
      entry("rpc-1", {
        message: {
          jsonrpc: "2.0",
          id: HOSTILE,
          method: HOSTILE,
          params: {},
        },
      }),
      entry("rpc-2", {
        message: { transportEvent: "error", error: HOSTILE },
      }),
    ]);
    expect(html).toContain(HOSTILE_ESCAPED);
    expect(html).not.toContain("<img");
  });

  it("says when a message was too large to keep, and still shows what was kept", () => {
    const html = renderToStaticMarkup(
      React.createElement(MessageBody, {
        entry: entry("rpc-1", {
          message: {
            jsonrpc: "2.0",
            id: 1,
            result: { truncated: true, bytes: 9_000_000 },
          },
          bytes: 9_000_000,
          truncated: true,
        }),
        t,
      }),
    );
    expect(html).toContain("Message larger than 4194304 bytes");
    expect(html).toContain("the body was not kept (9000000 bytes)");
  });
});

const info = (overrides: Partial<ServerInfo> = {}): ServerInfo => ({
  implementation: { name: "metamcp-unified-ns", version: "1.0.0" },
  capabilities: { tools: { listChanged: true } },
  protocolVersion: "2025-11-25",
  ...overrides,
});

const serverInfo = (
  value: ServerInfo | null,
  targetKind: "server" | "namespace" | "endpoint",
) =>
  renderToStaticMarkup(
    React.createElement(InspectorServerInfo, {
      serverInfo: value,
      targetKind,
      t,
    }),
  );

describe("the Server info tab", () => {
  it("shows what the server announced", () => {
    const html = serverInfo(
      info({
        implementation: {
          name: "fixture",
          title: "Fixture server",
          version: "3.1.4",
          description: "A fixture.",
        },
        instructions: "Call search_items first.",
      }),
      "server",
    );
    expect(html).toContain("fixture");
    expect(html).toContain("Fixture server");
    expect(html).toContain("3.1.4");
    expect(html).toContain("2025-11-25");
    expect(html).toContain("A fixture.");
    expect(html).toContain("Call search_items first.");
    expect(html).toContain("listChanged");
  });

  it("says None when there are no instructions, and unknown without a result", () => {
    expect(serverInfo(info(), "server")).toContain(">None<");
    const html = serverInfo(null, "server");
    expect(html).toContain(">unknown<");
  });

  it("shows every server-provided value as text, never a link, a picture or markup", () => {
    const html = serverInfo(
      info({
        implementation: {
          name: HOSTILE,
          title: HOSTILE,
          version: HOSTILE,
          description: HOSTILE,
          websiteUrl: "javascript:alert(1)",
          icons: [
            { src: "javascript:alert(2)" },
            { src: `data:${"A".repeat(5000)}` },
          ],
        },
        instructions: "<script>alert(1)</script>",
      }),
      "server",
    );
    expect(html).toContain(HOSTILE_ESCAPED);
    expect(html).toContain("javascript:alert(1)");
    expect(html).toContain("javascript:alert(2)");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toMatch(/<a[\s>]/);
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<script");
    expect(html).not.toContain("href=");
    // An icon address that is a long data URI is shortened.
    expect(html).not.toContain("A".repeat(300));
  });

  it("says a gateway target's own result does not include an endpoint's title or instructions", () => {
    for (const kind of ["namespace", "endpoint"] as const) {
      const html = serverInfo(info(), kind);
      expect(html).toContain('role="note"');
      expect(html).toContain(
        "the namespace server&#x27;s own initialize result",
      );
      expect(html).toContain(
        "Anything configured on an endpoint, such as its title or instructions, is not part of it.",
      );
    }
    expect(serverInfo(info(), "server")).not.toContain('role="note"');
  });
});

const NAMESPACE_TARGET: InspectorTarget = {
  kind: "namespace",
  namespaceUuid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  label: "ns-helpdesk",
};
const ENDPOINT_TARGET: InspectorTarget = {
  kind: "endpoint",
  endpointUuid: "e1e1e1e1-e1e1-4e1e-8e1e-e1e1e1e1e1e1",
  endpointName: "helpdesk-public",
  namespaceUuid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  namespaceName: "ns-helpdesk",
};

const notice = (target: InspectorTarget, includeInactive = false) =>
  renderToStaticMarkup(
    React.createElement(InspectorTargetNotice, {
      target,
      includeInactive,
      onIncludeInactiveChange: () => {},
      t,
    }),
  );

describe("the note under a gateway target", () => {
  it("tells an endpoint target it is a preview of the namespace and names what is not applied", () => {
    const html = notice(ENDPOINT_TARGET).replaceAll("&quot;", '"');
    expect(html).toContain("Preview of the namespace, not of the endpoint.");
    expect(html).toContain('the endpoint "helpdesk-public"');
    expect(html).toContain('its namespace "ns-helpdesk"');
    expect(html).toContain("Nothing configured on the endpoint is applied");
    expect(html).toContain("not its title or instructions");
    expect(html).toContain("listing mode or output trimming");
    expect(html).toContain("authentication, access groups or rate limits");
    expect(html).toContain("connect to the public endpoint with a real client");
  });

  it("says calls are real and audited as admin session calls, for both kinds", () => {
    for (const target of [NAMESPACE_TARGET, ENDPOINT_TARGET]) {
      const html = notice(target);
      expect(html).toContain("Tool calls are real");
      expect(html).toContain(
        "recorded in the audit log as admin session calls",
      );
      expect(html).toContain("one session per backend server in the namespace");
    }
  });

  it("does not claim an endpoint's settings for a namespace target", () => {
    const html = notice(NAMESPACE_TARGET);
    expect(html).not.toContain("Preview of the namespace");
    expect(html).not.toContain("Nothing configured on the endpoint");
  });

  it("shows nothing for a server or no target", () => {
    expect(notice({ kind: "none" })).toBe("");
    expect(
      notice({
        kind: "server",
        server: {
          uuid: "11111111-1111-4111-8111-111111111111",
          name: "alpha",
          description: null,
          type: "STDIO",
          command: "npx",
          args: [],
          env: {},
          url: null,
          created_at: "2026-10-01T00:00:00.000Z",
          bearerToken: null,
          headers: {},
          user_id: null,
          error_status: "NONE",
        },
      }),
    ).toBe("");
  });

  it("offers inactive servers, off unless chosen", () => {
    const checkboxOf = (html: string) =>
      html.match(/<button[^>]*id="inspector-include-inactive"[^>]*>/)?.[0] ??
      "";
    expect(checkboxOf(notice(NAMESPACE_TARGET, false))).toContain(
      'aria-checked="false"',
    );
    expect(checkboxOf(notice(NAMESPACE_TARGET, true))).toContain(
      'aria-checked="true"',
    );
    expect(notice(NAMESPACE_TARGET)).toContain("Include inactive servers");
  });

  it("shows an endpoint and namespace name as text", () => {
    const html = notice({
      ...ENDPOINT_TARGET,
      endpointName: HOSTILE,
      namespaceName: HOSTILE,
    });
    expect(html).toContain(HOSTILE_ESCAPED);
    expect(html).not.toContain("<img");
  });
});
