import { readFileSync } from "node:fs";
import path from "node:path";

import * as React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ToolResultView } from "@/app/[locale]/(sidebar)/mcp-inspector/components/inspector/tools/tool-result-view";
import { Tabs, TabsContent } from "@/components/ui/tabs";
import { getTranslation, type Translations } from "@/lib/i18n";

import { HIGHLIGHT_LIMIT, type ToolExecutionRecord } from "./tool-result";

const FRONTEND = path.join(__dirname, "..", "..");
const INSPECTOR_DIR = "app/[locale]/(sidebar)/mcp-inspector/components";

// The inspector files this change touches. The list is explicit because other
// inspector components (the prompts tab plays audio) legitimately contain
// markup this scan forbids here.
const SCANNED_FILES = [
  `${INSPECTOR_DIR}/inspector.tsx`,
  `${INSPECTOR_DIR}/inspector/inspector-tools.tsx`,
  `${INSPECTOR_DIR}/inspector/tools/tool-list.tsx`,
  `${INSPECTOR_DIR}/inspector/tools/tool-argument-form.tsx`,
  `${INSPECTOR_DIR}/inspector/tools/tool-result-view.tsx`,
];

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

// Server-provided text is untrusted. The Content Security Policy
// (lib/security-headers.ts) is script nonce only, frame-src none, and has no
// media-src, so it falls back to self; markup sinks would be the way around it.
describe("no markup sinks in the inspector files this change owns", () => {
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

  it("builds no link from a result", () => {
    const source = read(
      `${INSPECTOR_DIR}/inspector/tools/tool-result-view.tsx`,
    );
    expect(source).not.toMatch(/<a[\s>]/);
    expect(source).not.toMatch(/href\s*=/);
  });
});

// A write tool must not be cancelled because someone left the page: only the
// explicit button may abort a call.
describe("the call lifecycle in the tools container", () => {
  const source = read(`${INSPECTOR_DIR}/inspector/inspector-tools.tsx`);

  it("never aborts a request itself", () => {
    expect(source).not.toMatch(/\.abort\(/);
    expect(source).not.toContain("AbortController");
  });

  it("detaches, and does not stop, when the component unmounts", () => {
    expect(source).toMatch(
      /return \(\) => \{\s*runRef\.current\?\.detach\(\);\s*\};/,
    );
  });

  it("stops a call only from the button", () => {
    const stops = source.match(/\.stop\(\)/g) ?? [];
    expect(stops).toHaveLength(1);
    expect(source).toMatch(/onClick=\{\(\) => runRef\.current\?\.stop\(\)\}/);
  });
});

// The server page's tool refresh saves what it listed, and the save deletes
// saved tools that are not in the list it is given. A listing cut short by a
// repeated cursor or the page cap is not the whole list, so it must be shown
// but never saved (collectAllPages' own tests cover when a walk is cut short).
describe("the server page's tool refresh", () => {
  const source = read(
    "app/[locale]/(sidebar)/mcp-servers/[uuid]/components/tool-management.tsx",
  );

  it("walks the list with the guarded helper", () => {
    expect(source).toContain("collectAllPages");
    expect(source).not.toMatch(/while \(hasMore\)/);
  });

  it("saves the catalog only when the listing is complete", () => {
    expect(source.match(/saveToolsMutation\.mutate\(/g)).toHaveLength(1);
    expect(source).toMatch(
      /if \(collected\.truncated === null\) \{\s*const toolsToSave[\s\S]*?saveToolsMutation\.mutate\(/,
    );
  });
});

// Radix Tabs unmounts an inactive tab's content unless it is force-mounted
// (react-tabs TabsContent: `present && children`, present = forceMount ||
// selected). Unmounting the Tools tab would drop the tool list, the form and
// the results and lose track of a running call.
describe("the Tools tab survives a tab switch", () => {
  const render = (forceMount: boolean) =>
    renderToStaticMarkup(
      React.createElement(
        Tabs,
        { value: "other" },
        React.createElement(
          TabsContent,
          {
            value: "tools",
            forceMount: forceMount ? true : undefined,
            className: "data-[state=inactive]:hidden",
          },
          React.createElement("span", null, "tools-body"),
        ),
        React.createElement(
          TabsContent,
          { value: "other" },
          React.createElement("span", null, "other-body"),
        ),
      ),
    );

  it("keeps a force-mounted inactive panel in the page and hides it by class", () => {
    const html = render(true);
    expect(html).toContain("tools-body");
    expect(html).toContain('data-state="inactive"');
    expect(html).toContain("data-[state=inactive]:hidden");
    // Radix does not set `hidden` on a force-mounted panel, so the class must.
    const panel = html.match(/<div[^>]*data-state="inactive"[^>]*>/)?.[0] ?? "";
    expect(panel).not.toMatch(/\shidden(=|\s|>)/);
  });

  it("drops an inactive panel that is not force-mounted", () => {
    expect(render(false)).not.toContain("tools-body");
  });

  it("is what inspector.tsx asks for", () => {
    const source = read(`${INSPECTOR_DIR}/inspector.tsx`);
    expect(source).toMatch(
      /<TabsContent\s+value="tools"\s+forceMount\s+className="data-\[state=inactive\]:hidden"\s*>/,
    );
  });
});

function record(
  overrides: Partial<ToolExecutionRecord> & Pick<ToolExecutionRecord, "status">,
): ToolExecutionRecord {
  return {
    id: 1,
    toolName: "search_items",
    args: {},
    startedAt: 0,
    durationMs: 12,
    ...overrides,
  };
}

const view = (execution: ToolExecutionRecord) =>
  renderToStaticMarkup(React.createElement(ToolResultView, { execution, t }));

describe("ToolResultView", () => {
  it("shows server text as text, never as markup", () => {
    const html = view(
      record({
        status: "success",
        result: {
          content: [{ type: "text", text: "<img src=x onerror=alert(1)>" }],
        },
      }),
    );
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(html).not.toContain("<img");
  });

  it("shows a resource link as plain text with no anchor", () => {
    const html = view(
      record({
        status: "success",
        result: {
          content: [
            {
              type: "resource_link",
              uri: "javascript:alert(1)",
              name: "link",
            },
          ],
        },
      }),
    );
    expect(html).toContain("javascript:alert(1)");
    expect(html).not.toMatch(/<a[\s>]/);
    expect(html).not.toContain("href=");
  });

  it("shows a result with isError as a tool error and not a success", () => {
    const html = view(
      record({
        status: "tool_error",
        result: {
          isError: true,
          content: [{ type: "text", text: "no such tool" }],
        },
      }),
    );
    expect(html).toContain('data-status="tool_error"');
    expect(html).toContain("Tool error");
    expect(html).toContain("no such tool");
    expect(html).toContain('role="alert"');
    expect(html).not.toContain(">Success<");
  });

  it("shows a success with its duration, including 0 ms", () => {
    const html = view(
      record({
        status: "success",
        durationMs: 0,
        result: { content: [{ type: "text", text: "ok" }] },
      }),
    );
    expect(html).toContain(">Success<");
    expect(html).toContain("0ms");
  });

  it("shows structured content and offers to format a JSON text block", () => {
    const html = view(
      record({
        status: "success",
        result: {
          content: [{ type: "text", text: '{"a":1}' }],
          structuredContent: { total: 3 },
        },
      }),
    );
    expect(html).toContain("Structured content");
    expect(html).toContain("Format as JSON");
  });

  it("shows a protocol failure with its code and the unknown-outcome hint", () => {
    const html = view(
      record({
        status: "protocol_error",
        failure: {
          status: "protocol_error",
          message: "MCP error -32001: Request timed out",
          code: -32001,
          outcomeUnknown: true,
        },
      }),
    );
    expect(html).toContain("Request failed");
    expect(html).toContain("Error code -32001");
    expect(html).toContain("Request timed out");
    expect(html).toContain("read the target before retrying");
  });

  it("says a stop requested cancellation and the backend may still finish", () => {
    const html = view(
      record({
        status: "stopped",
        durationMs: 4300,
        failure: {
          status: "stopped",
          message: "MCP error -32001: Cancelled from the inspector",
          code: -32001,
          outcomeUnknown: true,
        },
      }),
    );
    expect(html).toContain("Stopped waiting");
    expect(html).toContain("Stopped waiting after 4300ms");
    expect(html).toContain(
      "Cancellation was requested; the backend may still finish the call.",
    );
    expect(html).toContain("read the target before retrying");
  });

  it("makes a picture only from an allowed raster type", () => {
    const png = view(
      record({
        status: "success",
        result: {
          content: [{ type: "image", mimeType: "image/png", data: "AAAA" }],
        },
      }),
    );
    expect(png).toContain('src="data:image/png;base64,AAAA"');

    const svg = view(
      record({
        status: "success",
        result: {
          content: [
            { type: "image", mimeType: "image/svg+xml", data: "PHN2Zz4=" },
          ],
        },
      }),
    );
    expect(svg).not.toContain("<img");
    expect(svg).toContain("Image not shown");
  });

  it("does not highlight a very large result", () => {
    const html = view(
      record({
        status: "success",
        result: {
          content: [],
          structuredContent: { big: "x".repeat(HIGHLIGHT_LIMIT) },
        },
      }),
    );
    expect(html).toContain("Large result shown without highlighting");
  });
});
