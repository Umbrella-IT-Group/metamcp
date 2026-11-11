import * as React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/trpc", () => ({
  trpc: {
    useUtils: () => ({}),
    frontend: {
      mcpServers: {
        update: { useMutation: () => ({ mutate: vi.fn() }) },
      },
    },
  },
}));

vi.mock("@/hooks/useTranslations", () => ({
  useTranslations: () => ({ t: (key: string) => key }),
}));

// Radix's dialog portal does not render on the server. Render its children
// inline so this test checks the form's real controls without a DOM.
vi.mock("@/components/ui/dialog", () => {
  const container = ({ children }: React.PropsWithChildren) =>
    React.createElement("div", null, children);
  return {
    Dialog: container,
    DialogContent: container,
    DialogDescription: container,
    DialogHeader: container,
    DialogTitle: container,
  };
});

import { EditMcpServer } from "./edit-mcp-server";

beforeEach(() => {
  // Next supplies the automatic JSX runtime; Vitest emits classic JSX.
  vi.stubGlobal("React", React);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the server editor's STDIO controls", () => {
  it("offers an explicit bearer clear after the URL fields are hidden", () => {
    // The form defaults to STDIO. Server effects do not run during rendering,
    // so this exercises the same branch shown after a switch to STDIO.
    const html = renderToStaticMarkup(
      React.createElement(EditMcpServer, {
        server: null,
        isOpen: true,
        onClose: vi.fn(),
        onSuccess: vi.fn(),
      }),
    );

    expect(html).toContain('id="edit-command"');
    expect(html).not.toContain('id="edit-url"');
    // Clearing the old URL is a destination change. A stored token therefore
    // needs this decision even though STDIO itself sends no bearer header.
    expect(html).toContain('id="edit-clearBearerToken"');
    expect(html).toContain('for="edit-clearBearerToken"');
  });
});
