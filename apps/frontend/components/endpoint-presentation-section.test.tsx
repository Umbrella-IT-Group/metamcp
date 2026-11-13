import { readFileSync } from "node:fs";
import path from "node:path";

import * as React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { queryMock, getSessionMock } = vi.hoisted(() => ({
  queryMock: vi.fn(),
  getSessionMock: vi.fn(),
}));

vi.mock("@/lib/trpc", () => ({
  trpc: {
    useUtils: () => ({
      frontend: { endpointPresentation: { get: { invalidate: vi.fn() } } },
    }),
    frontend: {
      endpointPresentation: {
        get: { useQuery: queryMock },
        set: { useMutation: () => ({ isPending: false, mutate: vi.fn() }) },
      },
    },
  },
}));
vi.mock("@/lib/auth-client", () => ({
  authClient: { getSession: getSessionMock },
}));
vi.mock("@/hooks/useTranslations", () => ({
  useTranslations: () => ({ t: (key: string) => key }),
}));

import { getTranslation, type Translations } from "@/lib/i18n";

import {
  EndpointPresentationForm,
  EndpointPresentationSection,
  ReadyForm,
} from "./endpoint-presentation-section";

/**
 * The translator the panel is given in production reads the real English
 * `endpoints.json`; reading the same file here is what lets these tests assert
 * the copy an administrator sees, including the audit-retention and
 * secrets warnings, rather than key names.
 */
const endpoints = JSON.parse(
  readFileSync(
    path.join(__dirname, "..", "public", "locales", "en", "endpoints.json"),
    "utf8",
  ),
);
const dictionary = { endpoints } as unknown as Translations;
const t = (key: string, params?: Record<string, string | number>) =>
  getTranslation(dictionary, key, params);

const UUID = "11111111-1111-4111-8111-111111111111";

type Stored = React.ComponentProps<typeof EndpointPresentationForm>["stored"];
const stored = (over: Record<string, unknown> = {}): Stored =>
  ({
    endpoint_uuid: UUID,
    title: "Desk",
    instructions: "Be brief.",
    tool_listing: "full",
    omit_output_schemas: true,
    updated_at: "2026-11-12T10:00:00.000Z",
    effective: { presentation_enabled: true, lean_enabled: false },
    ...over,
  }) as Stored;

function render(
  props: Partial<React.ComponentProps<typeof EndpointPresentationForm>> = {},
) {
  return renderToStaticMarkup(
    React.createElement(EndpointPresentationForm, {
      endpointUuid: UUID,
      t,
      status: "ready",
      stored: stored(),
      saving: false,
      onSave: vi.fn(),
      ...props,
    }),
  );
}

/** Every element in a tree of React elements, depth first. */
function elements(node: React.ReactNode): React.ReactElement[] {
  if (node === null || node === undefined || typeof node === "boolean")
    return [];
  if (Array.isArray(node)) return node.flatMap(elements);
  if (!React.isValidElement(node)) return [];
  const props = node.props as { children?: React.ReactNode };
  return [node, ...elements(props.children)];
}

/** The fields, called as a plain function (they hold no hooks). */
function fields(over: Partial<React.ComponentProps<typeof ReadyForm>> = {}): {
  tree: React.ReactElement[];
  onSave: ReturnType<typeof vi.fn>;
  setForm: ReturnType<typeof vi.fn>;
} {
  const onSave = vi.fn();
  const setForm = vi.fn();
  const element = ReadyForm({
    endpointUuid: UUID,
    t,
    stored: stored(),
    saving: false,
    onSave,
    form: { title: "Desk", instructions: "Be brief.", omitOutputSchemas: true },
    setForm,
    ...over,
  });
  return { tree: elements(element), onSave, setForm };
}

const byId = (tree: React.ReactElement[], id: string) =>
  tree.find((el) => (el.props as { id?: string }).id === id);
const buttonLabelled = (tree: React.ReactElement[], label: string) =>
  tree.find(
    (el) =>
      (el.props as { type?: string }).type === "button" &&
      (el.props as { children?: unknown }).children === label,
  );

beforeEach(() => {
  vi.clearAllMocks();
  // Next supplies the automatic JSX runtime; this Vitest config emits classic
  // JSX. Supply its React binding without changing the app's build config.
  vi.stubGlobal("React", React);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("EndpointPresentationForm", () => {
  it("offers no Save while the stored settings are loading", () => {
    const html = render({ status: "loading", stored: undefined });

    expect(html).toContain("Loading presentation settings...");
    expect(html).not.toContain(">Save</button>");
  });

  it("reports a failed read without offering to replace settings it could not read", () => {
    const html = render({
      status: "error",
      stored: undefined,
      errorMessage: "The settings could not be read",
    });

    expect(html).toContain("The settings could not be read");
    expect(html).not.toContain(">Save</button>");
    expect(html).not.toContain("<textarea");
  });

  it("fills the fields from the stored settings and disables Save while nothing changed", () => {
    const html = render();

    expect(html).toContain('value="Desk"');
    expect(html).toContain(">Be brief.</textarea>");
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Save<\/button>/);
  });

  it("shows how much of the instructions limit is used", () => {
    expect(render()).toContain("9 / 1500");
  });

  it("warns that the text reaches models, is kept in the audit log, and applies to new sessions only", () => {
    const html = render();

    expect(html).toContain("Do not put secrets or client data here");
    expect(html).toContain(
      "kept in the audit log, which cannot be edited later",
    );
    expect(html).toContain(
      "Changes apply to sessions that start after you save",
    );
  });

  it("says outright when the kill switch makes saved settings inert", () => {
    const off = render({
      stored: stored({
        effective: { presentation_enabled: false, lean_enabled: false },
      }),
    });
    expect(off).toContain("endpoint presentation turned off");
    expect(off).toContain("MCP_ENDPOINT_PRESENTATION");

    expect(render()).not.toContain("endpoint presentation turned off");
  });

  it("tells the administrator about a stored lean listing this gateway does not serve", () => {
    const html = render({ stored: stored({ tool_listing: "lean" }) });

    expect(html).toContain(
      "A lean listing is stored for this endpoint, but this gateway version does not serve it. Saving resets it to the full list.",
    );
    // Save stays available: it is how that row is cleared.
    expect(html).not.toMatch(/<button[^>]*disabled=""[^>]*>Save<\/button>/);
  });

  it("does not show the lean message for an ordinary stored state", () => {
    expect(render()).not.toContain("lean listing is stored");
  });
});

describe("the fields", () => {
  it("every button is type=button, so none submits the endpoint form around the panel", () => {
    const { tree } = fields();
    const buttons = tree.filter(
      (el) =>
        (el.type as { displayName?: string; name?: string }).name === "Button",
    );
    expect(buttons.length).toBe(2);
    for (const button of buttons) {
      expect((button.props as { type?: string }).type).toBe("button");
    }
  });

  it("Enter in the title is swallowed, and other keys are not", () => {
    const { tree } = fields();
    const title = byId(tree, "endpoint-presentation-title");
    const onKeyDown = (
      title?.props as {
        onKeyDown: (e: { key: string; preventDefault: () => void }) => void;
      }
    ).onKeyDown;

    const enter = vi.fn();
    onKeyDown({ key: "Enter", preventDefault: enter });
    const letter = vi.fn();
    onKeyDown({ key: "a", preventDefault: letter });

    expect(enter).toHaveBeenCalledTimes(1);
    expect(letter).not.toHaveBeenCalled();
  });

  it("Save sends the whole form as a full-listing request", () => {
    const { tree, onSave } = fields({
      stored: stored({
        title: null,
        instructions: null,
        omit_output_schemas: false,
      }),
      form: {
        title: "  New title ",
        instructions: "one\r\ntwo",
        omitOutputSchemas: true,
      },
    });

    buttonLabelled(tree, "Save")?.props.onClick();

    expect(onSave).toHaveBeenCalledWith({
      endpoint_uuid: UUID,
      title: "New title",
      instructions: "one\ntwo",
      tool_listing: "full",
      omit_output_schemas: true,
    });
  });

  it("Save from a stored lean state writes the full listing, which clears it", () => {
    const { tree, onSave } = fields({
      stored: stored({
        title: null,
        instructions: null,
        omit_output_schemas: false,
        tool_listing: "lean",
      }),
      form: { title: "", instructions: "", omitOutputSchemas: false },
    });

    buttonLabelled(tree, "Save")?.props.onClick();

    expect(onSave).toHaveBeenCalledWith({
      endpoint_uuid: UUID,
      title: null,
      instructions: null,
      tool_listing: "full",
      omit_output_schemas: false,
    });
  });

  it("Save is disabled when nothing changed, while saving, and when a text is invalid", () => {
    const unchanged = fields();
    expect(buttonLabelled(unchanged.tree, "Save")?.props.disabled).toBe(true);

    // A valid change, but a save is already in flight.
    const saving = fields({
      saving: true,
      form: {
        title: "Changed",
        instructions: "Be brief.",
        omitOutputSchemas: true,
      },
    });
    expect(buttonLabelled(saving.tree, "Saving...")?.props.disabled).toBe(true);

    const invalid = fields({
      form: {
        title: "t".repeat(81),
        instructions: "",
        omitOutputSchemas: true,
      },
    });
    expect(buttonLabelled(invalid.tree, "Save")?.props.disabled).toBe(true);
  });

  it("Save is enabled for a valid change", () => {
    const changed = fields({
      form: {
        title: "Changed",
        instructions: "Be brief.",
        omitOutputSchemas: true,
      },
    });
    expect(buttonLabelled(changed.tree, "Save")?.props.disabled).toBe(false);
  });

  it("names the rule an invalid text breaks, next to the field", () => {
    const html = renderToStaticMarkup(
      React.createElement(ReadyForm, {
        endpointUuid: UUID,
        t,
        stored: stored(),
        saving: false,
        onSave: vi.fn(),
        form: {
          title: "t".repeat(81),
          instructions: "",
          omitOutputSchemas: true,
        },
        setForm: vi.fn(),
      }),
    );
    expect(html).toContain("Must be 80 characters or fewer.");
  });

  it("Reset puts the stored settings back", () => {
    const { tree, setForm } = fields({
      form: {
        title: "Edited",
        instructions: "Edited",
        omitOutputSchemas: false,
      },
    });

    buttonLabelled(tree, "Reset")?.props.onClick();

    expect(setForm).toHaveBeenCalledWith({
      title: "Desk",
      instructions: "Be brief.",
      omitOutputSchemas: true,
    });
  });

  it("the trim switch updates only the trim flag", () => {
    const { tree, setForm } = fields();
    const trim = tree.find(
      (el) =>
        typeof (el.props as { onCheckedChange?: unknown }).onCheckedChange ===
        "function",
    );

    (
      trim?.props as { onCheckedChange: (checked: boolean) => void }
    ).onCheckedChange(false);

    expect(setForm).toHaveBeenCalledWith({
      title: "Desk",
      instructions: "Be brief.",
      omitOutputSchemas: false,
    });
  });
});

describe("EndpointPresentationSection", () => {
  it("renders nothing and does not read the settings before the session says the user is an administrator", () => {
    getSessionMock.mockReturnValue(new Promise(() => undefined));
    queryMock.mockReturnValue({ data: undefined, isError: false, error: null });

    const html = renderToStaticMarkup(
      React.createElement(EndpointPresentationSection, { endpointUuid: UUID }),
    );

    expect(html).toBe("");
    // The query exists but is switched off until the role is known.
    expect(queryMock).toHaveBeenCalledWith(
      { endpoint_uuid: UUID },
      { enabled: false },
    );
  });
});
