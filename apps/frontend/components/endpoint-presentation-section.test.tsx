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

type FormProps = React.ComponentProps<typeof EndpointPresentationForm>;
type Stored = NonNullable<FormProps["stored"]>;

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

function render(props: Partial<FormProps> = {}) {
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

/** The props the fields hand to their children, as a test reads them. */
interface FieldProps {
  id?: string;
  type?: string;
  children?: unknown;
  disabled?: boolean;
  onClick: () => void;
  onKeyDown: (event: { key: string; preventDefault: () => void }) => void;
  onCheckedChange: (checked: boolean) => void;
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
function fields(over: Partial<React.ComponentProps<typeof ReadyForm>> = {}) {
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
  const tree = elements(element);

  /** The one element matching `match`; a missing element fails the test. */
  const find = (match: (props: FieldProps) => boolean): FieldProps => {
    const found = tree.find((el) => match(el.props as FieldProps));
    if (!found) throw new Error("expected element not found in the fields");
    return found.props as FieldProps;
  };
  return {
    tree,
    onSave,
    setForm,
    byId: (id: string) => find((props) => props.id === id),
    button: (label: string) =>
      find((props) => props.type === "button" && props.children === label),
    trimSwitch: () =>
      find((props) => typeof props.onCheckedChange === "function"),
  };
}

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
      (el) => (el.type as { name?: string }).name === "Button",
    );
    expect(buttons.length).toBe(2);
    for (const button of buttons) {
      expect((button.props as FieldProps).type).toBe("button");
    }
  });

  it("Enter in the title is swallowed, and other keys are not", () => {
    const { byId } = fields();
    const { onKeyDown } = byId("endpoint-presentation-title");

    const enter = vi.fn();
    onKeyDown({ key: "Enter", preventDefault: enter });
    const letter = vi.fn();
    onKeyDown({ key: "a", preventDefault: letter });

    expect(enter).toHaveBeenCalledTimes(1);
    expect(letter).not.toHaveBeenCalled();
  });

  it("Save sends the whole form as a full-listing request", () => {
    const { button, onSave } = fields({
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

    button("Save").onClick();

    expect(onSave).toHaveBeenCalledWith({
      endpoint_uuid: UUID,
      title: "New title",
      instructions: "one\ntwo",
      tool_listing: "full",
      omit_output_schemas: true,
    });
  });

  it("Save from a stored lean state writes the full listing, which clears it", () => {
    const { button, onSave } = fields({
      stored: stored({
        title: null,
        instructions: null,
        omit_output_schemas: false,
        tool_listing: "lean",
      }),
      form: { title: "", instructions: "", omitOutputSchemas: false },
    });

    button("Save").onClick();

    expect(onSave).toHaveBeenCalledWith({
      endpoint_uuid: UUID,
      title: null,
      instructions: null,
      tool_listing: "full",
      omit_output_schemas: false,
    });
  });

  it("Save is disabled when nothing changed, while saving, and when a text is invalid", () => {
    expect(fields().button("Save").disabled).toBe(true);

    // A valid change, but a save is already in flight.
    const saving = fields({
      saving: true,
      form: {
        title: "Changed",
        instructions: "Be brief.",
        omitOutputSchemas: true,
      },
    });
    expect(saving.button("Saving...").disabled).toBe(true);

    const invalid = fields({
      form: {
        title: "t".repeat(81),
        instructions: "",
        omitOutputSchemas: true,
      },
    });
    expect(invalid.button("Save").disabled).toBe(true);
  });

  it("Save is enabled for a valid change", () => {
    const changed = fields({
      form: {
        title: "Changed",
        instructions: "Be brief.",
        omitOutputSchemas: true,
      },
    });
    expect(changed.button("Save").disabled).toBe(false);
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
    const { button, setForm } = fields({
      form: {
        title: "Edited",
        instructions: "Edited",
        omitOutputSchemas: false,
      },
    });

    button("Reset").onClick();

    expect(setForm).toHaveBeenCalledWith({
      title: "Desk",
      instructions: "Be brief.",
      omitOutputSchemas: true,
    });
  });

  it("the trim switch updates only the trim flag", () => {
    const { trimSwitch, setForm } = fields();

    trimSwitch().onCheckedChange(false);

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
