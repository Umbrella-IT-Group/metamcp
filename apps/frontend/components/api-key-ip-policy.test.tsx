import * as React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { queryMock } = vi.hoisted(() => ({ queryMock: vi.fn() }));

vi.mock("@/lib/trpc", () => ({
  trpc: {
    useUtils: () => ({
      frontend: { apiKeys: { getGlobalIpPolicy: { invalidate: vi.fn() } } },
    }),
    frontend: {
      apiKeys: {
        getGlobalIpPolicy: { useQuery: queryMock },
        setGlobalIpPolicy: {
          useMutation: () => ({ isPending: false, mutate: vi.fn() }),
        },
      },
    },
  },
}));

import { GlobalIpPolicyCard } from "./api-key-ip-policy";

beforeEach(() => {
  vi.clearAllMocks();
  // Next supplies the automatic JSX runtime; this Vitest config emits classic
  // JSX. Supply its React binding without changing the app's build config.
  vi.stubGlobal("React", React);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("GlobalIpPolicyCard", () => {
  it("does not offer to save a default policy while the stored policy is loading", () => {
    queryMock.mockReturnValue({ data: undefined, isError: false, error: null });

    const html = renderToStaticMarkup(React.createElement(GlobalIpPolicyCard));

    expect(html).toContain("Loading global IP policy");
    expect(html).not.toContain(">Save</button>");
  });

  it("reports a failed read without offering to replace an unknown policy", () => {
    queryMock.mockReturnValue({
      data: undefined,
      isError: true,
      error: { message: "Policy could not be read" },
    });

    const html = renderToStaticMarkup(React.createElement(GlobalIpPolicyCard));

    expect(html).toContain("Policy could not be read");
    expect(html).not.toContain(">Save</button>");
  });

  it("initializes the editor from the stored policy", () => {
    queryMock.mockReturnValue({
      data: {
        mode: "enforce",
        allowed_cidrs: ["203.0.113.0/24"],
        problems: [],
        kill_switch_active: false,
      },
      isError: false,
      error: null,
    });

    const html = renderToStaticMarkup(React.createElement(GlobalIpPolicyCard));

    expect(html).toContain("203.0.113.0/24");
    expect(html).toContain("Enforce: requests from addresses outside the list");
    expect(html).toContain(">Save</button>");
  });

  it("blocks saving stale cached data after a failed refetch", () => {
    queryMock.mockReturnValue({
      data: {
        mode: "enforce",
        allowed_cidrs: ["203.0.113.0/24"],
        problems: [],
        kill_switch_active: false,
      },
      isError: true,
      error: { message: "Policy refresh failed" },
    });

    const html = renderToStaticMarkup(React.createElement(GlobalIpPolicyCard));

    expect(html).toContain("Policy refresh failed");
    expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Save<\/button>/);
  });
});
