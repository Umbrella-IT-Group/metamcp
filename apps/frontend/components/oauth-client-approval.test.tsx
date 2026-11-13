import { readFileSync } from "node:fs";
import path from "node:path";

import * as React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getTranslation, type Translations } from "@/lib/i18n";
import {
  decisionCallbacks,
  isDecidableClient,
  refreshClientInventories,
  registrationSourceKey,
} from "@/lib/oauth-client-approval";

import {
  OAuthClientDecisionActions,
  OAuthClientsListState,
  OAuthClientStatusBadge,
  RegisteredFrom,
} from "./oauth-client-approval";

const LOCALES = ["en", "ko", "zh"] as const;

function dictionaryFor(locale: (typeof LOCALES)[number]) {
  const read = (namespace: string) =>
    JSON.parse(
      readFileSync(
        path.join(
          __dirname,
          "..",
          "public",
          "locales",
          locale,
          `${namespace}.json`,
        ),
        "utf8",
      ),
    );
  return {
    "oauth-clients": read("oauth-clients"),
    common: read("common"),
  } as unknown as Translations;
}

function translatorFor(locale: (typeof LOCALES)[number]) {
  const dictionary = dictionaryFor(locale);
  return (key: string, params?: Record<string, string | number>) =>
    getTranslation(dictionary, key, params);
}

const t = translatorFor("en");

beforeEach(() => {
  // Next supplies the automatic JSX runtime; this Vitest config emits classic
  // JSX. Supply its React binding without changing the app's build config.
  vi.stubGlobal("React", React);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const render = (element: React.ReactElement) => renderToStaticMarkup(element);
const tableWrap = (row: React.ReactElement) =>
  React.createElement("table", null, React.createElement("tbody", null, row));

describe("client status", () => {
  it.each([
    ["approved", "Approved"],
    ["pending", "Waiting for approval"],
    ["rejected", "Rejected"],
    ["something-else", "Not approved"],
    [null, "Not approved"],
  ])("labels %j as %s", (status, label) => {
    const html = render(
      React.createElement(OAuthClientStatusBadge, { status, t }),
    );
    expect(html).toContain(label);
  });

  it.each([
    ["dcr", "Self-registered"],
    ["admin", "Created by an administrator"],
    [null, "Created before sources were recorded"],
  ])("names provenance %j", (source, label) => {
    const html = render(
      React.createElement(OAuthClientStatusBadge, {
        status: "approved",
        source,
        t,
      }),
    );
    expect(html).toContain(label);
  });

  it("shows no provenance line when none is passed (Access token list)", () => {
    const html = render(
      React.createElement(OAuthClientStatusBadge, { status: "pending", t }),
    );
    expect(html).not.toContain("Self-registered");
  });
});

describe("registering address", () => {
  it("says unavailable when there is none", () => {
    for (const ip of [null, undefined, ""]) {
      const html = render(React.createElement(RegisteredFrom, { ip, t }));
      expect(html).toContain("Unavailable");
    }
  });

  it("shows the address, labelled as an observed network address", () => {
    const html = render(
      React.createElement(RegisteredFrom, { ip: "198.51.100.7", t }),
    );
    expect(html).toContain("198.51.100.7");
    expect(html).toContain("does not identify a person");
  });
});

describe("decision buttons", () => {
  const pending = {
    client_id: "mcp_client_a",
    registration_source: "dcr",
    approval_status: "pending",
  };
  const actions = (
    client: typeof pending,
    deciding: { clientId: string; kind: "approve" | "reject" } | null,
  ) =>
    render(
      React.createElement(OAuthClientDecisionActions, {
        client,
        deciding,
        onApprove: vi.fn(),
        onReject: vi.fn(),
        t,
      }),
    );

  it("offers Approve and Reject, enabled, for a pending self-registration", () => {
    const html = actions(pending, null);
    expect(html).toContain("Approve");
    expect(html).toContain("Reject");
    expect(html).not.toContain('disabled=""');
  });

  it.each([
    [{ ...pending, approval_status: "approved" }],
    [{ ...pending, approval_status: "rejected" }],
    [{ ...pending, registration_source: "admin" }],
    [{ ...pending, registration_source: null as unknown as string }],
  ])("offers nothing for %j", (client) => {
    expect(actions(client, null)).toBe("");
    expect(isDecidableClient(client)).toBe(false);
  });

  it("disables both buttons while any decision runs and names the one running", () => {
    const here = actions(pending, {
      clientId: "mcp_client_a",
      kind: "approve",
    });
    expect(here).toContain("Approving...");
    expect(here.match(/disabled=""/g)).toHaveLength(2);

    const elsewhere = actions(pending, {
      clientId: "mcp_client_b",
      kind: "reject",
    });
    expect(elsewhere).not.toContain("Rejecting...");
    expect(elsewhere.match(/disabled=""/g)).toHaveLength(2);
  });
});

describe("list states", () => {
  const state = (
    overrides: Partial<Parameters<typeof OAuthClientsListState>[0]>,
  ) =>
    render(
      tableWrap(
        React.createElement(OAuthClientsListState, {
          colSpan: 9,
          isLoading: false,
          isError: false,
          isEmpty: false,
          onRetry: vi.fn(),
          t,
          ...overrides,
        }),
      ),
    );

  it("reports a failed load with its message and a retry, not an empty list", () => {
    const html = state({
      isError: true,
      isEmpty: true,
      errorMessage: "Failed to fetch OAuth clients",
    });
    expect(html).toContain(
      "Could not load OAuth clients: Failed to fetch OAuth clients",
    );
    expect(html).toContain("Refresh");
    expect(html).not.toContain("No OAuth clients registered");
  });

  it("shows loading, then empty", () => {
    expect(state({ isLoading: true })).toContain("Loading OAuth clients");
    expect(state({ isEmpty: true })).toContain("No OAuth clients registered");
  });
});

describe("decision outcomes", () => {
  const harness = (kind: "approve" | "reject") => {
    const calls = {
      success: [] as string[],
      error: [] as string[],
      refresh: 0,
      done: 0,
    };
    const callbacks = decisionCallbacks({
      kind,
      t,
      notifySuccess: (m) => calls.success.push(m),
      notifyError: (m) => calls.error.push(m),
      refresh: () => {
        calls.refresh += 1;
      },
      done: () => {
        calls.done += 1;
      },
    });
    return { calls, callbacks };
  };

  it("refreshes the inventories and re-enables the buttons after a success", () => {
    const { calls, callbacks } = harness("approve");
    callbacks.onSuccess();
    callbacks.onSettled();
    expect(calls.success[0]).toContain("Client approved");
    expect(calls).toMatchObject({ refresh: 1, done: 1, error: [] });
  });

  it.each(["CONFLICT", "NOT_FOUND"])(
    "treats a %s as a stale list: says so and refreshes",
    (code) => {
      const { calls, callbacks } = harness("reject");
      callbacks.onError({
        message: "This client is no longer pending.",
        data: { code },
      });
      callbacks.onSettled();
      expect(calls.error[0]).toContain("changed since the list loaded");
      expect(calls.error[0]).toContain("no longer pending");
      expect(calls).toMatchObject({ refresh: 1, done: 1 });
    },
  );

  it("reports any other failure with its message and still refreshes", () => {
    const { calls, callbacks } = harness("approve");
    callbacks.onError({
      message:
        "This client has a callback that is not a local (loopback) address",
      data: { code: "BAD_REQUEST" },
    });
    expect(calls.error[0]).toBe(
      "Could not record the decision: This client has a callback that is not a local (loopback) address",
    );
    expect(calls.refresh).toBe(1);
  });

  it("invalidates both client inventory views", () => {
    const clients = vi.fn();
    const tokens = vi.fn();
    refreshClientInventories({
      frontend: {
        oauthClients: { list: { invalidate: clients } },
        oauthTokens: { list: { invalidate: tokens } },
      },
    });
    expect(clients).toHaveBeenCalledTimes(1);
    expect(tokens).toHaveBeenCalledTimes(1);
  });
});

describe("client metadata document clients", () => {
  it("labels the source and offers no decision for a pending one", () => {
    expect(registrationSourceKey("cimd")).toBe("oauth-clients:sourceCimd");
    expect(t("oauth-clients:sourceCimd")).toBe("Client metadata document");
    // Approval is the allowlist entry, not an administrator's click, so the
    // page never offers Approve or Reject for this source.
    expect(
      isDecidableClient({
        registration_source: "cimd",
        approval_status: "pending",
      }),
    ).toBe(false);
  });

  it.each([
    ["dcr", "oauth-clients:sourceDcr"],
    ["admin", "oauth-clients:sourceAdmin"],
    [null, "oauth-clients:sourceLegacy"],
    ["something-new", "oauth-clients:sourceLegacy"],
  ])("still labels %j as before", (source, key) => {
    expect(registrationSourceKey(source)).toBe(key);
  });

  it.each(LOCALES)("has the source label translated in %s", (locale) => {
    const label = translatorFor(locale)("oauth-clients:sourceCimd");
    expect(label).not.toBe("oauth-clients:sourceCimd");
    expect(label).not.toBe("");
  });
});

describe("translations", () => {
  const KEYS = [
    "columnStatus",
    "columnRegisteredFrom",
    "statusApproved",
    "statusPending",
    "statusRejected",
    "statusUnknown",
    "sourceDcr",
    "sourceAdmin",
    "sourceLegacy",
    "registeredFromUnavailable",
    "registeredFromHelp",
    "approve",
    "approving",
    "reject",
    "rejecting",
    "clientApproved",
    "clientRejected",
    "decisionError",
    "decisionStale",
    "listLoadError",
    "approvalExplanation",
  ];

  it.each(LOCALES)("%s has every approval string", (locale) => {
    const dictionary = dictionaryFor(locale) as unknown as Record<
      string,
      Record<string, string>
    >;
    for (const key of KEYS) {
      expect({
        locale,
        key,
        present: Boolean(dictionary["oauth-clients"]?.[key]),
      }).toEqual({
        locale,
        key,
        present: true,
      });
    }
  });
});
