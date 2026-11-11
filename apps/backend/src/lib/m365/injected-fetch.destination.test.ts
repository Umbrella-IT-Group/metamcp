/**
 * Invariant 7 at the guard: the per-user Graph token and user id are minted
 * and attached only on a hop whose destination the guarded fetch resolved,
 * pinned and found internal by address (url-guard.ts,
 * `InternalOnlyCredentials`). Each case below drives `makeM365InjectedFetch`
 * (the guarded fetch with the m365 credential) over a fake transport and a
 * fake resolver, so the addresses a name answers are part of the case.
 *
 * Covered: a name resolving to internal, public and mixed addresses; a host
 * on the allowlist (trusted by name, never pinned); redirects that keep the
 * POST (307/308), that rewrite it to a GET (301/302/303), that cross origins,
 * and that stay on the origin while the name re-resolves elsewhere.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../db/index", () => ({ db: {} }));
vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import logger from "@/utils/logger";

import {
  CROSS_ORIGIN_REDIRECT_REFUSED,
  type McpUrlGuardOptions,
} from "../metamcp/url-guard";
import { M365BrokerError } from "./errors";
import { makeM365InjectedFetch, USER_ID_HEADER } from "./injected-fetch";
import type { M365MintService } from "./mint-service";
import { runWithM365UserContext } from "./request-context";

const URL_NAMED = "http://mcp-m365:3000/mcp";

interface Sent {
  url: string;
  method: string;
  authorization: string | null;
  userId: string | null;
  body: unknown;
}

type Reply = (url: URL) => Response;

/** A transport that records each request and answers from `replies`, in order. */
function fakeTransport(replies: Reply[] = []) {
  const sent: Sent[] = [];
  const baseFetch = vi.fn(async (url: string | URL, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    sent.push({
      url: String(url),
      method: init?.method ?? "GET",
      authorization: headers.get("authorization"),
      userId: headers.get(USER_ID_HEADER),
      body: init?.body,
    });
    const reply = replies[sent.length - 1];
    return reply
      ? reply(new URL(String(url)))
      : new Response("{}", { status: 200 });
  });
  return { baseFetch, sent };
}

const redirect =
  (status: number, location: string): Reply =>
  () =>
    new Response(null, { status, headers: { location } });

function mintReturning(token: string) {
  return {
    getAccessToken: vi.fn(async () => token),
  } as unknown as M365MintService;
}

function mintFailing() {
  return {
    getAccessToken: vi.fn(async () => {
      throw new M365BrokerError("credential_missing", "not enrolled");
    }),
  } as unknown as M365MintService;
}

/** The pooled data plane's posture over the fake transport and resolver. */
const pooled = (
  baseFetch: McpUrlGuardOptions["baseFetch"],
  answers: Record<string, string[]> | ((host: string) => string[]),
  extra: McpUrlGuardOptions = {},
): McpUrlGuardOptions => ({
  allowPrivateAddresses: true,
  refuseCrossOriginRedirect: true,
  baseFetch,
  lookup: async (host) =>
    typeof answers === "function" ? answers(host) : (answers[host] ?? []),
  ...extra,
});

const toolCall = (): RequestInit => ({
  method: "POST",
  headers: {
    "content-type": "application/json",
    authorization: "Bearer row-level-credential",
  },
  body: JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name: "mail_search", arguments: {} },
  }),
});

const asUser = <T>(userId: string, run: () => Promise<T>) =>
  runWithM365UserContext({ userId }, run);

beforeEach(() => {
  vi.mocked(logger.warn).mockClear();
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("the destination decides, by resolved address", () => {
  it("a name resolving to an internal address gets the caller's token and user id", async () => {
    const mint = mintReturning("graph-token");
    const { baseFetch, sent } = fakeTransport();
    const injected = makeM365InjectedFetch(
      mint,
      pooled(baseFetch, { "mcp-m365": ["10.20.0.5"] }),
    );
    await asUser("user-a", () => injected(URL_NAMED, toolCall()));
    expect(sent).toHaveLength(1);
    expect(sent[0].authorization).toBe("Bearer graph-token");
    expect(sent[0].userId).toBe("user-a");
  });

  it.each([
    ["a public address", ["203.0.113.10"]],
    ["a public IPv6 address", ["2001:db8::10"]],
    ["one internal and one public address", ["10.20.0.5", "203.0.113.10"]],
  ])(
    "a name resolving to %s gets neither header, and nothing is minted even when minting would fail",
    async (_label, addresses) => {
      const mint = mintFailing();
      const { baseFetch, sent } = fakeTransport();
      const injected = makeM365InjectedFetch(
        mint,
        pooled(baseFetch, { "mcp-m365": addresses }),
      );
      await asUser("user-a", () => injected(URL_NAMED, toolCall()));
      expect(sent).toHaveLength(1);
      expect(sent[0].authorization).toBeNull();
      expect(sent[0].userId).toBeNull();
      expect(mint.getAccessToken).not.toHaveBeenCalled();
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining("(not_internal)"),
      );
    },
  );

  it("a host on the allowlist is trusted by name, not by address, so it gets neither header", async () => {
    const mint = mintFailing();
    const { baseFetch, sent } = fakeTransport();
    const lookup = vi.fn(async () => ["10.20.0.5"]);
    const injected = makeM365InjectedFetch(mint, {
      ...pooled(baseFetch, {}),
      lookup,
      allowedHosts: ["mcp-m365"],
    });
    await asUser("user-a", () => injected(URL_NAMED, toolCall()));
    expect(sent).toHaveLength(1);
    expect(sent[0].authorization).toBeNull();
    expect(sent[0].userId).toBeNull();
    expect(mint.getAccessToken).not.toHaveBeenCalled();
    // The allowlist shortcut never resolves the name; nothing was pinned.
    expect(lookup).not.toHaveBeenCalled();
    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining("(not_pinned)"),
    );
  });

  it("the allowlist from the environment is held to the same rule", async () => {
    vi.stubEnv("MCP_PROXY_URL_ALLOWED_HOSTS", "mcp-m365");
    const mint = mintFailing();
    const { baseFetch, sent } = fakeTransport();
    const injected = makeM365InjectedFetch(
      mint,
      pooled(baseFetch, { "mcp-m365": ["10.20.0.5"] }),
    );
    await asUser("user-a", () => injected(URL_NAMED, toolCall()));
    expect(sent[0].authorization).toBeNull();
    expect(mint.getAccessToken).not.toHaveBeenCalled();
  });

  it("a request with no user context sends no credential to an internal backend either", async () => {
    const mint = mintReturning("graph-token");
    const { baseFetch, sent } = fakeTransport();
    const injected = makeM365InjectedFetch(
      mint,
      pooled(baseFetch, { "mcp-m365": ["10.20.0.5"] }),
    );
    await injected(URL_NAMED, toolCall());
    expect(sent[0].authorization).toBeNull();
    expect(mint.getAccessToken).not.toHaveBeenCalled();
    expect(logger.warn).not.toHaveBeenCalled();
  });

  it("concurrent callers each get only their own token", async () => {
    const mint = {
      getAccessToken: vi.fn(async (userId: string) => {
        await new Promise((resolve) =>
          setTimeout(resolve, userId === "user-a" ? 15 : 1),
        );
        return `token-of-${userId}`;
      }),
    } as unknown as M365MintService;
    const { baseFetch, sent } = fakeTransport();
    const injected = makeM365InjectedFetch(
      mint,
      pooled(baseFetch, { "mcp-m365": ["10.20.0.5"] }),
    );
    await Promise.all([
      asUser("user-a", () => injected(URL_NAMED, toolCall())),
      asUser("user-b", () => injected(URL_NAMED, toolCall())),
    ]);
    expect(sent).toHaveLength(2);
    for (const request of sent) {
      expect(request.authorization).toBe(`Bearer token-of-${request.userId}`);
    }
    expect(new Set(sent.map((request) => request.userId))).toEqual(
      new Set(["user-a", "user-b"]),
    );
  });
});

describe("every redirect hop is decided again", () => {
  const internal = { "mcp-m365": ["10.20.0.5"] };

  it.each([307, 308])(
    "a same-origin %i replays the POST and keeps the token",
    async (status) => {
      const mint = mintReturning("graph-token");
      const { baseFetch, sent } = fakeTransport([
        redirect(status, "/mcp/next"),
      ]);
      const injected = makeM365InjectedFetch(mint, pooled(baseFetch, internal));
      await asUser("user-a", () => injected(URL_NAMED, toolCall()));
      expect(sent.map((request) => request.method)).toEqual(["POST", "POST"]);
      expect(sent[1].url).toBe("http://mcp-m365:3000/mcp/next");
      expect(sent[1].authorization).toBe("Bearer graph-token");
      expect(sent[1].userId).toBe("user-a");
      expect(sent[1].body).toBe(sent[0].body);
    },
  );

  it.each([301, 302, 303])(
    "a same-origin %i that turns the POST into a GET drops the token and the user id",
    async (status) => {
      const mint = mintReturning("graph-token");
      const { baseFetch, sent } = fakeTransport([
        redirect(status, "/mcp/next"),
      ]);
      const injected = makeM365InjectedFetch(mint, pooled(baseFetch, internal));
      await asUser("user-a", () => injected(URL_NAMED, toolCall()));
      expect(sent.map((request) => request.method)).toEqual(["POST", "GET"]);
      expect(sent[0].authorization).toBe("Bearer graph-token");
      expect(sent[1].authorization).toBeNull();
      expect(sent[1].userId).toBeNull();
      expect(sent[1].body).toBeUndefined();
    },
  );

  it("a same-origin 307 whose name now resolves to a public address loses the token", async () => {
    const mint = mintReturning("graph-token");
    const { baseFetch, sent } = fakeTransport([redirect(307, "/mcp/next")]);
    let lookups = 0;
    const injected = makeM365InjectedFetch(
      mint,
      pooled(baseFetch, () => {
        lookups += 1;
        return lookups === 1 ? ["10.20.0.5"] : ["203.0.113.10"];
      }),
    );
    await asUser("user-a", () => injected(URL_NAMED, toolCall()));
    expect(sent).toHaveLength(2);
    expect(sent[0].authorization).toBe("Bearer graph-token");
    expect(sent[1].authorization).toBeNull();
    expect(sent[1].userId).toBeNull();
  });

  it("a cross-origin redirect is refused, even under a posture that would follow it", async () => {
    const mint = mintReturning("graph-token");
    const { baseFetch, sent } = fakeTransport([
      redirect(307, "http://elsewhere:3000/mcp"),
    ]);
    const injected = makeM365InjectedFetch(mint, {
      ...pooled(baseFetch, {
        "mcp-m365": ["10.20.0.5"],
        elsewhere: ["10.20.0.9"],
      }),
      refuseCrossOriginRedirect: false,
    });
    await expect(
      asUser("user-a", () => injected(URL_NAMED, toolCall())),
    ).rejects.toThrow(CROSS_ORIGIN_REDIRECT_REFUSED);
    expect(sent).toHaveLength(1);
  });

  it("a redirect from a public first hop to an internal one on the same origin mints only for the internal hop", async () => {
    const mint = mintReturning("graph-token");
    const { baseFetch, sent } = fakeTransport([redirect(307, "/mcp/next")]);
    let lookups = 0;
    const injected = makeM365InjectedFetch(
      mint,
      pooled(baseFetch, () => {
        lookups += 1;
        return lookups === 1 ? ["203.0.113.10"] : ["10.20.0.5"];
      }),
    );
    await asUser("user-a", () => injected(URL_NAMED, toolCall()));
    expect(sent[0].authorization).toBeNull();
    expect(sent[1].authorization).toBe("Bearer graph-token");
    expect(mint.getAccessToken).toHaveBeenCalledTimes(1);
  });
});
