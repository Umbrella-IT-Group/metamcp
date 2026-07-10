/**
 * THE INJECTION INVARIANT (design doc §4.2): the gateway only ever
 * injects genuine Graph-scoped tokens minted for the request's own
 * user, never forwards the inbound consumer credential, and sends no
 * Authorization at all when no user context exists. These tests are
 * the unit-tested guarantee the design doc references.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

// injected-fetch imports the mint service, whose default repo import
// pulls in the drizzle client (hard-requires DATABASE_URL at module
// load). All tests here inject mint stubs — mock the db module away.
vi.mock("../../db/index", () => ({ db: {} }));

import { M365BrokerError } from "./errors";
import { makeM365InjectedFetch, USER_ID_HEADER } from "./injected-fetch";
import type { M365MintService } from "./mint-service";
import { runWithM365UserContext } from "./request-context";

function makeMintStub(result: string | Error) {
  return {
    getAccessToken: vi.fn(async (_userId: string) => {
      if (result instanceof Error) throw result;
      return result;
    }),
  } as unknown as M365MintService;
}

function makeBaseFetch() {
  const seen: { url: string; headers: Headers }[] = [];
  const baseFetch = vi.fn(async (url: string | URL, init?: RequestInit) => {
    seen.push({ url: String(url), headers: new Headers(init?.headers) });
    return new Response("{}", { status: 200 });
  });
  return { baseFetch, seen };
}

describe("m365 injected fetch — the injection invariant", () => {
  beforeEach(() => {
    vi.unstubAllEnvs();
  });

  it("invariant 3: no user context → NO Authorization header and no mint", async () => {
    const mint = makeMintStub("should-not-be-used");
    const { baseFetch, seen } = makeBaseFetch();
    const injected = makeM365InjectedFetch(mint, baseFetch);

    await injected("http://mcp-m365:3000/mcp", { method: "POST" });

    expect(mint.getAccessToken).not.toHaveBeenCalled();
    expect(seen[0].headers.has("authorization")).toBe(false);
    expect(seen[0].headers.has(USER_ID_HEADER)).toBe(false);
  });

  it("invariant 1: strips an inbound Authorization credential even without context", async () => {
    const mint = makeMintStub("unused");
    const { baseFetch, seen } = makeBaseFetch();
    const injected = makeM365InjectedFetch(mint, baseFetch);

    await injected("http://mcp-m365:3000/mcp", {
      method: "POST",
      headers: {
        Authorization: "Bearer mcp_token_CONSUMER_CREDENTIAL",
        "Content-Type": "application/json",
      },
    });

    expect(seen[0].headers.has("authorization")).toBe(false);
    // Non-credential headers survive untouched.
    expect(seen[0].headers.get("content-type")).toBe("application/json");
  });

  it("invariant 2: with context, injects exactly the token minted for that user", async () => {
    const mint = makeMintStub("graph-access-token-for-alex");
    const { baseFetch, seen } = makeBaseFetch();
    const injected = makeM365InjectedFetch(mint, baseFetch);

    await runWithM365UserContext({ userId: "user-alex" }, () =>
      injected("http://mcp-m365:3000/mcp", {
        method: "POST",
        headers: { Authorization: "Bearer mcp_token_CONSUMER_CREDENTIAL" },
      }),
    );

    expect(mint.getAccessToken).toHaveBeenCalledWith("user-alex");
    expect(seen[0].headers.get("authorization")).toBe(
      "Bearer graph-access-token-for-alex",
    );
    expect(seen[0].headers.get(USER_ID_HEADER)).toBe("user-alex");
  });

  it("invariant 2: the inbound consumer credential can never survive injection", async () => {
    const mint = makeMintStub("minted-token");
    const { baseFetch, seen } = makeBaseFetch();
    const injected = makeM365InjectedFetch(mint, baseFetch);

    await runWithM365UserContext({ userId: "u1" }, () =>
      injected("http://mcp-m365:3000/mcp", {
        headers: new Headers({
          authorization: "Bearer mcp_token_SHOULD_DIE",
          [USER_ID_HEADER]: "spoofed-user",
        }),
      }),
    );

    const auth = seen[0].headers.get("authorization");
    expect(auth).toBe("Bearer minted-token");
    expect(auth).not.toContain("mcp_token_");
    expect(seen[0].headers.get(USER_ID_HEADER)).toBe("u1");
  });

  it("context propagates through async hops (awaits between wrap and dispatch)", async () => {
    const mint = makeMintStub("token-after-hops");
    const { baseFetch, seen } = makeBaseFetch();
    const injected = makeM365InjectedFetch(mint, baseFetch);

    await runWithM365UserContext({ userId: "hop-user" }, async () => {
      await new Promise((resolve) => setTimeout(resolve, 5));
      await new Promise((resolve) => setImmediate(resolve));
      await injected("http://mcp-m365:3000/mcp");
    });

    expect(seen[0].headers.get(USER_ID_HEADER)).toBe("hop-user");
  });

  it("invariant 4: mint failure propagates as the typed broker error", async () => {
    const error = new M365BrokerError(
      "credential_missing",
      "No Microsoft 365 account is connected for your user yet.",
      "https://mcp.example.com/m365/enroll",
    );
    const mint = makeMintStub(error);
    const { baseFetch } = makeBaseFetch();
    const injected = makeM365InjectedFetch(mint, baseFetch);

    await expect(
      runWithM365UserContext({ userId: "u1" }, () =>
        injected("http://mcp-m365:3000/mcp"),
      ),
    ).rejects.toBe(error);
    expect(baseFetch).not.toHaveBeenCalled();
  });

  it("empty/partial context is treated as no context (fail-closed)", async () => {
    const mint = makeMintStub("unused");
    const { baseFetch, seen } = makeBaseFetch();
    const injected = makeM365InjectedFetch(mint, baseFetch);

    await runWithM365UserContext({ userId: "" }, () =>
      injected("http://mcp-m365:3000/mcp"),
    );

    expect(mint.getAccessToken).not.toHaveBeenCalled();
    expect(seen[0].headers.has("authorization")).toBe(false);
  });
});

describe("getInjectedFetchForServer wiring", () => {
  it("returns a fetch only for configured server names", async () => {
    vi.stubEnv("M365_INJECTED_SERVER_NAMES", "m365,m365-staging");
    const { getInjectedFetchForServer } = await import("./injected-fetch");
    expect(getInjectedFetchForServer("m365")).toBeDefined();
    expect(getInjectedFetchForServer("m365-staging")).toBeDefined();
    expect(getInjectedFetchForServer("m365-assistant")).toBeUndefined();
    expect(getInjectedFetchForServer("autotask")).toBeUndefined();
    vi.unstubAllEnvs();
  });

  it("defaults to exactly the `m365` server", async () => {
    vi.unstubAllEnvs();
    const { getInjectedFetchForServer } = await import("./injected-fetch");
    expect(getInjectedFetchForServer("m365")).toBeDefined();
    expect(getInjectedFetchForServer("m365-assistant")).toBeUndefined();
  });
});
