/**
 * The destination check on the mcp-proxy's remote-URL transports.
 *
 * DNS is injected on every test that needs it, so nothing here touches a
 * resolver: a suite that decides whether `internal.example.com` is private by
 * asking the network is a suite whose result depends on whose network it ran
 * on. The hostnames below are all `example.com` subdomains for the same
 * reason — they must never resolve to anything real.
 *
 * `server.remote-url.test.ts` next door proves the route actually calls this;
 * a validator can be perfectly correct and still be wired to nothing.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const {
  assertPublicMcpUrl,
  createGuardedFetch,
  createPinnedAgent,
  isBlockedSsrfAddress,
  NOT_A_PERMITTED_TARGET,
  TOO_MANY_REDIRECTS,
  UNREPLAYABLE_REDIRECT_BODY,
} = await import("./url-guard");

/** A routable public address, used wherever "somewhere on the internet" is the point. */
const PUBLIC_V4 = "93.184.216.34";

/** Resolver stub: every hostname answers with the same fixed address list. */
const resolvesTo = (...addresses: string[]) => vi.fn(async () => addresses);

const ORIGINAL_ALLOWED_HOSTS = process.env.MCP_PROXY_URL_ALLOWED_HOSTS;

beforeEach(() => {
  delete process.env.MCP_PROXY_URL_ALLOWED_HOSTS;
});

afterEach(() => {
  if (ORIGINAL_ALLOWED_HOSTS === undefined) {
    delete process.env.MCP_PROXY_URL_ALLOWED_HOSTS;
  } else {
    process.env.MCP_PROXY_URL_ALLOWED_HOSTS = ORIGINAL_ALLOWED_HOSTS;
  }
});

describe("isBlockedSsrfAddress — IPv4", () => {
  it.each([
    ["169.254.169.254", "cloud instance metadata"],
    ["169.254.0.1", "link-local"],
    ["127.0.0.1", "loopback"],
    ["127.255.255.254", "loopback, top of the /8"],
    ["10.1.2.3", "RFC 1918 ten-dot"],
    ["172.16.0.1", "RFC 1918, bottom of the /12"],
    ["172.31.255.255", "RFC 1918, top of the /12"],
    ["192.168.1.1", "RFC 1918 one-nine-two"],
    ["0.0.0.0", "this-network"],
    ["100.64.0.1", "carrier-grade NAT"],
    ["100.127.255.255", "carrier-grade NAT, top of the /10"],
    ["224.0.0.1", "multicast"],
    ["255.255.255.255", "broadcast"],
    ["192.0.0.1", "IETF protocol assignments"],
    ["192.0.0.170", "IETF protocol assignments (NAT64 discovery)"],
    ["192.88.99.1", "6to4 relay anycast"],
    ["198.18.0.1", "benchmarking, bottom of the /15"],
    ["198.19.255.255", "benchmarking, top of the /15"],
  ])("blocks %s (%s)", (address) => {
    expect(isBlockedSsrfAddress(address)).not.toBeNull();
  });

  it.each([
    // The addresses one step outside each blocked range. A check written with
    // an off-by-one mask blocks these too, and nobody notices until a real
    // server stops connecting.
    ["8.8.8.8"],
    ["1.1.1.1"],
    [PUBLIC_V4],
    ["9.255.255.255"],
    ["11.0.0.0"],
    ["100.63.255.255"],
    ["100.128.0.0"],
    ["172.15.255.255"],
    ["172.32.0.0"],
    ["192.167.255.255"],
    ["192.169.0.0"],
    ["192.0.1.1"],
    ["192.88.98.255"],
    ["192.88.100.0"],
    ["198.17.255.255"],
    ["198.20.0.0"],
    ["223.255.255.255"],
  ])("allows %s", (address) => {
    expect(isBlockedSsrfAddress(address)).toBeNull();
  });
});

describe("isBlockedSsrfAddress — IPv6", () => {
  it.each([
    ["::1", "loopback"],
    ["::", "unspecified"],
    ["fe80::1", "link-local"],
    ["febf::1", "link-local, top of the /10"],
    ["fec0::1", "site-local"],
    ["fc00::1", "unique local"],
    ["fd12:3456::1", "unique local"],
    ["ff02::1", "multicast"],
    ["::ffff:127.0.0.1", "IPv4-mapped loopback"],
    ["::ffff:7f00:1", "IPv4-mapped loopback, hextet spelling"],
    ["::ffff:169.254.169.254", "IPv4-mapped metadata address"],
    ["::ffff:10.0.0.1", "IPv4-mapped RFC 1918"],
    ["::127.0.0.1", "IPv4-compatible loopback"],
    ["64:ff9b::169.254.169.254", "NAT64 to the metadata address"],
    ["2002:7f00:1::", "6to4 wrapping loopback"],
    ["::ffff:0:7f00:1", "IPv4-translated (SIIT) loopback"],
    ["::ffff:0:a9fe:a9fe", "IPv4-translated (SIIT) metadata address"],
    ["64:ff9b:1::1", "local-use NAT64 prefix"],
  ])("blocks %s (%s)", (address) => {
    expect(isBlockedSsrfAddress(address)).not.toBeNull();
  });

  it.each([
    ["2606:4700:4700::1111"],
    ["2001:4860:4860::8888"],
    ["::ffff:8.8.8.8"],
    ["64:ff9b::8.8.8.8"],
    ["2002:808:808::"],
  ])("allows %s", (address) => {
    expect(isBlockedSsrfAddress(address)).toBeNull();
  });

  it("refuses anything that is not an IP literal at all", () => {
    // Fail closed. The callers only ever pass a URL host `isIP` accepted or a
    // string a resolver returned, so an unrecognisable value means an
    // assumption broke.
    expect(isBlockedSsrfAddress("mcp.example.com")).not.toBeNull();
    expect(isBlockedSsrfAddress("")).not.toBeNull();
    expect(isBlockedSsrfAddress("999.1.1.1")).not.toBeNull();
  });
});

describe("assertPublicMcpUrl — refusals", () => {
  it.each([
    ["http://169.254.169.254/latest/meta-data/", "cloud instance metadata"],
    ["http://127.0.0.1", "loopback"],
    ["http://127.0.0.1:8080/mcp", "loopback with a port"],
    ["http://10.1.2.3", "RFC 1918"],
    ["http://172.16.0.1", "RFC 1918"],
    ["http://192.168.1.1", "RFC 1918"],
    ["http://[::1]", "IPv6 loopback"],
    ["http://[fe80::1]", "IPv6 link-local"],
    ["http://[::ffff:127.0.0.1]", "IPv4-mapped loopback"],
    ["http://2130706433/", "decimal-literal loopback"],
    ["http://0x7f000001/", "hex-literal loopback"],
    ["http://017700000001/", "octal-literal loopback"],
    ["http://127.1/", "short-form loopback"],
  ])("refuses %s (%s)", async (url) => {
    // No resolver is supplied on purpose: an IP literal must be judged without
    // one, so a stub that answers "public" cannot paper over a missing check.
    await expect(assertPublicMcpUrl(url)).rejects.toThrow(
      NOT_A_PERMITTED_TARGET,
    );
  });

  it("refuses a hostname that RESOLVES to a private address", async () => {
    // The rebinding shape: nothing about the name looks internal, and the
    // answer is what decides.
    const lookup = resolvesTo("10.0.0.5");
    await expect(
      assertPublicMcpUrl("https://mcp.example.com/sse", { lookup }),
    ).rejects.toThrow(NOT_A_PERMITTED_TARGET);
    expect(lookup).toHaveBeenCalledWith("mcp.example.com");
  });

  it("refuses when ANY answer is private, even beside a public one", async () => {
    // Which record the client picks is not something this side controls.
    await expect(
      assertPublicMcpUrl("https://mcp.example.com/sse", {
        lookup: resolvesTo(PUBLIC_V4, "169.254.169.254"),
      }),
    ).rejects.toThrow(NOT_A_PERMITTED_TARGET);
  });

  it.each([
    ["file:///etc/passwd"],
    ["gopher://mcp.example.com/"],
    ["ftp://mcp.example.com/"],
    ["ws://mcp.example.com/"],
  ])("refuses the non-http(s) scheme in %s", async (url) => {
    await expect(
      assertPublicMcpUrl(url, { lookup: resolvesTo(PUBLIC_V4) }),
    ).rejects.toThrow(NOT_A_PERMITTED_TARGET);
  });

  it("refuses a URL that does not parse", async () => {
    await expect(assertPublicMcpUrl("not-a-url")).rejects.toThrow(
      NOT_A_PERMITTED_TARGET,
    );
  });

  it("refuses when the name does not resolve", async () => {
    await expect(
      assertPublicMcpUrl("https://mcp.example.com/sse", {
        lookup: vi.fn(async () => {
          throw new Error("ENOTFOUND");
        }),
      }),
    ).rejects.toThrow(NOT_A_PERMITTED_TARGET);
  });

  it("refuses when the name resolves to nothing", async () => {
    await expect(
      assertPublicMcpUrl("https://mcp.example.com/sse", {
        lookup: resolvesTo(),
      }),
    ).rejects.toThrow(NOT_A_PERMITTED_TARGET);
  });
});

describe("assertPublicMcpUrl — what must keep working", () => {
  it("accepts a public server and returns the parsed URL", async () => {
    // The flow the whole check has to preserve: point the Inspector at a
    // server that is not in the database yet and connect to it.
    const { url, addresses } = await assertPublicMcpUrl(
      "https://mcp.example.com/sse?x=1",
      { lookup: resolvesTo(PUBLIC_V4) },
    );
    expect(url.href).toBe("https://mcp.example.com/sse?x=1");
    // The addresses come back so the caller can PIN to them instead of letting
    // the HTTP client resolve the name a second time.
    expect(addresses).toEqual([PUBLIC_V4]);
  });

  it("accepts a public IPv6 answer", async () => {
    const { url } = await assertPublicMcpUrl("https://mcp.example.com/mcp", {
      lookup: resolvesTo("2606:4700:4700::1111"),
    });
    expect(url.hostname).toBe("mcp.example.com");
  });

  it("accepts a public IP literal without asking a resolver", async () => {
    const lookup = resolvesTo("10.0.0.1");
    const { url } = await assertPublicMcpUrl(`https://${PUBLIC_V4}/mcp`, {
      lookup,
    });
    expect(url.hostname).toBe(PUBLIC_V4);
    expect(lookup).not.toHaveBeenCalled();
  });
});

describe("assertPublicMcpUrl — the allowlist escape hatch", () => {
  it("lets an explicitly allowed host through the range check", async () => {
    const lookup = resolvesTo("10.0.0.5");
    const { url } = await assertPublicMcpUrl(
      "http://internal.example.com/mcp",
      {
        lookup,
        allowedHosts: ["internal.example.com"],
      },
    );
    expect(url.hostname).toBe("internal.example.com");
    expect(lookup).not.toHaveBeenCalled();
  });

  it("reads the allowlist from MCP_PROXY_URL_ALLOWED_HOSTS", async () => {
    process.env.MCP_PROXY_URL_ALLOWED_HOSTS =
      " Internal.Example.com , host.docker.internal ";
    const { url } = await assertPublicMcpUrl(
      "http://host.docker.internal:3000/",
      {
        lookup: resolvesTo("172.17.0.1"),
      },
    );
    expect(url.hostname).toBe("host.docker.internal");
  });

  it("matches a trailing-dot host against a plain allowlist entry", async () => {
    // "example.com." and "example.com" are the same name to a resolver, so
    // they must be the same name to the allowlist.
    const { url } = await assertPublicMcpUrl(
      "http://internal.example.com./mcp",
      {
        lookup: resolvesTo("10.0.0.5"),
        allowedHosts: ["internal.example.com"],
      },
    );
    expect(url.hostname).toBe("internal.example.com.");
  });

  it("is empty by default, so an internal host is still refused", async () => {
    await expect(
      assertPublicMcpUrl("http://internal.example.com/mcp", {
        lookup: resolvesTo("10.0.0.5"),
      }),
    ).rejects.toThrow(NOT_A_PERMITTED_TARGET);
  });

  it("does not let one allowed host vouch for another", async () => {
    await expect(
      assertPublicMcpUrl("http://other.example.com/mcp", {
        lookup: resolvesTo("10.0.0.5"),
        allowedHosts: ["internal.example.com"],
      }),
    ).rejects.toThrow(NOT_A_PERMITTED_TARGET);
  });
});

describe("createGuardedFetch", () => {
  const ok = () => new Response("ok", { status: 200 });
  const redirect = (status: number, location: string) =>
    new Response(null, { status, headers: { location } });

  it("refuses before the first connection, so nothing is opened", async () => {
    const baseFetch = vi.fn(async () => ok());
    const guarded = createGuardedFetch({ baseFetch });

    await expect(
      guarded("http://169.254.169.254/latest/meta-data/"),
    ).rejects.toThrow(NOT_A_PERMITTED_TARGET);
    expect(baseFetch).not.toHaveBeenCalled();
  });

  it("never lets the HTTP client follow a redirect itself", async () => {
    // `redirect: "follow"` means undici resolves and connects to the Location
    // target with none of these checks applied to it.
    const baseFetch = vi.fn(async (_url: string | URL, _init?: RequestInit) =>
      ok(),
    );
    const guarded = createGuardedFetch({
      baseFetch,
      lookup: resolvesTo(PUBLIC_V4),
    });

    await guarded("https://mcp.example.com/mcp");

    expect(baseFetch).toHaveBeenCalledTimes(1);
    expect(baseFetch.mock.calls[0][1]?.redirect).toBe("manual");
  });

  it("REFUSES a redirect that points at an internal address", async () => {
    // The bypass the range check alone does not stop: a URL that validates as
    // public answering 302 to the metadata address.
    const baseFetch = vi
      .fn()
      .mockResolvedValueOnce(redirect(302, "http://169.254.169.254/"))
      .mockResolvedValueOnce(ok());
    const guarded = createGuardedFetch({
      baseFetch,
      lookup: resolvesTo(PUBLIC_V4),
    });

    await expect(guarded("https://mcp.example.com/mcp")).rejects.toThrow(
      NOT_A_PERMITTED_TARGET,
    );
    expect(baseFetch).toHaveBeenCalledTimes(1);
  });

  it("follows a same-origin redirect", async () => {
    const baseFetch = vi
      .fn()
      .mockResolvedValueOnce(redirect(302, "https://mcp.example.com/mcp/"))
      .mockResolvedValueOnce(ok());
    const guarded = createGuardedFetch({
      baseFetch,
      lookup: resolvesTo(PUBLIC_V4),
    });

    const response = await guarded("https://mcp.example.com/mcp", {
      headers: { authorization: "Bearer caller-token", accept: "text/plain" },
    });

    expect(response.status).toBe(200);
    expect(baseFetch).toHaveBeenCalledTimes(2);
    expect(String(baseFetch.mock.calls[1][0])).toBe(
      "https://mcp.example.com/mcp/",
    );
    // Same origin, so the credential still belongs on the request.
    expect(baseFetch.mock.calls[1][1].headers.get("authorization")).toBe(
      "Bearer caller-token",
    );
  });

  it("strips credential headers when a redirect changes origin", async () => {
    // The headers on these requests carry the caller's bearer token and the
    // server row's stored vendor keys. A redirect is the cheapest way to ask
    // for them, and a custom-named auth header would survive fetch's own
    // Authorization-only rule.
    const baseFetch = vi
      .fn()
      .mockResolvedValueOnce(redirect(302, "https://elsewhere.example.com/mcp"))
      .mockResolvedValueOnce(ok());
    const guarded = createGuardedFetch({
      baseFetch,
      lookup: resolvesTo(PUBLIC_V4),
    });

    await guarded("https://mcp.example.com/mcp", {
      headers: {
        authorization: "Bearer caller-token",
        "x-vendor-api-key": "row-secret",
        accept: "text/event-stream",
      },
    });

    const forwarded = baseFetch.mock.calls[1][1].headers as Headers;
    expect(forwarded.get("authorization")).toBeNull();
    expect(forwarded.get("x-vendor-api-key")).toBeNull();
    expect(forwarded.get("accept")).toBe("text/event-stream");
  });

  it("rewrites a POST to a GET across a 303 and drops the body", async () => {
    const baseFetch = vi
      .fn()
      .mockResolvedValueOnce(redirect(303, "https://mcp.example.com/done"))
      .mockResolvedValueOnce(ok());
    const guarded = createGuardedFetch({
      baseFetch,
      lookup: resolvesTo(PUBLIC_V4),
    });

    await guarded("https://mcp.example.com/mcp", {
      method: "POST",
      body: '{"jsonrpc":"2.0"}',
      headers: { "content-type": "application/json" },
    });

    const followUp = baseFetch.mock.calls[1][1];
    expect(followUp.method).toBe("GET");
    expect(followUp.body).toBeUndefined();
    expect(followUp.headers.get("content-type")).toBeNull();
  });

  it("preserves method and body across a 307", async () => {
    const baseFetch = vi
      .fn()
      .mockResolvedValueOnce(redirect(307, "https://mcp.example.com/v2"))
      .mockResolvedValueOnce(ok());
    const guarded = createGuardedFetch({
      baseFetch,
      lookup: resolvesTo(PUBLIC_V4),
    });

    await guarded("https://mcp.example.com/mcp", {
      method: "POST",
      body: '{"jsonrpc":"2.0"}',
    });

    const followUp = baseFetch.mock.calls[1][1];
    expect(followUp.method).toBe("POST");
    expect(followUp.body).toBe('{"jsonrpc":"2.0"}');
  });

  it("refuses a method-preserving redirect whose body cannot be resent", async () => {
    const baseFetch = vi
      .fn()
      .mockResolvedValueOnce(redirect(308, "https://mcp.example.com/v2"))
      .mockResolvedValueOnce(ok());
    const guarded = createGuardedFetch({
      baseFetch,
      lookup: resolvesTo(PUBLIC_V4),
    });

    await expect(
      guarded("https://mcp.example.com/mcp", {
        method: "POST",
        body: new ReadableStream(),
        duplex: "half",
      } as RequestInit),
    ).rejects.toThrow(UNREPLAYABLE_REDIRECT_BODY);
  });

  it("gives up on an endless redirect chain", async () => {
    let hop = 0;
    const baseFetch = vi.fn(async () =>
      redirect(302, `https://mcp.example.com/hop${(hop += 1)}`),
    );
    const guarded = createGuardedFetch({
      baseFetch,
      lookup: resolvesTo(PUBLIC_V4),
    });

    await expect(guarded("https://mcp.example.com/mcp")).rejects.toThrow(
      TOO_MANY_REDIRECTS,
    );
    // Pins the cap itself: hop 0 plus MAX_REDIRECT_HOPS follow-ups, then stop.
    // Without this the chain could grow to any length and still "pass".
    expect(baseFetch.mock.calls.length).toBe(6);
  });

  it("returns a normal response untouched", async () => {
    const baseFetch = vi.fn(async () => ok());
    const guarded = createGuardedFetch({
      baseFetch,
      lookup: resolvesTo(PUBLIC_V4),
    });

    const response = await guarded("https://mcp.example.com/mcp");
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("ok");
  });
});

/**
 * The refusal must carry no information about WHY.
 *
 * `rejects.toThrow(str)` is a SUBSTRING match, so every refusal test above
 * would still pass if the message grew a "because 10.0.0.5 is private" tail.
 * These assert equality, and that the host never appears.
 */
describe("assertPublicMcpUrl — the refusal is an oracle-free constant", () => {
  const messageFor = async (
    url: string,
    options: Parameters<typeof assertPublicMcpUrl>[1] = {},
  ) => {
    try {
      await assertPublicMcpUrl(url, options);
      throw new Error("expected a refusal");
    } catch (error) {
      return (error as Error).message;
    }
  };

  it("is identical for a private literal, a private answer, and a dead name", async () => {
    const literal = await messageFor("http://10.1.2.3/mcp");
    const resolved = await messageFor("https://a.example.com/mcp", {
      lookup: resolvesTo("10.0.0.5"),
    });
    const dead = await messageFor("https://b.example.com/mcp", {
      lookup: vi.fn(async () => {
        throw new Error("ENOTFOUND");
      }),
    });

    expect(literal).toBe(NOT_A_PERMITTED_TARGET);
    expect(resolved).toBe(NOT_A_PERMITTED_TARGET);
    expect(dead).toBe(NOT_A_PERMITTED_TARGET);
    // Told apart, these three answer "is this address internal" and "does this
    // name exist" — the two questions a blind SSRF is asking.
    expect(new Set([literal, resolved, dead]).size).toBe(1);
  });

  it("never names the host or the address it refused", async () => {
    const message = await messageFor("https://leaky.example.com/mcp", {
      lookup: resolvesTo("169.254.169.254"),
    });

    expect(message).not.toContain("leaky");
    expect(message).not.toContain("169.254");
    expect(message).not.toContain("10.");
  });
});

describe("createGuardedFetch — the connection is pinned to the validated address", () => {
  const ok = () => new Response("ok", { status: 200 });

  it("connects to the pinned address even when the name cannot resolve AT ALL", async () => {
    // The pin, proven at socket level. `.invalid` is guaranteed unresolvable
    // (RFC 2606), so a connection that still succeeds can only have used the
    // pinned address — which is precisely what a rebind cannot influence,
    // because the second resolution never happens.
    const { createServer } = await import("node:http");
    const { fetch: undiciFetch } = await import("undici");

    const server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("pinned");
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", () => resolve()),
    );
    const { port } = server.address() as { port: number };

    const agent = createPinnedAgent(["127.0.0.1"]);
    try {
      const response = await undiciFetch(
        `http://this-name-cannot-resolve.invalid:${port}/`,
        { dispatcher: agent },
      );
      expect(response.status).toBe(200);
      expect(await response.text()).toBe("pinned");
    } finally {
      await agent.close();
      server.close();
    }
  });

  it("hands the transport a dispatcher built from the validated answer", async () => {
    // A resolver that turns hostile immediately after validation. It must be
    // consulted exactly once: everything after that rides the pin.
    const lookup = vi
      .fn()
      .mockResolvedValueOnce([PUBLIC_V4])
      .mockResolvedValue(["169.254.169.254"]);
    const dispatchers: unknown[] = [];
    const baseFetch = vi.fn(
      async (_url: URL, _init: RequestInit, dispatcher?: unknown) => {
        dispatchers.push(dispatcher);
        return ok();
      },
    );

    const guarded = createGuardedFetch({ baseFetch, lookup });
    await guarded("https://rebind.example.com/mcp");

    expect(lookup).toHaveBeenCalledTimes(1);
    expect(dispatchers[0]).toBeDefined();
  });

  it("does NOT pin an allowlisted host, which is trusted by name", async () => {
    const dispatchers: unknown[] = [];
    const baseFetch = vi.fn(
      async (_url: URL, _init: RequestInit, dispatcher?: unknown) => {
        dispatchers.push(dispatcher);
        return ok();
      },
    );

    const guarded = createGuardedFetch({
      baseFetch,
      allowedHosts: ["host.docker.internal"],
      allowlistOrigin: "http://host.docker.internal:3000",
      lookup: resolvesTo("172.17.0.1"),
    });
    await guarded("http://host.docker.internal:3000/sse");

    expect(dispatchers[0]).toBeUndefined();
  });
});

describe("createGuardedFetch — the allowlist covers hop 0 only", () => {
  const ok = () => new Response("ok", { status: 200 });
  const redirect = (status: number, location: string) =>
    new Response(null, { status, headers: { location } });

  const ALLOWED = "host.docker.internal";
  // The allowlisted host resolves PRIVATE — that is the whole reason it needs
  // an allowlist entry. Everything else is public.
  const lookup = vi.fn(async (hostname: string) =>
    hostname === ALLOWED ? ["172.17.0.1"] : [PUBLIC_V4],
  );
  const guardWith = (baseFetch: unknown) =>
    createGuardedFetch({
      baseFetch: baseFetch as never,
      allowedHosts: [ALLOWED],
      allowlistOrigin: "http://host.docker.internal:3000",
      lookup,
    });

  it("still connects to the operator's own allowlisted URL", async () => {
    const baseFetch = vi.fn(async () => ok());
    const response = await guardWith(baseFetch)(
      "http://host.docker.internal:3000/sse",
    );

    expect(response.status).toBe(200);
    expect(baseFetch).toHaveBeenCalledTimes(1);
  });

  it("REFUSES a public server that redirects into the allowlisted host", async () => {
    // The hole this closes: an entry meant to unblock the operator's own
    // internal host would otherwise unblock an attacker's 302 into it.
    const baseFetch = vi
      .fn()
      .mockResolvedValueOnce(
        redirect(302, "http://host.docker.internal:3000/sse"),
      )
      .mockResolvedValueOnce(ok());

    await expect(
      guardWith(baseFetch)("https://attacker.example.com/mcp"),
    ).rejects.toThrow(NOT_A_PERMITTED_TARGET);
    expect(baseFetch).toHaveBeenCalledTimes(1);
  });

  it("REFUSES an allowlisted destination reached from another origin", async () => {
    // The SSE back-channel shape: the endpoint is chosen by the REMOTE server,
    // so it is not the URL the operator vouched for even at hop 0.
    const baseFetch = vi.fn(async () => ok());

    await expect(
      guardWith(baseFetch)("http://host.docker.internal:9999/hijacked"),
    ).rejects.toThrow(NOT_A_PERMITTED_TARGET);
    expect(baseFetch).not.toHaveBeenCalled();
  });
});

describe("createGuardedFetch — every hop is re-validated, not just the first", () => {
  const ok = () => new Response("ok", { status: 200 });
  const redirect = (status: number, location: string) =>
    new Response(null, { status, headers: { location } });

  it("catches an internal target on the SECOND hop", async () => {
    // Pins the loop rather than the first iteration: a check written as
    // `if (hop === 0)` passes every other redirect test in this file.
    const baseFetch = vi
      .fn()
      .mockResolvedValueOnce(redirect(302, "https://second.example.com/b"))
      .mockResolvedValueOnce(redirect(302, "http://169.254.169.254/"))
      .mockResolvedValueOnce(ok());
    const guarded = createGuardedFetch({
      baseFetch,
      lookup: resolvesTo(PUBLIC_V4),
    });

    await expect(guarded("https://first.example.com/a")).rejects.toThrow(
      NOT_A_PERMITTED_TARGET,
    );
    // Two connections happened; the third was refused before it was opened.
    expect(baseFetch).toHaveBeenCalledTimes(2);
  });
});
