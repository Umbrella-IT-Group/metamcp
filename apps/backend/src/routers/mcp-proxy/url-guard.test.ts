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
    const url = await assertPublicMcpUrl("https://mcp.example.com/sse?x=1", {
      lookup: resolvesTo(PUBLIC_V4),
    });
    expect(url.href).toBe("https://mcp.example.com/sse?x=1");
  });

  it("accepts a public IPv6 answer", async () => {
    const url = await assertPublicMcpUrl("https://mcp.example.com/mcp", {
      lookup: resolvesTo("2606:4700:4700::1111"),
    });
    expect(url.hostname).toBe("mcp.example.com");
  });

  it("accepts a public IP literal without asking a resolver", async () => {
    const lookup = resolvesTo("10.0.0.1");
    const url = await assertPublicMcpUrl(`https://${PUBLIC_V4}/mcp`, {
      lookup,
    });
    expect(url.hostname).toBe(PUBLIC_V4);
    expect(lookup).not.toHaveBeenCalled();
  });
});

describe("assertPublicMcpUrl — the allowlist escape hatch", () => {
  it("lets an explicitly allowed host through the range check", async () => {
    const lookup = resolvesTo("10.0.0.5");
    const url = await assertPublicMcpUrl("http://internal.example.com/mcp", {
      lookup,
      allowedHosts: ["internal.example.com"],
    });
    expect(url.hostname).toBe("internal.example.com");
    expect(lookup).not.toHaveBeenCalled();
  });

  it("reads the allowlist from MCP_PROXY_URL_ALLOWED_HOSTS", async () => {
    process.env.MCP_PROXY_URL_ALLOWED_HOSTS =
      " Internal.Example.com , host.docker.internal ";
    const url = await assertPublicMcpUrl("http://host.docker.internal:3000/", {
      lookup: resolvesTo("172.17.0.1"),
    });
    expect(url.hostname).toBe("host.docker.internal");
  });

  it("matches a trailing-dot host against a plain allowlist entry", async () => {
    // "example.com." and "example.com" are the same name to a resolver, so
    // they must be the same name to the allowlist.
    const url = await assertPublicMcpUrl("http://internal.example.com./mcp", {
      lookup: resolvesTo("10.0.0.5"),
      allowedHosts: ["internal.example.com"],
    });
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
