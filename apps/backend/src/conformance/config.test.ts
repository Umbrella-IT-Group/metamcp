/**
 * The proxy attaches a gateway key to everything it forwards, so its config
 * parser is the guard that stops that key being pointed anywhere but loopback.
 *
 * Oracle: the contract in config.ts (loopback http only; key of at least 32
 * characters with no whitespace, matching the gateway's own bootstrap rule in
 * lib/bootstrap.service.ts; a valid TCP port).
 */
import { describe, expect, it } from "vitest";

import {
  parseFixtureConfig,
  parseProxyConfig,
  parseSmokeConfig,
} from "./config";

const KEY = `sk_mt_${"0123456789abcdef".repeat(4)}`;
const base = {
  CONFORMANCE_UPSTREAM_URL: "http://127.0.0.1:12009/metamcp/conformance/mcp",
  CONFORMANCE_API_KEY: KEY,
  CONFORMANCE_TOOL_PREFIX: "Fixture",
};

describe("parseProxyConfig", () => {
  it("accepts a loopback upstream and applies the default port", () => {
    expect(parseProxyConfig(base)).toEqual({
      upstreamUrl: base.CONFORMANCE_UPSTREAM_URL,
      apiKey: KEY,
      prefix: "Fixture",
      port: 3902,
    });
    expect(
      parseProxyConfig({
        ...base,
        CONFORMANCE_UPSTREAM_URL: "http://localhost:1/mcp",
      }).upstreamUrl,
    ).toBe("http://localhost:1/mcp");
  });

  it("refuses an upstream that is not loopback http, so the key cannot be sent elsewhere", () => {
    for (const url of [
      "http://gateway.example.com/mcp",
      "http://10.0.0.5:12009/mcp",
      "https://127.0.0.1:12009/mcp",
      "http://localhost.example.com/mcp",
      "not a url",
    ]) {
      expect(
        () => parseProxyConfig({ ...base, CONFORMANCE_UPSTREAM_URL: url }),
        url,
      ).toThrow();
    }
  });

  it("refuses a short or whitespace-bearing key without echoing it", () => {
    for (const key of ["short", `${KEY} `, `${KEY}\n`, "x y".repeat(20)]) {
      let message = "";
      try {
        parseProxyConfig({ ...base, CONFORMANCE_API_KEY: key });
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message, JSON.stringify(key)).not.toBe("");
      expect(message).not.toContain(key.trim() || "x");
    }
  });

  it("refuses a missing upstream, key or prefix, and a prefix with odd characters", () => {
    for (const drop of [
      "CONFORMANCE_UPSTREAM_URL",
      "CONFORMANCE_API_KEY",
      "CONFORMANCE_TOOL_PREFIX",
    ]) {
      expect(
        () => parseProxyConfig({ ...base, [drop]: undefined }),
        drop,
      ).toThrow();
    }
    expect(() =>
      parseProxyConfig({ ...base, CONFORMANCE_TOOL_PREFIX: "a b" }),
    ).toThrow();
    expect(() =>
      parseProxyConfig({ ...base, CONFORMANCE_TOOL_PREFIX: "a__b/c" }),
    ).toThrow();
  });

  it("validates the port", () => {
    expect(
      parseProxyConfig({ ...base, CONFORMANCE_PROXY_PORT: "4000" }).port,
    ).toBe(4000);
    for (const port of ["0", "65536", "abc", "-1", "3902.5"]) {
      expect(
        () => parseProxyConfig({ ...base, CONFORMANCE_PROXY_PORT: port }),
        port,
      ).toThrow();
    }
  });
});

describe("parseFixtureConfig", () => {
  it("defaults to 3901 and validates the port", () => {
    expect(parseFixtureConfig({}).port).toBe(3901);
    expect(parseFixtureConfig({ CONFORMANCE_FIXTURE_PORT: "5000" }).port).toBe(
      5000,
    );
    expect(() =>
      parseFixtureConfig({ CONFORMANCE_FIXTURE_PORT: "99999" }),
    ).toThrow();
  });
});

describe("parseSmokeConfig", () => {
  it("derives the proxy URL from the proxy port and keeps the gateway URL", () => {
    expect(
      parseSmokeConfig({ ...base, CONFORMANCE_PROXY_PORT: "4100" }),
    ).toEqual({
      gatewayUrl: base.CONFORMANCE_UPSTREAM_URL,
      proxyUrl: "http://127.0.0.1:4100/mcp",
      apiKey: KEY,
      prefix: "Fixture",
    });
  });
});
