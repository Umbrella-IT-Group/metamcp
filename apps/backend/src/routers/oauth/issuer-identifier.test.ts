/**
 * getIssuerIdentifier: the single normalised issuer identifier this server
 * publishes.
 *
 * The value must be byte-identical everywhere it appears. RFC 8414 metadata
 * advertises it as `issuer` and RFC 9207 has every authorization response carry
 * it as `iss`, and a strict client compares the two by simple string comparison
 * (RFC 9207 2.4). getBaseUrl alone omits the trailing slash the discovery
 * documents already normalise onto the issuer, so emitting getBaseUrl as the
 * response `iss` broke that comparison. Both sites now share this helper so they
 * cannot drift; these tests pin the normalisation that guarantee rests on.
 */

import type express from "express";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const { getIssuerIdentifier } = await import("./utils");

// getBaseUrl reads process.env.APP_URL at call time and prefers it, so setting
// it drives the helper deterministically regardless of what a prior test file
// left in the worker's environment. Restored after each test so this file
// leaves the environment as it found it.
const ORIGINAL_APP_URL = process.env.APP_URL;

afterEach(() => {
  if (ORIGINAL_APP_URL === undefined) {
    delete process.env.APP_URL;
  } else {
    process.env.APP_URL = ORIGINAL_APP_URL;
  }
});

function reqWithAppUrl(appUrl: string): express.Request {
  process.env.APP_URL = appUrl;
  return { headers: {} } as unknown as express.Request;
}

describe("getIssuerIdentifier", () => {
  it("adds a trailing slash when the base URL lacks one", () => {
    expect(getIssuerIdentifier(reqWithAppUrl("https://mcp.example.test"))).toBe(
      "https://mcp.example.test/",
    );
  });

  it("does not double the slash when the base URL already ends in one", () => {
    expect(
      getIssuerIdentifier(reqWithAppUrl("https://mcp.example.test/")),
    ).toBe("https://mcp.example.test/");
  });
});
