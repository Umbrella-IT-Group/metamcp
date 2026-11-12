/**
 * The three-state access badge classifier.
 *
 * The gate applies to OAuth sign-ins and to API keys by their owner, so the
 * badge reads `restricted` together with the two auth toggles, and only the
 * two toggles both being off makes a restricted endpoint inert. The oracle is
 * the rule in the backend (apps/backend/src/lib/endpoint-access-control.ts):
 * the gate runs on every request that authenticates, whichever credential it
 * carries.
 *
 * `require_scoped_api_key` is not an input at all: the cases pass it anyway, in
 * both values, to show it cannot change the answer.
 */
import { describe, expect, it } from "vitest";

import { endpointGateState } from "./endpoint-gate-state";

const withScoped = (
  input: Parameters<typeof endpointGateState>[0],
): Parameters<typeof endpointGateState>[0][] =>
  [true, false].map(
    (require_scoped_api_key) =>
      ({ ...input, require_scoped_api_key }) as typeof input,
  );

describe("endpointGateState", () => {
  it("is 'off' when the endpoint is not restricted, whatever else is on", () => {
    for (const input of withScoped({
      restricted: false,
      enable_oauth: true,
      enable_api_key_auth: true,
    })) {
      expect(endpointGateState(input)).toBe("off");
    }
  });

  it("is 'noAuth' only when restricted with OAuth and API keys both off", () => {
    for (const input of withScoped({
      restricted: true,
      enable_oauth: false,
      enable_api_key_auth: false,
    })) {
      expect(endpointGateState(input)).toBe("noAuth");
    }
  });

  it.each([
    ["OAuth only", { enable_oauth: true, enable_api_key_auth: false }],
    ["API keys only", { enable_oauth: false, enable_api_key_auth: true }],
    ["OAuth and API keys", { enable_oauth: true, enable_api_key_auth: true }],
  ])(
    "is 'enforcing' for a restricted endpoint that accepts %s",
    (_label, auth) => {
      // The case the old classifier got wrong: an API-key-only restricted
      // endpoint read as "no effect", and one with both read as a partial gate
      // that unscoped keys bypassed. Keys are judged by their owner now.
      for (const input of withScoped({ restricted: true, ...auth })) {
        expect(endpointGateState(input)).toBe("enforcing");
      }
    },
  );
});
