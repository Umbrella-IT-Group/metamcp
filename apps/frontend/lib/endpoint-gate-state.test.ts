/**
 * The four-state access badge classifier.
 *
 * The access-group gate governs OAuth callers only, so the badge cannot read
 * `restricted` alone. It also has to account for `require_scoped_api_key`,
 * because the endpoint create/update pairing forces that on with `restricted`:
 * a restricted endpoint is scoped-only on the API-key plane by construction, so
 * it reads as "enforcing" rather than as an endpoint unscoped keys can bypass.
 * The only way to be restricted with unscoped keys still passing is a legacy
 * row from before the pairing, which is the "oauthOnly" case the boot-time
 * pairing check flags.
 */
import { describe, expect, it } from "vitest";

import { endpointGateState } from "./endpoint-gate-state";

describe("endpointGateState", () => {
  it("is 'off' when the endpoint is not restricted", () => {
    expect(
      endpointGateState({
        restricted: false,
        enable_oauth: true,
        enable_api_key_auth: true,
        require_scoped_api_key: false,
      }),
    ).toBe("off");
  });

  it("is 'noOauth' when restricted but OAuth is off (the gate is inert)", () => {
    expect(
      endpointGateState({
        restricted: true,
        enable_oauth: false,
        enable_api_key_auth: true,
        require_scoped_api_key: false,
      }),
    ).toBe("noOauth");
  });

  it("is 'oauthOnly' for a legacy row where unscoped API keys still bypass the gate", () => {
    expect(
      endpointGateState({
        restricted: true,
        enable_oauth: true,
        enable_api_key_auth: true,
        require_scoped_api_key: false,
      }),
    ).toBe("oauthOnly");
  });

  it("is 'enforcing' when API keys are off entirely", () => {
    expect(
      endpointGateState({
        restricted: true,
        enable_oauth: true,
        enable_api_key_auth: false,
        require_scoped_api_key: false,
      }),
    ).toBe("enforcing");
  });

  it("is 'enforcing' for a paired endpoint: API keys on but scoped-only closes the bypass", () => {
    // This is the case the pairing creates. Before require_scoped_api_key was
    // factored in, this endpoint read as "oauthOnly" and the badge implied an
    // open API-key path that no longer exists.
    expect(
      endpointGateState({
        restricted: true,
        enable_oauth: true,
        enable_api_key_auth: true,
        require_scoped_api_key: true,
      }),
    ).toBe("enforcing");
  });
});
