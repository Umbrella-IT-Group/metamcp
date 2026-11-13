import type { OAuthClientProvider } from "@modelcontextprotocol/sdk/client/auth.js";
import { describe, expect, it, vi } from "vitest";

import { scopeAuthProviderToAttempt } from "./oauth-provider";

const REDIRECT_URL = "https://gateway.example.test/fe-oauth/callback";
const AUTHORIZATION_URL = new URL("https://login.example.test/authorize");
const CLIENT_METADATA = { redirect_uris: [REDIRECT_URL] };
const CLIENT_INFORMATION = {
  client_id: "client",
  issuer: "https://login.example.test",
};
const TOKENS = {
  access_token: "access",
  refresh_token: "rotated-refresh",
  token_type: "Bearer",
  issuer: "https://login.example.test",
};

function makeProvider() {
  const provider = {
    get redirectUrl() {
      expect(this).toBe(provider);
      return REDIRECT_URL;
    },
    get clientMetadata() {
      expect(this).toBe(provider);
      return CLIENT_METADATA;
    },
    clientInformation: vi.fn(() => CLIENT_INFORMATION),
    tokens: vi.fn(() => TOKENS),
    codeVerifier: vi.fn(() => "saved-verifier"),
    saveClientInformation: vi.fn(),
    saveTokens: vi.fn(),
    redirectToAuthorization: vi.fn(),
    saveCodeVerifier: vi.fn(),
  } satisfies OAuthClientProvider;
  return provider;
}

describe("an attempt-scoped OAuth provider", () => {
  it.each([true, false])(
    "delegates getters, reads and server-keyed writes when current is %s",
    async (current) => {
      const provider = makeProvider();
      const view = scopeAuthProviderToAttempt(provider, () => current);

      expect(view.redirectUrl).toBe(REDIRECT_URL);
      expect(view.clientMetadata).toBe(CLIENT_METADATA);
      expect(await view.clientInformation()).toBe(CLIENT_INFORMATION);
      expect(await view.tokens()).toBe(TOKENS);
      expect(await view.codeVerifier()).toBe("saved-verifier");
      await view.saveClientInformation(CLIENT_INFORMATION);
      await view.saveTokens(TOKENS);

      expect(provider.saveClientInformation).toHaveBeenCalledWith(
        CLIENT_INFORMATION,
      );
      // A stale refresh still has to keep the rotated refresh token.
      expect(provider.saveTokens).toHaveBeenCalledWith(TOKENS);
      for (const method of [
        provider.clientInformation,
        provider.tokens,
        provider.codeVerifier,
        provider.saveClientInformation,
        provider.saveTokens,
      ]) {
        expect(method).toHaveBeenCalledOnce();
        expect(method.mock.contexts[0]).toBe(provider);
      }
    },
  );

  it("delegates the sign-in calls and their results while current", async () => {
    const provider = makeProvider();
    const saved = Promise.resolve();
    provider.saveCodeVerifier.mockReturnValue(saved);
    const view = scopeAuthProviderToAttempt(provider, () => true);

    expect(view.saveCodeVerifier("new-verifier")).toBe(saved);
    expect(view.redirectToAuthorization(AUTHORIZATION_URL)).toBeUndefined();
    expect(provider.saveCodeVerifier).toHaveBeenCalledExactlyOnceWith(
      "new-verifier",
    );
    expect(provider.redirectToAuthorization).toHaveBeenCalledExactlyOnceWith(
      AUTHORIZATION_URL,
    );
    expect(provider.saveCodeVerifier.mock.contexts[0]).toBe(provider);
    expect(provider.redirectToAuthorization.mock.contexts[0]).toBe(provider);
    await saved;
  });

  it.each(["redirectToAuthorization", "saveCodeVerifier"] as const)(
    "throws before touching the provider for a stale %s call",
    async (method) => {
      const provider = makeProvider();
      const view = scopeAuthProviderToAttempt(provider, () => false);

      await expect(async () => {
        if (method === "redirectToAuthorization") {
          await view.redirectToAuthorization(AUTHORIZATION_URL);
        } else {
          await view.saveCodeVerifier("stale-verifier");
        }
      }).rejects.toThrow("Connection attempt was superseded");
      expect(provider.redirectToAuthorization).not.toHaveBeenCalled();
      expect(provider.saveCodeVerifier).not.toHaveBeenCalled();
    },
  );

  it("checks ownership when a saved sign-in function is called", () => {
    const provider = makeProvider();
    let current = true;
    const view = scopeAuthProviderToAttempt(provider, () => current);
    const redirect = view.redirectToAuthorization;
    const saveVerifier = view.saveCodeVerifier;
    current = false;

    expect(() => redirect(AUTHORIZATION_URL)).toThrow(
      "Connection attempt was superseded",
    );
    expect(() => saveVerifier("stale-verifier")).toThrow(
      "Connection attempt was superseded",
    );
    expect(provider.redirectToAuthorization).not.toHaveBeenCalled();
    expect(provider.saveCodeVerifier).not.toHaveBeenCalled();

    current = true;
    redirect(AUTHORIZATION_URL);
    saveVerifier("current-verifier");
    expect(provider.redirectToAuthorization).toHaveBeenCalledOnce();
    expect(provider.saveCodeVerifier).toHaveBeenCalledOnce();
  });

  it.each([true, false])(
    "preserves optional members when they are present is %s",
    async (present) => {
      const provider: OAuthClientProvider = makeProvider();
      const optional = {
        state: vi.fn(() => "state"),
        addClientAuthentication: vi.fn(),
        validateResourceURL: vi.fn(async () => AUTHORIZATION_URL),
        invalidateCredentials: vi.fn(),
        prepareTokenRequest: vi.fn(() => new URLSearchParams()),
        discoveryState: vi.fn(),
        saveDiscoveryState: vi.fn(),
        clientMetadataUrl: "https://gateway.example.test/client-metadata.json",
      };
      if (present) Object.assign(provider, optional);
      const view = scopeAuthProviderToAttempt(provider, () => false);

      for (const [key, value] of Object.entries(optional)) {
        expect(key in view).toBe(present);
        expect(Object.hasOwn(view, key)).toBe(present);
        if (!present) {
          expect(Reflect.get(view, key)).toBeUndefined();
        } else if (typeof value === "function") {
          // The SDK sometimes extracts a method before calling it.
          const method = Reflect.get(view, key);
          await method("argument");
          expect(value).toHaveBeenCalledExactlyOnceWith("argument");
          expect(value.mock.contexts[0]).toBe(provider);
        } else {
          expect(Reflect.get(view, key)).toBe(value);
        }
      }
      expect(Object.keys(view)).toEqual(Object.keys(provider));
    },
  );

  it("preserves an explicitly undefined optional member", () => {
    const provider = { ...makeProvider(), state: undefined };
    const view = scopeAuthProviderToAttempt(provider, () => false);
    expect("state" in view).toBe(true);
    expect(view.state).toBeUndefined();
    expect(
      "saveClientInformation" in
        scopeAuthProviderToAttempt(
          {
            ...makeProvider(),
            saveClientInformation: undefined,
          },
          () => false,
        ),
    ).toBe(true);
  });

  it("preserves errors from the underlying provider", async () => {
    const provider = makeProvider();
    const failure = new Error("credential store unavailable");
    provider.saveTokens.mockImplementation(() => {
      throw failure;
    });
    const view = scopeAuthProviderToAttempt(provider, () => false);
    await expect(async () => view.saveTokens(TOKENS)).rejects.toBe(failure);
  });
});
