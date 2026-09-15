// Client-side i18n utilities
export const SUPPORTED_LOCALES = ["en", "zh", "ko", "pt", "es"] as const;
export type SupportedLocale = (typeof SUPPORTED_LOCALES)[number];

export const LOCALE_NAMES = {
  en: "English",
  zh: "中文",
  ko: "한국어",
  pt: "Português",
  es: "Español",
} as const;

// Type for translations
export type Translations = {
  common: Record<string, any>;
  auth: Record<string, any>;
  navigation: Record<string, any>;
  "mcp-servers": Record<string, any>;
  namespaces: Record<string, any>;
  endpoints: Record<string, any>;
  "api-keys": Record<string, any>;
  "oauth-clients": Record<string, any>;
  access: Record<string, any>;
  settings: Record<string, any>;
  search: Record<string, any>;
  inspector: Record<string, any>;
  logs: Record<string, any>;
  validation: Record<string, any>;
};

// Utility functions for working with localized paths
export function getPathnameWithoutLocale(pathname: string): string {
  const segments = pathname.split("/").filter(Boolean);
  const firstSegment = segments[0];

  if (SUPPORTED_LOCALES.includes(firstSegment as SupportedLocale)) {
    return "/" + segments.slice(1).join("/");
  }

  return pathname;
}

export function getLocalizedPath(
  pathname: string,
  locale: SupportedLocale,
): string {
  const pathnameWithoutLocale = getPathnameWithoutLocale(pathname);

  if (locale === "en") {
    return pathnameWithoutLocale;
  }

  return `/${locale}${pathnameWithoutLocale === "/" ? "" : pathnameWithoutLocale}`;
}

// Client-side translation loader (for dynamic imports)
export async function loadTranslations(
  locale: SupportedLocale,
): Promise<Translations> {
  if (locale === "en") {
    return {
      common: (await import("../public/locales/en/common.json")).default,
      auth: (await import("../public/locales/en/auth.json")).default,
      navigation: (await import("../public/locales/en/navigation.json"))
        .default,
      "mcp-servers": (await import("../public/locales/en/mcp-servers.json"))
        .default,
      namespaces: (await import("../public/locales/en/namespaces.json"))
        .default,
      endpoints: (await import("../public/locales/en/endpoints.json")).default,
      "api-keys": (await import("../public/locales/en/api-keys.json")).default,
      "oauth-clients": (await import("../public/locales/en/oauth-clients.json"))
        .default,
      access: (await import("../public/locales/en/access.json")).default,
      settings: (await import("../public/locales/en/settings.json")).default,
      search: (await import("../public/locales/en/search.json")).default,
      inspector: (await import("../public/locales/en/inspector.json")).default,
      logs: (await import("../public/locales/en/logs.json")).default,
      validation: (await import("../public/locales/en/validation.json"))
        .default,
    };
  } else if (locale === "zh") {
    // Load Chinese translations with fallback to English
    const [
      commonZh,
      authZh,
      navigationZh,
      mcpServersZh,
      namespacesZh,
      endpointsZh,
      apiKeysZh,
      oauthClientsZh,
      accessZh,
      settingsZh,
      searchZh,
      inspectorZh,
      logsZh,
      validationZh,
    ] = await Promise.all([
      import("../public/locales/zh/common.json").catch(() => ({ default: {} })),
      import("../public/locales/zh/auth.json").catch(() => ({ default: {} })),
      import("../public/locales/zh/navigation.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/zh/mcp-servers.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/zh/namespaces.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/zh/endpoints.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/zh/api-keys.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/zh/oauth-clients.json").catch(() => ({
        default: {},
      })),
      // The zh access.json is an intentionally EMPTY object, not a missing
      // file: these imports are resolved statically at build time, so a file
      // that does not exist fails the build rather than falling into the
      // .catch(). Empty means the English strings below win the merge — an
      // honest untranslated fallback instead of a machine-translated one on a
      // security surface. Filling the file in translates the page with no
      // further wiring.
      import("../public/locales/zh/access.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/zh/settings.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/zh/search.json").catch(() => ({ default: {} })),
      import("../public/locales/zh/inspector.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/zh/logs.json").catch(() => ({ default: {} })),
      import("../public/locales/zh/validation.json").catch(() => ({
        default: {},
      })),
    ]);

    // Get English fallback
    const englishDict = await loadTranslations("en");

    return {
      common: { ...englishDict.common, ...commonZh.default },
      auth: { ...englishDict.auth, ...authZh.default },
      navigation: { ...englishDict.navigation, ...navigationZh.default },
      "mcp-servers": { ...englishDict["mcp-servers"], ...mcpServersZh.default },
      namespaces: { ...englishDict.namespaces, ...namespacesZh.default },
      endpoints: { ...englishDict.endpoints, ...endpointsZh.default },
      "api-keys": { ...englishDict["api-keys"], ...apiKeysZh.default },
      "oauth-clients": {
        ...englishDict["oauth-clients"],
        ...oauthClientsZh.default,
      },
      access: { ...englishDict.access, ...accessZh.default },
      settings: { ...englishDict.settings, ...settingsZh.default },
      search: { ...englishDict.search, ...searchZh.default },
      inspector: { ...englishDict.inspector, ...inspectorZh.default },
      logs: { ...englishDict.logs, ...logsZh.default },
      validation: { ...englishDict.validation, ...validationZh.default },
    };
  } else if (locale === "ko") {
    // Load Korean translations with fallback to English
    const [
      commonKo,
      authKo,
      navigationKo,
      mcpServersKo,
      namespacesKo,
      endpointsKo,
      apiKeysKo,
      oauthClientsKo,
      accessKo,
      settingsKo,
      searchKo,
      inspectorKo,
      logsKo,
      validationKo,
    ] = await Promise.all([
      import("../public/locales/ko/common.json").catch(() => ({ default: {} })),
      import("../public/locales/ko/auth.json").catch(() => ({ default: {} })),
      import("../public/locales/ko/navigation.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/ko/mcp-servers.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/ko/namespaces.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/ko/endpoints.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/ko/api-keys.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/ko/oauth-clients.json").catch(() => ({
        default: {},
      })),
      // The ko access.json is an intentionally EMPTY object, not a missing
      // file: these imports are resolved statically at build time, so a file
      // that does not exist fails the build rather than falling into the
      // .catch(). Empty means the English strings below win the merge — an
      // honest untranslated fallback instead of a machine-translated one on a
      // security surface. Filling the file in translates the page with no
      // further wiring.
      import("../public/locales/ko/access.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/ko/settings.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/ko/search.json").catch(() => ({ default: {} })),
      import("../public/locales/ko/inspector.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/ko/logs.json").catch(() => ({ default: {} })),
      import("../public/locales/ko/validation.json").catch(() => ({
        default: {},
      })),
    ]);

    // Get English fallback
    const englishDict = await loadTranslations("en");

    return {
      common: { ...englishDict.common, ...commonKo.default },
      auth: { ...englishDict.auth, ...authKo.default },
      navigation: { ...englishDict.navigation, ...navigationKo.default },
      "mcp-servers": { ...englishDict["mcp-servers"], ...mcpServersKo.default },
      namespaces: { ...englishDict.namespaces, ...namespacesKo.default },
      endpoints: { ...englishDict.endpoints, ...endpointsKo.default },
      "api-keys": { ...englishDict["api-keys"], ...apiKeysKo.default },
      "oauth-clients": {
        ...englishDict["oauth-clients"],
        ...oauthClientsKo.default,
      },
      access: { ...englishDict.access, ...accessKo.default },
      settings: { ...englishDict.settings, ...settingsKo.default },
      search: { ...englishDict.search, ...searchKo.default },
      inspector: { ...englishDict.inspector, ...inspectorKo.default },
      logs: { ...englishDict.logs, ...logsKo.default },
      validation: { ...englishDict.validation, ...validationKo.default },
    };
  } else if (locale === "pt") {
    // Load Portuguese translations with fallback to English.
    // oauth-clients/access have no pt translation yet: the empty JSON
    // files let English win the merge (same honest-fallback pattern as
    // the ko access.json comment above). (ai-dev c870b83 + c885885 +
    // ca4075e + 00d2c61 + 8929867 + 4a0d45c + 4df720f.)
    const [
      commonPt,
      authPt,
      navigationPt,
      mcpServersPt,
      namespacesPt,
      endpointsPt,
      apiKeysPt,
      oauthClientsPt,
      accessPt,
      settingsPt,
      searchPt,
      inspectorPt,
      logsPt,
      validationPt,
    ] = await Promise.all([
      import("../public/locales/pt/common.json").catch(() => ({ default: {} })),
      import("../public/locales/pt/auth.json").catch(() => ({ default: {} })),
      import("../public/locales/pt/navigation.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/pt/mcp-servers.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/pt/namespaces.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/pt/endpoints.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/pt/api-keys.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/pt/oauth-clients.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/pt/access.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/pt/settings.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/pt/search.json").catch(() => ({ default: {} })),
      import("../public/locales/pt/inspector.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/pt/logs.json").catch(() => ({ default: {} })),
      import("../public/locales/pt/validation.json").catch(() => ({
        default: {},
      })),
    ]);

    // Get English fallback
    const englishDict = await loadTranslations("en");

    return {
      common: { ...englishDict.common, ...commonPt.default },
      auth: { ...englishDict.auth, ...authPt.default },
      navigation: { ...englishDict.navigation, ...navigationPt.default },
      "mcp-servers": { ...englishDict["mcp-servers"], ...mcpServersPt.default },
      namespaces: { ...englishDict.namespaces, ...namespacesPt.default },
      endpoints: { ...englishDict.endpoints, ...endpointsPt.default },
      "api-keys": { ...englishDict["api-keys"], ...apiKeysPt.default },
      "oauth-clients": {
        ...englishDict["oauth-clients"],
        ...oauthClientsPt.default,
      },
      access: { ...englishDict.access, ...accessPt.default },
      settings: { ...englishDict.settings, ...settingsPt.default },
      search: { ...englishDict.search, ...searchPt.default },
      inspector: { ...englishDict.inspector, ...inspectorPt.default },
      logs: { ...englishDict.logs, ...logsPt.default },
      validation: { ...englishDict.validation, ...validationPt.default },
    };
  } else if (locale === "es") {
    // Load Spanish translations with fallback to English (same shape and
    // empty-file fallback as the pt branch above).
    const [
      commonEs,
      authEs,
      navigationEs,
      mcpServersEs,
      namespacesEs,
      endpointsEs,
      apiKeysEs,
      oauthClientsEs,
      accessEs,
      settingsEs,
      searchEs,
      inspectorEs,
      logsEs,
      validationEs,
    ] = await Promise.all([
      import("../public/locales/es/common.json").catch(() => ({ default: {} })),
      import("../public/locales/es/auth.json").catch(() => ({ default: {} })),
      import("../public/locales/es/navigation.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/es/mcp-servers.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/es/namespaces.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/es/endpoints.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/es/api-keys.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/es/oauth-clients.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/es/access.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/es/settings.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/es/search.json").catch(() => ({ default: {} })),
      import("../public/locales/es/inspector.json").catch(() => ({
        default: {},
      })),
      import("../public/locales/es/logs.json").catch(() => ({ default: {} })),
      import("../public/locales/es/validation.json").catch(() => ({
        default: {},
      })),
    ]);

    // Get English fallback
    const englishDictEs = await loadTranslations("en");

    return {
      common: { ...englishDictEs.common, ...commonEs.default },
      auth: { ...englishDictEs.auth, ...authEs.default },
      navigation: { ...englishDictEs.navigation, ...navigationEs.default },
      "mcp-servers": { ...englishDictEs["mcp-servers"], ...mcpServersEs.default },
      namespaces: { ...englishDictEs.namespaces, ...namespacesEs.default },
      endpoints: { ...englishDictEs.endpoints, ...endpointsEs.default },
      "api-keys": { ...englishDictEs["api-keys"], ...apiKeysEs.default },
      "oauth-clients": {
        ...englishDictEs["oauth-clients"],
        ...oauthClientsEs.default,
      },
      access: { ...englishDictEs.access, ...accessEs.default },
      settings: { ...englishDictEs.settings, ...settingsEs.default },
      search: { ...englishDictEs.search, ...searchEs.default },
      inspector: { ...englishDictEs.inspector, ...inspectorEs.default },
      logs: { ...englishDictEs.logs, ...logsEs.default },
      validation: { ...englishDictEs.validation, ...validationEs.default },
    };
  } else {
    // Fallback to English for unsupported locales
    return loadTranslations("en");
  }
}

// Helper function to get nested translation value
export function getTranslation(
  dictionary: Translations,
  key: string,
  params?: Record<string, string | number>,
): string {
  const parts = key.split(":");
  let value: any = dictionary;

  // First, navigate to the correct namespace (before the colon)
  if (parts.length > 1) {
    const namespace = parts[0]!;
    if (value && typeof value === "object" && namespace in value) {
      value = value[namespace];
    } else {
      return key; // Return the key if namespace not found
    }

    // Then navigate through the nested structure using dots
    const nestedKeys = parts[1]!.split(".");
    for (const k of nestedKeys) {
      if (value && typeof value === "object" && k in value) {
        value = value[k];
      } else {
        return key; // Return the key if translation not found
      }
    }
  } else {
    // Handle keys without namespace (legacy support)
    const keys = key.split(".");
    for (const k of keys) {
      if (value && typeof value === "object" && k in value) {
        value = value[k];
      } else {
        return key; // Return the key if translation not found
      }
    }
  }

  if (typeof value !== "string") {
    return key; // Return the key if the final value is not a string
  }

  // Simple parameter interpolation
  if (params) {
    return value.replace(/\{\{(\w+)\}\}/g, (match, paramKey) => {
      return params[paramKey]?.toString() || match;
    });
  }

  return value;
}

// Supported key formats:
// - "namespace:key" - simple namespace with key
// - "namespace:nested.key" - namespace with nested key using dots
// - "namespace:deeply.nested.key.path" - namespace with deeply nested key path
// - "key" - legacy format without namespace (uses dots for nesting)
// Example: "search:dialog.form.ownership.private" will access dictionary.search.dialog.form.ownership.private
