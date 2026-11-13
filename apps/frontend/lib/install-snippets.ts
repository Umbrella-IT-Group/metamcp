// SKELETON: the final exported API with inert bodies, committed first so the
// tests can be shown failing by assertion. The next commit replaces it.

export type InstallClientId = "claudeCode" | "codex" | "cursor" | "vscode";
export type InstallAuth = "apiKey" | "oauth" | "none";
export type InstallBlockKind = "command" | "config" | "login";
export type InstallBlockLanguage = "bash" | "json" | "toml";

export interface InstallDestination {
  scope: "project" | "user";
  path: string;
}

export interface InstallBlock {
  kind: InstallBlockKind;
  language: InstallBlockLanguage;
  destinations: InstallDestination[];
  text: string;
}

export interface InstallNote {
  key: string;
  params?: Record<string, string>;
}

export interface InstallOption {
  auth: InstallAuth;
  blocks: InstallBlock[];
  steps: InstallNote[];
  notes: InstallNote[];
}

export interface InstallInput {
  appUrl: string;
  endpointName: string;
  serverName?: string;
  enableApiKeyAuth: boolean;
  enableOauth: boolean;
  requireScopedApiKey: boolean;
}

export interface InstallSnippets {
  serverName: string;
  mcpUrl: string;
  apiKeyEnvVar: string | null;
  clients: Record<InstallClientId, InstallOption[]>;
  claudeWeb: InstallOption | null;
}

export type InstallResult =
  | { ok: false; reason: "invalidUrl" }
  | ({ ok: true } & InstallSnippets);

export const API_KEY_PLACEHOLDER = "YOUR_API_KEY";

export function clientServerName(name: string): string {
  return name;
}

export function apiKeyEnvVarName(serverName: string): string {
  return serverName;
}

export function shellQuote(value: string): string {
  return value;
}

export function tomlString(value: string): string {
  return value;
}

export function buildInstallSnippets(_input: InstallInput): InstallResult {
  return {
    ok: true,
    serverName: "",
    mcpUrl: "",
    apiKeyEnvVar: null,
    clients: { claudeCode: [], codex: [], cursor: [], vscode: [] },
    claudeWeb: null,
  };
}
