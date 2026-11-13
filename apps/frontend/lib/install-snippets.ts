/**
 * Snippets for the endpoints list's "Add to client" dialog: what an operator
 * pastes into Claude Code, Codex, Cursor or VS Code (and the steps for Claude on
 * the web and desktop) to connect to one gateway endpoint.
 *
 * Why this is a pure module with no key in its input type: a snippet is copied
 * into shells, dotfiles and chat, so it must never carry a credential, and the
 * simplest way to be sure is that the builder has nowhere to read one from. It
 * reads only the named fields below (never a spread of the endpoint row), so a
 * key or the endpoint's query-parameter switch on the object cannot reach the
 * output either. Where a client documents an environment-variable reference
 * for a header, the snippet uses it and names the variable; the one literal
 * header is the `claude mcp add` command, which Claude Code documents only in
 * that form, and it carries a placeholder.
 *
 * The per-client shapes follow each vendor's own documentation, fetched
 * 2026-11-12:
 * - Claude Code: https://code.claude.com/docs/en/mcp (`claude mcp add
 *   --transport http <name> <url> --header "..."`; `.mcp.json` needs `type`
 *   and expands `${VAR}` in `headers`; OAuth through `claude mcp login`)
 * - Codex: https://learn.chatgpt.com/docs/extend/mcp (`[mcp_servers.<name>]`,
 *   `url`, `bearer_token_env_var` holding a variable NAME, `codex mcp login`)
 * - Cursor: https://cursor.com/docs/context/mcp (`mcpServers`, `url`,
 *   `headers`, `${env:NAME}` interpolation)
 * - VS Code: https://code.visualstudio.com/docs/agents/reference/mcp-configuration
 *   (native `mcpServers` with `type: "http"`, `headers` with `${NAME}`)
 * The generator shape was informed by mcp-use's `install-targets.ts` (MIT); no
 * code is copied, and none of its one-click deep links are built here.
 */

export type InstallClientId = "claudeCode" | "codex" | "cursor" | "vscode";
export type InstallAuth = "apiKey" | "oauth" | "none";
export type InstallBlockKind = "command" | "config" | "login";
export type InstallBlockLanguage = "bash" | "json" | "toml";

export type InstallNoteKey =
  | "apiKeyNote"
  | "scopedKeyNote"
  | "envVarNote"
  | "headerNote"
  | "oauthNote"
  | "oauthLoopbackNote"
  | "claudeCodeMcpPanelNote"
  | "vscodeFormatNote"
  | "noAuthNote"
  | "claudeStep1"
  | "claudeStep2"
  | "claudeStep3"
  | "claudeStep4"
  | "claudeTeamNote";

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
  key: InstallNoteKey;
  params?: Record<string, string>;
}

export interface InstallOption {
  auth: InstallAuth;
  blocks: InstallBlock[];
  /** Ordered instructions for a client that has no file or command. */
  steps: InstallNote[];
  notes: InstallNote[];
}

export interface InstallInput {
  /** The gateway's public base URL, as the endpoints list already shows it. */
  appUrl: string;
  endpointName: string;
  /** What the operator wants the client to call the server; defaults to the endpoint name. */
  serverName?: string;
  enableApiKeyAuth: boolean;
  enableOauth: boolean;
  requireScopedApiKey: boolean;
}

export interface InstallSnippets {
  serverName: string;
  mcpUrl: string;
  /** The variable the snippets read the key from, or null when API key auth is off. */
  apiKeyEnvVar: string | null;
  clients: Record<InstallClientId, InstallOption[]>;
  /** Present only when OAuth is on: a hosted connector signs in, it has no API key path here. */
  claudeWeb: InstallOption | null;
}

export type InstallResult =
  | { ok: false; reason: "invalidUrl" }
  | ({ ok: true } & InstallSnippets);

/**
 * The string the endpoints list already uses for "a key you hold". Appears in
 * exactly one snippet, the `claude mcp add` command (see the module comment).
 */
export const API_KEY_PLACEHOLDER = "YOUR_API_KEY";

/**
 * The name a client stores the server under. Claude Code and Codex prefix tool
 * names with it, and a CLI parses a leading `-` as a flag, so anything outside
 * letters, digits, `_` and `-` becomes `_`, and a leading `-` does too.
 */
export function clientServerName(name: string): string {
  const cleaned = name.replace(/[^A-Za-z0-9_-]/g, "_").replace(/^-/, "_");
  return cleaned === "" ? "mcp" : cleaned;
}

/**
 * The environment variable a snippet reads the key from. The `MCP_` prefix is
 * deliberate: Claude Code reads credential-looking names it owns (such as
 * ANTHROPIC_API_KEY or AWS_*) as empty inside a remote server's headers, so a
 * name derived from the server must never be able to equal one of them.
 */
export function apiKeyEnvVarName(serverName: string): string {
  const stem = clientServerName(serverName).toUpperCase().replace(/-/g, "_");
  return `MCP_${stem}_API_KEY`;
}

// The characters POSIX `shlex.quote` leaves bare; anything else is
// single-quoted, with each embedded `'` written as `'\''`.
const SHELL_SAFE = /^[A-Za-z0-9_@%+=:,./-]+$/;

export function shellQuote(value: string): string {
  if (SHELL_SAFE.test(value)) return value;
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

const TOML_SHORT_ESCAPES: Record<string, string> = {
  "\b": "\\b",
  "\t": "\\t",
  "\n": "\\n",
  "\f": "\\f",
  "\r": "\\r",
};

/**
 * A TOML basic string. Escapes exactly what TOML v1.0.0 requires (the quote,
 * the backslash and control characters), so a value cannot end its own string
 * and start a new key. A lone surrogate is not a legal TOML scalar value and
 * becomes U+FFFD.
 */
export function tomlString(value: string): string {
  let out = '"';
  for (const ch of value) {
    const code = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (TOML_SHORT_ESCAPES[ch] !== undefined)
      out += TOML_SHORT_ESCAPES[ch];
    else if (code < 0x20 || code === 0x7f)
      out += `\\u${code.toString(16).toUpperCase().padStart(4, "0")}`;
    else if (code >= 0xd800 && code <= 0xdfff) out += "\\uFFFD";
    else out += ch;
  }
  return `${out}"`;
}

// new URL() drops tabs and newlines and encodes spaces, so a URL with any of
// them validates as something other than the text a snippet would print.
function hasUnprintable(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code <= 0x20 || code === 0x7f) return true;
  }
  return false;
}

/**
 * `<app URL>/metamcp/<endpoint>/mcp`, by concatenation like the endpoints
 * list's own copy buttons (so a path-prefixed app URL keeps working), or null
 * when the result is not the plain http(s) URL it should be: no credentials in
 * it, no query or fragment swallowing the path, and the path ends where we put
 * it (an endpoint named `..` would otherwise resolve somewhere else).
 */
function buildMcpUrl(appUrl: string, endpointName: string): string | null {
  const suffix = `/metamcp/${encodeURIComponent(endpointName)}/mcp`;
  const url = `${appUrl.trim().replace(/\/+$/, "")}${suffix}`;
  if (hasUnprintable(url)) return null;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    return null;
  }
  return parsed.pathname.endsWith(suffix) ? url : null;
}

const json = (value: unknown): string => JSON.stringify(value, null, 2);

const note = (
  key: InstallNoteKey,
  params?: Record<string, string>,
): InstallNote => (params ? { key, params } : { key });

function block(
  kind: InstallBlockKind,
  language: InstallBlockLanguage,
  text: string,
  destinations: InstallDestination[] = [],
): InstallBlock {
  return { kind, language, destinations, text };
}

function option(
  auth: InstallAuth,
  blocks: InstallBlock[],
  notes: InstallNote[],
  steps: InstallNote[] = [],
): InstallOption {
  return { auth, blocks, steps, notes };
}

export function buildInstallSnippets(input: InstallInput): InstallResult {
  const mcpUrl = buildMcpUrl(input.appUrl, input.endpointName);
  if (mcpUrl === null) return { ok: false, reason: "invalidUrl" };

  const serverName = clientServerName(input.serverName ?? input.endpointName);
  const apiKey = input.enableApiKeyAuth === true;
  const oauth = input.enableOauth === true;
  const scoped = input.requireScopedApiKey === true;
  const envVar = apiKeyEnvVarName(serverName);
  const quotedName = shellQuote(serverName);

  const auths: InstallAuth[] = [];
  if (apiKey) auths.push("apiKey");
  if (oauth) auths.push("oauth");
  if (auths.length === 0) auths.push("none");

  // Notes every API-key option carries, wherever the key goes.
  const keyNotes = (): InstallNote[] => [
    note("envVarNote", { envVar }),
    ...(scoped ? [note("scopedKeyNote")] : []),
  ];

  const claudeCode = auths.map((auth) => {
    const add = `claude mcp add --transport http ${quotedName} ${shellQuote(mcpUrl)}`;
    if (auth === "apiKey") {
      return option(
        auth,
        [
          block(
            "command",
            "bash",
            `${add} --header "Authorization: Bearer ${API_KEY_PLACEHOLDER}"`,
          ),
          block(
            "config",
            "json",
            json({
              mcpServers: {
                [serverName]: {
                  type: "http",
                  url: mcpUrl,
                  headers: { Authorization: `Bearer \${${envVar}}` },
                },
              },
            }),
            [{ scope: "project", path: ".mcp.json" }],
          ),
        ],
        [
          note("apiKeyNote", { placeholder: API_KEY_PLACEHOLDER }),
          ...keyNotes(),
          // A header Claude Code sends itself replaces its OAuth fallback.
          ...(oauth ? [note("headerNote")] : []),
        ],
      );
    }
    if (auth === "oauth") {
      return option(
        auth,
        [
          block("command", "bash", add),
          block("login", "bash", `claude mcp login ${quotedName}`),
        ],
        [note("claudeCodeMcpPanelNote"), note("oauthNote")],
      );
    }
    return option(auth, [block("command", "bash", add)], [note("noAuthNote")]);
  });

  const codexTable = `[mcp_servers.${serverName}]\nurl = ${tomlString(mcpUrl)}\n`;
  const codex = auths.map((auth) => {
    const destinations: InstallDestination[] = [
      { scope: "user", path: "~/.codex/config.toml" },
    ];
    if (auth === "apiKey") {
      return option(
        auth,
        [
          block(
            "config",
            "toml",
            `${codexTable}bearer_token_env_var = ${tomlString(envVar)}\n`,
            destinations,
          ),
        ],
        keyNotes(),
      );
    }
    if (auth === "oauth") {
      return option(
        auth,
        [
          block("config", "toml", codexTable, destinations),
          block("login", "bash", `codex mcp login ${quotedName}`),
        ],
        [note("oauthNote")],
      );
    }
    return option(
      auth,
      [block("config", "toml", codexTable, destinations)],
      [note("noAuthNote")],
    );
  });

  const cursorDestinations: InstallDestination[] = [
    { scope: "project", path: ".cursor/mcp.json" },
    { scope: "user", path: "~/.cursor/mcp.json" },
  ];
  const cursor = auths.map((auth) => {
    const entry: Record<string, unknown> = { url: mcpUrl };
    if (auth === "apiKey") {
      entry.headers = { Authorization: `Bearer \${env:${envVar}}` };
    }
    const config = block(
      "config",
      "json",
      json({ mcpServers: { [serverName]: entry } }),
      cursorDestinations,
    );
    if (auth === "apiKey") return option(auth, [config], keyNotes());
    if (auth === "oauth") {
      return option(
        auth,
        [config],
        [note("oauthNote"), note("oauthLoopbackNote")],
      );
    }
    return option(auth, [config], [note("noAuthNote")]);
  });

  const vscodeDestinations: InstallDestination[] = [
    { scope: "project", path: ".mcp.json" },
    { scope: "user", path: "~/.copilot/mcp-config.json" },
  ];
  const vscode = auths.map((auth) => {
    const entry: Record<string, unknown> = { type: "http", url: mcpUrl };
    if (auth === "apiKey") {
      entry.headers = { Authorization: `Bearer \${${envVar}}` };
    }
    entry.tools = ["*"];
    const config = block(
      "config",
      "json",
      json({ mcpServers: { [serverName]: entry } }),
      vscodeDestinations,
    );
    if (auth === "apiKey") {
      return option(auth, [config], [...keyNotes(), note("vscodeFormatNote")]);
    }
    if (auth === "oauth") {
      return option(
        auth,
        [config],
        [
          note("oauthNote"),
          note("oauthLoopbackNote"),
          note("vscodeFormatNote"),
        ],
      );
    }
    return option(
      auth,
      [config],
      [note("noAuthNote"), note("vscodeFormatNote")],
    );
  });

  return {
    ok: true,
    serverName,
    mcpUrl,
    apiKeyEnvVar: apiKey ? envVar : null,
    clients: { claudeCode, codex, cursor, vscode },
    claudeWeb: oauth
      ? option(
          "oauth",
          [],
          [note("claudeTeamNote")],
          [
            note("claudeStep1"),
            note("claudeStep2"),
            note("claudeStep3"),
            note("claudeStep4"),
          ],
        )
      : null,
  };
}
