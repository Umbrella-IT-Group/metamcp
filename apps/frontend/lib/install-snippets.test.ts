/**
 * Credential custody for the "Add to client" dialog: the snippets an operator
 * copies must never carry a key, must prefer an environment-variable reference
 * wherever the client documents one, and must survive a real shell and a real
 * TOML parser. The expected strings are written out by hand from each client's
 * own documentation (fetched 2026-11-12) so the tests do not mirror the code:
 *
 * - Claude Code, https://code.claude.com/docs/en/mcp: `claude mcp add
 *   --transport http <name> <url> --header "Authorization: Bearer ..."`;
 *   `.mcp.json` entries need `type`, and `${VAR}` expands in `headers`; a name
 *   such as ANTHROPIC_API_KEY is read as empty in a remote server's headers.
 * - Codex, https://learn.chatgpt.com/docs/extend/mcp (served at
 *   developers.openai.com/codex/mcp before it moved): `[mcp_servers.<name>]`
 *   with `url`, and `bearer_token_env_var` holding the variable's NAME.
 * - Cursor, https://cursor.com/docs/context/mcp: `mcpServers` with `url` and
 *   `headers`, and `${env:NAME}` interpolation in `headers`.
 * - VS Code, https://code.visualstudio.com/docs/agents/reference/mcp-configuration:
 *   native `mcpServers` with `type: "http"`, `url`, `headers` (`${NAME}`) and
 *   `tools`.
 *
 * The shell and TOML cases run the real `sh` and Python's `tomllib` (3.11+),
 * both present on the CI runner image.
 */
import { execFileSync } from "node:child_process";

import { describe, expect, it } from "vitest";

import {
  apiKeyEnvVarName,
  buildInstallSnippets,
  clientServerName,
  type InstallInput,
  type InstallOption,
  type InstallSnippets,
  shellQuote,
  tomlString,
} from "./install-snippets";

const APP = "https://gw.example.com";
const MCP_URL = "https://gw.example.com/metamcp/ops-tools/mcp";
const ENV_VAR = "MCP_OPS_TOOLS_API_KEY";
const PLACEHOLDER = "YOUR_API_KEY";

function input(overrides: Partial<InstallInput> = {}): InstallInput {
  return {
    appUrl: APP,
    endpointName: "ops-tools",
    enableApiKeyAuth: false,
    enableOauth: false,
    requireScopedApiKey: false,
    ...overrides,
  };
}

function snippets(overrides: Partial<InstallInput> = {}): InstallSnippets {
  const result = buildInstallSnippets(input(overrides));
  if (!result.ok) {
    throw new Error(`expected snippets, got ${result.reason}`);
  }
  return result;
}

function option(
  options: InstallOption[],
  auth: InstallOption["auth"],
): InstallOption {
  const found = options.find((o) => o.auth === auth);
  if (!found) {
    throw new Error(
      `no ${auth} option in [${options.map((o) => o.auth).join(", ")}]`,
    );
  }
  return found;
}

function noteKeys(o: InstallOption): string[] {
  return o.notes.map((n) => n.key);
}

const AUTH_MATRIX: { apiKey: boolean; oauth: boolean }[] = [
  { apiKey: true, oauth: false },
  { apiKey: false, oauth: true },
  { apiKey: true, oauth: true },
  { apiKey: false, oauth: false },
];

function matrixInput(
  m: { apiKey: boolean; oauth: boolean },
  scoped = false,
): Partial<InstallInput> {
  return {
    enableApiKeyAuth: m.apiKey,
    enableOauth: m.oauth,
    requireScopedApiKey: scoped,
  };
}

/** Parse a TOML document with the real parser (Python 3.11+ `tomllib`). */
function parseToml(text: string): Record<string, unknown> {
  const out = execFileSync(
    "python3",
    [
      "-I",
      "-c",
      "import sys, json, tomllib; print(json.dumps(tomllib.loads(sys.stdin.read())))",
    ],
    { input: text, encoding: "utf8" },
  );
  return JSON.parse(out) as Record<string, unknown>;
}

/**
 * Run `claude <rest>` through a real POSIX shell with the program replaced by
 * a printer, so the result is exactly the argv the shell would hand `claude`.
 */
function shellArgv(commandLine: string): string[] {
  const rest = commandLine.replace(/^claude /, "");
  const out = execFileSync("sh", ["-c", `printf '%s\\0' ${rest}`], {
    encoding: "utf8",
  });
  return out.split("\0").slice(0, -1);
}

describe("install snippets, name and URL", () => {
  it("derives the URL, the client-side name and the key variable from the endpoint", () => {
    const s = snippets({ enableApiKeyAuth: true });
    expect(s.serverName).toBe("ops-tools");
    expect(s.mcpUrl).toBe(MCP_URL);
    expect(s.apiKeyEnvVar).toBe(ENV_VAR);
  });

  it("names no key variable for an endpoint without API key auth", () => {
    expect(snippets({ enableOauth: true }).apiKeyEnvVar).toBeNull();
  });

  it("strips trailing slashes and keeps a path prefix on the app URL", () => {
    expect(snippets({ appUrl: "https://gw.example.com///" }).mcpUrl).toBe(
      MCP_URL,
    );
    expect(snippets({ appUrl: "https://gw.example.com/gateway/" }).mcpUrl).toBe(
      "https://gw.example.com/gateway/metamcp/ops-tools/mcp",
    );
  });

  it("percent-encodes the endpoint name in the URL but sanitizes it for the client", () => {
    const s = snippets({ endpointName: "ops tools/é" });
    expect(s.mcpUrl).toBe(
      "https://gw.example.com/metamcp/ops%20tools%2F%C3%A9/mcp",
    );
    expect(s.serverName).toBe("ops_tools__");
  });

  it("uses an edited server name, sanitized, for the client side only", () => {
    const s = snippets({ serverName: "my server!", enableApiKeyAuth: true });
    expect(s.serverName).toBe("my_server_");
    expect(s.apiKeyEnvVar).toBe("MCP_MY_SERVER__API_KEY");
    expect(s.mcpUrl).toBe(MCP_URL);
  });

  it.each([
    ["empty", ""],
    ["not a URL", "not a url"],
    ["a non-http scheme", "ftp://gw.example.com"],
    ["a script URL", "javascript:alert(1)"],
    ["a URL carrying a user and password", "https://user:pw@gw.example.com"],
    ["a query string", "https://gw.example.com?x=1"],
    ["a fragment", "https://gw.example.com#frag"],
    // new URL() silently drops tabs and newlines and encodes spaces, so the
    // text it validates would differ from the text a snippet prints.
    ["a space", "https://gw.example.com/a b"],
    ["a newline", "https://gw.example.com/a\nb"],
  ])("refuses an app URL that is %s", (_label, appUrl) => {
    expect(buildInstallSnippets(input({ appUrl }))).toEqual({
      ok: false,
      reason: "invalidUrl",
    });
  });
});

describe("clientServerName", () => {
  it("keeps letters, digits, hyphen and underscore and replaces the rest", () => {
    expect(clientServerName("Ops-Tools_2")).toBe("Ops-Tools_2");
    expect(clientServerName("a b.c")).toBe("a_b_c");
  });

  it("never starts with a hyphen, which a CLI would read as a flag", () => {
    expect(clientServerName("-s")).toBe("_s");
    expect(clientServerName("--x").startsWith("-")).toBe(false);
  });

  it("falls back to mcp for an empty name", () => {
    expect(clientServerName("")).toBe("mcp");
  });
});

describe("apiKeyEnvVarName", () => {
  it.each(["ops-tools", "a", "9lives", "anthropic", "AWS", "x y!"])(
    "is a legal variable name and carries the MCP_ prefix for %j",
    (name) => {
      const v = apiKeyEnvVarName(name);
      expect(v).toMatch(/^[A-Z][A-Z0-9_]*$/);
      // Claude Code reads names such as ANTHROPIC_API_KEY and AWS_* as empty
      // in a remote server's headers; a private prefix can never collide.
      expect(v.startsWith("MCP_")).toBe(true);
      expect(v.endsWith("_API_KEY")).toBe(true);
    },
  );
});

describe("shellQuote against a real POSIX shell", () => {
  it.each([
    ["a'b"],
    ["has space"],
    ["$HOME"],
    ["`id`"],
    ["$(echo pwned)"],
    [";ls"],
    ['say "hi"'],
    ["*"],
    ["back\\slash"],
    ["two\nlines"],
    [""],
    ["-x"],
    ["héllo ✓"],
    ["a&b|c"],
    ["~"],
    ["#c"],
    ["!x"],
    ["https://gw.example.com/metamcp/ops-tools/mcp"],
  ])("round-trips %j unchanged", (value) => {
    const out = execFileSync("sh", ["-c", `printf %s ${shellQuote(value)}`], {
      encoding: "utf8",
    });
    expect(out).toBe(value);
  });
});

describe("tomlString against a real TOML parser", () => {
  it.each([
    ['a"b'],
    ["back\\slash"],
    ["line\nbreak"],
    ["tab\there"],
    ["\u0001\u007f"],
    ["héllo ✓ 😀"],
    ['" ]\n[mcp_servers.evil]\nurl = "x'],
  ])("round-trips %j unchanged and stays one string", (value) => {
    const parsed = parseToml(`key = ${tomlString(value)}\n`);
    expect(parsed).toEqual({ key: value });
  });
});

describe("Claude Code", () => {
  const CLAUDE_KEY_COMMAND = `claude mcp add --transport http ops-tools ${MCP_URL} --header "Authorization: Bearer ${PLACEHOLDER}"`;
  const CLAUDE_URL_COMMAND = `claude mcp add --transport http ops-tools ${MCP_URL}`;

  it("API key: the documented command with a placeholder header, plus an environment-variable .mcp.json", () => {
    const o = option(
      snippets({ enableApiKeyAuth: true }).clients.claudeCode,
      "apiKey",
    );
    expect(o.blocks).toHaveLength(2);
    expect(o.blocks[0]).toMatchObject({
      kind: "command",
      language: "bash",
      text: CLAUDE_KEY_COMMAND,
    });
    expect(o.blocks[1]).toMatchObject({
      kind: "config",
      language: "json",
      destinations: [{ scope: "project", path: ".mcp.json" }],
    });
    expect(JSON.parse(o.blocks[1]!.text)).toEqual({
      mcpServers: {
        "ops-tools": {
          type: "http",
          url: MCP_URL,
          headers: { Authorization: `Bearer \${${ENV_VAR}}` },
        },
      },
    });
  });

  it("OAuth: the command with no header, then claude mcp login", () => {
    const o = option(
      snippets({ enableOauth: true }).clients.claudeCode,
      "oauth",
    );
    expect(o.blocks.map((b) => [b.kind, b.text])).toEqual([
      ["command", CLAUDE_URL_COMMAND],
      ["login", "claude mcp login ops-tools"],
    ]);
  });

  it("no auth: the command with no header and no sign-in step", () => {
    const o = option(snippets().clients.claudeCode, "none");
    expect(o.blocks.map((b) => [b.kind, b.text])).toEqual([
      ["command", CLAUDE_URL_COMMAND],
    ]);
  });

  it("hands a real shell exactly one URL argument whatever the app URL holds", () => {
    const hostile = "https://gw.example.com/a'b$HOME;x&y`id`$(id)";
    const s = snippets({ appUrl: hostile, enableApiKeyAuth: true });
    const command = option(s.clients.claudeCode, "apiKey").blocks[0]!.text;
    expect(shellArgv(command)).toEqual([
      "mcp",
      "add",
      "--transport",
      "http",
      "ops-tools",
      `${hostile}/metamcp/ops-tools/mcp`,
      "--header",
      `Authorization: Bearer ${PLACEHOLDER}`,
    ]);
  });

  it("warns that a header turns off the OAuth fallback only when both modes are on", () => {
    const both = snippets({ enableApiKeyAuth: true, enableOauth: true });
    expect(noteKeys(option(both.clients.claudeCode, "apiKey"))).toContain(
      "headerNote",
    );
    const keyOnly = snippets({ enableApiKeyAuth: true });
    expect(
      noteKeys(option(keyOnly.clients.claudeCode, "apiKey")),
    ).not.toContain("headerNote");
  });
});

describe("Codex", () => {
  it("API key: bearer_token_env_var holds the variable name, never a token or header", () => {
    const o = option(
      snippets({ enableApiKeyAuth: true }).clients.codex,
      "apiKey",
    );
    expect(o.blocks).toHaveLength(1);
    const block = o.blocks[0]!;
    expect(block).toMatchObject({
      kind: "config",
      language: "toml",
      destinations: [{ scope: "user", path: "~/.codex/config.toml" }],
      text: `[mcp_servers.ops-tools]\nurl = "${MCP_URL}"\nbearer_token_env_var = "${ENV_VAR}"\n`,
    });
    expect(parseToml(block.text)).toEqual({
      mcp_servers: {
        "ops-tools": { url: MCP_URL, bearer_token_env_var: ENV_VAR },
      },
    });
  });

  it("OAuth: the URL alone, then codex mcp login", () => {
    const o = option(snippets({ enableOauth: true }).clients.codex, "oauth");
    expect(o.blocks.map((b) => [b.kind, b.text])).toEqual([
      ["config", `[mcp_servers.ops-tools]\nurl = "${MCP_URL}"\n`],
      ["login", "codex mcp login ops-tools"],
    ]);
  });

  it("no auth: the URL alone", () => {
    const o = option(snippets().clients.codex, "none");
    expect(o.blocks.map((b) => b.text)).toEqual([
      `[mcp_servers.ops-tools]\nurl = "${MCP_URL}"\n`,
    ]);
  });

  it("keeps a hostile app URL inside its TOML string", () => {
    const hostile = 'https://gw.example.com/x"y\\z';
    const s = snippets({ appUrl: hostile, enableApiKeyAuth: true });
    const parsed = parseToml(
      option(s.clients.codex, "apiKey").blocks[0]!.text,
    ) as { mcp_servers: Record<string, { url: string }> };
    expect(Object.keys(parsed.mcp_servers)).toEqual(["ops-tools"]);
    expect(parsed.mcp_servers["ops-tools"]!.url).toBe(
      `${hostile}/metamcp/ops-tools/mcp`,
    );
  });
});

describe("Cursor", () => {
  it("API key: mcpServers with a ${env:NAME} reference in headers", () => {
    const o = option(
      snippets({ enableApiKeyAuth: true }).clients.cursor,
      "apiKey",
    );
    expect(o.blocks).toHaveLength(1);
    expect(o.blocks[0]).toMatchObject({
      kind: "config",
      language: "json",
      destinations: [
        { scope: "project", path: ".cursor/mcp.json" },
        { scope: "user", path: "~/.cursor/mcp.json" },
      ],
    });
    expect(JSON.parse(o.blocks[0]!.text)).toEqual({
      mcpServers: {
        "ops-tools": {
          url: MCP_URL,
          headers: { Authorization: `Bearer \${env:${ENV_VAR}}` },
        },
      },
    });
  });

  it("OAuth and no auth: the URL alone", () => {
    for (const [overrides, auth] of [
      [{ enableOauth: true }, "oauth"],
      [{}, "none"],
    ] as const) {
      const o = option(snippets(overrides).clients.cursor, auth);
      expect(JSON.parse(o.blocks[0]!.text)).toEqual({
        mcpServers: { "ops-tools": { url: MCP_URL } },
      });
    }
  });

  it("says why an OAuth sign-in can fail: only loopback callbacks self-register", () => {
    const o = option(snippets({ enableOauth: true }).clients.cursor, "oauth");
    expect(noteKeys(o)).toContain("oauthLoopbackNote");
  });
});

describe("VS Code", () => {
  it("API key: the native mcpServers shape with an HTTP entry, a ${NAME} reference and its destinations", () => {
    const o = option(
      snippets({ enableApiKeyAuth: true }).clients.vscode,
      "apiKey",
    );
    expect(o.blocks).toHaveLength(1);
    expect(o.blocks[0]).toMatchObject({
      kind: "config",
      language: "json",
      destinations: [
        { scope: "project", path: ".mcp.json" },
        { scope: "user", path: "~/.copilot/mcp-config.json" },
      ],
    });
    expect(JSON.parse(o.blocks[0]!.text)).toEqual({
      mcpServers: {
        "ops-tools": {
          type: "http",
          url: MCP_URL,
          headers: { Authorization: `Bearer \${${ENV_VAR}}` },
          tools: ["*"],
        },
      },
    });
  });

  it("OAuth and no auth: the HTTP entry with no headers", () => {
    for (const [overrides, auth] of [
      [{ enableOauth: true }, "oauth"],
      [{}, "none"],
    ] as const) {
      const o = option(snippets(overrides).clients.vscode, auth);
      expect(JSON.parse(o.blocks[0]!.text)).toEqual({
        mcpServers: {
          "ops-tools": { type: "http", url: MCP_URL, tools: ["*"] },
        },
      });
    }
  });
});

describe("Claude (web and desktop)", () => {
  it.each(AUTH_MATRIX)(
    "is offered only when OAuth is on (api key $apiKey, oauth $oauth)",
    (m) => {
      const s = snippets(matrixInput(m));
      if (m.oauth) {
        expect(s.claudeWeb).not.toBeNull();
        expect(s.claudeWeb!.steps.map((n) => n.key)).toEqual([
          "claudeStep1",
          "claudeStep2",
          "claudeStep3",
          "claudeStep4",
        ]);
        expect(s.claudeWeb!.blocks).toEqual([]);
      } else {
        expect(s.claudeWeb).toBeNull();
      }
    },
  );
});

describe("which options a client gets", () => {
  it.each(AUTH_MATRIX)("api key $apiKey, oauth $oauth", (m) => {
    const expected: InstallOption["auth"][] = [];
    if (m.apiKey) expected.push("apiKey");
    if (m.oauth) expected.push("oauth");
    if (expected.length === 0) expected.push("none");
    const s = snippets(matrixInput(m));
    for (const client of ["claudeCode", "codex", "cursor", "vscode"] as const) {
      expect(s.clients[client].map((o) => o.auth)).toEqual(expected);
    }
  });

  it("only the auth-disabled case carries unauthenticated-endpoint guidance", () => {
    for (const m of AUTH_MATRIX) {
      const s = snippets(matrixInput(m));
      const keys = Object.values(s.clients).flatMap((os) =>
        os.flatMap(noteKeys),
      );
      expect(keys.includes("noAuthNote")).toBe(!m.apiKey && !m.oauth);
    }
  });

  it("a scoped-key endpoint tells every API key option to use a key scoped to it", () => {
    const s = snippets({ enableApiKeyAuth: true, requireScopedApiKey: true });
    for (const client of ["claudeCode", "codex", "cursor", "vscode"] as const) {
      const keys = noteKeys(option(s.clients[client], "apiKey"));
      expect(keys).toContain("scopedKeyNote");
    }
    const open = snippets({ enableApiKeyAuth: true });
    for (const client of ["claudeCode", "codex", "cursor", "vscode"] as const) {
      expect(noteKeys(option(open.clients[client], "apiKey"))).not.toContain(
        "scopedKeyNote",
      );
    }
  });
});

describe("no secret in any snippet", () => {
  it.each(AUTH_MATRIX)(
    "never carries a key or a query-parameter key (api key $apiKey, oauth $oauth)",
    (m) => {
      const hostile = {
        ...input(matrixInput(m)),
        apiKey: "sk_mt_live_SECRET123",
        api_key: "sk_mt_live_SECRET456",
        bearerToken: "sk_mt_live_SECRET789",
        useQueryParamAuth: true,
        use_query_param_auth: true,
      } as unknown as InstallInput;
      const result = buildInstallSnippets(hostile);
      expect(result.ok).toBe(true);
      const all = JSON.stringify(result);
      expect(all).not.toMatch(/sk_mt_/);
      expect(all).not.toContain("SECRET");
      expect(all).not.toContain("api_key=");
    },
  );

  it("shows the placeholder only in the one Claude Code command that needs a literal header", () => {
    for (const m of AUTH_MATRIX) {
      const s = snippets(matrixInput(m));
      const blocks = Object.entries(s.clients).flatMap(([client, os]) =>
        os.flatMap((o) =>
          o.blocks.map((b) => ({ client, auth: o.auth, block: b })),
        ),
      );
      const carriers = blocks.filter((b) => b.block.text.includes(PLACEHOLDER));
      if (m.apiKey) {
        expect(carriers.map((c) => [c.client, c.auth, c.block.kind])).toEqual([
          ["claudeCode", "apiKey", "command"],
        ]);
      } else {
        expect(carriers).toEqual([]);
        expect(JSON.stringify(s)).not.toContain("Authorization");
      }
    }
  });

  it("puts a variable reference, never a literal key, in every config file", () => {
    const s = snippets({ enableApiKeyAuth: true });
    const configs = Object.values(s.clients)
      .flatMap((os) => os.flatMap((o) => o.blocks))
      .filter((b) => b.kind === "config");
    expect(configs).toHaveLength(4);
    for (const c of configs) {
      expect(c.text).toContain(ENV_VAR);
      expect(c.text).not.toContain(PLACEHOLDER);
    }
  });
});
