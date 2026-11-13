/**
 * Pre-suite smoke test: proves the stack is what the suite assumes before a
 * single scenario runs, so a broken harness fails here, fast and named, instead
 * of becoming 32 confusing scenario results.
 *
 * Two surfaces, checked separately on purpose:
 *
 *  1. The gateway itself, with the key sent here and PREFIXED names. This proves
 *     the mount is real (a seed that forgot the mapping lists nothing, and
 *     `tools-list` would pass on an empty namespace), that a call reaches the
 *     fixture, and, with a keyed 200 beside each, that the endpoint refuses a
 *     request with no credential, an unknown well-formed key and a Basic
 *     scheme. An unknown endpoint also answers 401, so a bare 401 proves
 *     nothing without the 200.
 *  2. The alias proxy, with NO credential sent here and UNPREFIXED names. This
 *     proves the proxy injects the right key (a wrong key makes the gateway
 *     answer 401 and this fails before the suite) and maps the prefix both ways.
 *
 * It is retried for up to a minute on connection trouble only: a rejected
 * credential fails at once, because waiting cannot fix it.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  StreamableHTTPClientTransport,
  StreamableHTTPError,
} from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { isMainModule } from "./cli";
import { parseSmokeConfig, type SmokeConfig } from "./config";
import { FIXTURE_TOOL_NAMES } from "./fixture-tools";

export interface SmokeIo {
  out(text: string): void;
  err(text: string): void;
}

export interface SmokeDeps {
  sleep(ms: number): Promise<void>;
}

const ATTEMPTS = 30;
const RETRY_DELAY_MS = 2000;
const SIMPLE_TEXT = "This is a simple text response for testing.";
const UNKNOWN_KEY = `sk_mt_${"0".repeat(64)}`;

const INITIALIZE = JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "conformance-smoke", version: "1.0.0" },
  },
});

const redact = (text: string) =>
  text.replace(/(sk_mt_|confsec_)[0-9a-f]{64}/g, "$1[redacted]");

const describeError = (error: unknown) =>
  redact(error instanceof Error ? error.message : String(error));

function isCredentialRejection(error: unknown): boolean {
  return (
    error instanceof StreamableHTTPError &&
    (error.code === 401 || error.code === 403)
  );
}

async function withClient<T>(
  url: string,
  headers: Record<string, string>,
  fn: (client: Client) => Promise<T>,
): Promise<T> {
  const client = new Client(
    { name: "conformance-smoke", version: "1.0.0" },
    { capabilities: {} },
  );
  await client.connect(
    new StreamableHTTPClientTransport(new URL(url), {
      requestInit: { headers },
    }),
  );
  try {
    return await fn(client);
  } finally {
    await client.close().catch(() => undefined);
  }
}

async function retrying<T>(
  deps: SmokeDeps,
  attempt: () => Promise<T>,
): Promise<T> {
  let last: unknown;
  for (let i = 1; i <= ATTEMPTS; i++) {
    try {
      return await attempt();
    } catch (error) {
      last = error;
      if (isCredentialRejection(error)) throw error;
      if (i < ATTEMPTS) await deps.sleep(RETRY_DELAY_MS);
    }
  }
  throw last;
}

async function rawInitializeStatus(
  url: string,
  headers: Record<string, string>,
): Promise<number> {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...headers,
    },
    body: INITIALIZE,
  });
  // A 200 answers as an open event stream; nothing here needs its body.
  await response.body?.cancel().catch(() => undefined);
  return response.status;
}

const sorted = (names: readonly string[]) => [...names].sort();
const same = (a: readonly string[], b: readonly string[]) =>
  JSON.stringify(sorted(a)) === JSON.stringify(sorted(b));

// The SDK types a call result as a union that includes a compatibility
// `toolResult` shape, so the content is read through a narrow view.
const textOf = (result: unknown) =>
  (result as { content?: Array<{ type: string; text?: string }> }).content?.[0]
    ?.text;

export async function runSmoke(
  config: SmokeConfig,
  io: SmokeIo,
  deps: SmokeDeps = { sleep: (ms) => new Promise((r) => setTimeout(r, ms)) },
): Promise<number> {
  let failures = 0;
  const pass = (name: string) => io.out(`PASS ${name}\n`);
  const fail = (name: string, detail: string) => {
    failures += 1;
    io.err(`FAIL ${name}: ${detail}\n`);
  };
  const step = async (name: string, fn: () => Promise<string | undefined>) => {
    try {
      const problem = await fn();
      if (problem === undefined) pass(name);
      else fail(name, problem);
    } catch (error) {
      fail(name, describeError(error));
    }
  };

  const prefixed = FIXTURE_TOOL_NAMES.map((n) => `${config.prefix}__${n}`);
  const keyed = { authorization: `Bearer ${config.apiKey}` };

  await step("gateway: tools/list is exactly the fixture tools, prefixed", () =>
    retrying(deps, () =>
      withClient(config.gatewayUrl, keyed, async (client) => {
        const { tools } = await client.listTools();
        const names = tools.map((t) => t.name);
        return same(names, prefixed)
          ? undefined
          : `listed [${sorted(names).join(", ")}], expected [${sorted(prefixed).join(", ")}]`;
      }),
    ),
  );

  await step("gateway: a prefixed call reaches the fixture", () =>
    withClient(config.gatewayUrl, keyed, async (client) => {
      const result = await client.callTool({
        name: `${config.prefix}__test_simple_text`,
        arguments: {},
      });
      return textOf(result) === SIMPLE_TEXT
        ? undefined
        : `unexpected result ${redact(JSON.stringify(result.content))}`;
    }),
  );

  await step("gateway: the keyed request is accepted (200)", async () => {
    const status = await rawInitializeStatus(config.gatewayUrl, keyed);
    return status === 200 ? undefined : `expected 200, got ${status}`;
  });
  const refusals: Array<[string, Record<string, string>]> = [
    ["no credential", {}],
    ["an unknown well-formed key", { authorization: `Bearer ${UNKNOWN_KEY}` }],
    ["a Basic scheme", { authorization: "Basic Zm9vOmJhcg==" }],
  ];
  for (const [label, headers] of refusals) {
    await step(`gateway: ${label} is refused (401)`, async () => {
      const status = await rawInitializeStatus(config.gatewayUrl, headers);
      return status === 401 ? undefined : `expected 401, got ${status}`;
    });
  }

  await step("proxy: tools/list is exactly the fixture tools, unprefixed", () =>
    retrying(deps, () =>
      withClient(config.proxyUrl, {}, async (client) => {
        const { tools } = await client.listTools();
        const names = tools.map((t) => t.name);
        return same(names, FIXTURE_TOOL_NAMES)
          ? undefined
          : `listed [${sorted(names).join(", ")}], expected [${sorted(FIXTURE_TOOL_NAMES).join(", ")}]`;
      }),
    ),
  );

  await step("proxy: an unprefixed call reaches the fixture", () =>
    withClient(config.proxyUrl, {}, async (client) => {
      const result = await client.callTool({
        name: "test_simple_text",
        arguments: {},
      });
      return textOf(result) === SIMPLE_TEXT
        ? undefined
        : `unexpected result ${redact(JSON.stringify(result.content))}`;
    }),
  );

  io.out(
    failures === 0
      ? "smoke: all checks passed\n"
      : `smoke: ${failures} check(s) failed\n`,
  );
  return failures === 0 ? 0 : 1;
}

async function entry(): Promise<number> {
  let config: SmokeConfig;
  try {
    config = parseSmokeConfig(process.env);
  } catch (error) {
    process.stderr.write(`smoke: ${describeError(error)}\n`);
    return 2;
  }
  return runSmoke(config, {
    out: (text) => void process.stdout.write(text),
    err: (text) => void process.stderr.write(text),
  });
}

if (isMainModule(import.meta.url)) {
  entry().then((code) => {
    process.exitCode = code;
  });
}
