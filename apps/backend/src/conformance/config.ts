/**
 * Environment parsing for the harness entry points. Every `CONFORMANCE_*` read
 * goes through these functions (so the names are declared once, in turbo.json,
 * and the lint rule on undeclared env vars stays satisfied), and none of them
 * ever puts a credential in an error message.
 */

export type Env = Readonly<Record<string, string | undefined>>;

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);
const MIN_API_KEY_LENGTH = 32;

function parsePort(env: Env, name: string, fallback: number): number {
  const raw = env[name];
  if (raw === undefined || raw === "") return fallback;
  if (!/^\d{1,5}$/.test(raw) || Number(raw) < 1 || Number(raw) > 65535) {
    throw new Error(`${name} must be a port number between 1 and 65535`);
  }
  return Number(raw);
}

function required(env: Env, name: string): string {
  const value = env[name];
  if (value === undefined || value === "") {
    throw new Error(`${name} is required`);
  }
  return value;
}

export interface FixtureConfig {
  port: number;
}

export function parseFixtureConfig(env: Env): FixtureConfig {
  return { port: parsePort(env, "CONFORMANCE_FIXTURE_PORT", 3901) };
}

export interface ProxyConfig {
  upstreamUrl: string;
  apiKey: string;
  prefix: string;
  port: number;
}

/**
 * The proxy attaches the API key to everything it forwards, so the upstream
 * must be a loopback http URL: a mistyped or hostile `CONFORMANCE_UPSTREAM_URL`
 * must not be able to send the key anywhere else.
 */
function parseLoopbackUrl(name: string, raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`${name} is not a valid URL`);
  }
  if (url.protocol !== "http:" || !LOOPBACK_HOSTS.has(url.hostname)) {
    throw new Error(`${name} must be an http URL on a loopback host`);
  }
  return raw;
}

function parsePrefix(env: Env): string {
  const prefix = required(env, "CONFORMANCE_TOOL_PREFIX");
  if (!/^[a-zA-Z0-9_-]+$/.test(prefix)) {
    throw new Error(
      "CONFORMANCE_TOOL_PREFIX may only contain letters, digits, _ and -",
    );
  }
  return prefix;
}

function parseApiKey(env: Env): string {
  const apiKey = required(env, "CONFORMANCE_API_KEY");
  if (apiKey.length < MIN_API_KEY_LENGTH || /\s/.test(apiKey)) {
    throw new Error(
      `CONFORMANCE_API_KEY must be at least ${MIN_API_KEY_LENGTH} characters with no whitespace`,
    );
  }
  return apiKey;
}

export function parseProxyConfig(env: Env): ProxyConfig {
  return {
    upstreamUrl: parseLoopbackUrl(
      "CONFORMANCE_UPSTREAM_URL",
      required(env, "CONFORMANCE_UPSTREAM_URL"),
    ),
    apiKey: parseApiKey(env),
    prefix: parsePrefix(env),
    port: parsePort(env, "CONFORMANCE_PROXY_PORT", 3902),
  };
}

export interface SmokeConfig {
  /** The gateway endpoint itself (prefixed tool names, key sent by the smoke). */
  gatewayUrl: string;
  /** The alias proxy (unprefixed names, key injected by the proxy). */
  proxyUrl: string;
  apiKey: string;
  prefix: string;
}

export function parseSmokeConfig(env: Env): SmokeConfig {
  const proxyPort = parsePort(env, "CONFORMANCE_PROXY_PORT", 3902);
  return {
    gatewayUrl: parseLoopbackUrl(
      "CONFORMANCE_UPSTREAM_URL",
      required(env, "CONFORMANCE_UPSTREAM_URL"),
    ),
    proxyUrl: `http://127.0.0.1:${proxyPort}/mcp`,
    apiKey: parseApiKey(env),
    prefix: parsePrefix(env),
  };
}
