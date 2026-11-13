/**
 * Entry: the alias proxy, bound to loopback only. The API key comes from the
 * environment and is never logged; the log carries fixed wording, methods and
 * statuses only. Closes on SIGTERM.
 */
import { createAliasProxy } from "./alias-proxy";
import { parseProxyConfig } from "./config";

const config = parseProxyConfig(process.env);
const proxy = createAliasProxy({
  upstream: config.upstreamUrl,
  apiKey: config.apiKey,
  prefix: config.prefix,
  log: (message) => console.log(`alias-proxy: ${message}`),
});

const bound = await proxy.listen(config.port, "127.0.0.1");
console.log(`alias-proxy listening on 127.0.0.1:${bound}`);

process.once("SIGTERM", () => {
  proxy.close().then(() => {
    process.exitCode = 0;
  });
});
