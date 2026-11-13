/** Entry: the conformance fixture backend on loopback. Closes on SIGTERM. */
import { parseFixtureConfig } from "./config";
import { createFixtureServer } from "./fixture-server";

const { port } = parseFixtureConfig(process.env);
const server = createFixtureServer();

const bound = await server.listen(port, "127.0.0.1");
console.log(`conformance fixture listening on 127.0.0.1:${bound}`);

process.once("SIGTERM", () => {
  server.close().then(() => {
    process.exitCode = 0;
  });
});
