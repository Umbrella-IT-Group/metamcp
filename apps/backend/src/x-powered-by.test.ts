/**
 * The backend must not announce its framework in a response header.
 *
 * Express sets `X-Powered-By: Express` by default; `index.ts` now turns it off
 * with `app.disable("x-powered-by")`. index.ts calls `app.listen()` at
 * module scope and so cannot be imported by a test, the same constraint that
 * moved the body-parser wiring into lib/global-body-parser. So this pins the
 * mechanism that one line relies on over a real socket: an app configured the
 * way index.ts configures it emits no such header, and a default app (the
 * pre-fix control) does. Deleting the disable in index.ts reintroduces exactly
 * the control app's behaviour.
 */

import type { Server } from "node:http";

import express from "express";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

async function startApp(disablePoweredBy: boolean): Promise<{
  server: Server;
  baseUrl: string;
}> {
  const app = express();
  if (disablePoweredBy) {
    app.disable("x-powered-by");
  }
  app.get("/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

let hardened: { server: Server; baseUrl: string };
let control: { server: Server; baseUrl: string };

beforeAll(async () => {
  hardened = await startApp(true);
  control = await startApp(false);
});

afterAll(async () => {
  await new Promise((resolve) => hardened.server.close(resolve));
  await new Promise((resolve) => control.server.close(resolve));
});

describe("x-powered-by", () => {
  it("is absent once disabled the way index.ts disables it", async () => {
    const response = await fetch(`${hardened.baseUrl}/health`);
    expect(response.headers.get("x-powered-by")).toBeNull();
  });

  it("is present without the disable, so the test guards a real change", async () => {
    const response = await fetch(`${control.baseUrl}/health`);
    expect(response.headers.get("x-powered-by")).toBe("Express");
  });
});
