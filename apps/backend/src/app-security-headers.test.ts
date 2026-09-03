/**
 * Every backend response must carry a security-header baseline, not only the
 * per-router /trpc and /mcp-proxy legs. index.ts now mounts helmet app-wide
 * ahead of the routers so /api/auth, /health and /metamcp answer with nosniff,
 * frame denial and a default CSP too.
 *
 * index.ts calls app.listen() at module scope and cannot be imported by a test
 * (the same constraint that moved the body-parser wiring into a module and is
 * pinned the same way in x-powered-by.test.ts). So this pins the mechanism the
 * one line relies on over a real socket: an app with the app-wide helmet
 * emits the baseline on a plain route, and a default app (the pre-fix control)
 * does not. Deleting the app-wide mount reintroduces the control behaviour.
 */

import type { Server } from "node:http";

import express from "express";
import helmet from "helmet";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

async function startApp(withHelmet: boolean): Promise<{
  server: Server;
  baseUrl: string;
}> {
  const app = express();
  if (withHelmet) {
    // The same app-wide mount index.ts uses, ahead of the route below.
    app.use(helmet());
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

describe("app-wide security headers", () => {
  it("adds the baseline to a plain route the way index.ts does", async () => {
    const response = await fetch(`${hardened.baseUrl}/health`);
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("x-frame-options")).toBe("SAMEORIGIN");
    expect(response.headers.get("content-security-policy")).toBeTruthy();
  });

  it("a default app carries none of it, so the test guards a real change", async () => {
    const response = await fetch(`${control.baseUrl}/health`);
    expect(response.headers.get("x-content-type-options")).toBeNull();
    expect(response.headers.get("x-frame-options")).toBeNull();
    expect(response.headers.get("content-security-policy")).toBeNull();
  });
});
