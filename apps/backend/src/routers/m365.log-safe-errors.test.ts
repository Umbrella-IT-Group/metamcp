import type { Server } from "node:http";
import { format } from "node:util";

import { DrizzleQueryError } from "drizzle-orm/errors";
import express from "express";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

const { loggerMock } = vi.hoisted(() => ({
  loggerMock: {
    error: vi.fn(),
    warn: vi.fn(),
    info: vi.fn(),
    debug: vi.fn(),
  },
}));
vi.mock("@/utils/logger", () => ({ default: loggerMock }));
vi.mock("@/auth", () => ({
  auth: {
    api: {
      getSession: vi.fn(async () => ({
        user: { id: "user-1", email: "member@example.test" },
      })),
    },
  },
}));
vi.mock("@/db/repositories/users.repo", () => ({
  usersRepository: { isDisabled: vi.fn(async () => false) },
}));
vi.mock("@/db/repositories/m365-tokens.repo", () => ({
  m365TokensRepository: { findByUserId: vi.fn(), deleteByUserId: vi.fn() },
}));
vi.mock("../lib/m365/mint-service", () => ({
  m365MintService: { invalidateUser: vi.fn() },
}));

import { m365TokensRepository } from "@/db/repositories/m365-tokens.repo";
import {
  errorHandler,
  INTERNAL_ERROR_BODY,
} from "@/middleware/error-handler.middleware";

import m365Router from "./m365";

const SECRET = "fake-m365-row-secret-hhhh8888";
const QUERY = 'delete from "m365_user_tokens" where "user_id" = $1 returning *';

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  const app = express();
  // The real index.ts mounts this router before the terminal error handler.
  // Express 5 forwards both routes' uncaught repository rejections to it.
  app.use(m365Router);
  app.use(errorHandler);
  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (typeof address !== "object" || !address) throw new Error("No address");
  baseUrl = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(() => {
  vi.clearAllMocks();
  const error = new DrizzleQueryError(
    QUERY,
    [SECRET],
    Object.assign(new Error(SECRET), {
      code: "23514",
      constraint: "m365_user_tokens_check",
      detail: `Failing row contains (${SECRET})`,
    }),
  );
  vi.mocked(m365TokensRepository.findByUserId).mockRejectedValue(error);
  vi.mocked(m365TokensRepository.deleteByUserId).mockRejectedValue(error);
});

describe("M365 repository errors reaching the terminal handler", () => {
  it.each([
    ["GET", "/m365/status"],
    ["POST", "/m365/disconnect"],
  ])(
    "%s %s keeps row data out of the log and response",
    async (method, path) => {
      const response = await fetch(`${baseUrl}${path}`, { method });
      expect(response.status).toBe(500);
      expect(await response.json()).toEqual(INTERNAL_ERROR_BODY);

      const logged = loggerMock.error.mock.calls
        .map((args) => format(...args))
        .join("\n");
      expect(logged).not.toContain(SECRET);
      expect(logged).not.toContain(QUERY);
      expect(logged).toContain(path);
      expect(logged).toContain("DrizzleQueryError");
      expect(logged).toContain("23514");
      expect(logged).toContain("m365_user_tokens_check");
    },
  );
});
