/**
 * Regression guard: a tRPC implementation never hands a caught error to the
 * logger as it is.
 *
 * Every `*.impl.ts` handler here runs repository calls, and Drizzle wraps a
 * failed query in a DrizzleQueryError whose message is
 * "Failed query: <sql>\nparams: <bound values>". The logger formats its
 * arguments with util.format, so `logger.error("...", error)` copies the bound
 * values (credentials, API key rows, OAuth rows, administrator-authored text)
 * into the container log. A caught error goes to the logger through
 * `describeDbError` (lib/db-error-summary.ts), which keeps the error class and
 * the database's own codes and drops everything that can quote a value.
 *
 * The scan is static and deterministic: it parses each implementation file,
 * finds every logger or console call that mentions a caught identifier (the
 * variable of an enclosing `catch`, the parameter of a `.catch(...)` or
 * two-argument `.then(...)` handler, or `.reason` of a settled result) outside
 * a `describeDbError(...)` call, and compares the list with ALLOWED below.
 * An allowed entry names a call by file and message and states why its catch
 * can never see a database error; an entry that no longer matches a call
 * fails the test, so the list cannot go stale.
 */
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";
import { describe, expect, it } from "vitest";

type Finding = {
  file: string;
  line: number;
  /** The text of the message (first argument), to the first interpolation. */
  message: string;
  /** What was passed: the identifier, or the expression that mentions it. */
  argument: string;
};

const LOG_CALL =
  /^(logger\.(error|warn|info|debug)|console\.(error|warn|info|log|debug))$/;

function messageOf(call: ts.CallExpression): string {
  const first = call.arguments[0];
  if (!first) return "";
  if (ts.isStringLiteralLike(first)) return first.text.slice(0, 100);
  if (ts.isTemplateExpression(first)) return first.head.text.slice(0, 100);
  return first.getText().slice(0, 100);
}

/** Names a `catch` clause or a rejection handler binds around `node`. */
function caughtNamesAround(node: ts.Node): Set<string> {
  const names = new Set<string>();
  for (let current = node.parent; current; current = current.parent) {
    if (ts.isCatchClause(current) && current.variableDeclaration) {
      names.add(current.variableDeclaration.name.getText());
    }
    if (
      (ts.isArrowFunction(current) || ts.isFunctionExpression(current)) &&
      current.parent &&
      ts.isCallExpression(current.parent) &&
      ts.isPropertyAccessExpression(current.parent.expression)
    ) {
      const method = current.parent.expression.name.text;
      const isRejectionHandler =
        method === "catch" ||
        (method === "then" && current.parent.arguments[1] === current);
      const first = current.parameters[0];
      if (isRejectionHandler && first) names.add(first.name.getText());
    }
  }
  return names;
}

/** Does `node` mention a caught identifier outside a describeDbError call? */
function mentions(node: ts.Node, caught: Set<string>): string | undefined {
  if (
    ts.isCallExpression(node) &&
    ts.isIdentifier(node.expression) &&
    node.expression.text === "describeDbError"
  ) {
    return undefined;
  }
  if (ts.isIdentifier(node) && caught.has(node.text)) return node.text;
  if (ts.isPropertyAccessExpression(node) && node.name.text === "reason") {
    return node.getText();
  }
  let found: string | undefined;
  ts.forEachChild(node, (child) => {
    found ??= mentions(child, caught);
  });
  return found;
}

export function findRawCaughtErrorLogs(
  source: string,
  file: string,
): Finding[] {
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
  const findings: Finding[] = [];
  const visit = (node: ts.Node): void => {
    if (
      ts.isCallExpression(node) &&
      LOG_CALL.test(node.expression.getText(sf).replace(/\s+/g, ""))
    ) {
      const caught = caughtNamesAround(node);
      for (const argument of node.arguments) {
        const hit = mentions(argument, caught);
        if (hit) {
          findings.push({
            file,
            line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1,
            message: messageOf(node),
            argument: hit,
          });
          break;
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return findings;
}

const keyOf = (finding: Finding): string =>
  `${finding.file} | ${finding.message}`;

/**
 * Logger calls in an implementation that mention a caught error and are not
 * wrapped, each with the reason its catch can never see a database error.
 */
const ALLOWED: Record<string, string> = {
  "logs.impl.ts | Error getting logs:":
    "reads the in-memory log ring buffer; no repository call",
  "mcp-servers.impl.ts | Error ensuring idle session for newly created server ":
    "detached .catch on the pool's idle-session connect, which swallows its own repository errors",
  "mcp-servers.impl.ts | Error ensuring idle session for bulk imported server ":
    "detached .catch on the pool's idle-session connect, which swallows its own repository errors",
  "mcp-servers.impl.ts | Error invalidating idle MetaMCP servers after deleting server ":
    "detached .catch on pool invalidation (transport close and in-memory rebuild)",
  "mcp-servers.impl.ts | Error invalidating OpenAPI sessions after deleting server ":
    "detached .catch on pool invalidation (transport close and in-memory rebuild)",
  "mcp-servers.impl.ts | Error invalidating idle session for updated server ":
    "detached .catch on the pool's idle-session rebuild, which swallows its own repository errors",
  "mcp-servers.impl.ts | Error invalidating idle MetaMCP servers after updating server ":
    "detached .catch on pool invalidation (transport close and in-memory rebuild)",
  "mcp-servers.impl.ts | Error invalidating OpenAPI sessions after updating server ":
    "detached .catch on pool invalidation (transport close and in-memory rebuild)",
  "mcp-servers.impl.ts | Error invalidating idle MetaMCP servers during reconnect of ":
    "rejection of pool invalidation (transport close and in-memory rebuild)",
  "mcp-servers.impl.ts | Error invalidating OpenAPI sessions during reconnect of ":
    "rejection of pool invalidation (transport close and in-memory rebuild)",
  "namespaces.impl.ts | Error ensuring idle MetaMCP server for new namespace ":
    "detached .catch on the pool's server build, which only assembles handlers",
  "namespaces.impl.ts | Error cleaning up idle MetaMCP server for deleted namespace ":
    "pool teardown (transport close); no repository call",
  "namespaces.impl.ts | Error invalidating idle MetaMCP server for namespace ":
    "detached .catch on pool invalidation (transport close and in-memory rebuild)",
  "namespaces.impl.ts | Error invalidating OpenAPI session for namespace ":
    "detached .catch on pool invalidation (transport close and in-memory rebuild)",
};

const here = path.dirname(fileURLToPath(import.meta.url));

function implementationFiles(): string[] {
  return readdirSync(here)
    .filter((name) => name.endsWith(".impl.ts"))
    .sort();
}

describe("tRPC implementations never log a caught error as it is", () => {
  it("scans the implementation files it is meant to scan", () => {
    const files = implementationFiles();
    expect(files.length).toBeGreaterThan(10);
    expect(files).toContain("mcp-servers.impl.ts");
    expect(files).toContain("endpoint-presentation.impl.ts");
  });

  it("finds no logger call that mentions a caught error outside describeDbError", () => {
    const unlisted: string[] = [];
    const seen = new Set<string>();
    for (const file of implementationFiles()) {
      const source = readFileSync(path.join(here, file), "utf8");
      for (const finding of findRawCaughtErrorLogs(source, file)) {
        const key = keyOf(finding);
        seen.add(key);
        if (!(key in ALLOWED)) {
          unlisted.push(
            `${finding.file}:${finding.line} logs ${finding.argument} from "${finding.message}"; route it through describeDbError`,
          );
        }
      }
    }
    expect(unlisted).toEqual([]);

    const stale = Object.keys(ALLOWED).filter((key) => !seen.has(key));
    expect(stale).toEqual([]);
  });

  it("explains every allowed call", () => {
    for (const [key, reason] of Object.entries(ALLOWED)) {
      expect(reason.length, key).toBeGreaterThan(20);
    }
  });
});

describe("the scanner", () => {
  const scan = (body: string) =>
    findRawCaughtErrorLogs(body, "planted.impl.ts");

  it("flags a caught error passed to the logger as it is", () => {
    const findings = scan(`
      async function create() {
        try { await repo.create(); }
        catch (error) { logger.error("Error creating thing:", error); }
      }`);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      message: "Error creating thing:",
      argument: "error",
    });
  });

  it("flags the message, a template and a console call too", () => {
    expect(
      scan(`try { a(); } catch (e) { logger.warn("x", e.message); }`),
    ).toHaveLength(1);
    expect(
      scan("try { a(); } catch (e) { logger.warn(`x ${e}`); }"),
    ).toHaveLength(1);
    expect(
      scan(`try { a(); } catch (e) { console.error("x", e); }`),
    ).toHaveLength(1);
  });

  it("flags a rejection handler and a settled result's reason", () => {
    expect(scan(`p.catch((err) => { logger.error("x", err); });`)).toHaveLength(
      1,
    );
    expect(scan(`p.then(ok, (err) => logger.error("x", err));`)).toHaveLength(
      1,
    );
    expect(scan(`logger.error("x", settled.reason);`)).toHaveLength(1);
  });

  it("accepts the same calls through describeDbError", () => {
    expect(
      scan(
        `try { a(); } catch (error) { logger.error("x", describeDbError(error)); }`,
      ),
    ).toEqual([]);
    expect(
      scan(
        "try { a(); } catch (e) { logger.warn(`x ${describeDbError(e)}`); }",
      ),
    ).toEqual([]);
    expect(scan(`logger.error("x", describeDbError(settled.reason));`)).toEqual(
      [],
    );
  });

  it("ignores a logger call that mentions no caught error", () => {
    expect(
      scan(`try { a(); } catch (error) { logger.info("done", id); }`),
    ).toEqual([]);
    expect(scan(`logger.info("started", { error: false });`)).toEqual([]);
  });
});
