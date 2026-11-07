import { McpError } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";

import {
  describeListingFailure,
  MAX_REASON_CHARS,
  scrubForTesting,
} from "./audit-listing-log";

// The words the log panels count as failures (whole word, any case).
const PANEL_WORDS = /\b(error|fatal|panic|exception)\b/i;
// What may never reach a log line: C0, DEL, C1, the line and paragraph
// separators, bidirectional and zero-width format characters, lone surrogates.
const UNSAFE = /[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029]/u;

const describeMessage = (message: string) =>
  describeListingFailure(new Error(message));

describe("describeListingFailure", () => {
  it("names the class and the message", () => {
    class PoolRefused extends Error {
      constructor(message: string) {
        super(message);
        this.name = "PoolRefused";
      }
    }
    expect(describeListingFailure(new PoolRefused("connection cap hit"))).toBe(
      "PoolRefused: connection cap hit",
    );
    expect(describeListingFailure(new TypeError("fetch refused"))).toBe(
      "TypeError: fetch refused",
    );
  });

  it("describes a rejection that is not an Error without reading its fields", () => {
    expect(describeListingFailure("plain string reason")).toBe(
      "string: plain string reason",
    );
    expect(describeListingFailure({ token: "hunter2", args: { q: 1 } })).toBe(
      "object",
    );
    expect(describeListingFailure(undefined)).toBe("undefined");
  });

  it("keeps the line clear of the words the panels count, whatever the text says", () => {
    const samples = [
      new Error("Error POSTing to endpoint (HTTP 404): Session not found"),
      new McpError(-32600, 'Fatal: {"error":{"code":-32600}} panic exception'),
      new Error("an EXCEPTION was thrown"),
    ];
    for (const sample of samples) {
      const text = describeListingFailure(sample);
      expect(text).not.toMatch(PANEL_WORDS);
    }
    // The cut is visible and keeps the rest of the message readable.
    expect(describeMessage("Error POSTing to endpoint")).toBe(
      "Err*: Err* POSTing to endpoint",
    );
    // A name that merely contains one is not cut; the SDK's own prefix is.
    expect(
      describeListingFailure(new McpError(-32000, "Connection closed")),
    ).toBe("McpError: MCP err* -32000: Connection closed");
  });

  it("keeps text that is not a credential, so the cause stays readable", () => {
    expect(describeMessage("HTTP 401 Unauthorized: invalid token")).toBe(
      "Err*: HTTP 401 Unauthorized: invalid token",
    );
    expect(describeMessage("connect ECONNREFUSED 10.0.0.5:3000")).toBe(
      "Err*: connect ECONNREFUSED 10.0.0.5:3000",
    );
    expect(describeMessage("POST http://backend:3000/mcp timed out")).toBe(
      "Err*: POST http://backend:3000/mcp timed out",
    );
  });
});

describe("one line, no control characters", () => {
  // Every C0 control, DEL and every C1 control, one at a time, in the class
  // name and in the message: none survives, and none becomes a line break.
  const controls = [
    ...Array.from({ length: 0x20 }, (_, i) => i),
    ...Array.from({ length: 0x21 }, (_, i) => 0x7f + i),
  ];

  it.each(controls.map((code) => [code.toString(16).padStart(4, "0"), code]))(
    "U+%s does not reach the line",
    (_hex, code) => {
      const ch = String.fromCharCode(code as number);
      const err = new Error(`first${ch}second`);
      err.name = `Cls${ch}Name`;
      const text = describeListingFailure(err);
      expect(text).not.toMatch(UNSAFE);
      expect(text).not.toMatch(/[\r\n]/);
      // A deleted control joins its neighbours; a line break becomes a space.
      expect(text).toMatch(/^Cls(Name| Name): first(second| second)$/);
    },
  );

  it("neutralizes the separators, terminal escapes and format characters a message can carry", () => {
    expect(describeMessage("a\nb\rc\u0085d\u2028e\u2029f")).toBe(
      "Err*: a b c d e f",
    );
    expect(describeMessage("\u001b[31mred\u001b[0m\u0000end")).toBe(
      "Err*: [31mred[0mend",
    );
    // Right-to-left override and zero-width space are deleted; the BOM is
    // whitespace to JavaScript, so it becomes a space.
    expect(describeMessage("a\u202Eb\u200Bc\uFEFFd")).toBe("Err*: abc d");
    // A forged line must not survive as a second line.
    const forged = describeMessage(
      "first\n[ERROR] 2026/11/07 | forged\r\nline",
    );
    expect(forged).not.toMatch(/[\r\n]/);
    expect(forged).toContain("first [ERR*]");
  });

  it("does not split a credential at a control character", () => {
    const text = describeMessage("password=abc\u0000def\u001bghi");
    expect(text).not.toMatch(/abc|def|ghi/);
  });

  it("leaves no lone surrogate when the cut lands inside an emoji", () => {
    // 2-unit characters at every alignment of the cut.
    for (const pad of ["", "x"]) {
      const text = describeMessage(`${pad}${"\u{1F600}".repeat(400)}`);
      expect(text).not.toMatch(UNSAFE);
      expect(text.length).toBeLessThanOrEqual(MAX_REASON_CHARS);
    }
  });
});

describe("the length bound", () => {
  it("is the total, the ellipsis included, for every length around it", () => {
    // "string: " is 8 characters of class, so a message of n characters is a
    // line of 8 + n before any cut.
    for (let n = 200; n <= 300; n++) {
      const text = describeListingFailure("x".repeat(n));
      expect(text.length).toBeLessThanOrEqual(MAX_REASON_CHARS);
      if (8 + n <= MAX_REASON_CHARS) {
        expect(text).toBe(`string: ${"x".repeat(n)}`);
      } else {
        expect(text).toHaveLength(MAX_REASON_CHARS);
        expect(text.endsWith("...")).toBe(true);
      }
    }
    // The class "string" is not masked, so the cut line is exactly the bound.
    expect(describeListingFailure("x".repeat(5_000))).toHaveLength(
      MAX_REASON_CHARS,
    );
    // Masking "Error" to "Err*" only shortens the line.
    expect(describeMessage("x".repeat(5_000)).length).toBeLessThanOrEqual(
      MAX_REASON_CHARS,
    );
  });

  it("holds when the message is far past the read bound too", () => {
    const text = describeMessage("word ".repeat(2_000_000));
    expect(text.length).toBeLessThanOrEqual(MAX_REASON_CHARS);
    expect(text.endsWith("...")).toBe(true);
  });
});

describe("credentials", () => {
  // Every case: the secret is gone, and the line says something was removed.
  it.each([
    // userinfo, any scheme
    [
      "userinfo, postgres",
      "connect postgres://svc:SECRET@db:5432/app",
      "SECRET",
    ],
    [
      "userinfo, redis with an empty user",
      "dial redis://:SECRET@cache:6379",
      "SECRET",
    ],
    ["userinfo, ftp", "fetch ftp://u:SECRET@files/export.csv", "SECRET"],
    ["userinfo, http", "GET http://svc:SECRET@backend/mcp", "SECRET"],
    // a password holding "@": redacted to the LAST "@" of the authority
    [
      "userinfo with an @ in the password",
      "http://svc:pa@SECRET11@host/mcp",
      "SECRET11",
    ],
    [
      "userinfo with an @ in the password, ws",
      "ws://svc:SEC@RET@host:9/x",
      "RET",
    ],
    // compound names: snake, upper, kebab, camel, bare, quoted
    ["client_secret=", "retry with client_secret=SECRET now", "SECRET"],
    ["AUTOTASK_API_KEY=", "env AUTOTASK_API_KEY=SECRET set", "SECRET"],
    ["oauth_access_token=", "grant oauth_access_token=SECRET issued", "SECRET"],
    ["kebab x-gateway-auth:", "headers x-gateway-auth: SECRET sent", "SECRET"],
    ["camel apiKey:", "config apiKey: SECRET loaded", "SECRET"],
    ["upper AUTH=", "AUTH=SECRET given", "SECRET"],
    ["camel gatewayAuth=", "gatewayAuth=SECRET given", "SECRET"],
    ["a JSON field, camel", 'body {"clientSecret":"SECRET","ok":1}', "SECRET"],
    [
      "a JSON field, single quotes",
      "body {'refresh_token': 'SECRET'}",
      "SECRET",
    ],
    // quoted values: redacted to the closing quote
    [
      "a quoted value with spaces",
      'body {"password":"SECRET7 two words"}',
      "two words",
    ],
    [
      "a quoted value with spaces, single",
      "password='SECRET7 two words' end",
      "two words",
    ],
    [
      "a quoted value with an escaped quote",
      'body {"secret":"SEC\\"RET tail"}',
      "RET tail",
    ],
    [
      "an unterminated quoted value",
      'body {"password":"SECRET7 two words',
      "two words",
    ],
    // a nested pair inside another value
    [
      "a credential inside a quoted value of a plain name",
      'outer="password=SECRET8" after',
      "SECRET8",
    ],
    // query strings, absolute and relative
    [
      "a relative query, sessionId",
      "POST /messages?sessionId=SECRET timed out",
      "SECRET",
    ],
    ["a relative query, key", "GET /mcp?key=SECRET timed out", "SECRET"],
    [
      "an absolute query",
      "GET https://backend/mcp?api_key=SECRET&x=1",
      "SECRET",
    ],
    // Names no list would hold: the whole query string goes, not its values.
    [
      "a relative query, ordinary name",
      "GET /mcp?c=SECRET&x=1 timed out",
      "SECRET",
    ],
    ["a query with a single parameter", "POST /cb?code=SECRET", "SECRET"],
    [
      "an absolute query, ordinary name",
      "GET http://backend:3000/sse?sid=SECRET",
      "SECRET",
    ],
    // headers
    ["a Cookie header", "headers Cookie: sid=SECRET; theme=dark", "theme=dark"],
    [
      "a Set-Cookie header",
      "reply Set-Cookie: sid=SECRET; Path=/; HttpOnly",
      "Path",
    ],
    ["a cookie field", 'headers {"cookie":"a=SECRET; b=OTHER"}', "OTHER"],
    [
      "an Authorization header",
      "upstream said Authorization: Bearer abc.def.ghi",
      "abc",
    ],
    // Another scheme: no bearer pattern applies, the header rule does.
    [
      "an Authorization header, other scheme",
      "sent Authorization: Token SECRET trailing",
      "SECRET",
    ],
    [
      "an Authorization header, digest",
      'sent Authorization: Digest username="u", response="SECRET"',
      "SECRET",
    ],
    [
      "a Proxy-Authorization header",
      "sent Proxy-Authorization: Negotiate SECRET",
      "SECRET",
    ],
    ["a bare bearer token", "saw Bearer abcDEF123456 on the wire", "abcDEF"],
    [
      "a bare JWT",
      "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.SIGNATURE1 seen",
      "SIGNATURE1",
    ],
    [
      "a JWT cut inside its payload",
      "seen eyJhbGciOiJIUzI1NiJ9.eyJzdWIi",
      "eyJzdWIi",
    ],
  ])("redacts %s", (_label, message, secret) => {
    const text = describeMessage(message);
    expect(text).not.toContain(secret);
    expect(text).toContain("[redacted]");
  });

  it("redacts to the last @ of the authority, and only the authority", () => {
    expect(describeMessage("http://svc:pa@SECRET11@host/mcp")).toBe(
      "Err*: http://[redacted]@host/mcp",
    );
    // An @ after the path is not userinfo.
    expect(describeMessage("GET http://host/@user/profile")).toBe(
      "Err*: GET http://host/@user/profile",
    );
  });

  it("redacts a cookie header's whole value", () => {
    expect(describeMessage("Cookie: sid=SECRET; theme=dark")).toBe(
      "Err*: Cookie: [redacted]",
    );
    expect(describeMessage("Set-Cookie: sid=SECRET; Path=/; HttpOnly")).toBe(
      "Err*: Set-Cookie: [redacted]",
    );
  });

  it("keeps a plain name's value and a key that merely sits near a credential", () => {
    expect(describeMessage("status=502 upstream=autotask retry=3")).toBe(
      "Err*: status=502 upstream=autotask retry=3",
    );
  });
});

describe("a message longer than the read bound", () => {
  // Each secret starts inside the 240 characters that survive and runs past
  // the 4096-character read bound, so the bound cuts it: its first characters
  // are read, the rest (and, for userinfo, the "@" that marks it) is not. A
  // cut must never leave those first characters in the line.
  it.each([
    ["userinfo whose @ is past the cut", "x://user:"],
    ["a bare value", "token="],
    ["a quoted value", 'password="'],
    ["a query string", "GET /mcp?key="],
    ["a bearer token", "Authorization: Bearer "],
    ["a bare bearer token", "saw Bearer "],
    ["a cookie", "Cookie: sid="],
    ["a JWT payload", "eyJhbGciOiJIUzI1NiJ9."],
  ])("redacts %s", (_label, head) => {
    const message = `${"filler ".repeat(10)}${head}${"Q".repeat(10_000)}@host/tail`;
    expect(message.length).toBeGreaterThan(4_096 + 100);
    const text = describeMessage(message);
    expect(text).not.toContain("QQQQ");
    expect(text).toContain("[redacted]");
  });

  it("redacts a userinfo secret whose @ is exactly past the cut", () => {
    // The password is fully inside the bound; only the "@" is beyond it.
    const head = `x://user:${"Q".repeat(20)}`;
    const message = `${head}${"y".repeat(4_096 - head.length)}@host/tail`;
    const text = describeMessage(message);
    expect(text).not.toContain("QQQQ");
  });
});

describe("cost", () => {
  it("does not grow with the message", () => {
    const message = "a=".repeat(5_000_000);
    const start = performance.now();
    describeMessage(message);
    expect(performance.now() - start).toBeLessThan(250);
  });

  // 200 KB of each shape that has made a backtracking pattern quadratic: back
  // to back "http://" blocked the event loop for 1.7 s at 100 KB and 6.6 s at
  // 200 KB. scrub() runs here directly, with no read bound in front of it, so
  // this is the patterns' own cost. A linear scrub takes a few tens of
  // milliseconds; the bound is 25 times that.
  const shapes: Record<string, string> = {
    "back-to-back http://": "http://".repeat(28_572),
    "back-to-back ://": "://".repeat(66_667),
    "one long identifier": "a".repeat(200_000),
    "dotted identifier": "a.".repeat(100_000),
    "question marks": "?".repeat(200_000),
    "name=": "a=".repeat(100_000),
    "name:": "a:".repeat(100_000),
    "sensitive name=": "token=".repeat(33_334),
    "at signs": "@".repeat(200_000),
    "scheme and at": "a://b@".repeat(33_334),
    "double quotes": '"'.repeat(200_000),
    "unterminated quoted value": 'password="'.repeat(20_000),
    "single quoted value": "key='".repeat(40_000),
    bearer: "Bearer ".repeat(28_572),
    cookie: "cookie=".repeat(28_572),
    authorization: "authorization: ".repeat(13_334),
    "jwt prefix": "eyJ".repeat(66_667),
    escapes: "\u001b".repeat(200_000),
    backslashes: "\\".repeat(200_000),
    "backslash quotes": '"\\'.repeat(100_000),
    spaces: " ".repeat(200_000),
    separators: ", ".repeat(100_000),
  };

  it.each(Object.entries(shapes))("scrub is linear on %s", (_name, input) => {
    expect(input.length).toBeGreaterThanOrEqual(190_000);
    for (const cut of [false, true]) {
      const start = performance.now();
      scrubForTesting(input, cut);
      expect(performance.now() - start).toBeLessThan(1_000);
    }
  });

  it("describeListingFailure stays fast on the same shapes", () => {
    for (const input of Object.values(shapes)) {
      const start = performance.now();
      describeMessage(input);
      expect(performance.now() - start).toBeLessThan(100);
    }
  });
});

describe("a reason that cannot be read", () => {
  it("returns a fixed string when reading it throws", () => {
    const hostile = new Error("fine");
    Object.defineProperty(hostile, "message", {
      get() {
        throw new Error("getter exploded");
      },
    });
    expect(() => describeListingFailure(hostile)).not.toThrow();
    expect(describeListingFailure(hostile)).toBe(
      "the reason could not be read",
    );
  });
});
