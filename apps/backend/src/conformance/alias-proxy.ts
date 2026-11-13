// Stub: forwards every request verbatim with no auth and no rewrite, committed
// first so the tests fail on assertions rather than on a missing import.
// Replaced by the real implementation in the next commit.
import http from "node:http";

export interface AliasProxyOptions {
  upstream: string;
  apiKey: string;
  prefix: string;
  log: (message: string) => void;
  maxBodyBytes?: number;
}

export interface AliasProxy {
  listen(port: number, host?: string): Promise<number>;
  close(): Promise<void>;
}

export function createAliasProxy(opts: AliasProxyOptions): AliasProxy {
  const upstream = new URL(opts.upstream);
  const server = http.createServer((req, res) => {
    const out = http.request(
      {
        host: upstream.hostname,
        port: upstream.port,
        path: req.url,
        method: req.method,
        headers: req.headers,
      },
      (up) => {
        res.writeHead(up.statusCode ?? 502, up.headers);
        up.pipe(res);
      },
    );
    out.on("error", () => {
      res.writeHead(502);
      res.end();
    });
    req.pipe(out);
  });
  return {
    listen: (port, host = "127.0.0.1") =>
      new Promise((resolve) =>
        server.listen(port, host, () => {
          const address = server.address();
          resolve(typeof address === "object" && address ? address.port : port);
        }),
      ),
    close: () =>
      new Promise((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  };
}
