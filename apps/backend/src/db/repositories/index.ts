export * from "./namespaces.repo";
export * from "./namespace-mappings.repo";
export * from "./endpoints.repo";
export * from "./mcp-servers.repo";
export * from "./tools.repo";
export * from "./oauth-sessions.repo";
export * from "./oauth.repo";
export * from "./api-keys.repo";
export * from "./users.repo";
export * from "./m365-tokens.repo";
export * from "./tool-call-audit.repo";
export * from "./audit-log.repo";
// `gateway-events.repo` is deliberately NOT re-exported here, and the omission
// is load-bearing rather than an oversight. Nothing consumes it through this
// barrel: the writer and the retention sweeper import it lazily to keep their
// own module graphs database-free, and `trpc/logs.impl.ts` imports the file
// directly. Re-exporting it would drag `../gateway-events-db` — which throws at
// import time when DATABASE_URL is unset, like every db module here — into the
// graph of every suite that imports this barrel for an unrelated repository,
// forcing each of them to mock a third database module to stay green.
export { configRepo } from "./config.repo";
