/*
 * The refusal of a server write that would give a second server the same name
 * in the same owner scope, kept apart from the repository so the tRPC layer
 * and its tests can use it without loading the database module.
 *
 * The database's unique rule on (name, owner) covers the servers one person
 * owns, but treats a NULL owner as distinct from every other, so it never
 * stops two public servers from sharing a name. The repository judges the rule
 * itself for every owner scope (NULL counted as one scope), under the name's
 * lock (db/repositories/admin-plane-locks `lockMcpServerName`), on every write
 * that can put a name in a scope: a create, the full update and the
 * metadata-only update.
 */

/**
 * The fixed sentence of the refusal. It names no server and no owner. It keeps
 * the two phrases the admin UI reads to flag the name field ("already exists"
 * and "Server names must be unique"), which the database's own message used to
 * carry for a person's server.
 */
export const SERVER_NAME_TAKEN_MESSAGE =
  "A server with that name already exists. Server names must be unique within an owner scope. Choose a different name.";

/** Thrown inside the write's transaction, which the caller then rolls back. */
export class ServerNameTakenError extends Error {
  constructor() {
    super(SERVER_NAME_TAKEN_MESSAGE);
    this.name = "ServerNameTakenError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
