import { eq } from "drizzle-orm";

import { db } from "../index";
import { usersTable } from "../schema";

/**
 * Minimal read-only lookup over the better-auth users table. Exists so
 * server-side policy checks (e.g. the api-key create path verifying an
 * acts_as_user_id target actually exists — migration 0024) have a
 * repository seam instead of reaching into `db` directly, matching how the
 * other impls consume `endpointsRepository`. Deliberately NOT a full CRUD
 * surface: user lifecycle belongs to better-auth, and there is no
 * list-users tRPC by design (the admin UI takes a user id, it does not
 * enumerate accounts).
 */
export class UsersRepository {
  async findById(
    id: string,
  ): Promise<{ id: string; email: string; name: string } | undefined> {
    const [user] = await db
      .select({
        id: usersTable.id,
        email: usersTable.email,
        name: usersTable.name,
      })
      .from(usersTable)
      .where(eq(usersTable.id, id));

    return user;
  }

  /**
   * Read a user's RBAC role straight from the database.
   *
   * Exists for authorization checks that run OUTSIDE tRPC, where there is no
   * `ctx.user` to read `role` from — currently the express `/health/upstream`
   * handler, which decides whether to attach server topology to its response.
   * Those paths only have a session user id, and re-reading the role here
   * keeps the decision independent of how better-auth happens to serialise
   * the session (`additionalFields` in auth.ts), which is a presentation
   * detail rather than the record of record.
   *
   * Returns undefined for an unknown id, so callers can fail closed on a
   * strict `=== "admin"` test rather than on the absence of a truthy value.
   */
  async findRoleById(id: string): Promise<string | undefined> {
    const [user] = await db
      .select({ role: usersTable.role })
      .from(usersTable)
      .where(eq(usersTable.id, id));

    return user?.role;
  }
}

// Export the repository instance
export const usersRepository = new UsersRepository();
