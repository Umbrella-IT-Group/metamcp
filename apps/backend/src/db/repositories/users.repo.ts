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
}

// Export the repository instance
export const usersRepository = new UsersRepository();
