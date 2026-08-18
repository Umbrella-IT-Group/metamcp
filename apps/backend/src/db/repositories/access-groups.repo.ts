import { and, asc, count, eq } from "drizzle-orm";

import { db } from "../index";
import {
  accessGroupEndpointsTable,
  accessGroupMembersTable,
  accessGroupsTable,
  endpointsTable,
  usersTable,
} from "../schema";

/**
 * Named access groups and the grants they carry (migration 0033).
 *
 * WHICH POOL: the MAIN pool (`../index`), not the bounded audit pool. Every
 * read here is on an AUTHORIZATION path — `hasEndpointGrant` decides whether a
 * request is served — so it must not share a budget with telemetry that is
 * designed to shed load under flood. `db/audit-db`'s pool is `max: 2` with a 1s
 * checkout timeout precisely because dropping an audit row is acceptable;
 * dropping an authorization answer is not, and would fail closed into a 403 for
 * a legitimate caller.
 */
export class AccessGroupsRepository {
  /**
   * Is this user granted access to this endpoint by ANY group?
   *
   * The single hot query behind the middleware gate. `limit(1)` and a projection
   * of one column because the answer is a boolean: the caller never needs to
   * know WHICH group admitted them, and an endpoint mapped to several groups a
   * user belongs to must not drag a row per group back to compute `true`.
   *
   * Both indexes added by 0033 are used here — `access_group_members_user_id_idx`
   * for the filter and `access_group_endpoints_endpoint_uuid_idx` for the join
   * side. Neither composite primary key can serve this shape, because both have
   * `group_uuid` as their leading column and this query knows neither group.
   */
  async hasEndpointGrant(
    userId: string,
    endpointUuid: string,
  ): Promise<boolean> {
    const [row] = await db
      .select({ group_uuid: accessGroupMembersTable.group_uuid })
      .from(accessGroupMembersTable)
      .innerJoin(
        accessGroupEndpointsTable,
        eq(
          accessGroupEndpointsTable.group_uuid,
          accessGroupMembersTable.group_uuid,
        ),
      )
      .where(
        and(
          eq(accessGroupMembersTable.user_id, userId),
          eq(accessGroupEndpointsTable.endpoint_uuid, endpointUuid),
        ),
      )
      .limit(1);

    return Boolean(row);
  }

  /**
   * Groups with their member and endpoint counts, oldest first.
   *
   * Counts come from two grouped aggregates rather than from correlated
   * subqueries in the projection: a raw `sql` fragment inside a drizzle
   * projection loses the decoder drizzle would otherwise attach, so a bigint
   * `count(*)` arrives as a STRING and the router's `.output()` schema rejects
   * the whole response. That failure is invisible to the type system and to any
   * mock — see the note at the top of `access-queries.integration.test.ts`.
   * drizzle's own `count()` helper is decoded, so these two extra round trips
   * buy a response that actually validates.
   */
  async listWithCounts() {
    const [groups, memberCounts, endpointCounts] = await Promise.all([
      db
        .select({
          uuid: accessGroupsTable.uuid,
          name: accessGroupsTable.name,
          description: accessGroupsTable.description,
          created_at: accessGroupsTable.created_at,
        })
        .from(accessGroupsTable)
        .orderBy(asc(accessGroupsTable.name)),
      db
        .select({
          group_uuid: accessGroupMembersTable.group_uuid,
          value: count(),
        })
        .from(accessGroupMembersTable)
        .groupBy(accessGroupMembersTable.group_uuid),
      db
        .select({
          group_uuid: accessGroupEndpointsTable.group_uuid,
          value: count(),
        })
        .from(accessGroupEndpointsTable)
        .groupBy(accessGroupEndpointsTable.group_uuid),
    ]);

    const members = new Map(memberCounts.map((r) => [r.group_uuid, r.value]));
    const endpoints = new Map(
      endpointCounts.map((r) => [r.group_uuid, r.value]),
    );

    return groups.map((group) => ({
      ...group,
      member_count: members.get(group.uuid) ?? 0,
      endpoint_count: endpoints.get(group.uuid) ?? 0,
    }));
  }

  async findByUuid(uuid: string) {
    const [group] = await db
      .select({
        uuid: accessGroupsTable.uuid,
        name: accessGroupsTable.name,
        description: accessGroupsTable.description,
        created_at: accessGroupsTable.created_at,
      })
      .from(accessGroupsTable)
      .where(eq(accessGroupsTable.uuid, uuid));

    return group;
  }

  async findByName(name: string) {
    const [group] = await db
      .select({ uuid: accessGroupsTable.uuid })
      .from(accessGroupsTable)
      .where(eq(accessGroupsTable.name, name));

    return group;
  }

  /**
   * One group with its members and mapped endpoints resolved to names.
   *
   * Joined rather than returned as bare ids: the admin screen shows people and
   * endpoints, and resolving ids client-side would need the whole user list
   * loaded alongside every group detail.
   */
  async findDetailByUuid(uuid: string) {
    const group = await this.findByUuid(uuid);
    if (!group) return undefined;

    const [members, endpoints] = await Promise.all([
      db
        .select({
          user_id: usersTable.id,
          name: usersTable.name,
          email: usersTable.email,
          role: usersTable.role,
        })
        .from(accessGroupMembersTable)
        .innerJoin(
          usersTable,
          eq(usersTable.id, accessGroupMembersTable.user_id),
        )
        .where(eq(accessGroupMembersTable.group_uuid, uuid))
        .orderBy(asc(usersTable.email)),
      db
        .select({
          endpoint_uuid: endpointsTable.uuid,
          name: endpointsTable.name,
          restricted: endpointsTable.restricted,
        })
        .from(accessGroupEndpointsTable)
        .innerJoin(
          endpointsTable,
          eq(endpointsTable.uuid, accessGroupEndpointsTable.endpoint_uuid),
        )
        .where(eq(accessGroupEndpointsTable.group_uuid, uuid))
        .orderBy(asc(endpointsTable.name)),
    ]);

    return {
      ...group,
      member_count: members.length,
      endpoint_count: endpoints.length,
      members,
      endpoints,
    };
  }

  /** The groups mapped to one endpoint, for the endpoint-detail Access panel. */
  async findGroupsForEndpoint(endpointUuid: string) {
    const groups = await db
      .select({
        uuid: accessGroupsTable.uuid,
        name: accessGroupsTable.name,
      })
      .from(accessGroupEndpointsTable)
      .innerJoin(
        accessGroupsTable,
        eq(accessGroupsTable.uuid, accessGroupEndpointsTable.group_uuid),
      )
      .where(eq(accessGroupEndpointsTable.endpoint_uuid, endpointUuid))
      .orderBy(asc(accessGroupsTable.name));

    if (groups.length === 0) return [];

    const memberCounts = await db
      .select({
        group_uuid: accessGroupMembersTable.group_uuid,
        value: count(),
      })
      .from(accessGroupMembersTable)
      .groupBy(accessGroupMembersTable.group_uuid);
    const members = new Map(memberCounts.map((r) => [r.group_uuid, r.value]));

    return groups.map((group) => ({
      ...group,
      member_count: members.get(group.uuid) ?? 0,
    }));
  }

  async create(input: { name: string; description?: string | null }) {
    const [created] = await db
      .insert(accessGroupsTable)
      .values({ name: input.name, description: input.description ?? null })
      .returning();

    if (!created) throw new Error("Failed to create access group");
    return created;
  }

  async update(input: {
    uuid: string;
    name: string;
    description?: string | null;
  }) {
    const [updated] = await db
      .update(accessGroupsTable)
      .set({ name: input.name, description: input.description ?? null })
      .where(eq(accessGroupsTable.uuid, input.uuid))
      .returning();

    return updated;
  }

  /** Returns the deleted row, or undefined when nothing matched. */
  async deleteByUuid(uuid: string) {
    const [deleted] = await db
      .delete(accessGroupsTable)
      .where(eq(accessGroupsTable.uuid, uuid))
      .returning();

    return deleted;
  }

  /**
   * Add a member, tolerating a repeat.
   *
   * `onConflictDoNothing` on the composite primary key: two administrators
   * adding the same person from two open tabs is a normal race, and the second
   * one should be a no-op rather than a 500 the caller has to interpret.
   * `added` distinguishes the two so the audit row is not written for a
   * no-op — see the impl.
   */
  async addMember(groupUuid: string, userId: string): Promise<boolean> {
    const inserted = await db
      .insert(accessGroupMembersTable)
      .values({ group_uuid: groupUuid, user_id: userId })
      .onConflictDoNothing()
      .returning({ user_id: accessGroupMembersTable.user_id });

    return inserted.length > 0;
  }

  async removeMember(groupUuid: string, userId: string): Promise<boolean> {
    const deleted = await db
      .delete(accessGroupMembersTable)
      .where(
        and(
          eq(accessGroupMembersTable.group_uuid, groupUuid),
          eq(accessGroupMembersTable.user_id, userId),
        ),
      )
      .returning({ user_id: accessGroupMembersTable.user_id });

    return deleted.length > 0;
  }

  async addEndpoint(groupUuid: string, endpointUuid: string): Promise<boolean> {
    const inserted = await db
      .insert(accessGroupEndpointsTable)
      .values({ group_uuid: groupUuid, endpoint_uuid: endpointUuid })
      .onConflictDoNothing()
      .returning({ endpoint_uuid: accessGroupEndpointsTable.endpoint_uuid });

    return inserted.length > 0;
  }

  async removeEndpoint(
    groupUuid: string,
    endpointUuid: string,
  ): Promise<boolean> {
    const deleted = await db
      .delete(accessGroupEndpointsTable)
      .where(
        and(
          eq(accessGroupEndpointsTable.group_uuid, groupUuid),
          eq(accessGroupEndpointsTable.endpoint_uuid, endpointUuid),
        ),
      )
      .returning({ endpoint_uuid: accessGroupEndpointsTable.endpoint_uuid });

    return deleted.length > 0;
  }

  /**
   * Flip one endpoint's `restricted` gate.
   *
   * Its own statement rather than a field on `endpointsRepository.update`,
   * because that method rewrites the whole row from an `EndpointUpdateInput`
   * and is driven by the endpoint edit form. Turning an endpoint's
   * authorization gate on has to be a deliberate act with its own audit event,
   * not a value that can ride along in a rename.
   *
   * Returns the new row so the caller can emit the change and report the miss
   * when no endpoint matched.
   */
  async setEndpointRestricted(endpointUuid: string, restricted: boolean) {
    const [updated] = await db
      .update(endpointsTable)
      .set({ restricted, updated_at: new Date() })
      .where(eq(endpointsTable.uuid, endpointUuid))
      .returning({
        uuid: endpointsTable.uuid,
        name: endpointsTable.name,
        restricted: endpointsTable.restricted,
      });

    return updated;
  }
}

export const accessGroupsRepository = new AccessGroupsRepository();
