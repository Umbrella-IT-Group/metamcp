import {
  AccessGroupEndpointRequestSchema,
  AccessGroupMemberRequestSchema,
  AccessGroupMutationResponseSchema,
  CreateAccessGroupRequestSchema,
  CreateAccessGroupResponseSchema,
  DeleteAccessGroupRequestSchema,
  GetAccessGroupRequestSchema,
  GetAccessGroupResponseSchema,
  GetEndpointAccessRequestSchema,
  GetEndpointAccessResponseSchema,
  ListAccessGroupsResponseSchema,
  ListEndpointOptionsResponseSchema,
  SetEndpointRestrictedRequestSchema,
  UpdateAccessGroupRequestSchema,
} from "@repo/zod-types";
import { z } from "zod";

import {
  adminProcedure,
  type AuditActor,
  auditActor,
  router,
} from "../../trpc";

export const createAccessGroupsRouter = (implementations: {
  list: () => Promise<z.infer<typeof ListAccessGroupsResponseSchema>>;
  get: (
    input: z.infer<typeof GetAccessGroupRequestSchema>,
  ) => Promise<z.infer<typeof GetAccessGroupResponseSchema>>;
  listEndpoints: () => Promise<
    z.infer<typeof ListEndpointOptionsResponseSchema>
  >;
  getEndpointAccess: (
    input: z.infer<typeof GetEndpointAccessRequestSchema>,
  ) => Promise<z.infer<typeof GetEndpointAccessResponseSchema>>;
  create: (
    input: z.infer<typeof CreateAccessGroupRequestSchema>,
    actor: AuditActor,
  ) => Promise<z.infer<typeof CreateAccessGroupResponseSchema>>;
  update: (
    input: z.infer<typeof UpdateAccessGroupRequestSchema>,
    actor: AuditActor,
  ) => Promise<z.infer<typeof AccessGroupMutationResponseSchema>>;
  delete: (
    input: z.infer<typeof DeleteAccessGroupRequestSchema>,
    actor: AuditActor,
  ) => Promise<z.infer<typeof AccessGroupMutationResponseSchema>>;
  addMember: (
    input: z.infer<typeof AccessGroupMemberRequestSchema>,
    actor: AuditActor,
  ) => Promise<z.infer<typeof AccessGroupMutationResponseSchema>>;
  removeMember: (
    input: z.infer<typeof AccessGroupMemberRequestSchema>,
    actor: AuditActor,
  ) => Promise<z.infer<typeof AccessGroupMutationResponseSchema>>;
  addEndpoint: (
    input: z.infer<typeof AccessGroupEndpointRequestSchema>,
    actor: AuditActor,
  ) => Promise<z.infer<typeof AccessGroupMutationResponseSchema>>;
  removeEndpoint: (
    input: z.infer<typeof AccessGroupEndpointRequestSchema>,
    actor: AuditActor,
  ) => Promise<z.infer<typeof AccessGroupMutationResponseSchema>>;
  setEndpointRestricted: (
    input: z.infer<typeof SetEndpointRestrictedRequestSchema>,
    actor: AuditActor,
  ) => Promise<z.infer<typeof AccessGroupMutationResponseSchema>>;
}) => {
  return router({
    // EVERY procedure here is adminProcedure, queries included, and that is not
    // symmetry for its own sake. These rows ARE the authorization policy for
    // OAuth callers: the group list tells a reader which endpoints are gated
    // and who gets through them, which is a map of the estate's access model
    // and of the accounts worth phishing. Unlike api-keys — where a member
    // legitimately owns their own keys and reads them through
    // `protectedProcedure` — there is no per-user slice of this data that a
    // member has any business seeing, so there is nothing to scope and no
    // reason to open the read side.
    list: adminProcedure
      .output(ListAccessGroupsResponseSchema)
      .query(async () => {
        return implementations.list();
      }),

    get: adminProcedure
      .input(GetAccessGroupRequestSchema)
      .output(GetAccessGroupResponseSchema)
      .query(async ({ input }) => {
        return implementations.get(input);
      }),

    // The mapping picker's option list — every endpoint on the gateway, not
    // just the caller's, which is why it cannot reuse `endpoints.list`.
    listEndpoints: adminProcedure
      .output(ListEndpointOptionsResponseSchema)
      .query(async () => {
        return implementations.listEndpoints();
      }),

    // Backs the Access panel on the endpoint edit dialog: the gate's state plus
    // the groups that would be admitted through it.
    getEndpointAccess: adminProcedure
      .input(GetEndpointAccessRequestSchema)
      .output(GetEndpointAccessResponseSchema)
      .query(async ({ input }) => {
        return implementations.getEndpointAccess(input);
      }),

    create: adminProcedure
      .input(CreateAccessGroupRequestSchema)
      .output(CreateAccessGroupResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.create(input, auditActor(ctx));
      }),

    update: adminProcedure
      .input(UpdateAccessGroupRequestSchema)
      .output(AccessGroupMutationResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.update(input, auditActor(ctx));
      }),

    // Cascades to every membership and every endpoint mapping the group held.
    delete: adminProcedure
      .input(DeleteAccessGroupRequestSchema)
      .output(AccessGroupMutationResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.delete(input, auditActor(ctx));
      }),

    addMember: adminProcedure
      .input(AccessGroupMemberRequestSchema)
      .output(AccessGroupMutationResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.addMember(input, auditActor(ctx));
      }),

    removeMember: adminProcedure
      .input(AccessGroupMemberRequestSchema)
      .output(AccessGroupMutationResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.removeMember(input, auditActor(ctx));
      }),

    addEndpoint: adminProcedure
      .input(AccessGroupEndpointRequestSchema)
      .output(AccessGroupMutationResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.addEndpoint(input, auditActor(ctx));
      }),

    removeEndpoint: adminProcedure
      .input(AccessGroupEndpointRequestSchema)
      .output(AccessGroupMutationResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.removeEndpoint(input, auditActor(ctx));
      }),

    // The switch that turns the whole gate on for one endpoint. Its own
    // procedure rather than a field on `endpoints.update`, so flipping a live
    // endpoint's authorization posture is a deliberate act with its own audit
    // row instead of a value that can ride along in a rename.
    setEndpointRestricted: adminProcedure
      .input(SetEndpointRestrictedRequestSchema)
      .output(AccessGroupMutationResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.setEndpointRestricted(input, auditActor(ctx));
      }),
  });
};
