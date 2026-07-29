import {
  CreateApiKeyRequestSchema,
  CreateApiKeyResponseSchema,
  DeleteApiKeyRequestSchema,
  DeleteApiKeyResponseSchema,
  ListAllApiKeysResponseSchema,
  ListApiKeysResponseSchema,
  UpdateApiKeyRequestSchema,
  UpdateApiKeyResponseSchema,
  ValidateApiKeyRequestSchema,
  ValidateApiKeyResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import { adminProcedure, protectedProcedure, router } from "../../trpc";

export const createApiKeysRouter = (implementations: {
  create: (
    input: z.infer<typeof CreateApiKeyRequestSchema>,
    userId: string,
    isAdmin: boolean,
  ) => Promise<z.infer<typeof CreateApiKeyResponseSchema>>;
  list: (userId: string) => Promise<z.infer<typeof ListApiKeysResponseSchema>>;
  listAll: () => Promise<z.infer<typeof ListAllApiKeysResponseSchema>>;
  update: (
    input: z.infer<typeof UpdateApiKeyRequestSchema>,
    userId: string,
    isAdmin: boolean,
  ) => Promise<z.infer<typeof UpdateApiKeyResponseSchema>>;
  delete: (
    input: z.infer<typeof DeleteApiKeyRequestSchema>,
    userId: string,
    isAdmin: boolean,
  ) => Promise<z.infer<typeof DeleteApiKeyResponseSchema>>;
  validate: (
    input: z.infer<typeof ValidateApiKeyRequestSchema>,
  ) => Promise<z.infer<typeof ValidateApiKeyResponseSchema>>;
}) => {
  return router({
    // Create a key. Minting is effectively ADMIN-ONLY since the migration
    // 0023 scope rules landed: every new key must name the ONE endpoint it may
    // reach or pass the explicit all_endpoints escape hatch, and BOTH of those
    // scope selections are admin-gated in the impl (FORBIDDEN-before-write) —
    // so a member has no valid scope to submit and every member create fails.
    // Ownership is likewise admin-gated (only admins mint public/'everyone'
    // keys or assign a key to another user).
    //
    // Why still protectedProcedure and not adminProcedure: the impl needs the
    // session's user id to attribute a member's (rejected) attempt and to own
    // an admin's private key, and it derives the admin flag from the session
    // role to return precise FORBIDDEN/BAD_REQUEST messages. Swapping to
    // adminProcedure would coarsen those into a generic gate; the RBAC lives
    // in the impl, which this passes `ctx.user.role === "admin"` into.
    create: protectedProcedure
      .input(CreateApiKeyRequestSchema)
      .output(CreateApiKeyResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.create(
          input,
          ctx.user.id,
          ctx.user.role === "admin",
        );
      }),

    // Protected: list the caller's own + public keys (unchanged).
    list: protectedProcedure
      .output(ListApiKeysResponseSchema)
      .query(async ({ ctx }) => {
        return implementations.list(ctx.user.id);
      }),

    // Admin only: cross-user key listing (owner, created, last-used, active).
    listAll: adminProcedure
      .output(ListAllApiKeysResponseSchema)
      .query(async () => {
        return implementations.listAll();
      }),

    // Protected: members update their own keys; admins bypass the ownership
    // filter (revoke/disable/rename any key). The impl branches on the flag.
    update: protectedProcedure
      .input(UpdateApiKeyRequestSchema)
      .output(UpdateApiKeyResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.update(
          input,
          ctx.user.id,
          ctx.user.role === "admin",
        );
      }),

    // Protected: members delete their own keys; admins bypass the ownership
    // filter (delete/revoke any key). The impl branches on the flag.
    delete: protectedProcedure
      .input(DeleteApiKeyRequestSchema)
      .output(DeleteApiKeyResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.delete(
          input,
          ctx.user.id,
          ctx.user.role === "admin",
        );
      }),

    validate: protectedProcedure
      .input(ValidateApiKeyRequestSchema)
      .output(ValidateApiKeyResponseSchema)
      .query(async ({ input }) => {
        return implementations.validate(input);
      }),
  });
};
