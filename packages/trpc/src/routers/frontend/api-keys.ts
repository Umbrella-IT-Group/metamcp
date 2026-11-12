import {
  CreateApiKeyRequestSchema,
  CreateApiKeyResponseSchema,
  DeactivateApiKeyRequestSchema,
  DeactivateApiKeyResponseSchema,
  DeleteApiKeyRequestSchema,
  DeleteApiKeyResponseSchema,
  GetGlobalIpPolicyResponseSchema,
  ListAllApiKeysResponseSchema,
  ListApiKeysResponseSchema,
  SetApiKeyIpPolicyRequestSchema,
  SetApiKeyIpPolicyResponseSchema,
  SetGlobalIpPolicyRequestSchema,
  SetGlobalIpPolicyResponseSchema,
  UpdateApiKeyRequestSchema,
  UpdateApiKeyResponseSchema,
  ValidateApiKeyRequestSchema,
  ValidateApiKeyResponseSchema,
} from "@repo/zod-types";
import { TRPCError } from "@trpc/server";
import { z } from "zod";

import {
  ADMIN_PLANE_FORBIDDEN_MESSAGE,
  adminPlaneOrigin,
  adminProcedure,
  type AuditActor,
  auditActor,
  protectedProcedure,
  router,
} from "../../trpc";

/**
 * Is this the cause tRPC attaches when an input schema refuses a request: a
 * zod error, carrying its list of issues? Read structurally rather than with
 * `instanceof`, because the schema package and this one may resolve different
 * copies of zod. A BAD_REQUEST an implementation throws has no such cause, so
 * its own fixed sentence is never replaced.
 */
function isSchemaFailure(cause: unknown): boolean {
  return (
    typeof cause === "object" &&
    cause !== null &&
    Array.isArray((cause as { issues?: unknown }).issues)
  );
}

export const createApiKeysRouter = (implementations: {
  create: (
    input: z.infer<typeof CreateApiKeyRequestSchema>,
    userId: string,
    isAdmin: boolean,
    actor: AuditActor,
  ) => Promise<z.infer<typeof CreateApiKeyResponseSchema>>;
  /**
   * The error to answer an admin-plane key's create request with when the
   * input schema refused it (see the middleware on `create`). Receives the raw
   * request and returns an error whose message is one fixed sentence.
   */
  mintInputRefusal: (rawInput: unknown, actor: AuditActor) => TRPCError;
  list: (userId: string) => Promise<z.infer<typeof ListApiKeysResponseSchema>>;
  listAll: () => Promise<z.infer<typeof ListAllApiKeysResponseSchema>>;
  update: (
    input: z.infer<typeof UpdateApiKeyRequestSchema>,
    userId: string,
    isAdmin: boolean,
    actor: AuditActor,
  ) => Promise<z.infer<typeof UpdateApiKeyResponseSchema>>;
  delete: (
    input: z.infer<typeof DeleteApiKeyRequestSchema>,
    userId: string,
    isAdmin: boolean,
    actor: AuditActor,
  ) => Promise<z.infer<typeof DeleteApiKeyResponseSchema>>;
  deactivate: (
    input: z.infer<typeof DeactivateApiKeyRequestSchema>,
    actor: AuditActor,
  ) => Promise<z.infer<typeof DeactivateApiKeyResponseSchema>>;
  validate: (
    input: z.infer<typeof ValidateApiKeyRequestSchema>,
  ) => Promise<z.infer<typeof ValidateApiKeyResponseSchema>>;
  setIpPolicy: (
    input: z.infer<typeof SetApiKeyIpPolicyRequestSchema>,
    actor: AuditActor,
  ) => Promise<z.infer<typeof SetApiKeyIpPolicyResponseSchema>>;
  getGlobalIpPolicy: () => Promise<
    z.infer<typeof GetGlobalIpPolicyResponseSchema>
  >;
  setGlobalIpPolicy: (
    input: z.infer<typeof SetGlobalIpPolicyRequestSchema>,
    actor: AuditActor,
  ) => Promise<z.infer<typeof SetGlobalIpPolicyResponseSchema>>;
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
    //
    // An operator-scope admin-plane key reaches this procedure (it is on that
    // scope's set only) and the implementation then takes its agent-mint branch,
    // which creates one narrow kind of data-plane key and nothing else. The
    // branch is chosen from the origin the backend verified, carried in the
    // actor bundle below; the check right after is belt and braces: if an
    // admin-plane origin ever failed to reach the bundle, this must refuse
    // rather than fall through to the human branch, which can mint anything.
    //
    // The middleware ahead of the input schema is for an admin-plane key only:
    // when the schema refuses its request, the caller would otherwise get the
    // schema's issue list as a JSON dump, not the fixed sentence every other
    // refusal of this procedure carries. A request from a browser session keeps
    // the schema's own messages, which the admin UI reads.
    create: protectedProcedure
      .use(async ({ ctx, getRawInput, next }) => {
        const result = await next();
        if (
          result.ok ||
          !adminPlaneOrigin(ctx) ||
          result.error.code !== "BAD_REQUEST" ||
          !isSchemaFailure(result.error.cause)
        ) {
          return result;
        }
        throw implementations.mintInputRefusal(
          await getRawInput(),
          auditActor(ctx),
        );
      })
      .input(CreateApiKeyRequestSchema)
      .output(CreateApiKeyResponseSchema)
      .mutation(async ({ input, ctx }) => {
        const actor = auditActor(ctx);
        if (adminPlaneOrigin(ctx) && !actor.admin_plane) {
          throw new TRPCError({
            code: "FORBIDDEN",
            message: ADMIN_PLANE_FORBIDDEN_MESSAGE,
          });
        }
        return implementations.create(
          input,
          ctx.user.id,
          ctx.user.role === "admin",
          actor,
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
          auditActor(ctx),
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
          auditActor(ctx),
        );
      }),

    // Admin only: deactivate one key (containment). Input is the uuid alone: it
    // cannot rename, re-activate or delete, it refuses the key that is calling,
    // and re-activation stays an administrator's act in the admin UI. On an
    // operator-scope admin-plane key's set; the state change and its audit row
    // are one transaction (see the implementation).
    deactivate: adminProcedure
      .input(DeactivateApiKeyRequestSchema)
      .output(DeactivateApiKeyResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.deactivate(input, auditActor(ctx));
      }),

    validate: protectedProcedure
      .input(ValidateApiKeyRequestSchema)
      .output(ValidateApiKeyResponseSchema)
      .query(async ({ input }) => {
        return implementations.validate(input);
      }),

    // API-key IP allowlists (migration 0041). ADMIN ONLY, all three: a policy
    // decides which networks may use a credential, so who may change it is
    // the same question as who may mint one. Each write emits an admin audit
    // row with the old and new value (apikey.ip_policy.set /
    // config.api_key_ip_policy.set).
    setIpPolicy: adminProcedure
      .input(SetApiKeyIpPolicyRequestSchema)
      .output(SetApiKeyIpPolicyResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.setIpPolicy(input, auditActor(ctx));
      }),

    getGlobalIpPolicy: adminProcedure
      .output(GetGlobalIpPolicyResponseSchema)
      .query(async () => {
        return implementations.getGlobalIpPolicy();
      }),

    setGlobalIpPolicy: adminProcedure
      .input(SetGlobalIpPolicyRequestSchema)
      .output(SetGlobalIpPolicyResponseSchema)
      .mutation(async ({ input, ctx }) => {
        return implementations.setGlobalIpPolicy(input, auditActor(ctx));
      }),
  });
};
