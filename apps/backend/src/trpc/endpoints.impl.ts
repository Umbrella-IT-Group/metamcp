import type { AuditActor } from "@repo/trpc";
import {
  CreateEndpointRequestSchema,
  CreateEndpointResponseSchema,
  DeleteEndpointResponseSchema,
  GetEndpointResponseSchema,
  ListEndpointsResponseSchema,
  UpdateEndpointRequestSchema,
  UpdateEndpointResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import logger from "@/utils/logger";

import {
  ApiKeysRepository,
  endpointsRepository,
  mcpServersRepository,
  namespacesRepository,
} from "../db/repositories";
import { EndpointsSerializer } from "../db/serializers";
import { emitAdminEvent } from "../lib/audit/admin-event";

const apiKeysRepository = new ApiKeysRepository();

export const endpointsImplementations = {
  create: async (
    input: z.infer<typeof CreateEndpointRequestSchema>,
    userId: string,
    actor?: AuditActor,
  ): Promise<z.infer<typeof CreateEndpointResponseSchema>> => {
    try {
      // Check if endpoint name already exists (must be globally unique)
      const existingEndpoint = await endpointsRepository.findByName(input.name);
      if (existingEndpoint) {
        return {
          success: false as const,
          message: "Endpoint name already exists",
        };
      }

      // Determine user ownership based on input.user_id or default to current user
      const effectiveUserId =
        input.user_id !== undefined ? input.user_id : null;
      const isPublicEndpoint = effectiveUserId === null;

      // Validate namespace accessibility and relationship rules
      const namespace = await namespacesRepository.findByUuid(
        input.namespaceUuid,
      );
      if (!namespace) {
        return {
          success: false as const,
          message: "Selected namespace could not be found",
        };
      }

      // Check if user has access to this namespace (own namespace or public namespace)
      if (namespace.user_id && namespace.user_id !== userId) {
        return {
          success: false as const,
          message: `Access denied: You don't have permission to use namespace "${namespace.name}"`,
        };
      }

      // Enforce relationship rules: public endpoints can only use public namespaces
      if (isPublicEndpoint && namespace.user_id !== null) {
        return {
          success: false as const,
          message: `Access denied: Public endpoints can only use public namespaces. Namespace "${namespace.name}" is private`,
        };
      }

      logger.info(input);

      const result = await endpointsRepository.create({
        name: input.name,
        description: input.description,
        namespace_uuid: input.namespaceUuid,
        enable_api_key_auth: input.enableApiKeyAuth ?? true,
        require_scoped_api_key: input.requireScopedApiKey ?? false,
        enable_max_rate: input.enableMaxRate ?? false,
        enable_client_max_rate: input.enableClientMaxRate ?? false,
        max_rate: input.maxRate,
        max_rate_seconds: input.maxRateSeconds,
        client_max_rate: input.clientMaxRate,
        client_max_rate_seconds: input.clientMaxRateSeconds,
        client_max_rate_strategy: input.clientMaxRateStrategy,
        client_max_rate_strategy_key: input.clientMaxRateStrategyKey,
        enable_oauth: input.enableOauth ?? true,
        use_query_param_auth: input.useQueryParamAuth ?? false,
        user_id: effectiveUserId,
      });

      // Create MCP server if requested
      if (input.createMcpServer) {
        try {
          const mcpServerName = `${input.name}-endpoint`;
          const mcpServerDescription = `Auto-generated MCP server for endpoint "${input.name}"`;

          const baseUrl = process.env.APP_URL;
          const endpointUrl = `${baseUrl}/metamcp/${input.name}/mcp`;

          // Get an API key for the bearer token only if API key auth is
          // enabled. This ALWAYS mints a fresh key rather than reusing one of
          // the user's existing keys, and that is forced rather than chosen:
          // since migration 0034 the gateway stores only a hash, so no
          // existing key's value can be read back to embed here. The mint is
          // SCOPED to the endpoint being created — an internal convenience
          // mint must not produce an unscoped (gateway-wide) key silently.
          //
          // The key's name carries the endpoint name because api_keys is
          // UNIQUE on (user_id, name): a fixed literal would collide on the
          // second endpoint the same user creates this way, and the collision
          // would surface as an MCP server silently configured with an empty
          // bearer token rather than as an error. Endpoint names are globally
          // unique (checked at the top of this handler), so this is unique per
          // user too, and the key is cascade-deleted with its endpoint, so
          // recreating an endpoint under the same name does not collide with
          // its own predecessor.
          let bearerToken = "";
          if (input.enableApiKeyAuth) {
            try {
              const newApiKey = await apiKeysRepository.create({
                name: `Auto-generated for MCP Server (${input.name})`,
                user_id: userId,
                endpoint_uuid: result.uuid,
                is_active: true,
              });
              bearerToken = newApiKey.key;
            } catch (apiKeyError) {
              logger.error(
                "Error getting API key for MCP server:",
                apiKeyError,
              );
              // Continue without bearer token if API key operation fails
            }
          }

          await mcpServersRepository.create({
            name: mcpServerName,
            description: mcpServerDescription,
            type: "STREAMABLE_HTTP",
            url: endpointUrl,
            bearerToken: bearerToken,
            command: "",
            args: [],
            env: {},
            user_id: effectiveUserId,
          });
        } catch (mcpError) {
          logger.error("Error creating MCP server:", mcpError);
          // Don't fail the endpoint creation if MCP server creation fails
          // Just log the error and continue
        }
      }

      // An endpoint is a publicly reachable MCP surface, so its creation and
      // its auth posture (API-key gate, scoped-key requirement, OAuth) are
      // the breadcrumbs that answer "when did this URL start existing, and
      // did it ever require a credential". Never the bearer token the block
      // above may have embedded in the companion MCP server.
      emitAdminEvent(actor, {
        action: "endpoint.create",
        target_type: "endpoint",
        target_id: result.uuid,
        detail: {
          name: result.name,
          namespace_uuid: input.namespaceUuid,
          owner_user_id: effectiveUserId,
          enable_api_key_auth: input.enableApiKeyAuth,
          require_scoped_api_key: input.requireScopedApiKey,
          enable_oauth: input.enableOauth,
        },
      });

      return {
        success: true as const,
        data: EndpointsSerializer.serializeEndpoint(result),
        message: "Endpoint created successfully",
      };
    } catch (error) {
      logger.error("Error creating endpoint:", error);
      return {
        success: false as const,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  list: async (
    userId: string,
  ): Promise<z.infer<typeof ListEndpointsResponseSchema>> => {
    try {
      // Get endpoints accessible to user (public + user's own) with namespace data
      const endpoints =
        await endpointsRepository.findAllAccessibleToUserWithNamespaces(userId);

      return {
        success: true as const,
        data: EndpointsSerializer.serializeEndpointWithNamespaceList(endpoints),
        message: "Endpoints retrieved successfully",
      };
    } catch (error) {
      logger.error("Error fetching endpoints:", error);
      return {
        success: false as const,
        data: [],
        message: "Failed to fetch endpoints",
      };
    }
  },

  get: async (
    input: {
      uuid: string;
    },
    userId: string,
  ): Promise<z.infer<typeof GetEndpointResponseSchema>> => {
    try {
      const endpoint = await endpointsRepository.findByUuidWithNamespace(
        input.uuid,
      );

      if (!endpoint) {
        return {
          success: false as const,
          message: "Endpoint not found",
        };
      }

      // Check if user has access to this endpoint (own endpoint or public endpoint)
      if (endpoint.user_id && endpoint.user_id !== userId) {
        return {
          success: false as const,
          message:
            "Access denied: You can only view endpoints you own or public endpoints",
        };
      }

      return {
        success: true as const,
        data: EndpointsSerializer.serializeEndpointWithNamespace(endpoint),
        message: "Endpoint retrieved successfully",
      };
    } catch (error) {
      logger.error("Error fetching endpoint:", error);
      return {
        success: false as const,
        message: "Failed to fetch endpoint",
      };
    }
  },

  delete: async (
    input: {
      uuid: string;
    },
    userId: string,
    actor?: AuditActor,
  ): Promise<z.infer<typeof DeleteEndpointResponseSchema>> => {
    try {
      // First, check if the endpoint exists and user has permission to delete it
      const existingEndpoint =
        await endpointsRepository.findByUuidWithNamespace(input.uuid);

      if (!existingEndpoint) {
        return {
          success: false as const,
          message: "Endpoint not found",
        };
      }

      // Check if user owns this endpoint (only owners can delete, protect public endpoints)
      if (existingEndpoint.user_id && existingEndpoint.user_id !== userId) {
        return {
          success: false as const,
          message: "Access denied: You can only delete endpoints you own",
        };
      }

      const deletedEndpoint = await endpointsRepository.deleteByUuid(
        input.uuid,
      );

      if (!deletedEndpoint) {
        return {
          success: false as const,
          message: "Endpoint not found",
        };
      }

      emitAdminEvent(actor, {
        action: "endpoint.delete",
        target_type: "endpoint",
        target_id: input.uuid,
        detail: { name: deletedEndpoint.name },
      });

      return {
        success: true as const,
        message: "Endpoint deleted successfully",
      };
    } catch (error) {
      logger.error("Error deleting endpoint:", error);
      return {
        success: false as const,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  update: async (
    input: z.infer<typeof UpdateEndpointRequestSchema>,
    userId: string,
    actor?: AuditActor,
  ): Promise<z.infer<typeof UpdateEndpointResponseSchema>> => {
    try {
      // First, check if the endpoint exists and user has permission to update it
      const existingEndpoint =
        await endpointsRepository.findByUuidWithNamespace(input.uuid);

      if (!existingEndpoint) {
        return {
          success: false as const,
          message: "Endpoint not found",
        };
      }

      // Check if user owns this endpoint (only owners can update)
      if (existingEndpoint.user_id && existingEndpoint.user_id !== userId) {
        return {
          success: false as const,
          message: "Access denied: You can only update endpoints you own",
        };
      }

      const isPublicEndpoint = existingEndpoint.user_id === null;

      // Validate namespace accessibility and relationship rules if namespace is being updated
      if (input.namespaceUuid !== existingEndpoint.namespace_uuid) {
        const namespace = await namespacesRepository.findByUuid(
          input.namespaceUuid,
        );
        if (!namespace) {
          return {
            success: false as const,
            message: "Selected namespace could not be found",
          };
        }

        // Check if user has access to this namespace (own namespace or public namespace)
        if (namespace.user_id && namespace.user_id !== userId) {
          return {
            success: false as const,
            message: `Access denied: You don't have permission to use namespace "${namespace.name}"`,
          };
        }

        // Enforce relationship rules: public endpoints can only use public namespaces
        if (isPublicEndpoint && namespace.user_id !== null) {
          return {
            success: false as const,
            message: `Access denied: Public endpoints can only use public namespaces. Namespace "${namespace.name}" is private`,
          };
        }
      }

      // Check if another endpoint with the same name exists (excluding current one)
      const duplicateEndpoint = await endpointsRepository.findByName(
        input.name,
      );
      if (duplicateEndpoint && duplicateEndpoint.uuid !== input.uuid) {
        return {
          success: false as const,
          message: "Endpoint name already exists",
        };
      }

      const result = await endpointsRepository.update({
        uuid: input.uuid,
        name: input.name,
        description: input.description,
        namespace_uuid: input.namespaceUuid,
        enable_api_key_auth: input.enableApiKeyAuth,
        require_scoped_api_key: input.requireScopedApiKey,
        enable_max_rate: input.enableMaxRate ?? false,
        enable_client_max_rate: input.enableClientMaxRate ?? false,
        max_rate: input.maxRate,
        max_rate_seconds: input.maxRateSeconds,
        client_max_rate: input.clientMaxRate,
        client_max_rate_seconds: input.clientMaxRateSeconds,
        client_max_rate_strategy: input.clientMaxRateStrategy,
        client_max_rate_strategy_key: input.clientMaxRateStrategyKey,
        enable_oauth: input.enableOauth,
        use_query_param_auth: input.useQueryParamAuth,
      });

      // The auth-posture fields are carried for the same reason as on create:
      // turning `enable_api_key_auth` off on a live endpoint opens it to the
      // internet, and that has to be attributable to a person and a moment.
      emitAdminEvent(actor, {
        action: "endpoint.update",
        target_type: "endpoint",
        target_id: result.uuid,
        detail: {
          name: result.name,
          namespace_uuid: input.namespaceUuid,
          enable_api_key_auth: input.enableApiKeyAuth,
          require_scoped_api_key: input.requireScopedApiKey,
          enable_oauth: input.enableOauth,
        },
      });

      return {
        success: true as const,
        data: EndpointsSerializer.serializeEndpoint(result),
        message: "Endpoint updated successfully",
      };
    } catch (error) {
      logger.error("Error updating endpoint:", error);
      return {
        success: false as const,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },
};
