import { ListActiveOAuthTokensResponseSchema } from "@repo/zod-types";
import { z } from "zod";

import { adminProcedure, router } from "../../trpc";

export const createOAuthTokensRouter = (implementations: {
  list: () => Promise<z.infer<typeof ListActiveOAuthTokensResponseSchema>>;
}) => {
  return router({
    // Admin only, for the same reason the sibling oauth-clients router is:
    // this enumerates who is connected to the gateway and through which
    // client, across every account. There is no per-user slice of that which
    // would be useful to a member and safe to expose.
    //
    // The response carries token METADATA only. The repository never selects
    // the token or refresh-token columns, the serializer re-states the field
    // list, and this `.output()` schema strips anything else — three points
    // where a bearer credential would have to be added on purpose to leak.
    list: adminProcedure
      .output(ListActiveOAuthTokensResponseSchema)
      .query(async () => {
        return implementations.list();
      }),
  });
};
