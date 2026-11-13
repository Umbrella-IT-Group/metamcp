import type {
  Implementation,
  ServerCapabilities,
} from "@modelcontextprotocol/sdk/types.js";

/**
 * What the server said in its initialize response, as the connection hook
 * reports it. `protocolVersion` is read from the captured initialize result
 * (the SSE transport has no getter for it).
 */
export interface InspectorServerInfo {
  implementation?: Implementation;
  capabilities?: ServerCapabilities;
  instructions?: string;
  protocolVersion?: string;
}
