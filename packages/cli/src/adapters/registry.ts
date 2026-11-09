import type { ProtocolAdapter, ProtocolType } from "./types.js";
import { McpAdapter } from "./mcp-adapter.js";
import { OpenAiAdapter } from "./openai-adapter.js";
import { LangChainAdapter } from "./langchain-adapter.js";
import { RestApiAdapter } from "./rest-adapter.js";
import { GraphQlAdapter } from "./graphql-adapter.js";
import { GrpcAdapter } from "./grpc-adapter.js";
import { A2aAdapter } from "./a2a-adapter.js";

/**
 * Protocol adapter factory.
 * Creates the appropriate adapter for the given protocol type.
 */
const ADAPTER_FACTORIES: Record<ProtocolType, () => ProtocolAdapter> = {
  "mcp": () => new McpAdapter(),
  "openai-functions": () => new OpenAiAdapter(),
  "langchain-tools": () => new LangChainAdapter(),
  "rest-api": () => new RestApiAdapter(),
  "graphql": () => new GraphQlAdapter(),
  "grpc": () => new GrpcAdapter(),
  "a2a": () => new A2aAdapter(),
};

/**
 * Create a protocol adapter by type.
 * Defaults to MCP if no type is specified.
 */
export function createAdapter(protocol: ProtocolType = "mcp"): ProtocolAdapter {
  const factory = ADAPTER_FACTORIES[protocol];
  if (!factory) {
    throw new Error(
      `Unknown protocol: "${protocol}". Supported: ${getSupportedProtocols().join(", ")}`
    );
  }
  return factory();
}

/**
 * Get all supported protocol types.
 */
export function getSupportedProtocols(): ProtocolType[] {
  return Object.keys(ADAPTER_FACTORIES) as ProtocolType[];
}

/**
 * Check if a protocol type is valid.
 */
export function isProtocolType(value: string): value is ProtocolType {
  return value in ADAPTER_FACTORIES;
}
