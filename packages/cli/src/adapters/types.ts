import type { ServerCapabilities } from "../types/report.js";

/**
 * Supported protocol types for agent tool interfaces.
 * MCP is fully implemented; others are planned for v0.2+.
 */
export type ProtocolType =
  | "mcp"
  | "openai-functions"
  | "langchain-tools"
  | "rest-api"
  | "graphql"
  | "grpc"
  | "a2a";

/**
 * Connection options for a protocol adapter.
 */
export interface AdapterConnectOptions {
  /** Connection timeout in milliseconds */
  timeoutMs?: number;
  /** Verbose logging */
  verbose?: boolean;
  /** Protocol-specific connection parameters */
  params: Record<string, unknown>;
}

/**
 * Abstract interface for connecting to and auditing any AI agent tool interface.
 *
 * Each protocol adapter handles:
 * 1. Connection/handshake with the target
 * 2. Capability discovery (tools, resources, prompts)
 * 3. Tool/function invocation for active scanning
 * 4. Graceful disconnection
 *
 * All adapters normalize their output to the universal ServerCapabilities model,
 * so the entire downstream audit pipeline (modules, scorer, reporter) is protocol-agnostic.
 */
export interface ProtocolAdapter {
  /** Protocol identifier */
  readonly protocol: ProtocolType;
  /** Human-readable protocol name */
  readonly displayName: string;

  /**
   * Connect to the target and discover capabilities.
   * Returns the universal ServerCapabilities model.
   */
  connect(options: AdapterConnectOptions): Promise<ServerCapabilities>;

  /**
   * Invoke a capability (tool/function/endpoint) on the target.
   * Used by active audit modules for fuzzing and probing.
   */
  invoke(name: string, args: Record<string, unknown>, timeoutMs?: number): Promise<unknown>;

  /**
   * Gracefully disconnect from the target.
   */
  disconnect(): Promise<void>;
}
