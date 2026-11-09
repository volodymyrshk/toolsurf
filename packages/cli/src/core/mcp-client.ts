/**
 * @deprecated Use `McpAdapter` from `../adapters/mcp-adapter.js` or
 * `createAdapter("mcp")` from `../adapters/registry.js` instead.
 *
 * This file exists as a backward-compatibility facade.
 * The MCPClientEngine class has been migrated to the protocol adapter pattern.
 */

import { McpAdapter } from "../adapters/mcp-adapter.js";
import type { ServerCapabilities } from "../types/report.js";

export interface ConnectOptions {
  command: string;
  args: string[];
  env?: Record<string, string>;
  timeoutMs?: number;
  verbose?: boolean;
}

/**
 * Backward-compatible wrapper around McpAdapter.
 * New code should use `createAdapter("mcp")` instead.
 */
export class MCPClientEngine {
  private adapter = new McpAdapter();

  async connect(options: ConnectOptions): Promise<ServerCapabilities> {
    return this.adapter.connect({
      timeoutMs: options.timeoutMs,
      verbose: options.verbose,
      params: {
        command: options.command,
        args: options.args,
        env: options.env,
      },
    });
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<unknown> {
    return this.adapter.invoke(name, args);
  }

  async disconnect(): Promise<void> {
    return this.adapter.disconnect();
  }
}
