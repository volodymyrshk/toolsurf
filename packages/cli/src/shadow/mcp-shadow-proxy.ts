/**
 * MCP Shadow Proxy — Safe Active Scanning Backend
 *
 * A synthetic MCP server that mirrors a real server's tool schemas
 * but responds to all tool calls with canned benign responses.
 * This lets active modules (fuzzer, SSRF, shadowing, etc.) exercise
 * their full detection logic without any real backend executing payloads.
 *
 * Usage:
 *   const proxy = new McpShadowProxy(serverCapabilities);
 *   const { callTool, getCallLog } = proxy;
 *   // Pass callTool to ModuleContext for active modules
 *   // After scan, inspect getCallLog() for analysis
 */

import type { ServerCapabilities } from "../types/report.js";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ShadowCallRecord {
  /** Timestamp of the call */
  timestamp: string;
  /** Tool name that was called */
  toolName: string;
  /** Full arguments passed to the tool */
  args: Record<string, unknown>;
  /** What the fuzzer/module classified this as (if detectable from args) */
  payloadClassification?: string;
  /** The canned response that was returned */
  response: unknown;
  /** Duration to process (always near-zero for shadow) */
  durationMs: number;
}

export interface ShadowProxyStats {
  /** Total calls received */
  totalCalls: number;
  /** Calls per tool */
  callsByTool: Record<string, number>;
  /** Calls by detected payload type */
  callsByPayloadType: Record<string, number>;
  /** Tools that were never called */
  uncalledTools: string[];
}

// ─── Payload classification patterns ─────────────────────────────────────────

const PAYLOAD_PATTERNS: Array<[string, RegExp]> = [
  ["command-injection", /[;|`$]|&&|\bwhoami\b|\bls\b|\bcat\b|\bcurl\b|\bwget\b/i],
  ["path-traversal", /\.\.[/\\]|%2e%2e|%252f|\.\.\//i],
  ["sql-injection", /(['"]?\s*(OR|AND|UNION|SELECT|DROP|INSERT|DELETE|UPDATE)\s)/i],
  ["xss", /<script|onerror=|javascript:|<svg|<img\s/i],
  ["ssrf", /127\.0\.0\.1|169\.254|localhost|::1|metadata\.google|0x7f/i],
  ["prompt-injection", /ignore.*previous|system prompt|IMPORTANT.*before/i],
  ["oversized-input", /.{10000,}/],  // 10KB+ string
  ["unicode-attack", /[\uFF00-\uFFEF]|[\u2000-\u206F]|%u00/],
  ["template-injection", /\{\{.*\}\}|\$\{.*\}/],
];

function classifyPayload(args: Record<string, unknown>): string | undefined {
  const argsStr = JSON.stringify(args);
  for (const [label, pattern] of PAYLOAD_PATTERNS) {
    if (pattern.test(argsStr)) return label;
  }
  return undefined;
}

// ─── Canned response generators ──────────────────────────────────────────────

/**
 * Generate a realistic-looking but completely safe response for any tool call.
 * Varies the response slightly based on the tool name to make detection logic
 * work realistically (e.g., a "read_file" tool returns text, a "query" tool
 * returns rows).
 */
function generateCannedResponse(toolName: string, _args: Record<string, unknown>): unknown {
  const name = toolName.toLowerCase();

  // File/path tools → return fake file content
  if (/file|read|path|directory|folder|ls|cat/.test(name)) {
    return {
      content: [
        {
          type: "text",
          text: "# Shadow Proxy Response\nThis is a canned response from the shadow proxy.\nNo real file was accessed.",
        },
      ],
    };
  }

  // Database/query tools → return fake query result
  if (/query|sql|database|db|select|table/.test(name)) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            rows: [{ id: 1, name: "shadow_row", value: "safe" }],
            rowCount: 1,
          }),
        },
      ],
    };
  }

  // HTTP/fetch/request tools → return fake HTTP response
  if (/http|fetch|request|url|api|get|post/.test(name)) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            status: 200,
            headers: { "content-type": "application/json" },
            body: { message: "Shadow proxy response" },
          }),
        },
      ],
    };
  }

  // Search tools → return fake search results
  if (/search|find|lookup|query/.test(name)) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            results: [{ title: "Shadow result", url: "https://example.com" }],
            totalCount: 1,
          }),
        },
      ],
    };
  }

  // Send/write/create tools → return acknowledgement
  if (/send|write|create|update|delete|post|put|push/.test(name)) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({ success: true, id: "shadow-001" }),
        },
      ],
    };
  }

  // Default: generic text response
  return {
    content: [
      {
        type: "text",
        text: `Shadow proxy response for tool "${toolName}". No real operation was performed.`,
      },
    ],
  };
}

// ─── Shadow Proxy ────────────────────────────────────────────────────────────

export class McpShadowProxy {
  private capabilities: ServerCapabilities;
  private callLog: ShadowCallRecord[] = [];
  private toolNames: Set<string>;

  constructor(capabilities: ServerCapabilities) {
    this.capabilities = capabilities;
    this.toolNames = new Set(capabilities.tools.map((t) => t.name));
  }

  /**
   * The callTool function to pass to ModuleContext.
   * Drop-in replacement for the real adapter's invoke method.
   */
  callTool = async (
    name: string,
    args: Record<string, unknown>
  ): Promise<unknown> => {
    const start = performance.now();
    const classification = classifyPayload(args);
    const response = generateCannedResponse(name, args);
    const durationMs = Math.round((performance.now() - start) * 100) / 100;

    this.callLog.push({
      timestamp: new Date().toISOString(),
      toolName: name,
      args,
      payloadClassification: classification,
      response,
      durationMs,
    });

    return response;
  };

  /**
   * Get the full call log for analysis.
   */
  getCallLog(): ShadowCallRecord[] {
    return [...this.callLog];
  }

  /**
   * Get aggregated statistics about shadow proxy usage.
   */
  getStats(): ShadowProxyStats {
    const callsByTool: Record<string, number> = {};
    const callsByPayloadType: Record<string, number> = {};

    for (const record of this.callLog) {
      callsByTool[record.toolName] = (callsByTool[record.toolName] ?? 0) + 1;
      if (record.payloadClassification) {
        callsByPayloadType[record.payloadClassification] =
          (callsByPayloadType[record.payloadClassification] ?? 0) + 1;
      }
    }

    const calledTools = new Set(this.callLog.map((r) => r.toolName));
    const uncalledTools = [...this.toolNames].filter((t) => !calledTools.has(t));

    return {
      totalCalls: this.callLog.length,
      callsByTool,
      callsByPayloadType,
      uncalledTools,
    };
  }

  /**
   * Get the server capabilities this proxy is shadowing.
   */
  getCapabilities(): ServerCapabilities {
    return this.capabilities;
  }

  /**
   * Reset the call log (for multi-run scenarios).
   */
  reset(): void {
    this.callLog = [];
  }

  /**
   * Export call log as JSON for research analysis.
   */
  exportCallLog(): string {
    return JSON.stringify(
      {
        server: this.capabilities.serverInfo.name,
        stats: this.getStats(),
        calls: this.callLog,
      },
      null,
      2
    );
  }
}

/**
 * Create a shadow proxy from a previous scan report's capabilities.
 * This is the main entry point for shadow-mode scanning:
 *
 *   1. Run passive scan → get capabilities
 *   2. Create shadow proxy from capabilities
 *   3. Run active scan against shadow proxy
 */
export function createShadowFromCapabilities(
  capabilities: ServerCapabilities
): McpShadowProxy {
  return new McpShadowProxy(capabilities);
}

/**
 * Create a shadow proxy from a scan report JSON file.
 * Reads the server capabilities from a previous passive scan result.
 */
export function createShadowFromReport(reportJson: Record<string, unknown>): McpShadowProxy {
  const server = reportJson.server as ServerCapabilities | undefined;
  if (!server || !server.tools) {
    throw new Error("Invalid scan report: missing server.tools");
  }
  return new McpShadowProxy(server);
}
