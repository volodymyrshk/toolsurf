import { readFileSync } from "node:fs";
import type {
  ServerCapabilities,
  ToolInfo,
} from "../types/report.js";
import type { ProtocolAdapter, ProtocolType, AdapterConnectOptions } from "./types.js";

/**
 * OpenAI Function Calling adapter.
 *
 * OpenAI function-calling has no introspection API — functions are defined
 * by the caller in each request. This adapter accepts a tool manifest
 * (JSON file listing the functions) and normalizes them for auditing.
 *
 * Connect params:
 *   - specFile: path to JSON file containing OpenAI tool definitions
 *   - url: (optional) base URL of OpenAI-compatible API for invoke()
 *   - apiKey: (optional) API key for invoke()
 *   - model: (optional) model to use for invoke() (default: "gpt-4")
 *
 * The spec file should contain an array of OpenAI tool objects:
 * [
 *   {
 *     "type": "function",
 *     "function": {
 *       "name": "get_weather",
 *       "description": "Get weather for a location",
 *       "parameters": { "type": "object", "properties": { ... } }
 *     }
 *   }
 * ]
 *
 * Or simply an array of function objects:
 * [
 *   {
 *     "name": "get_weather",
 *     "description": "Get weather",
 *     "parameters": { ... }
 *   }
 * ]
 */
export class OpenAiAdapter implements ProtocolAdapter {
  readonly protocol: ProtocolType = "openai-functions";
  readonly displayName = "OpenAI Function Calling";

  private verbose = false;
  private tools: ToolInfo[] = [];
  private baseUrl?: string;
  private apiKey?: string;
  private model = "gpt-4";

  async connect(options: AdapterConnectOptions): Promise<ServerCapabilities> {
    this.verbose = options.verbose ?? false;

    const specFile = options.params.specFile as string | undefined;
    const specUrl = options.params.specUrl as string | undefined;
    this.baseUrl = (options.params.url as string) ?? "https://api.openai.com/v1";
    this.apiKey = options.params.apiKey as string | undefined;
    this.model = (options.params.model as string) ?? "gpt-4";

    let rawSpec: unknown;

    if (specFile) {
      this.log(`Loading tool definitions from: ${specFile}`);
      const content = readFileSync(specFile, "utf-8");
      rawSpec = JSON.parse(content);
    } else if (specUrl) {
      this.log(`Fetching tool definitions from: ${specUrl}`);
      const resp = await fetch(specUrl, {
        signal: AbortSignal.timeout(options.timeoutMs ?? 30_000),
      });
      if (!resp.ok) {
        throw new Error(`Failed to fetch spec from ${specUrl}: ${resp.status} ${resp.statusText}`);
      }
      rawSpec = await resp.json();
    } else {
      throw new Error(
        "OpenAI adapter requires a tool manifest. " +
        "Pass --server <path-to-tools.json> or provide specFile/specUrl in params."
      );
    }

    this.tools = this.parseToolDefinitions(rawSpec);
    this.log(`Parsed ${this.tools.length} function definitions`);

    return {
      serverInfo: {
        name: specFile ?? specUrl ?? "openai-functions",
        version: "unknown",
      },
      protocolVersion: "2024-01-25",
      capabilities: { functions: true },
      tools: this.tools,
      resources: [],
      prompts: [],
      protocol: "openai-functions",
    };
  }

  async invoke(name: string, args: Record<string, unknown>, timeoutMs?: number): Promise<unknown> {
    if (!this.apiKey) {
      throw new Error(
        "Cannot invoke OpenAI functions without an API key. " +
        "Set OPENAI_API_KEY environment variable or pass apiKey in params."
      );
    }

    this.log(`Invoking function: ${name}`);

    // Build a minimal chat completion that forces the model to call this function
    const resp = await fetch(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.apiKey}`,
      },
      signal: AbortSignal.timeout(timeoutMs ?? 30_000),
      body: JSON.stringify({
        model: this.model,
        messages: [
          {
            role: "user",
            content: `Call the function "${name}" with these arguments: ${JSON.stringify(args)}`,
          },
        ],
        tools: this.tools.map((t) => ({
          type: "function",
          function: {
            name: t.name,
            description: t.description,
            parameters: t.inputSchema,
          },
        })),
        tool_choice: { type: "function", function: { name } },
      }),
    });

    if (!resp.ok) {
      const body = await resp.text();
      throw new Error(`OpenAI API error ${resp.status}: ${body}`);
    }

    const result = await resp.json() as Record<string, unknown>;
    return result;
  }

  async disconnect(): Promise<void> {
    this.tools = [];
  }

  private parseToolDefinitions(raw: unknown): ToolInfo[] {
    if (!Array.isArray(raw)) {
      // Try unwrapping { tools: [...] } or { functions: [...] }
      if (raw && typeof raw === "object") {
        const obj = raw as Record<string, unknown>;
        if (Array.isArray(obj.tools)) return this.parseToolDefinitions(obj.tools);
        if (Array.isArray(obj.functions)) return this.parseToolDefinitions(obj.functions);
      }
      throw new Error("Tool manifest must be a JSON array of tool/function definitions");
    }

    return raw.map((item: unknown, idx: number) => {
      if (!item || typeof item !== "object") {
        throw new Error(`Tool definition at index ${idx} is not an object`);
      }

      const obj = item as Record<string, unknown>;

      // Handle OpenAI format: { type: "function", function: { name, description, parameters } }
      if (obj.type === "function" && obj.function && typeof obj.function === "object") {
        const fn = obj.function as Record<string, unknown>;
        return this.parseFunctionDef(fn, idx);
      }

      // Handle direct format: { name, description, parameters }
      if (typeof obj.name === "string") {
        return this.parseFunctionDef(obj, idx);
      }

      throw new Error(`Tool definition at index ${idx} has no recognizable format`);
    });
  }

  private parseFunctionDef(fn: Record<string, unknown>, idx: number): ToolInfo {
    const name = fn.name as string | undefined;
    if (!name) {
      throw new Error(`Function at index ${idx} has no name`);
    }

    return {
      name,
      description: (fn.description as string) ?? undefined,
      inputSchema: (fn.parameters as Record<string, unknown>) ?? { type: "object", properties: {} },
      sourceProtocol: "openai-functions",
      nativeType: "function",
    };
  }

  private log(message: string): void {
    if (this.verbose) {
      console.error(`[toolsurf:openai] ${message}`);
    }
  }
}
