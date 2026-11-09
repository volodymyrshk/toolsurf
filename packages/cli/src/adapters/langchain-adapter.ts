import { readFileSync } from "node:fs";
import type {
  ServerCapabilities,
  ToolInfo,
} from "../types/report.js";
import type { ProtocolAdapter, ProtocolType, AdapterConnectOptions } from "./types.js";

/**
 * LangChain Tools adapter.
 *
 * LangChain tools are code-defined (Python @tool decorator / TS tool() helper),
 * so there's no wire protocol to introspect. This adapter reads an exported
 * tool manifest — a JSON file containing the tool schemas.
 *
 * Connect params:
 *   - specFile: path to JSON file containing LangChain tool definitions
 *   - specUrl: URL to fetch tool definitions from
 *
 * The spec file should contain an array of tool objects:
 * [
 *   {
 *     "name": "get_weather",
 *     "description": "Get weather for a location",
 *     "schema": { "type": "object", "properties": { ... } }
 *   }
 * ]
 *
 * Generate this from a LangChain app:
 *   Python: json.dumps([{"name": t.name, "description": t.description, "schema": t.args} for t in tools])
 *   TS:     JSON.stringify(tools.map(t => ({ name: t.name, description: t.description, schema: t.schema })))
 */
export class LangChainAdapter implements ProtocolAdapter {
  readonly protocol: ProtocolType = "langchain-tools";
  readonly displayName = "LangChain Tools";

  private verbose = false;
  private tools: ToolInfo[] = [];

  async connect(options: AdapterConnectOptions): Promise<ServerCapabilities> {
    this.verbose = options.verbose ?? false;

    const specFile = options.params.specFile as string | undefined;
    const specUrl = options.params.specUrl as string | undefined;

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
        throw new Error(`Failed to fetch spec from ${specUrl}: ${resp.status}`);
      }
      rawSpec = await resp.json();
    } else {
      throw new Error(
        "LangChain adapter requires a tool manifest. " +
        "Export your tools as JSON and pass --server <path-to-tools.json>.\n" +
        "Generate with: JSON.stringify(tools.map(t => ({ name: t.name, description: t.description, schema: t.schema })))"
      );
    }

    this.tools = this.parseToolDefinitions(rawSpec);
    this.log(`Parsed ${this.tools.length} tool definitions`);

    return {
      serverInfo: {
        name: specFile ?? specUrl ?? "langchain-tools",
        version: "unknown",
      },
      protocolVersion: "langchain-core",
      capabilities: { tools: true },
      tools: this.tools,
      resources: [],
      prompts: [],
      protocol: "langchain-tools",
    };
  }

  async invoke(_name: string, _args: Record<string, unknown>): Promise<unknown> {
    throw new Error(
      "LangChain tools cannot be invoked remotely — they run in-process. " +
      "Active scanning is not supported for LangChain tool manifests. " +
      "Use passive scanning (omit --active) to audit tool schemas."
    );
  }

  async disconnect(): Promise<void> {
    this.tools = [];
  }

  private parseToolDefinitions(raw: unknown): ToolInfo[] {
    if (!Array.isArray(raw)) {
      if (raw && typeof raw === "object") {
        const obj = raw as Record<string, unknown>;
        if (Array.isArray(obj.tools)) return this.parseToolDefinitions(obj.tools);
      }
      throw new Error("Tool manifest must be a JSON array of tool definitions");
    }

    return raw.map((item: unknown, idx: number) => {
      if (!item || typeof item !== "object") {
        throw new Error(`Tool at index ${idx} is not an object`);
      }

      const obj = item as Record<string, unknown>;
      const name = obj.name as string | undefined;
      if (!name) {
        throw new Error(`Tool at index ${idx} has no name`);
      }

      // LangChain uses "schema" or "args" or "args_schema" or "parameters"
      const schema =
        (obj.schema as Record<string, unknown>) ??
        (obj.args as Record<string, unknown>) ??
        (obj.args_schema as Record<string, unknown>) ??
        (obj.parameters as Record<string, unknown>) ??
        { type: "object", properties: {} };

      return {
        name,
        description: (obj.description as string) ?? undefined,
        inputSchema: schema,
        sourceProtocol: "langchain-tools" as const,
        nativeType: "tool",
      };
    });
  }

  private log(message: string): void {
    if (this.verbose) {
      console.error(`[toolsurf:langchain] ${message}`);
    }
  }
}
