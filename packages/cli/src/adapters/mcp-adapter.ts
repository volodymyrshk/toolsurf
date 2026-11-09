import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import type { ChildProcess } from "node:child_process";
import type {
  ServerCapabilities,
  ToolInfo,
  ResourceInfo,
  PromptInfo,
} from "../types/report.js";
import type { ProtocolAdapter, ProtocolType, AdapterConnectOptions } from "./types.js";

// ─── Native stdio transport — bypasses cross-spawn bundling issues ──────────

interface JSONRPCMessage {
  jsonrpc: string;
  id?: number | string;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: unknown;
}

/**
 * NativeStdioTransport — implements the MCP Transport interface using
 * Node's built-in child_process.spawn instead of cross-spawn.
 *
 * Root cause of the hang in bun-bundled CJS: cross-spawn is bundled
 * incorrectly and never resolves the spawn promise. This transport
 * uses Node's native spawn, which works reliably in all bundle targets.
 */
class NativeStdioTransport {
  private process: ChildProcess | null = null;
  private _started = false;

  onmessage?: (message: JSONRPCMessage) => void;
  onerror?: (error: Error) => void;
  onclose?: () => void;

  constructor(
    private command: string,
    private args: string[],
    private env?: Record<string, string>,
  ) {}

  async start(): Promise<void> {
    if (this._started) return;
    this._started = true;

    const env = this.env
      ? { ...process.env, ...this.env } as NodeJS.ProcessEnv
      : (process.env as NodeJS.ProcessEnv);

    this.process = spawn(this.command, this.args, {
      env,
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
    });

    if (!this.process.stdout || !this.process.stdin) {
      throw new Error("Failed to open stdio streams on child process");
    }

    // Use readline to handle newline-delimited JSON-RPC messages
    const rl = createInterface({ input: this.process.stdout, crlfDelay: Infinity });
    rl.on("line", (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      try {
        const msg = JSON.parse(trimmed) as JSONRPCMessage;
        this.onmessage?.(msg);
      } catch {
        // Non-JSON output from server (startup logs etc.) — ignore
      }
    });

    this.process.on("error", (err) => this.onerror?.(err));
    // L-4: Handle exit-with-error-code — report to onerror so callers know the
    // server crashed, rather than silently closing. Partial JSON lines in the
    // readline buffer are discarded by rl.close() but this is now at least reported.
    this.process.on("exit", (code, signal) => {
      rl.close();
      if (code !== null && code !== 0) {
        this.onerror?.(new Error(
          `MCP server process exited with code ${code}${signal ? ` (signal: ${signal})` : ""}`
        ));
      }
      this.onclose?.();
    });

    // Drain stderr silently (avoids blocking if the server writes to stderr)
    this.process.stderr?.resume();
  }

  async send(message: JSONRPCMessage): Promise<void> {
    if (!this.process?.stdin?.writable) {
      throw new Error("Transport not started or stdin closed");
    }
    const payload = JSON.stringify(message) + "\n";
    await new Promise<void>((resolve, reject) => {
      this.process!.stdin!.write(payload, "utf8", (err) => {
        if (err) reject(err); else resolve();
      });
    });
  }

  async close(): Promise<void> {
    try {
      this.process?.stdin?.end();
      this.process?.kill("SIGTERM");
    } catch {
      // Ignore cleanup errors
    }
    this.process = null;
  }
}

import { CLI_VERSION } from "../version.js";
const PROTOCOL_VERSION = "2025-11-05";

/**
 * MCP (Model Context Protocol) adapter.
 * Connects to MCP servers via stdio transport, performs the initialization
 * handshake, and enumerates all server capabilities (tools, resources, prompts).
 */
export class McpAdapter implements ProtocolAdapter {
  readonly protocol: ProtocolType = "mcp";
  readonly displayName = "MCP (Model Context Protocol)";

  private client: Client | null = null;
  private nativeTransport: NativeStdioTransport | null = null;
  private verbose: boolean = false;

  async connect(options: AdapterConnectOptions): Promise<ServerCapabilities> {
    this.verbose = options.verbose ?? false;
    const timeoutMs = options.timeoutMs ?? 30_000;

    const url = options.params.url as string | undefined;
    if (url) {
      const headers = options.params.headers as Record<string, string> | undefined;
      this.log(`Connecting to MCP server over Streamable HTTP: ${url}`);
      await this.connectStreamableHttp(url, headers, timeoutMs);
      this.log("MCP handshake completed via Streamable HTTP transport");
      return await this.enumerate();
    }

    const command = options.params.command as string;
    const args = (options.params.args as string[]) ?? [];
    const env = options.params.env as Record<string, string> | undefined;

    this.log(`Connecting to MCP server: ${command} ${args.join(" ")}`);

    // Strategy: try native transport first (bypasses cross-spawn bundling issues).
    // If native fails fast (bad command), fall back to SDK StdioClientTransport.
    let connectError: Error | null = null;

    try {
      await this.connectNative(command, args, env, timeoutMs);
      this.log("MCP handshake completed via native transport");
    } catch (err) {
      connectError = err instanceof Error ? err : new Error(String(err));
      this.log(`Native transport failed: ${connectError.message} — retrying with SDK transport`);

      // Cleanup native attempt
      await this.nativeTransport?.close().catch(() => {});
      this.nativeTransport = null;
      this.client = null;

      // Fall back to SDK StdioClientTransport
      await this.connectSdk(command, args, env, timeoutMs);
      this.log("MCP handshake completed via SDK transport");
    }

    const capabilities = await this.enumerate();
    return capabilities;
  }

  /** Connect using the MCP SDK Streamable HTTP transport. */
  private async connectStreamableHttp(
    url: string,
    headers: Record<string, string> | undefined,
    timeoutMs: number,
  ): Promise<void> {
    const transport = new StreamableHTTPClientTransport(new URL(url), {
      requestInit: headers ? { headers } : undefined,
    });

    this.client = new Client(
      { name: "toolsurf", version: CLI_VERSION },
      { capabilities: {} }
    );

    const connectPromise = this.client.connect(transport);
    let timer: ReturnType<typeof setTimeout> | undefined = undefined;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Streamable HTTP connection timed out after ${timeoutMs}ms`)), timeoutMs);
    });

    try {
      await Promise.race([connectPromise, timeoutPromise]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  /** Connect using native child_process transport (cross-spawn-free). */
  private async connectNative(
    command: string,
    args: string[],
    env: Record<string, string> | undefined,
    timeoutMs: number,
  ): Promise<void> {
    const native = new NativeStdioTransport(command, args, env);
    this.nativeTransport = native;

    this.client = new Client(
      { name: "toolsurf", version: CLI_VERSION },
      { capabilities: {} }
    );

    // The SDK Client expects a Transport-like object.
    // NativeStdioTransport implements the same interface.
    const connectPromise = this.client.connect(native as unknown as StdioClientTransport);
    // Fix: clear timeout on success to prevent keeping the process alive
    let timer: ReturnType<typeof setTimeout> | undefined = undefined;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Native connection timed out after ${timeoutMs}ms`)), timeoutMs);
    });

    try {
      await Promise.race([connectPromise, timeoutPromise]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  /** Connect using the MCP SDK StdioClientTransport (uses cross-spawn). */
  private async connectSdk(
    command: string,
    args: string[],
    env: Record<string, string> | undefined,
    timeoutMs: number,
  ): Promise<void> {
    const sdkTransport = new StdioClientTransport({
      command,
      args,
      env: env ? { ...process.env, ...env } as Record<string, string> : undefined,
    });
    this.client = new Client(
      { name: "toolsurf", version: CLI_VERSION },
      { capabilities: {} }
    );

    const connectPromise = this.client.connect(sdkTransport);
    // Fix: clear timeout on success to prevent keeping the process alive
    let timer: ReturnType<typeof setTimeout> | undefined = undefined;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`SDK connection timed out after ${timeoutMs}ms`)), timeoutMs);
    });

    try {
      await Promise.race([connectPromise, timeoutPromise]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  async invoke(
    name: string,
    args: Record<string, unknown>,
    timeoutMs?: number
  ): Promise<unknown> {
    if (!this.client) throw new Error("Not connected");
    this.log(`Calling tool: ${name} with args: ${JSON.stringify(args)}`);

    const timeout = timeoutMs ?? 8000; // default 8s per tool call

    const callPromise = this.client.callTool({
      name,
      arguments: args,
    });

    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutHandle = setTimeout(
        () => reject(new Error(`Tool call "${name}" timed out after ${timeout}ms`)),
        timeout
      );
      // Don't keep the process alive for the timer
      if (typeof timeoutHandle === "object" && "unref" in timeoutHandle) {
        (timeoutHandle as any).unref();
      }
    });

    try {
      const result = await Promise.race([callPromise, timeoutPromise]);
      return result;
    } finally {
      clearTimeout(timeoutHandle);
    }
  }

  async disconnect(): Promise<void> {
    this.log("Disconnecting from MCP server");
    try {
      await this.client?.close();
    } catch {
      // Ignore disconnect errors
    }
    try {
      await this.nativeTransport?.close();
    } catch {
      // Ignore native transport cleanup errors
    }
    this.client = null;
    this.nativeTransport = null;
  }

  private async enumerate(): Promise<ServerCapabilities> {
    if (!this.client) throw new Error("Not connected");

    const serverInfo = this.client.getServerVersion() ?? {
      name: "unknown",
      version: "unknown",
    };
    const serverCapabilities = this.client.getServerCapabilities() ?? {};

    this.log(`Server: ${serverInfo.name} v${serverInfo.version}`);

    const tools = await this.enumerateTools();
    this.log(`Discovered ${tools.length} tools`);

    const resources = await this.enumerateResources();
    this.log(`Discovered ${resources.length} resources`);

    const prompts = await this.enumeratePrompts();
    this.log(`Discovered ${prompts.length} prompts`);

    return {
      serverInfo: {
        name: serverInfo.name ?? "unknown",
        version: serverInfo.version ?? "unknown",
      },
      protocolVersion:
        (serverInfo as Record<string, unknown>).protocolVersion as string ??
        PROTOCOL_VERSION,
      capabilities: serverCapabilities,
      tools,
      resources,
      prompts,
      protocol: "mcp",
    };
  }

  private static readonly MAX_PAGINATION_PAGES = 100;

  private async enumerateTools(): Promise<ToolInfo[]> {
    if (!this.client) throw new Error("Not connected");

    const allTools: ToolInfo[] = [];
    let cursor: string | undefined;
    let pageCount = 0;

    try {
      do {
        if (++pageCount > McpAdapter.MAX_PAGINATION_PAGES) {
          this.log(`Tool pagination limit (${McpAdapter.MAX_PAGINATION_PAGES} pages) reached — stopping`);
          break;
        }
        const result = await this.client.listTools(
          cursor ? { cursor } : undefined
        );
        for (const tool of result.tools) {
          allTools.push({
            name: tool.name,
            description: tool.description,
            inputSchema: tool.inputSchema as Record<string, unknown>,
            annotations: tool.annotations as ToolInfo["annotations"],
            sourceProtocol: "mcp",
            nativeType: "tool",
          });
        }
        cursor = result.nextCursor;
      } while (cursor);
    } catch (err) {
      this.log(`Tool enumeration failed (server may not support tools): ${err}`);
    }

    return allTools;
  }

  private async enumerateResources(): Promise<ResourceInfo[]> {
    if (!this.client) throw new Error("Not connected");

    const allResources: ResourceInfo[] = [];
    let cursor: string | undefined;
    let pageCount = 0;

    try {
      do {
        if (++pageCount > McpAdapter.MAX_PAGINATION_PAGES) {
          this.log(`Resource pagination limit (${McpAdapter.MAX_PAGINATION_PAGES} pages) reached — stopping`);
          break;
        }
        const result = await this.client.listResources(
          cursor ? { cursor } : undefined
        );
        for (const resource of result.resources) {
          allResources.push({
            uri: resource.uri,
            name: resource.name,
            description: resource.description,
            mimeType: resource.mimeType,
          });
        }
        cursor = result.nextCursor;
      } while (cursor);
    } catch (err) {
      this.log(`Resource enumeration failed: ${err}`);
    }

    return allResources;
  }

  private async enumeratePrompts(): Promise<PromptInfo[]> {
    if (!this.client) throw new Error("Not connected");

    const allPrompts: PromptInfo[] = [];
    let cursor: string | undefined;
    let pageCount = 0;

    try {
      do {
        if (++pageCount > McpAdapter.MAX_PAGINATION_PAGES) {
          this.log(`Prompt pagination limit (${McpAdapter.MAX_PAGINATION_PAGES} pages) reached — stopping`);
          break;
        }
        const result = await this.client.listPrompts(
          cursor ? { cursor } : undefined
        );
        for (const prompt of result.prompts) {
          allPrompts.push({
            name: prompt.name,
            description: prompt.description,
            arguments: prompt.arguments?.map((a) => ({
              name: a.name,
              description: a.description,
              required: a.required,
            })),
          });
        }
        cursor = result.nextCursor;
      } while (cursor);
    } catch (err) {
      this.log(`Prompt enumeration failed: ${err}`);
    }

    return allPrompts;
  }

  private log(message: string): void {
    if (this.verbose) {
      console.error(`[toolsurf:mcp] ${message}`);
    }
  }
}
