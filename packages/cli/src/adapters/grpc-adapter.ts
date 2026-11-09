import { readFileSync } from "node:fs";
import type {
  ServerCapabilities,
  ToolInfo,
} from "../types/report.js";
import type { ProtocolAdapter, ProtocolType, AdapterConnectOptions } from "./types.js";

/**
 * Thrown when grpcurl is required for gRPC scanning but is not found on PATH.
 * Provides actionable installation instructions.
 */
export class GrpcurlNotFoundError extends Error {
  constructor() {
    super(
      "grpcurl is required for gRPC scanning but was not found on PATH.\n" +
      "Install: brew install grpcurl\n" +
      "Or: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest\n" +
      "Docs: https://github.com/fullstorydev/grpcurl#installation"
    );
    this.name = "GrpcurlNotFoundError";
  }
}

/**
 * gRPC adapter.
 *
 * Discovers services and methods from a gRPC server via reflection,
 * or from a proto descriptor / JSON service definition file.
 *
 * Connect params:
 *   - url: gRPC server address (host:port) for reflection
 *   - specFile: path to service definition JSON (offline mode)
 *
 * The spec file for offline mode should be a JSON array:
 * [
 *   {
 *     "service": "myapp.WeatherService",
 *     "methods": [
 *       {
 *         "name": "GetWeather",
 *         "description": "Get weather for a location",
 *         "inputType": "WeatherRequest",
 *         "outputType": "WeatherResponse",
 *         "clientStreaming": false,
 *         "serverStreaming": false,
 *         "fields": [
 *           { "name": "location", "type": "string", "number": 1 },
 *           { "name": "unit", "type": "string", "number": 2, "enum": ["celsius", "fahrenheit"] }
 *         ]
 *       }
 *     ]
 *   }
 * ]
 *
 * Generate this from proto files using:
 *   grpcurl -plaintext localhost:50051 describe | parse-to-json
 *   or: buf build -o descriptor.json
 */

interface GrpcMethodDef {
  name: string;
  description?: string;
  inputType?: string;
  outputType?: string;
  clientStreaming?: boolean;
  serverStreaming?: boolean;
  fields?: Array<{
    name: string;
    type: string;
    number: number;
    repeated?: boolean;
    optional?: boolean;
    enum?: string[];
    description?: string;
    oneofGroup?: string;
  }>;
}

interface GrpcServiceDef {
  service: string;
  description?: string;
  methods: GrpcMethodDef[];
}

export class GrpcAdapter implements ProtocolAdapter {
  readonly protocol: ProtocolType = "grpc";
  readonly displayName = "gRPC";

  private verbose = false;
  private tools: ToolInfo[] = [];
  private url = "";
  private services: GrpcServiceDef[] = [];

  async connect(options: AdapterConnectOptions): Promise<ServerCapabilities> {
    this.verbose = options.verbose ?? false;
    this.url = (options.params.url as string) ?? "";

    const specFile = options.params.specFile as string | undefined;

    if (specFile) {
      this.log(`Loading service definitions from: ${specFile}`);
      const content = readFileSync(specFile, "utf-8");
      this.services = JSON.parse(content);
    } else if (this.url) {
      this.log(`Connecting to gRPC server: ${this.url}`);
      this.services = await this.discoverViaReflection(options.timeoutMs ?? 30_000);
    } else {
      throw new Error(
        "gRPC adapter requires a server address or service definition file. " +
        "Pass --server <host:port> for reflection or provide specFile in params."
      );
    }

    this.tools = this.parseServices(this.services);
    this.log(`Discovered ${this.tools.length} RPC methods`);

    const serviceNames = this.services.map((s) => s.service);

    return {
      serverInfo: {
        name: this.url || specFile || "grpc",
        version: "proto3",
      },
      protocolVersion: "gRPC",
      capabilities: {
        services: serviceNames,
        reflection: !specFile,
      },
      tools: this.tools,
      resources: [],
      prompts: [],
      protocol: "grpc",
    };
  }

  async invoke(name: string, args: Record<string, unknown>): Promise<unknown> {
    if (!this.url) {
      throw new Error(
        "Cannot invoke gRPC methods without a server address. " +
        "Active scanning requires a live gRPC server."
      );
    }

    const tool = this.tools.find((t) => t.name === name);
    if (!tool) throw new Error(`Unknown method: ${name}`);

    // Skip streaming methods — not suitable for unary active fuzzing
    if (tool.nativeType && tool.nativeType !== "unary" && tool.nativeType !== "") {
      return { skipped: true, reason: `streaming method (${tool.nativeType}) not fuzzed` };
    }

    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const execFileAsync = promisify(execFile);

    // Build JSON payload — use execFile (not exec) so args never touch a shell
    const jsonInput = JSON.stringify(Object.keys(args).length > 0 ? args : {});

    // name format: "package.ServiceName/MethodName"
    // grpcurl format: grpcurl -plaintext -d '<json>' host:port package.ServiceName/MethodName
    try {
      const { stdout, stderr } = await execFileAsync(
        "grpcurl",
        ["-plaintext", "-d", jsonInput, this.url, name],
        { timeout: 15_000 }
      );

      // grpcurl writes response JSON to stdout
      if (stdout.trim()) {
        try {
          return JSON.parse(stdout);
        } catch {
          return { raw: stdout.trim() };
        }
      }

      // gRPC-level errors land in stderr (e.g. "Code: Unimplemented")
      if (stderr.trim()) {
        return { grpcError: stderr.trim(), grpcStatus: this.extractGrpcStatus(stderr) };
      }

      return {};
    } catch (err: unknown) {
      const e = err as { killed?: boolean; stderr?: string; stdout?: string; message?: string; code?: string };

      if (e.killed) throw new Error("gRPC invoke timed out after 15s");

      if (e.code === "ENOENT") {
        throw new Error(
          "grpcurl not found. Install: brew install grpcurl  " +
          "or: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest"
        );
      }

      // grpcurl exits non-zero on gRPC error responses — those ARE valid fuzzing results
      const errText = (e.stderr ?? "") + (e.stdout ?? "");
      if (errText.trim()) {
        return { grpcError: errText.trim(), grpcStatus: this.extractGrpcStatus(errText) };
      }

      throw new Error(`gRPC invoke failed: ${e.message}`);
    }
  }

  private extractGrpcStatus(text: string): string {
    const match = text.match(/Code:\s*(\w+)/i) ?? text.match(/status[_ ]code[:\s]+(\w+)/i);
    return match ? match[1].toUpperCase() : "UNKNOWN";
  }

  async disconnect(): Promise<void> {
    this.tools = [];
    this.services = [];
  }

  private async discoverViaReflection(timeoutMs: number): Promise<GrpcServiceDef[]> {
    // Use grpcurl for reflection since @grpc/grpc-js reflection is complex
    // and would add heavy dependencies.
    // SECURITY: Use execFile (not execSync) to avoid shell injection via this.url.
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const execFileAsync = promisify(execFile);

    // Pre-flight: verify grpcurl is installed
    try {
      await execFileAsync("grpcurl", ["--version"], { timeout: 5_000, encoding: "utf-8" });
    } catch {
      throw new GrpcurlNotFoundError();
    }

    try {
      // List services
      const { stdout: listOutput } = await execFileAsync(
        "grpcurl",
        ["-plaintext", this.url, "list"],
        { timeout: timeoutMs, encoding: "utf-8" }
      );

      const serviceNames = listOutput
        .trim()
        .split("\n")
        .filter((s) => s && !s.startsWith("grpc.reflection"));

      this.log(`Found services: ${serviceNames.join(", ")}`);

      const services: GrpcServiceDef[] = [];

      for (const serviceName of serviceNames) {
        // Describe each service
        const { stdout: descOutput } = await execFileAsync(
          "grpcurl",
          ["-plaintext", this.url, "describe", serviceName],
          { timeout: timeoutMs, encoding: "utf-8" }
        );

        const methods = this.parseGrpcurlDescribe(serviceName, descOutput);
        services.push({
          service: serviceName,
          methods,
        });
      }

      return services;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);

      if (message.includes("command not found") || message.includes("ENOENT")) {
        throw new Error(
          "grpcurl is required for gRPC reflection but was not found. " +
          "Install it: brew install grpcurl (macOS) or visit https://github.com/fullstorydev/grpcurl\n" +
          "Alternatively, provide a service definition file with --server <path.json>"
        );
      }

      throw new Error(`gRPC reflection failed: ${message}`);
    }
  }

  private parseGrpcurlDescribe(_serviceName: string, output: string): GrpcMethodDef[] {
    const methods: GrpcMethodDef[] = [];

    // Parse grpcurl describe output:
    // service MyService {
    //   rpc GetWeather ( .myapp.WeatherRequest ) returns ( .myapp.WeatherResponse );
    // }
    const rpcPattern = /rpc\s+(\w+)\s*\(\s*(?:stream\s+)?\.?(\S+)\s*\)\s*returns\s*\(\s*(?:stream\s+)?\.?(\S+)\s*\)/g;
    let match;

    while ((match = rpcPattern.exec(output)) !== null) {
      const clientStreaming = output.substring(match.index).includes("( stream");
      const serverStreaming = output.substring(match.index + match[0].indexOf("returns")).includes("( stream");

      methods.push({
        name: match[1],
        inputType: match[2],
        outputType: match[3],
        clientStreaming,
        serverStreaming,
      });
    }

    return methods;
  }

  private parseServices(services: GrpcServiceDef[]): ToolInfo[] {
    const tools: ToolInfo[] = [];

    for (const service of services) {
      for (const method of service.methods) {
        const properties: Record<string, unknown> = {};
        const required: string[] = [];

        if (method.fields) {
          for (const field of method.fields) {
            const schema: Record<string, unknown> = {
              type: this.protoTypeToJsonType(field.type),
              ...(field.description ? { description: field.description } : {}),
              ...(field.enum ? { enum: field.enum } : {}),
            };

            if (field.repeated) {
              properties[field.name] = { type: "array", items: schema };
            } else {
              properties[field.name] = schema;
            }

            if (!field.optional) {
              required.push(field.name);
            }
          }
        }

        const streamingNote = this.getStreamingNote(method);

        tools.push({
          name: `${service.service}/${method.name}`,
          description:
            (method.description ?? `gRPC method: ${service.service}/${method.name}`) +
            (streamingNote ? ` (${streamingNote})` : "") +
            (method.inputType ? ` [input: ${method.inputType}]` : ""),
          inputSchema: {
            type: "object",
            properties,
            ...(required.length > 0 ? { required } : {}),
          },
          sourceProtocol: "grpc",
          nativeType: streamingNote || "unary",
          endpointPath: `${service.service}/${method.name}`,
        });
      }
    }

    return tools;
  }

  private getStreamingNote(method: GrpcMethodDef): string {
    if (method.clientStreaming && method.serverStreaming) return "bidirectional-streaming";
    if (method.clientStreaming) return "client-streaming";
    if (method.serverStreaming) return "server-streaming";
    return "";
  }

  private protoTypeToJsonType(protoType: string): string {
    switch (protoType) {
      case "string":
        return "string";
      case "int32":
      case "int64":
      case "uint32":
      case "uint64":
      case "sint32":
      case "sint64":
      case "fixed32":
      case "fixed64":
      case "sfixed32":
      case "sfixed64":
        return "integer";
      case "float":
      case "double":
        return "number";
      case "bool":
        return "boolean";
      case "bytes":
        return "string"; // base64 encoded
      default:
        return "string"; // unknown types default to string
    }
  }

  private log(message: string): void {
    if (this.verbose) {
      console.error(`[toolsurf:grpc] ${message}`);
    }
  }
}
