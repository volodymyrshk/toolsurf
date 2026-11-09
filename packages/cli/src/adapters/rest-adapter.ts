import { readFileSync } from "node:fs";
import type {
  ServerCapabilities,
  ToolInfo,
} from "../types/report.js";
import type { ProtocolAdapter, ProtocolType, AdapterConnectOptions } from "./types.js";

/**
 * Common paths where OpenAPI/Swagger specs are typically served.
 * Ordered by likelihood — most common first to minimize discovery time.
 */
const SPEC_DISCOVERY_PATHS = [
  "/openapi.json",
  "/swagger.json",
  "/api-docs",
  "/api/openapi.json",
  "/api/swagger.json",
  "/v2/swagger.json",
  "/v3/api-docs",
  "/v2/api-docs",
  "/docs/openapi.json",
  "/swagger/v1/swagger.json",
  "/.well-known/openapi.json",
  "/api/v1/openapi.json",
  "/api/v2/openapi.json",
  "/openapi.yaml",
  "/swagger.yaml",
  "/api/docs",
  "/api-docs.json",
];

/**
 * REST API adapter.
 *
 * Discovers API endpoints from an OpenAPI/Swagger specification, normalizes
 * each operation into a ToolInfo for auditing. Supports both OpenAPI 3.x
 * and Swagger 2.0 specs.
 *
 * Connect params:
 *   - specFile: path to OpenAPI spec file (JSON or YAML)
 *   - specUrl: URL to fetch the OpenAPI spec from
 *   - url: base URL of the API (for invoke, auto-detected from spec if not provided)
 *   - headers: additional headers for invoke() (e.g., auth tokens)
 *
 * Common spec locations to try:
 *   /openapi.json, /swagger.json, /v2/swagger.json, /.well-known/openapi.json
 */
export class RestApiAdapter implements ProtocolAdapter {
  readonly protocol: ProtocolType = "rest-api";
  readonly displayName = "REST API (OpenAPI/Swagger)";

  private verbose = false;
  private tools: ToolInfo[] = [];
  private baseUrl = "";
  private headers: Record<string, string> = {};
  private specTitle = "REST API";
  private specVersion = "unknown";
  private componentsStore: Record<string, unknown> | undefined;

  async connect(options: AdapterConnectOptions): Promise<ServerCapabilities> {
    this.verbose = options.verbose ?? false;
    this.headers = (options.params.headers as Record<string, string>) ?? {};

    const specFile = options.params.specFile as string | undefined;
    const specUrl = options.params.specUrl as string | undefined;
    const explicitBaseUrl = options.params.url as string | undefined;

    let rawSpec: Record<string, unknown>;

    if (specFile) {
      this.log(`Loading OpenAPI spec from: ${specFile}`);
      const content = readFileSync(specFile, "utf-8");
      rawSpec = /\.ya?ml$/i.test(specFile)
        ? (await import("yaml")).parse(content)
        : JSON.parse(content);
    } else if (specUrl) {
      this.log(`Fetching OpenAPI spec from: ${specUrl}`);
      rawSpec = await this.fetchSpec(specUrl, options.timeoutMs ?? 30_000);
    } else if (explicitBaseUrl) {
      // Auto-discovery: try common OpenAPI/Swagger spec paths on the base URL
      this.log(`No spec provided — trying auto-discovery on ${explicitBaseUrl}`);
      const discovered = await this.autoDiscoverSpec(explicitBaseUrl, options.timeoutMs ?? 30_000);
      if (discovered) {
        rawSpec = discovered.spec;
        this.log(`Auto-discovered spec at: ${discovered.path}`);
      } else {
        throw new Error(
          `REST API adapter: auto-discovery failed on ${explicitBaseUrl}. ` +
          `Tried ${SPEC_DISCOVERY_PATHS.length} common paths. ` +
          `Pass --server <path-or-url-to-openapi.json> explicitly.`
        );
      }
    } else {
      throw new Error(
        "REST API adapter requires an OpenAPI/Swagger spec. " +
        "Pass --server <path-or-url-to-openapi.json> or provide a base URL for auto-discovery."
      );
    }

    // Detect base URL from spec, falling back to the spec URL's origin
    let detectedBase = explicitBaseUrl ?? this.extractBaseUrl(rawSpec) ?? "";

    // If the base URL is empty or relative (common in VAmPI, local APIs),
    // derive it from the spec URL origin: http://host:port/openapi.json → http://host:port
    if ((!detectedBase || detectedBase === "/" || detectedBase === "") && specUrl) {
      try {
        const specUrlObj = new URL(specUrl);
        detectedBase = specUrlObj.origin;
        this.log(`Base URL derived from spec URL origin: ${detectedBase}`);
      } catch {
        // specUrl is not a valid URL (e.g., a file path) — leave base empty
      }
    }

    this.baseUrl = detectedBase;
    this.log(`Base URL: ${this.baseUrl || "(not set)"}`);

    // Parse spec
    this.tools = this.parseOpenApiSpec(rawSpec);
    this.log(`Discovered ${this.tools.length} operations`);

    // HARDENING: Emit explicit warning when spec yields zero tools.
    // This happens when the URL returns JSON but it's not an OpenAPI spec
    // (e.g., health check JSON, status endpoint, API response).
    if (this.tools.length === 0) {
      console.error(
        `[toolsurf:rest] WARNING: Spec at ${specUrl ?? specFile ?? "(unknown)"} ` +
        `parsed successfully but yielded 0 tools. This target will produce ` +
        `transport-only findings (scan tier: transport-only). If this is a JSON ` +
        `health/status endpoint rather than an OpenAPI spec, this is expected.`,
      );
    }

    return {
      serverInfo: {
        name: this.specTitle,
        version: this.specVersion,
      },
      protocolVersion: this.detectSpecVersion(rawSpec),
      capabilities: { rest: true, openapi: true },
      tools: this.tools,
      resources: [],
      prompts: [],
      protocol: "rest-api",
    };
  }

  async invoke(name: string, args: Record<string, unknown>): Promise<unknown> {
    // Find the tool to get its HTTP method and path
    const tool = this.tools.find((t) => t.name === name);
    if (!tool) throw new Error(`Unknown operation: ${name}`);

    const method = (tool.httpMethod ?? "GET").toUpperCase();
    let path = tool.endpointPath ?? "/";

    // Substitute path parameters — work on a copy so the caller's args are not mutated
    const remainingArgs = { ...args };
    for (const [key, value] of Object.entries(args)) {
      const placeholder = `{${key}}`;
      if (path.includes(placeholder)) {
        path = path.replace(placeholder, encodeURIComponent(String(value)));
        delete remainingArgs[key];
      }
    }

    const url = new URL(path, this.baseUrl);

    // Remaining args go as query params (GET/DELETE) or body (POST/PUT/PATCH)
    const hasBody = ["POST", "PUT", "PATCH"].includes(method);
    if (!hasBody) {
      for (const [key, value] of Object.entries(remainingArgs)) {
        url.searchParams.set(key, String(value));
      }
    }

    this.log(`${method} ${url.toString()}`);

    const resp = await fetch(url.toString(), {
      method,
      headers: {
        ...this.headers,
        ...(hasBody ? { "Content-Type": "application/json" } : {}),
      },
      body: hasBody ? JSON.stringify(remainingArgs) : undefined,
      signal: AbortSignal.timeout(15_000),
    });

    const contentType = resp.headers.get("content-type") ?? "";

    // SECURITY: Classify HTTP status codes for active fuzzing
    // 5xx = server crash on malformed input = potential vulnerability
    // 4xx = request blocked (expected behavior)
    const isServerError = resp.status >= 500 && resp.status < 600;
    const isClientError = resp.status >= 400 && resp.status < 500;

    if (isServerError) {
      const bodyText = await resp.text();
      return {
        status: resp.status,
        body: bodyText,
        classification: "SERVER_ERROR",
        fuzzingNote: `Server crashed (${resp.status}) on fuzzed input — potential vulnerability`,
      };
    }

    if (isClientError) {
      const bodyText = await resp.text();
      return {
        status: resp.status,
        body: bodyText,
        classification: "BLOCKED",
        fuzzingNote: `Request blocked (${resp.status}) — server rejected malformed input`,
      };
    }

    if (contentType.includes("application/json")) {
      return await resp.json();
    }
    return { status: resp.status, body: await resp.text() };
  }

  async disconnect(): Promise<void> {
    this.tools = [];
  }

  private async fetchSpec(url: string, timeoutMs: number): Promise<Record<string, unknown>> {
    const resp = await fetch(url, {
      headers: this.headers,
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!resp.ok) {
      throw new Error(`Failed to fetch OpenAPI spec: ${resp.status} ${resp.statusText}`);
    }

    // HARDENING: Validate content-type before parsing to avoid silent failures
    // when spec URL returns HTML instead of JSON/YAML (e.g., login pages, 404 pages).
    const contentType = resp.headers.get("content-type") ?? "";
    if (contentType.includes("text/html")) {
      const bodyPreview = (await resp.text()).slice(0, 200);
      throw new Error(
        `OpenAPI spec URL returned HTML instead of JSON/YAML (content-type: ${contentType}). ` +
        `This usually means the URL is a web page, not an API spec endpoint. ` +
        `Preview: ${bodyPreview.replace(/\n/g, " ").trim()}`,
      );
    }

    // Try JSON first, fall back to YAML for .yaml/.yml URLs or YAML content-types
    const bodyText = await resp.text();
    const isYaml = /\.ya?ml$/i.test(url) || contentType.includes("yaml") || contentType.includes("x-yaml");

    try {
      if (isYaml) {
        return (await import("yaml")).parse(bodyText) as Record<string, unknown>;
      }
      return JSON.parse(bodyText) as Record<string, unknown>;
    } catch (firstErr) {
      // If JSON parse fails, try YAML as fallback (some servers serve YAML without proper content-type)
      if (!isYaml) {
        try {
          return (await import("yaml")).parse(bodyText) as Record<string, unknown>;
        } catch {
          // Fall through to the original error
        }
      }
      const message = firstErr instanceof Error ? firstErr.message : String(firstErr);
      throw new Error(
        `Failed to parse OpenAPI spec from ${url} as JSON/YAML: ${message}. ` +
        `Content-type was "${contentType}". ` +
        `Ensure the URL points to a JSON or YAML OpenAPI/Swagger specification.`,
      );
    }
  }

  /**
   * Try common OpenAPI/Swagger spec paths on a base URL.
   * Returns the first valid spec found, or null if none match.
   */
  private async autoDiscoverSpec(
    baseUrl: string,
    timeoutMs: number
  ): Promise<{ spec: Record<string, unknown>; path: string } | null> {
    const normalizedBase = baseUrl.replace(/\/$/, "");

    for (const path of SPEC_DISCOVERY_PATHS) {
      const url = `${normalizedBase}${path}`;
      try {
        this.log(`  Trying: ${url}`);
        const resp = await fetch(url, {
          headers: this.headers,
          signal: AbortSignal.timeout(Math.min(timeoutMs, 5_000)), // 5s max per attempt
        });

        if (!resp.ok) continue;

        const contentType = resp.headers.get("content-type") ?? "";
        if (contentType.includes("text/html")) continue; // skip HTML pages

        const body = await resp.json() as Record<string, unknown>;

        // Validate it looks like an OpenAPI/Swagger spec
        if (body.openapi || body.swagger || body.paths) {
          return { spec: body, path: url };
        }
      } catch (err) {
        // M-6: Distinguish JSON parse errors from network errors.
        // A server returning malformed JSON at a spec URL likely has a broken spec —
        // warn the user instead of silently trying the next path.
        if (err instanceof SyntaxError) {
          console.warn(
            `[rest-adapter] Warning: ${url} returned malformed JSON (${err.message}). ` +
            `If this is your spec URL, the file may be corrupted.`
          );
        }
        // Network error, timeout — try next path
        continue;
      }
    }

    return null;
  }

  private extractBaseUrl(spec: Record<string, unknown>): string | null {
    // OpenAPI 3.x: servers[0].url
    const servers = spec.servers as Array<{ url: string }> | undefined;
    if (servers && servers.length > 0) {
      return servers[0].url;
    }

    // Swagger 2.0: host + basePath + schemes
    if (spec.host) {
      const scheme = (spec.schemes as string[])?.[0] ?? "https";
      const basePath = (spec.basePath as string) ?? "";
      return `${scheme}://${spec.host}${basePath}`;
    }

    return null;
  }

  private detectSpecVersion(spec: Record<string, unknown>): string {
    if (typeof spec.openapi === "string") return `OpenAPI ${spec.openapi}`;
    if (typeof spec.swagger === "string") return `Swagger ${spec.swagger}`;
    return "unknown";
  }

  private parseOpenApiSpec(spec: Record<string, unknown>): ToolInfo[] {
    const info = spec.info as Record<string, unknown> | undefined;
    this.specTitle = (info?.title as string) ?? "REST API";
    this.specVersion = (info?.version as string) ?? "unknown";

    const paths = spec.paths as Record<string, Record<string, unknown>> | undefined;
    if (!paths) return [];

    const tools: ToolInfo[] = [];
    const components = spec.components as Record<string, unknown> | undefined;
    const definitions = spec.definitions as Record<string, unknown> | undefined;
    // For $ref resolution
    const schemaStore = (components?.schemas ?? definitions ?? {}) as Record<string, unknown>;
    this.componentsStore = components;

    for (const [pathStr, pathItem] of Object.entries(paths)) {
      if (!pathItem || typeof pathItem !== "object") continue;

      for (const method of ["get", "post", "put", "patch", "delete", "head", "options"]) {
        const operation = pathItem[method] as Record<string, unknown> | undefined;
        if (!operation) continue;

        const operationId = (operation.operationId as string) ??
          `${method.toUpperCase()}_${pathStr.replace(/[{}\/]/g, "_").replace(/_+/g, "_").replace(/^_|_$/g, "")}`;

        const description = (operation.summary as string) ??
          (operation.description as string) ??
          `${method.toUpperCase()} ${pathStr}`;

        // Build input schema from parameters + requestBody
        const inputSchema = this.buildInputSchema(operation, pathItem, schemaStore);

        tools.push({
          name: operationId,
          description,
          inputSchema,
          sourceProtocol: "rest-api",
          nativeType: "endpoint",
          httpMethod: method.toUpperCase(),
          endpointPath: pathStr,
        });
      }
    }

    return tools;
  }

  private buildInputSchema(
    operation: Record<string, unknown>,
    pathItem: Record<string, unknown>,
    schemaStore: Record<string, unknown>,
  ): Record<string, unknown> {
    const properties: Record<string, unknown> = {};
    const required: string[] = [];

    // Collect parameters (from both path-level and operation-level)
    const pathParams = (pathItem.parameters as Array<Record<string, unknown>>) ?? [];
    const opParams = (operation.parameters as Array<Record<string, unknown>>) ?? [];
    const allParams = [...pathParams, ...opParams];

    for (const param of allParams) {
      if (!param || typeof param !== "object") continue;

      // Resolve $ref
      const resolved = this.resolveRef(param, schemaStore);

      const name = resolved.name as string;
      if (!name) continue;

      const paramSchema = (resolved.schema as Record<string, unknown>) ?? { type: "string" };
      const inLocation = resolved.in as string;

      properties[name] = {
        ...paramSchema,
        description: (resolved.description as string) ??
          (paramSchema.description as string) ??
          `${inLocation} parameter`,
      };

      if (resolved.required === true) {
        required.push(name);
      }
    }

    // Handle requestBody (OpenAPI 3.x)
    const requestBody = operation.requestBody as Record<string, unknown> | undefined;
    if (requestBody) {
      const resolvedBody = this.resolveRef(requestBody, schemaStore);
      const content = resolvedBody.content as Record<string, Record<string, unknown>> | undefined;
      const jsonContent = content?.["application/json"];
      if (jsonContent?.schema) {
        const bodySchema = this.resolveRef(
          jsonContent.schema as Record<string, unknown>,
          schemaStore,
        );
        // Merge body properties into the top-level schema
        const bodyProps = bodySchema.properties as Record<string, unknown> | undefined;
        if (bodyProps) {
          Object.assign(properties, bodyProps);
          const bodyRequired = bodySchema.required as string[] | undefined;
          if (bodyRequired) required.push(...bodyRequired);
        } else {
          // Whole body as a single "body" parameter
          properties.body = bodySchema;
        }
      }
    }

    return {
      type: "object",
      properties,
      ...(required.length > 0 ? { required } : {}),
    };
  }

  private resolveRef(
    obj: Record<string, unknown>,
    schemaStore: Record<string, unknown>,
  ): Record<string, unknown> {
    const ref = obj.$ref as string | undefined;
    if (!ref) return obj;

    // "#/components/schemas/Foo" or "#/definitions/Foo"
    const match = ref.match(/^#\/(?:components\/schemas|definitions)\/(.+)$/);
    if (match && schemaStore[match[1]]) {
      return schemaStore[match[1]] as Record<string, unknown>;
    }

    // "#/components/{section}/Foo" — parameters, requestBodies, headers, responses
    const componentMatch = ref.match(/^#\/components\/(parameters|requestBodies|headers|responses)\/(.+)$/);
    if (componentMatch) {
      const section = this.componentsStore?.[componentMatch[1]] as Record<string, unknown> | undefined;
      if (section?.[componentMatch[2]]) {
        return section[componentMatch[2]] as Record<string, unknown>;
      }
    }

    if (ref.startsWith("http")) {
      this.log(`External $ref not resolved: ${ref}`);
    }

    return obj;
  }

  private log(message: string): void {
    if (this.verbose) {
      console.error(`[toolsurf:rest] ${message}`);
    }
  }
}
