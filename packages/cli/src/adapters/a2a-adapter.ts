import { readFileSync } from "node:fs";
import type { ServerCapabilities, ToolInfo } from "../types/report.js";
import type { ProtocolAdapter, ProtocolType, AdapterConnectOptions } from "./types.js";

/**
 * Agent-to-Agent (A2A) Protocol Adapter.
 *
 * Discovers agent capabilities from an A2A server via Agent Cards,
 * normalizes each skill/task into a ToolInfo for auditing.
 *
 * A2A uses "Agent Cards" describing agent capabilities. This adapter supports:
 *   - URL-based discovery (fetches Agent Card from .well-known/agent-card.json)
 *   - Legacy URL discovery (fetches .well-known/agent.json)
 *   - specFile: path to saved Agent Card JSON
 *
 * Connect params:
 *   - url: A2A server endpoint or Agent Card URL (e.g., http://localhost:5000)
 *   - specFile: path to Agent Card JSON file (offline mode)
 *   - headers: additional HTTP headers
 *
 * References:
 *   - A2A Protocol Spec: https://a2a-protocol.org/latest/specification/
 *   - Agent Card format: JSON with "skills", "capabilities", and interfaces
 */

interface A2aAgentCard {
  protocolVersion?: string;
  name?: string;
  description?: string;
  version?: string;
  url?: string;
  preferredTransport?: string;
  capabilities?: {
    streaming?: boolean;
    pushNotifications?: boolean;
    push_notifications?: boolean;
    stateTransitionHistory?: boolean;
    state_transition_history?: boolean;
    extendedAgentCard?: boolean;
    extended_agent_card?: boolean;
    supportsAuthenticatedExtendedCard?: boolean;
    extensions?: unknown[];
  };
  supportsAuthenticatedExtendedCard?: boolean;
  supportedInterfaces?: A2aAgentInterface[];
  additionalInterfaces?: A2aLegacyInterface[];
  securitySchemes?: Record<string, unknown>;
  security?: Array<Record<string, string[]>>;
  skills?: Array<{
    id: string;
    name?: string;
    description?: string;
    tags?: string[];
    examples?: string[];
    inputSchema?: Record<string, unknown>;
    outputSchema?: Record<string, unknown>;
  }>;
  authentication?: {
    schemes?: string[];
    credentials?: string;
  } | null;
  signatures?: unknown[];
}

interface A2aAgentInterface {
  url?: string;
  protocolBinding?: string;
  protocolVersion?: string;
  tenant?: string;
}

interface A2aLegacyInterface {
  url?: string;
  endpoint?: string;
  protocolBinding?: string;
  transport?: string;
  protocolVersion?: string;
  tenant?: string;
}

interface A2aJsonRpcCandidate {
  method: string;
  url: string;
  params: Record<string, unknown>;
}

export class A2aAdapter implements ProtocolAdapter {
  readonly protocol: ProtocolType = "a2a" as ProtocolType;
  readonly displayName = "Agent-to-Agent (A2A)";

  private verbose = false;
  private tools: ToolInfo[] = [];
  private url = "";
  private serviceUrl = "";
  private selectedInterface: A2aAgentInterface | null = null;
  private headers: Record<string, string> = {};
  private agentCard: A2aAgentCard | null = null;
  private requestCounter = 0;

  async connect(options: AdapterConnectOptions): Promise<ServerCapabilities> {
    this.verbose = options.verbose ?? false;
    this.url = (options.params.url as string) ?? "";
    this.headers = (options.params.headers as Record<string, string>) ?? {};

    const specFile = options.params.specFile as string | undefined;

    if (specFile) {
      this.log(`Loading Agent Card from: ${specFile}`);
      const content = readFileSync(specFile, "utf-8");
      this.agentCard = JSON.parse(content) as A2aAgentCard;
    } else if (this.url) {
      this.log(`Discovering A2A agent at: ${this.url}`);
      this.agentCard = await this.discoverAgentCard(options.timeoutMs ?? 30_000);
    } else {
      throw new Error(
        "A2A adapter requires a server URL or Agent Card file. " +
        "Pass --server <a2a-url> or provide specFile in params."
      );
    }

    this.resolveServiceUrl(this.agentCard);
    this.tools = this.parseAgentCard(this.agentCard);
    this.log(`Discovered ${this.tools.length} skills/tasks`);

    return {
      serverInfo: {
        name: this.agentCard.name ?? this.url ?? "a2a-agent",
        version: this.agentCard.version ?? "unknown",
      },
      protocolVersion: this.agentCard.protocolVersion
        ? `A2A ${this.agentCard.protocolVersion}`
        : "A2A unknown",
      capabilities: {
        a2a: true,
        streaming: this.agentCard.capabilities?.streaming ?? false,
        pushNotifications:
          this.agentCard.capabilities?.pushNotifications ??
          this.agentCard.capabilities?.push_notifications ??
          false,
        stateTransitionHistory:
          this.agentCard.capabilities?.stateTransitionHistory ??
          this.agentCard.capabilities?.state_transition_history ??
          false,
        extendedAgentCard:
          this.agentCard.capabilities?.extendedAgentCard ??
          this.agentCard.capabilities?.extended_agent_card ??
          this.agentCard.capabilities?.supportsAuthenticatedExtendedCard ??
          this.agentCard.supportsAuthenticatedExtendedCard ??
          false,
        supportedInterfaces: this.agentCard.supportedInterfaces ?? [],
        additionalInterfaces: this.agentCard.additionalInterfaces ?? [],
        selectedInterface: this.selectedInterface ?? undefined,
        serviceUrl: this.serviceUrl,
        securitySchemes: this.agentCard.securitySchemes ?? {},
        security: this.agentCard.security ?? [],
        authenticationSchemes: this.extractAuthenticationSchemes(this.agentCard),
        credentialHintsPresent: Boolean(this.agentCard.authentication?.credentials),
        signedAgentCard: Boolean(this.agentCard.signatures?.length),
      },
      tools: this.tools,
      resources: [],
      prompts: [],
      protocol: "a2a",
    };
  }

  async invoke(name: string, args: Record<string, unknown>): Promise<unknown> {
    if (!this.serviceUrl) {
      throw new Error("Cannot invoke A2A tasks without a server URL");
    }

    const tool = this.tools.find((t) => t.name === name);
    if (!tool) throw new Error(`Unknown skill/task: ${name}`);

    const requestId = ++this.requestCounter;
    const candidates = this.buildJsonRpcCandidates(name, args, requestId);
    const failures: Array<{ method: string; url: string; status?: number; error?: string }> = [];

    for (const candidate of candidates) {
      const request = {
        jsonrpc: "2.0",
        method: candidate.method,
        params: candidate.params,
        id: requestId,
      };

      this.log(`JSON-RPC ${candidate.method} → ${candidate.url}`);

      try {
        const resp = await fetch(candidate.url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "A2A-Version": this.normalizedProtocolVersion(),
            ...this.headers,
          },
          body: JSON.stringify(request),
          signal: AbortSignal.timeout(15_000),
        });

        if (!resp.ok) {
          failures.push({
            method: candidate.method,
            url: candidate.url,
            status: resp.status,
            error: resp.statusText,
          });
          continue;
        }

        const result = (await resp.json()) as { result?: unknown; error?: { message: string; code: number } };

        if (result.error) {
          failures.push({
            method: candidate.method,
            url: candidate.url,
            error: `${result.error.code}: ${result.error.message}`,
          });
          continue;
        }

        return result.result ?? {};
      } catch (err) {
        failures.push({
          method: candidate.method,
          url: candidate.url,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    return {
      error: "A2A invocation failed for all known JSON-RPC method variants",
      failures,
    };
  }

  async disconnect(): Promise<void> {
    this.tools = [];
    this.agentCard = null;
    this.serviceUrl = "";
    this.selectedInterface = null;
    this.requestCounter = 0;
  }

  // ── Discovery ─────────────────────────────────────────────────────────────

  private async discoverAgentCard(timeoutMs: number): Promise<A2aAgentCard> {
    const wellKnownUrls = this.discoveryCandidates();

    for (const wellKnownUrl of wellKnownUrls) {
      try {
        this.log(`  Trying well-known: ${wellKnownUrl}`);
        const resp = await fetch(wellKnownUrl, {
          headers: this.headers,
          signal: AbortSignal.timeout(Math.min(timeoutMs, 10_000)),
        });

        if (resp.ok) {
          const card = (await resp.json()) as A2aAgentCard;
          this.log(`  Agent Card discovered via well-known`);
          return card;
        }
      } catch {
        // Continue to the next well-known URI.
      }
    }

    // Fallback: JSON-RPC agent/discover method
    try {
      this.log(`  Trying JSON-RPC agent/discover`);
      const resp = await fetch(this.url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...this.headers,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "agent/discover",
          params: {},
          id: 1,
        }),
        signal: AbortSignal.timeout(Math.min(timeoutMs, 10_000)),
      });

      if (resp.ok) {
        const data = (await resp.json()) as { result?: A2aAgentCard };
        if (data.result) return data.result;
      }
    } catch {
      // Fall through
    }

    throw new Error(
      `A2A agent card discovery failed at ${this.url}. ` +
      `Tried: ${wellKnownUrls.join(", ")} and JSON-RPC agent/discover. ` +
      `Provide a specFile with --server <path-to-agent-card.json>`
    );
  }

  // ── Parsing ───────────────────────────────────────────────────────────────

  private parseAgentCard(card: A2aAgentCard): ToolInfo[] {
    const tools: ToolInfo[] = [];

    // Parse skills from Agent Card
    const skills = card.skills ?? [];
    for (const skill of skills) {
      const inputSchema = skill.inputSchema ?? this.inferSchemaFromExamples(skill.examples);

      tools.push({
        name: skill.id,
        description: skill.description ?? skill.name ?? `A2A skill: ${skill.id}`,
        inputSchema,
        sourceProtocol: "a2a",
        nativeType: "skill",
        httpMethod: this.selectedInterface?.protocolBinding ?? "JSON-RPC",
        endpointPath: this.serviceUrl || this.agentCard?.url || "",
      });
    }

    return tools;
  }

  private discoveryCandidates(): string[] {
    const urls = new Set<string>();
    if (!this.url) return [];

    try {
      const parsed = new URL(this.url);
      if (
        parsed.pathname.endsWith("/.well-known/agent-card.json") ||
        parsed.pathname.endsWith("/.well-known/agent.json")
      ) {
        urls.add(parsed.toString());
      }

      urls.add(new URL("/.well-known/agent-card.json", parsed.origin).toString());
      urls.add(new URL("/.well-known/agent.json", parsed.origin).toString());
    } catch {
      // Fall through to the raw URL; fetch will surface a useful error.
      urls.add(this.url);
    }

    return [...urls];
  }

  private selectServiceInterface(card: A2aAgentCard): A2aAgentInterface | null {
    const interfaces: A2aAgentInterface[] = [
      ...(card.supportedInterfaces ?? []),
      ...(card.additionalInterfaces ?? []).map((entry) => ({
        url: entry.url ?? entry.endpoint,
        protocolBinding: entry.protocolBinding ?? entry.transport,
        protocolVersion: entry.protocolVersion,
        tenant: entry.tenant,
      })),
    ];

    const jsonRpc = interfaces.find((entry) =>
      this.isJsonRpcBinding(entry.protocolBinding)
    );
    if (jsonRpc?.url) return jsonRpc;

    const httpJson = interfaces.find((entry) =>
      this.isHttpJsonBinding(entry.protocolBinding)
    );
    if (httpJson?.url) return httpJson;

    if (card.url) {
      return {
        url: card.url,
        protocolBinding: card.preferredTransport ?? "JSONRPC",
        protocolVersion: card.protocolVersion,
      };
    }

    return null;
  }

  private resolveServiceUrl(card: A2aAgentCard): void {
    this.selectedInterface = this.selectServiceInterface(card);
    this.serviceUrl = this.selectedInterface?.url ?? this.fallbackServiceUrl();
  }

  private fallbackServiceUrl(): string {
    if (!this.url) return "";

    try {
      const parsed = new URL(this.url);
      if (
        parsed.pathname.endsWith("/.well-known/agent-card.json") ||
        parsed.pathname.endsWith("/.well-known/agent.json")
      ) {
        return parsed.origin;
      }
    } catch {
      // Return the raw value below.
    }

    return this.url;
  }

  private isJsonRpcBinding(binding: string | undefined): boolean {
    return String(binding ?? "").toLowerCase().replace(/[-_\s]/g, "") === "jsonrpc";
  }

  private isHttpJsonBinding(binding: string | undefined): boolean {
    const normalized = String(binding ?? "").toLowerCase().replace(/[-_\s+]/g, "");
    return normalized === "httpjson" || normalized === "rest";
  }

  private normalizedProtocolVersion(): string {
    const version =
      this.selectedInterface?.protocolVersion ??
      this.agentCard?.protocolVersion ??
      "0.3.0";
    return version.startsWith("A2A ") ? version.slice(4) : version;
  }

  private buildJsonRpcCandidates(
    name: string,
    args: Record<string, unknown>,
    requestId: number,
  ): A2aJsonRpcCandidate[] {
    const version = this.normalizedProtocolVersion();
    const text = `Scanner probe for A2A skill "${name}" with JSON input: ${JSON.stringify(args)}`;
    const sendMessageParams = {
      tenant: this.selectedInterface?.tenant,
      message: {
        messageId: `audit-${requestId}`,
        role: "user",
        parts: [
          {
            kind: "text",
            type: "text",
            text,
          },
        ],
      },
      metadata: {
        skillId: name,
        arguments: args,
      },
    };
    const legacyTasksParams = {
      id: `audit-${requestId}`,
      skill: name,
      input: args,
    };
    const tasksUrl = new URL(
      "tasks/send",
      this.serviceUrl.endsWith("/") ? this.serviceUrl : `${this.serviceUrl}/`,
    ).toString();

    const methods = version.startsWith("1.")
      ? ["SendMessage", "message/send"]
      : ["message/send", "SendMessage"];

    return [
      ...methods.map((method) => ({
        method,
        url: this.serviceUrl,
        params: sendMessageParams,
      })),
      {
        method: "tasks/send",
        url: tasksUrl,
        params: legacyTasksParams,
      },
    ];
  }

  private extractAuthenticationSchemes(card: A2aAgentCard): string[] {
    const schemes = new Set<string>();

    for (const scheme of card.authentication?.schemes ?? []) {
      schemes.add(scheme);
    }

    for (const scheme of Object.keys(card.securitySchemes ?? {})) {
      schemes.add(scheme);
    }

    for (const requirement of card.security ?? []) {
      for (const scheme of Object.keys(requirement)) {
        schemes.add(scheme);
      }
    }

    return [...schemes].sort();
  }

  /**
   * Infer a basic JSON schema from example inputs.
   */
  private inferSchemaFromExamples(examples: string[] | undefined): Record<string, unknown> {
    if (!examples || examples.length === 0) {
      return { type: "object", properties: {} };
    }

    // Try to parse first example as JSON
    try {
      const example = JSON.parse(examples[0]);
      if (typeof example === "object" && example !== null) {
        const properties: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(example)) {
          properties[key] = { type: typeof value, description: `Example: ${JSON.stringify(value).substring(0, 100)}` };
        }
        return { type: "object", properties };
      }
    } catch {
      // Not JSON — return generic schema
    }

    return { type: "object", properties: { input: { type: "string", description: examples[0].substring(0, 200) } } };
  }

  private log(message: string): void {
    if (this.verbose) {
      console.error(`[toolsurf:a2a] ${message}`);
    }
  }
}
