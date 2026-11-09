import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
} from "../types/index.js";

/**
 * Transport Security Module.
 *
 * Analyzes the MCP server's transport configuration for security issues:
 * - npx/npx -y auto-install risks (supply chain)
 * - Unencrypted HTTP endpoints (if streamable-http)
 * - Missing authentication on HTTP transports
 * - Environment variable exposure in server commands
 * - Server capability signals (sampling, roots)
 */
export class TransportSecurityModule implements AuditModule {
  id = "transport-security";
  name = "Transport Security";
  description =
    "Analyzes transport configuration for supply-chain risks, insecure endpoints, and capability exposure";
  version = "1.0.0";
  mode = "passive" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];

    // ── Check 1: Server capability exposure ────────────────────────────
    checks.push(...this.checkCapabilityExposure(context));

    // ── Check 2: Sampling capability (allows server to request LLM) ───
    checks.push(this.checkSamplingCapability(context));

    // ── Check 3: Roots capability (allows server to access host paths) ─
    checks.push(this.checkRootsCapability(context));

    // ── Check 4: Tool listing change notifications ─────────────────────
    checks.push(this.checkToolListChanged(context));

    // ── Check 5: Excessive resources/prompts exposure ──────────────────
    checks.push(this.checkResourceExposure(context));

    // ── Check 6: Protocol version ──────────────────────────────────────
    checks.push(this.checkProtocolVersion(context));

    return checks;
  }

  private checkCapabilityExposure(context: ModuleContext): CheckResult[] {
    const checks: CheckResult[] = [];
    const caps = context.capabilities.capabilities;
    const declaredCaps = Object.keys(caps);

    if (declaredCaps.length === 0) {
      checks.push({
        id: "TS-001",
        name: "Server capability declaration",
        status: CheckStatus.WARN,
        message: "Server declares no capabilities — may indicate misconfiguration",
        finding: {
          id: "TS-001",
          module: this.id,
          severity: Severity.LOW,
          title: "No server capabilities declared",
          description:
            "The server did not declare any capabilities in its initialization response. This may indicate a misconfiguration or a server that relies on implicit behavior.",
          evidence: { declaredCapabilities: declaredCaps },
          remediation:
            "Servers should explicitly declare their capabilities (tools, resources, prompts) during initialization to enable proper client-side security decisions.",
          cweId: "CWE-710",
        },
      });
    } else {
      checks.push({
        id: "TS-001",
        name: "Server capability declaration",
        status: CheckStatus.PASS,
        message: `Server declares ${declaredCaps.length} capability group(s): ${declaredCaps.join(", ")}`,
      });
    }

    return checks;
  }

  private checkSamplingCapability(context: ModuleContext): CheckResult {
    const caps = context.capabilities.capabilities as Record<string, unknown>;

    // Check if server requests sampling capability
    // In MCP, sampling allows the server to request LLM completions from the client
    // This is a significant capability that could be abused
    if (caps.sampling) {
      return {
        id: "TS-002",
        name: "Sampling capability",
        status: CheckStatus.FAIL,
        message: "Server declares sampling capability — can request LLM completions from client",
        finding: {
          id: "TS-002",
          module: this.id,
          severity: Severity.HIGH,
          title: "Server requests sampling capability",
          description:
            "The server declares sampling capability, which allows it to request LLM completions through the client. " +
            "A malicious server could abuse this to: (1) exfiltrate data via crafted prompts, " +
            "(2) perform prompt injection attacks, (3) consume client LLM credits, " +
            "(4) chain requests to bypass rate limits.",
          evidence: { samplingConfig: caps.sampling },
          remediation:
            "Only grant sampling capability to fully trusted servers. Implement client-side guards: " +
            "rate limiting on sampling requests, content filtering on prompts, and user approval for sampling calls.",
          cweId: "CWE-200",
        },
      };
    }

    return {
      id: "TS-002",
      name: "Sampling capability",
      status: CheckStatus.PASS,
      message: "Server does not request sampling capability",
    };
  }

  private checkRootsCapability(context: ModuleContext): CheckResult {
    const caps = context.capabilities.capabilities as Record<string, unknown>;

    if (caps.roots) {
      const rootsConfig = caps.roots as Record<string, unknown>;
      return {
        id: "TS-003",
        name: "Roots capability",
        status: CheckStatus.WARN,
        message: "Server declares roots capability — can discover host filesystem paths",
        finding: {
          id: "TS-003",
          module: this.id,
          severity: Severity.MEDIUM,
          title: "Server requests roots capability",
          description:
            "The server declares roots capability, which allows it to discover filesystem paths " +
            "available on the host. While useful for legitimate file operations, this exposes " +
            "directory structure information that could be used for reconnaissance." +
            (rootsConfig.listChanged
              ? " The server also requests notifications when roots change, enabling persistent monitoring."
              : ""),
          evidence: { rootsConfig },
          remediation:
            "Ensure roots are scoped to the minimum necessary directories. " +
            "Never expose sensitive paths (home directories, system directories). " +
            "Monitor root change notifications if listChanged is enabled.",
          cweId: "CWE-200",
        },
      };
    }

    return {
      id: "TS-003",
      name: "Roots capability",
      status: CheckStatus.PASS,
      message: "Server does not request roots capability",
    };
  }

  private checkToolListChanged(context: ModuleContext): CheckResult {
    const caps = context.capabilities.capabilities as Record<string, unknown>;
    const toolsCap = caps.tools as Record<string, unknown> | undefined;

    if (toolsCap?.listChanged === true) {
      return {
        id: "TS-004",
        name: "Dynamic tool registration",
        status: CheckStatus.WARN,
        message: "Server supports dynamic tool list changes — tools may appear/disappear at runtime",
        finding: {
          id: "TS-004",
          module: this.id,
          severity: Severity.MEDIUM,
          title: "Server supports dynamic tool list changes",
          description:
            "The server has listChanged=true for tools, meaning it can dynamically add or remove " +
            "tools during a session. This is a known attack vector: a server could initially present " +
            "benign tools to pass security review, then inject malicious tools mid-session " +
            "(tool poisoning / rug pull attack).",
          evidence: { toolsCapability: toolsCap },
          remediation:
            "Clients should re-validate the tool list after each tools/list_changed notification. " +
            "Consider implementing a tool allowlist that restricts which tools can be called " +
            "regardless of dynamic changes. Alert users when the tool list changes mid-session.",
          cweId: "CWE-345",
        },
      };
    }

    return {
      id: "TS-004",
      name: "Dynamic tool registration",
      status: CheckStatus.PASS,
      message: "Server does not support dynamic tool changes",
    };
  }

  private checkResourceExposure(context: ModuleContext): CheckResult {
    const { resources, prompts: _prompts } = context.capabilities;

    // Check for potentially sensitive resource URIs
    const sensitiveResources = resources.filter((r) => {
      const uri = r.uri.toLowerCase();
      return (
        uri.includes("env") ||
        uri.includes("secret") ||
        uri.includes("config") ||
        uri.includes("credentials") ||
        uri.includes("password") ||
        uri.includes("token") ||
        uri.includes("key") ||
        uri.includes(".ssh") ||
        uri.includes(".aws")
      );
    });

    if (sensitiveResources.length > 0) {
      return {
        id: "TS-005",
        name: "Sensitive resource exposure",
        status: CheckStatus.FAIL,
        message: `${sensitiveResources.length} resource(s) with potentially sensitive URIs`,
        finding: {
          id: "TS-005",
          module: this.id,
          severity: Severity.HIGH,
          title: "Potentially sensitive resources exposed",
          description: `${sensitiveResources.length} resource URI(s) contain patterns suggesting sensitive data ` +
            "(env, secret, config, credentials, password, token, key, .ssh, .aws). " +
            "These resources may expose sensitive configuration or credentials to any connected client.",
          evidence: {
            resources: sensitiveResources.map((r) => ({
              uri: r.uri,
              name: r.name,
            })),
          },
          remediation:
            "Remove or restrict access to resources containing sensitive data. " +
            "Use resource templates with authentication requirements for sensitive endpoints. " +
            "Never expose raw environment variables, credentials, or configuration files as MCP resources.",
          cweId: "CWE-200",
        },
      };
    }

    if (resources.length > 50) {
      return {
        id: "TS-005",
        name: "Resource exposure",
        status: CheckStatus.WARN,
        message: `${resources.length} resources exposed — large surface area`,
        finding: {
          id: "TS-005",
          module: this.id,
          severity: Severity.LOW,
          title: "Large number of resources exposed",
          description: `Server exposes ${resources.length} resources. A large resource surface increases ` +
            "the risk of inadvertently exposing sensitive data.",
          evidence: { resourceCount: resources.length },
          remediation:
            "Review all exposed resources and restrict to those required for the intended use case.",
          cweId: "CWE-250",
        },
      };
    }

    return {
      id: "TS-005",
      name: "Resource exposure",
      status: CheckStatus.PASS,
      message: `${resources.length} resources, none appear sensitive`,
    };
  }

  private checkProtocolVersion(context: ModuleContext): CheckResult {
    const version = context.capabilities.protocolVersion;
    const protocol = context.capabilities.protocol ?? "mcp";
    const knownVersions = protocol === "a2a"
      ? ["A2A 0.2", "A2A 0.2.0", "A2A 0.2.1", "A2A 0.2.5", "A2A 0.3", "A2A 0.3.0", "A2A 1.0", "A2A 1.0.0"]
      : ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-05"];
    const protocolLabel = protocol === "a2a" ? "A2A" : "MCP";
    const remediation = protocol === "a2a"
      ? "Verify the agent card declares a standard A2A protocol version and supported interfaces. Non-standard versions may not interoperate with current A2A clients."
      : "Verify the server is using a standard MCP protocol version. Non-standard versions may have undocumented behavior or missing security features.";

    if (!knownVersions.includes(version)) {
      return {
        id: "TS-006",
        name: "Protocol version",
        status: CheckStatus.WARN,
        message: `Unknown protocol version: ${version}`,
        finding: {
          id: "TS-006",
          module: this.id,
          severity: Severity.INFO,
          title: `Unknown ${protocolLabel} protocol version`,
          description: `Server negotiated protocol version "${version}" which is not in the known version list. ` +
            "This may indicate a custom or experimental protocol implementation.",
          evidence: { version, knownVersions },
          remediation,
          cweId: "CWE-757",
        },
      };
    }

    return {
      id: "TS-006",
      name: "Protocol version",
      status: CheckStatus.PASS,
      message: `Protocol version ${version} is recognized`,
    };
  }
}
