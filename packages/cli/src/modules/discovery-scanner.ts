import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
} from "../types/index.js";

/**
 * MCP Discovery Scanner Module (Passive).
 *
 * Analyzes server metadata for /.well-known/mcp.json discovery endpoint
 * security (SEP-1960). This federated discovery mechanism allows AI clients
 * to automatically detect and connect to MCP servers.
 *
 * Security concerns:
 * 1. Information leakage via discovery endpoint
 * 2. Trust bootstrapping without verification
 * 3. Missing TLS on discovery endpoints
 * 4. Redirect chain manipulation
 * 5. Schema poisoning via discovery metadata
 */
export class DiscoveryScannerModule implements AuditModule {
  id = "discovery-scanner";
  name = "MCP Discovery Scanner";
  description = "Analyzes MCP server discovery metadata for SEP-1960 compliance and security";
  version = "1.0.0";
  mode = "passive" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const { capabilities } = context;
    const serverInfo = capabilities.serverInfo;
    const capabilitiesStr = JSON.stringify(capabilities).toLowerCase();
    const transportType = context.transport?.type;
    // HTTP-family transports (streamable-http, http, websocket) are the only
    // ones for which SSE / batching protocol-version checks are meaningful.
    const isHttpTransport =
      transportType === "streamable-http" ||
      transportType === "http" ||
      transportType === "websocket";

    // Check 1: Discovery endpoint exposure analysis
    checks.push(this.checkDiscoveryExposure(serverInfo, capabilitiesStr, capabilities.protocol));

    // Check 2: Server identity verification
    checks.push(this.checkServerIdentity(serverInfo));

    // Check 3: Capability declaration trust
    checks.push(this.checkCapabilityTrust(capabilities));

    // Check 4: Protocol version compliance — gated to HTTP-family transports.
    // Stdio targets cannot be vulnerable to deprecated SSE/HTTP transports.
    if (isHttpTransport) {
      checks.push(this.checkProtocolVersion(serverInfo, capabilities));
    } else {
      checks.push({
        id: "DS-004",
        name: "Protocol version compliance",
        status: CheckStatus.SKIP,
        message: `Skipped — transport "${transportType ?? "unknown"}" not subject to HTTP/SSE protocol version checks`,
      });
    }

    return checks;
  }

  private checkDiscoveryExposure(
    serverInfo: { name: string; version: string },
    capStr: string,
    protocol: ModuleContext["capabilities"]["protocol"] = "mcp"
  ): CheckResult {
    const exposures: string[] = [];

    // Check if server advertises too much metadata
    if (capStr.includes("well-known") || capStr.includes("/.well-known/mcp.json")) {
      exposures.push(
        protocol === "a2a"
          ? "Agent Card or interface metadata references a well-known discovery endpoint"
          : "Server references /.well-known/mcp.json discovery endpoint"
      );
    }

    // Check for verbose server identification
    const version = serverInfo.version;
    if (capStr.includes("node") || capStr.includes("python") || capStr.includes("deno") || capStr.includes("bun")) {
      exposures.push("Runtime environment leaked in server metadata");
    }
    if (capStr.includes("express") || capStr.includes("fastapi") || capStr.includes("fastmcp")) {
      exposures.push("Framework information leaked in server metadata");
    }
    if (version && /^\d+\.\d+\.\d+/.test(version)) {
      // Specific version can help attackers identify vulnerable versions
      exposures.push(`Specific version exposed: ${version} — aids vulnerability fingerprinting`);
    }

    if (exposures.length === 0) {
      return {
        id: "DS-001",
        name: "Discovery information exposure",
        status: CheckStatus.PASS,
        message: "Server metadata does not over-expose implementation details",
      };
    }

    return {
      id: "DS-001",
      name: "Discovery information exposure",
      status: CheckStatus.WARN,
      message: `${exposures.length} information exposure concern(s) in discovery metadata`,
      finding: {
        id: "DS-001",
        module: this.id,
        severity: Severity.LOW,
        title: "Server leaks implementation details via discovery metadata",
        description:
          "The server's discovery metadata exposes implementation details that could aid " +
          "an attacker in identifying vulnerable framework versions or runtime environments.",
        evidence: { exposures },
        remediation: protocol === "a2a"
          ? "Minimize metadata exposed via the Agent Card. Remove runtime/framework details from public card metadata, declare only required interfaces, and sign Agent Cards when clients rely on discovery trust."
          : "Minimize metadata exposed via /.well-known/mcp.json. Remove runtime/framework details from server identification. Use generic version identifiers in production.",
        cweId: "CWE-200",
      },
    };
  }

  private checkServerIdentity(serverInfo: { name: string; version: string }): CheckResult {
    const issues: string[] = [];

    if (!serverInfo.name || serverInfo.name.trim() === "") {
      issues.push("Server name is empty — cannot verify identity");
    }

    if (!serverInfo.version || serverInfo.version.trim() === "") {
      issues.push("Server version is empty — cannot track updates");
    }

    // Check for impersonation indicators
    const name = serverInfo.name.toLowerCase();
    const officialPrefixes = ["@modelcontextprotocol/", "mcp-server-", "@anthropic/"];
    for (const prefix of officialPrefixes) {
      if (name.startsWith(prefix.replace("@", "").replace("/", "-"))) {
        // Could be legitimate or impersonation — flag for manual review
        issues.push(`Server claims official naming convention: "${serverInfo.name}" — verify authenticity`);
      }
    }

    if (issues.length === 0) {
      return {
        id: "DS-002",
        name: "Server identity verification",
        status: CheckStatus.PASS,
        message: `Server identity: "${serverInfo.name}" v${serverInfo.version}`,
      };
    }

    return {
      id: "DS-002",
      name: "Server identity verification",
      status: CheckStatus.WARN,
      message: `${issues.length} identity verification concern(s)`,
      finding: {
        id: "DS-002",
        module: this.id,
        severity: Severity.MEDIUM,
        title: "Server identity cannot be fully verified",
        description: "The server's identity information is incomplete or potentially misleading. " +
          issues.join(". ") + ".",
        evidence: { serverName: serverInfo.name, version: serverInfo.version, issues },
        remediation:
          "Provide complete, verifiable server identification. " +
          "Use scoped package names (@org/server-name) for authenticity. " +
          "Publish server checksums or signatures for verification.",
        cweId: "CWE-290",
      },
    };
  }

  private checkCapabilityTrust(capabilities: ModuleContext["capabilities"]): CheckResult {
    const concerns: string[] = [];

    // Check for capability declarations that should trigger extra scrutiny
    const capStr = JSON.stringify(capabilities).toLowerCase();

    if (capStr.includes("sampling")) {
      concerns.push("Server requests 'sampling' capability — can prompt the LLM directly");
    }
    if (capStr.includes("roots")) {
      concerns.push("Server requests 'roots' capability — gains filesystem context awareness");
    }
    if (capStr.includes("listchanged") || capStr.includes("list_changed")) {
      concerns.push("Server advertises tool list change notifications — potential for rug-pull via schema mutation");
    }
    if (capStr.includes("elicitation")) {
      concerns.push("Server uses 'elicitation' capability — can request out-of-band user input (phishing surface)");
    }

    if (concerns.length === 0) {
      return {
        id: "DS-003",
        name: "Capability trust assessment",
        status: CheckStatus.PASS,
        message: "No high-risk capability declarations detected",
      };
    }

    return {
      id: "DS-003",
      name: "Capability trust assessment",
      status: CheckStatus.WARN,
      message: `${concerns.length} high-risk capability declaration(s) found`,
      finding: {
        id: "DS-003",
        module: this.id,
        severity: Severity.MEDIUM,
        title: "Server requests high-risk capabilities",
        description:
          "The server requests capabilities that grant significant access to the host environment or LLM. " +
          concerns.join(". ") + ". " +
          "These capabilities should only be granted to trusted servers after manual review.",
        evidence: { concerns },
        remediation:
          "Review and approve each capability request individually. " +
          "Only grant 'sampling' to servers that legitimately need LLM access. " +
          "Monitor 'listChanged' notifications for unexpected tool mutations. " +
          "Treat 'elicitation' requests with high scrutiny (potential phishing).",
        cweId: "CWE-269",
      },
    };
  }

  private checkProtocolVersion(
    _serverInfo: { name: string; version: string },
    capabilities: ModuleContext["capabilities"]
  ): CheckResult {
    const issues: string[] = [];
    const decl = (capabilities.capabilities ?? {}) as Record<string, unknown>;
    const protocolVersion = capabilities.protocolVersion;

    // Structured probe: look for explicit transport keys on the capabilities
    // object rather than substring-matching the entire JSON dump (which used
    // to match "sse" inside words like "passes" or "responses").
    const transports = (decl.transports ?? decl.transport) as
      | Record<string, unknown>
      | string
      | undefined;
    const usesSse = (() => {
      if (!transports) return false;
      if (typeof transports === "string") return /\bsse\b/i.test(transports);
      if (typeof transports === "object")
        return "sse" in transports && !("streamableHttp" in transports || "streamable-http" in transports);
      return false;
    })();
    if (usesSse) {
      issues.push("Server declares SSE transport without streamable-http (deprecated in 2025-03-26 spec)");
    }

    // Batching is declared, not name-matched — `batch` substring previously
    // matched any tool description containing "batch process".
    if (decl.batching === true || decl.batch === true) {
      issues.push("Server declares JSON-RPC batching (removed in 2025-06-18 spec)");
    }

    if (!protocolVersion || protocolVersion.trim() === "") {
      issues.push("No protocol version declared — cannot verify spec compliance");
    }

    if (issues.length === 0) {
      return {
        id: "DS-004",
        name: "Protocol version compliance",
        status: CheckStatus.PASS,
        message: "Server appears to use current protocol version",
      };
    }

    return {
      id: "DS-004",
      name: "Protocol version compliance",
      status: CheckStatus.WARN,
      message: `${issues.length} protocol compliance concern(s)`,
      finding: {
        id: "DS-004",
        module: this.id,
        severity: Severity.LOW,
        title: "Server may use outdated or non-compliant protocol features",
        description:
          "The server's capability metadata suggests it may use deprecated or removed " +
          "protocol features. Outdated protocol implementations may lack security patches. " +
          issues.join(". ") + ".",
        evidence: { issues },
        remediation:
          "Update to the latest MCP specification (2025-11-25). " +
          "Replace SSE with Streamable HTTP transport. " +
          "Remove JSON-RPC batching support. " +
          "Declare protocolVersion in server capabilities.",
        cweId: "CWE-1104",
      },
    };
  }
}
