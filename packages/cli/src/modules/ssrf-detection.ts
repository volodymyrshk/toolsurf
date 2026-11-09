import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
  type ToolInfo,
} from "../types/index.js";
import { URL_PARAM_PATTERNS } from "../utils/patterns.js";
import { existsSync, readFileSync } from "node:fs";

interface SsrfProbe {
  payload: string;
  category: string;
  description: string;
  captureFile?: string;
}

/**
 * SSRF canary domains — if the server resolves/fetches these, it proves
 * URL input is not properly validated.
 *
 * These are all controlled or non-routable addresses.
 * NO actual traffic is sent to external services.
 */
const SSRF_PROBES: SsrfProbe[] = [
  // Internal network probes (RFC 1918 / loopback)
  { payload: "http://127.0.0.1:80", category: "loopback", description: "IPv4 loopback" },
  { payload: "http://[::1]:80", category: "loopback", description: "IPv6 loopback" },
  { payload: "http://0.0.0.0:80", category: "loopback", description: "All-interfaces bind" },
  { payload: "http://localhost:80", category: "loopback", description: "Localhost hostname" },

  // Cloud metadata endpoints (AWS, GCP, Azure)
  { payload: "http://169.254.169.254/latest/meta-data/", category: "cloud-metadata", description: "AWS IMDS v1" },
  { payload: "http://metadata.google.internal/computeMetadata/v1/", category: "cloud-metadata", description: "GCP metadata" },
  { payload: "http://169.254.169.254/metadata/instance", category: "cloud-metadata", description: "Azure IMDS" },

  // Protocol smuggling
  { payload: "file:///etc/passwd", category: "protocol-smuggling", description: "file:// protocol" },
  { payload: "gopher://127.0.0.1:25/", category: "protocol-smuggling", description: "gopher:// protocol" },

  // DNS rebinding / bypass attempts
  { payload: "http://0x7f000001:80", category: "bypass", description: "Hex-encoded loopback" },
  { payload: "http://017700000001:80", category: "bypass", description: "Octal-encoded loopback" },
  { payload: "http://127.1:80", category: "bypass", description: "Shortened loopback" },
  { payload: "hTtP://127.0.0.1:80", category: "bypass", description: "Mixed-case protocol" },
  { payload: "http://[::ffff:127.0.0.1]:80", category: "bypass", description: "IPv4-mapped IPv6 loopback" },
  { payload: "http://[0:0:0:0:0:ffff:7f00:1]:80", category: "bypass", description: "Expanded IPv4-mapped IPv6" },
  { payload: "http://%31%32%37%2e%30%2e%30%2e%31:80", category: "bypass", description: "URL-encoded loopback" },
  { payload: "http://localtest.me:80", category: "bypass", description: "Public domain to 127.0.0.1" },
  { payload: "http://127.0.0.1.nip.io:80", category: "bypass", description: "nip.io wildcard DNS" },

  // P2-14 [§ADV]: Additional SSRF bypass payloads from security audit
  { payload: "http://2130706433/", category: "bypass", description: "Integer IP notation for 127.0.0.1" },
  { payload: "http://0177.0.0.1/", category: "bypass", description: "Dotted-octal notation for 127.0.0.1" },
  { payload: "http://127.0.0.1%0d%0aHost:%20evil.com/", category: "bypass", description: "CRLF injection via URL" },

  // Internal network ranges
  { payload: "http://10.0.0.1:80", category: "internal-network", description: "10.x.x.x range" },
  { payload: "http://192.168.1.1:80", category: "internal-network", description: "192.168.x.x range" },
  { payload: "http://172.16.0.1:80", category: "internal-network", description: "172.16.x.x range" },

  // DNS rebinding simulation probes
  { payload: "http://rebind.it/dns?127.0.0.1", category: "dns-rebinding", description: "DNS rebinding via public resolver" },
  { payload: "http://A.1.2.3.4.1time.127.0.0.1.1time.repeat.rebind.network/", category: "dns-rebinding", description: "Time-based DNS rebinding" },
];

// Removed URL_PARAM_PATTERNS from here, moved to utils/patterns.ts

function countCaptureLines(captureFile: string | undefined): number | undefined {
  if (!captureFile || !existsSync(captureFile)) return captureFile ? 0 : undefined;
  const content = readFileSync(captureFile, "utf-8").trim();
  return content.length === 0 ? 0 : content.split("\n").length;
}

function captureIncreased(before: number | undefined, after: number | undefined): boolean {
  return before !== undefined && after !== undefined && after > before;
}

/**
 * SSRF Detection Module (Active).
 *
 * This module identifies tools that accept URL parameters and probes them
 * with SSRF payloads to test whether the server properly validates URLs.
 *
 * ACTIVE MODULE: This module makes actual tool calls to the server.
 * Only enabled with --active flag.
 *
 * Detection approach:
 * 1. Identify tools with URL-like parameters from their schemas
 * 2. Send SSRF probe payloads (internal IPs, cloud metadata, protocol smuggling)
 * 3. Analyze responses for evidence of successful resolution/fetch
 * 4. Report findings with severity based on what resolved
 */
export class SsrfDetectionModule implements AuditModule {
  id = "ssrf-detection";
  name = "SSRF Detection";
  description =
    "Probes tools with URL parameters for SSRF vulnerabilities using controlled payloads";
  version = "1.0.0";
  mode = "active" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const { tools } = context.capabilities;

    // DNS rebinding risk assessment (passive — always runs)
    checks.push(...this.checkDnsRebindingRisk(context));

    // Step 1: Identify tools with URL parameters
    const urlTools = this.findUrlTools(tools);

    if (urlTools.length === 0) {
      checks.push({
        id: "SSRF-001",
        name: "URL-accepting tools",
        status: CheckStatus.PASS,
        message: "No tools accept URL parameters",
      });
      return checks;
    }

    checks.push({
      id: "SSRF-001",
      name: "URL-accepting tools",
      status: CheckStatus.WARN,
      message: `${urlTools.length} tool(s) accept URL parameters: ${urlTools.map((t) => t.tool.name).join(", ")}`,
      finding: {
        id: "SSRF-001",
        module: this.id,
        severity: Severity.LOW,
        title: "Tools accept URL parameters",
        description: `${urlTools.length} tool(s) accept URL parameters, which are potential SSRF vectors if not properly validated.`,
        evidence: {
          tools: urlTools.map((t) => ({
            name: t.tool.name,
            paramName: t.paramName,
          })),
        },
        remediation:
          "Implement URL allowlisting, block private IP ranges, and validate URL schemes (allow only https://).",
      },
    });

    // Step 2: If we have callTool, probe each URL tool
    if (!context.callTool) {
      checks.push({
        id: "SSRF-002",
        name: "SSRF active probing",
        status: CheckStatus.SKIP,
        message: "Active probing requires --active flag and callTool access",
      });
      return checks;
    }

    // Step 3: Probe each tool with SSRF payloads
    for (const { tool, paramName } of urlTools) {
      const probeResults = await this.probeToolForSsrf(
        tool,
        paramName,
        context.callTool,
        context.verbose,
        context.chamber
      );
      checks.push(...probeResults);
    }

    return checks;
  }

  /**
   * Find tools that have URL-like parameters in their input schema.
   */
  private findUrlTools(
    tools: ToolInfo[]
  ): Array<{ tool: ToolInfo; paramName: string }> {
    const urlTools: Array<{ tool: ToolInfo; paramName: string }> = [];

    for (const tool of tools) {
      const properties =
        (tool.inputSchema as Record<string, unknown>)?.properties as
          | Record<string, Record<string, unknown>>
          | undefined;

      if (!properties) continue;

      let matched = false;

      // Phase 1: Name-based matching (original behavior)
      for (const [paramName, paramSchema] of Object.entries(properties)) {
        if (URL_PARAM_PATTERNS.test(paramName)) {
          // For ambiguous param names like "destination", "target", "source",
          // verify the schema actually indicates URL input (not just a file path)
          const isAmbiguousName = /^(destination|target|source|endpoint|origin)$/i.test(paramName);
          if (isAmbiguousName) {
            const desc = ((paramSchema as Record<string, unknown>)?.description as string ?? "").toLowerCase();
            const format = (paramSchema as Record<string, unknown>)?.format as string ?? "";
            const pattern = (paramSchema as Record<string, unknown>)?.pattern as string ?? "";
            const hasUrlEvidence =
              format === "uri" || format === "url" ||
              /\burl\b|\buri\b|\bhttps?\b|\bendpoint\b/.test(desc) ||
              /https?/.test(pattern);
            if (!hasUrlEvidence) continue; // Skip — likely a file path, not a URL
          }
          urlTools.push({ tool, paramName });
          matched = true;
          break;
        }
      }
      if (matched) continue;

      // Phase 2: Schema-based matching — check format:"uri"/"url" or description
      // containing URL-related keywords, regardless of parameter name
      for (const [paramName, paramSchema] of Object.entries(properties)) {
        const schema = paramSchema as Record<string, unknown> | undefined;
        if (!schema || schema.type !== "string") continue;
        const format = (schema.format as string ?? "").toLowerCase();
        const desc = (schema.description as string ?? "").toLowerCase();

        if (
          format === "uri" || format === "url" ||
          /\b(url|uri|href|link|endpoint|webhook|callback|redirect)\b/.test(desc)
        ) {
          urlTools.push({ tool, paramName });
          matched = true;
          break;
        }
      }
    }

    return urlTools;
  }

  /**
   * Probe a single tool with SSRF payloads and analyze responses.
   */
  private async probeToolForSsrf(
    tool: ToolInfo,
    paramName: string,
    callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
    verbose: boolean,
    chamber: ModuleContext["chamber"],
  ): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const successfulProbes: Array<{
      payload: string;
      category: string;
      description: string;
      captureFile?: string;
      captureLinesBefore?: number;
      captureLinesAfter?: number;
      response: string;
    }> = [];

    const probes = [...this.buildChamberProbes(chamber), ...SSRF_PROBES];

    // Group probes by category — only need one success per category
    const probesByCategory = new Map<string, SsrfProbe[]>();
    for (const probe of probes) {
      const list = probesByCategory.get(probe.category) ?? [];
      list.push(probe);
      probesByCategory.set(probe.category, list);
    }

    for (const [, probes] of probesByCategory) {
      let categoryHit = false;

      for (const probe of probes) {
        if (categoryHit) break; // One hit per category is enough
        const captureLinesBefore = countCaptureLines(probe.captureFile);

        try {
          if (verbose) {
            console.error(
              `[toolsurf:ssrf] Probing ${tool.name}.${paramName} with ${probe.description}: ${probe.payload}`
            );
          }

          const result = await callTool(tool.name, {
            [paramName]: probe.payload,
          });

          // Analyze the response
          const responseStr =
            typeof result === "string"
              ? result
              : JSON.stringify(result);

          const captureLinesAfter = countCaptureLines(probe.captureFile);
          const chamberCaptured = captureIncreased(captureLinesBefore, captureLinesAfter);
          const isSuccessful = this.analyzeResponse(responseStr, probe) || chamberCaptured;

          if (isSuccessful) {
            categoryHit = true;
            successfulProbes.push({
              payload: probe.payload,
              category: probe.category,
              description: probe.description,
              captureFile: probe.captureFile,
              captureLinesBefore,
              captureLinesAfter,
              response: responseStr.substring(0, 500), // Truncate for evidence
            });
          }
        } catch (err) {
          const captureLinesAfter = countCaptureLines(probe.captureFile);
          if (captureIncreased(captureLinesBefore, captureLinesAfter)) {
            categoryHit = true;
            successfulProbes.push({
              payload: probe.payload,
              category: probe.category,
              description: probe.description,
              captureFile: probe.captureFile,
              captureLinesBefore,
              captureLinesAfter,
              response: `Tool call errored after chamber capture: ${err instanceof Error ? err.message : String(err)}`.slice(0, 500),
            });
            continue;
          }
          // Tool call errors are expected for blocked probes
          if (verbose) {
            console.error(
              `[toolsurf:ssrf] Probe blocked (expected): ${probe.description} → ${err instanceof Error ? err.message : String(err)}`
            );
          }
        }
      }
    }

    // Generate findings from successful probes
    if (successfulProbes.length === 0) {
      checks.push({
        id: `SSRF-010-${tool.name}`,
        name: `SSRF probing: ${tool.name}`,
        status: CheckStatus.PASS,
        message: "All SSRF probes blocked or rejected",
      });
    } else {
      // Determine severity based on what category succeeded
      const categories = new Set(successfulProbes.map((p) => p.category));
      let severity = Severity.MEDIUM;

      if (categories.has("cloud-metadata")) {
        severity = Severity.CRITICAL;
      } else if (categories.has("chamber-metadata")) {
        severity = Severity.CRITICAL;
      } else if (categories.has("chamber-http")) {
        severity = Severity.HIGH;
      } else if (categories.has("loopback") || categories.has("internal-network")) {
        severity = Severity.HIGH;
      } else if (categories.has("protocol-smuggling")) {
        severity = Severity.HIGH;
      } else if (categories.has("bypass")) {
        severity = Severity.HIGH;
      }

      checks.push({
        id: `SSRF-010-${tool.name}`,
        name: `SSRF probing: ${tool.name}`,
        status: CheckStatus.FAIL,
        message: `${successfulProbes.length} SSRF probe(s) succeeded across ${categories.size} category(ies)`,
        finding: {
          id: `SSRF-010-${tool.name}`,
          module: this.id,
          severity,
          title: `SSRF vulnerability in tool "${tool.name}"`,
          description:
            `Tool "${tool.name}" accepted and processed ${successfulProbes.length} SSRF probe payload(s). ` +
            `Affected categories: ${[...categories].join(", ")}. ` +
            (categories.has("cloud-metadata") || categories.has("chamber-metadata")
              ? "CRITICAL: Metadata endpoint was accessible, which may allow credential theft."
              : categories.has("chamber-http")
                ? "Detonation chamber HTTP capture confirms the target can reach a scanner-controlled sink."
                : "The server does not properly validate URL inputs to prevent internal network access."),
          evidence: {
            toolName: tool.name,
            paramName,
            successfulProbes: successfulProbes.map((p) => ({
              payload: p.payload,
              category: p.category,
              description: p.description,
              captureFile: p.captureFile,
              captureLinesBefore: p.captureLinesBefore,
              captureLinesAfter: p.captureLinesAfter,
              // Don't include full response in evidence to avoid leaking sensitive data
              responseLength: p.response.length,
            })),
          },
          remediation:
            "Implement comprehensive URL validation: " +
            "(1) Block private/reserved IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16). " +
            "(2) Allowlist URL schemes (https:// only). " +
            "(3) Resolve DNS before fetching and validate the resolved IP. " +
            "(4) Block cloud metadata endpoints. " +
            "(5) Use a URL allowlist if possible.",
          toolName: tool.name,
          cweId: "CWE-918",
        },
      });
    }

    return checks;
  }

  /**
   * Analyze a tool response to determine if an SSRF probe was successful.
   * A successful probe means the server resolved/fetched the target.
   */
  private analyzeResponse(
    response: string,
    probe: SsrfProbe
  ): boolean {
    const lowerResponse = response.toLowerCase();

    // If the response contains an error about the probe being blocked, it's NOT successful
    const blockedPatterns = [
      "blocked",
      "denied",
      "forbidden",
      "not allowed",
      "invalid url",
      "url validation",
      "private ip",
      "internal address",
      "ssrf",
      "security",
      "restricted",
    ];

    for (const pattern of blockedPatterns) {
      if (lowerResponse.includes(pattern)) {
        return false;
      }
    }

    // Category-specific success indicators
    switch (probe.category) {
      case "chamber-http":
      case "chamber-metadata":
        return (
          lowerResponse.includes("captured") &&
          (lowerResponse.includes("fake-http") || lowerResponse.includes("fake-metadata"))
        );

      case "cloud-metadata":
        // AWS metadata response patterns
        return (
          lowerResponse.includes("ami-id") ||
          lowerResponse.includes("instance-id") ||
          lowerResponse.includes("security-credentials") ||
          lowerResponse.includes("computemetadata") ||
          lowerResponse.includes("instance/") ||
          (response.length > 50 && !lowerResponse.includes("error"))
        );

      case "loopback":
      case "internal-network":
      case "bypass":
        // Any substantial response that's not an error suggests resolution
        return (
          response.length > 20 &&
          !lowerResponse.includes("error") &&
          !lowerResponse.includes("econnrefused") &&
          !lowerResponse.includes("timeout") &&
          !lowerResponse.includes("enotfound")
        );

      case "protocol-smuggling":
        // file:// protocol success indicators
        if (probe.payload.startsWith("file://")) {
          return (
            lowerResponse.includes("root:") || // /etc/passwd content
            lowerResponse.includes("/bin/") ||
            (response.length > 10 && !lowerResponse.includes("error"))
          );
        }
        // gopher:// success — any non-error response
        return response.length > 10 && !lowerResponse.includes("error");

      case "dns-rebinding":
        // Same logic as loopback — any substantial non-error response suggests resolution
        return (
          response.length > 20 &&
          !lowerResponse.includes("error") &&
          !lowerResponse.includes("econnrefused") &&
          !lowerResponse.includes("timeout") &&
          !lowerResponse.includes("enotfound")
        );

      default:
        return false;
    }
  }

  private buildChamberProbes(chamber: ModuleContext["chamber"]): SsrfProbe[] {
    if (!chamber) return [];
    return [
      {
        payload: `${chamber.fakeHttpUrl}/ssrf-probe`,
        category: "chamber-http",
        description: "Detonation chamber fake HTTP sink",
        captureFile: chamber.captures?.http,
      },
      {
        payload: `${chamber.fakeMetadataUrl}/latest/meta-data/iam/security-credentials/`,
        category: "chamber-metadata",
        description: "Detonation chamber fake metadata service",
        captureFile: chamber.captures?.metadata,
      },
    ];
  }

  /**
   * Passive DNS rebinding risk assessment.
   * Checks server metadata for indicators of DNS rebinding vulnerability.
   *
   * CWE-350: Reliance on Reverse DNS Resolution
   */
  private checkDnsRebindingRisk(context: ModuleContext): CheckResult[] {
    const checks: CheckResult[] = [];
    const indicators: string[] = [];

    // Check transport config for all-interfaces binding
    const transportHints = JSON.stringify(context.capabilities).toLowerCase();

    if (transportHints.includes("0.0.0.0") || transportHints.includes("::")) {
      indicators.push("Server appears bound to all interfaces (0.0.0.0 or ::)");
    }

    // Check for Streamable HTTP without explicit rebinding protection
    if (transportHints.includes("streamable") || transportHints.includes("sse")) {
      indicators.push("Uses Streamable HTTP/SSE transport — vulnerable to DNS rebinding without explicit protection (CVE-2025-66414)");
    }

    // Check if server exposes localhost-only services
    if (transportHints.includes("localhost") || transportHints.includes("127.0.0.1")) {
      if (!transportHints.includes("authentication") && !transportHints.includes("oauth")) {
        indicators.push("Localhost transport without authentication — DNS rebinding can bypass browser SOP");
      }
    }

    if (indicators.length === 0) {
      checks.push({
        id: "SSRF-020",
        name: "DNS rebinding risk assessment",
        status: CheckStatus.PASS,
        message: "No DNS rebinding risk indicators found",
      });
    } else {
      checks.push({
        id: "SSRF-020",
        name: "DNS rebinding risk assessment",
        status: CheckStatus.WARN,
        message: `${indicators.length} DNS rebinding risk indicator(s) found`,
        finding: {
          id: "SSRF-020",
          module: "ssrf-detection",
          severity: Severity.HIGH,
          title: "Server susceptible to DNS rebinding attacks",
          description: "DNS rebinding allows attackers to bypass browser same-origin policy and access localhost MCP servers from malicious websites. " +
            "This affects all Streamable HTTP and SSE-based MCP servers that lack explicit DNS rebinding protection. " +
            "Reference: CVE-2025-66414, CVE-2025-66416 (official MCP SDK DNS rebinding vulnerabilities).",
          evidence: { indicators },
          remediation: "1) Validate Host header on all incoming requests. " +
            "2) Bind to 127.0.0.1 instead of 0.0.0.0. " +
            "3) Enable DNS rebinding protection in FastMCP/SDK configuration. " +
            "4) Implement authentication even for localhost servers. " +
            "5) Add X-DNS-Prefetch-Control: off header.",
          cweId: "CWE-350",
        },
      });
    }
    return checks;
  }
}
