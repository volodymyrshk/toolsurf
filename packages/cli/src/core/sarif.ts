import { Severity, type ScanReport } from "../types/index.js";
import { CWE_COMPLIANCE_MAP } from "../data/compliance-mappings.js";

/**
 * SARIF (Static Analysis Results Interchange Format) v2.1.0 output.
 *
 * Enables integration with:
 * - GitHub Code Scanning (upload via `github/codeql-action/upload-sarif`)
 * - VS Code SARIF Viewer extension
 * - Azure DevOps
 * - Any SARIF-compatible security dashboard
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 * 
 */

const SARIF_SCHEMA =
  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: "error" | "warning" | "note" | "none";
  message: { text: string };
  locations: Array<{
    physicalLocation?: {
      artifactLocation: { uri: string; uriBaseId?: string };
    };
    logicalLocations?: Array<{
      name: string;
      kind: string;
      fullyQualifiedName?: string;
    }>;
  }>;
  fixes?: Array<{
    description: { text: string };
  }>;
  properties?: Record<string, unknown>;
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  helpUri?: string;
  help?: { text: string; markdown?: string };
  defaultConfiguration: {
    level: "error" | "warning" | "note" | "none";
  };
  properties?: Record<string, unknown>;
}

interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: SarifRule[];
      };
    };
    results: SarifResult[];
    invocations: Array<{
      executionSuccessful: boolean;
      startTimeUtc?: string;
      endTimeUtc?: string;
      properties?: Record<string, unknown>;
    }>;
    properties?: Record<string, unknown>;
  }>;
}

/**
 * Map toolsurf severity to SARIF level.
 */
function severityToLevel(
  severity: Severity
): "error" | "warning" | "note" | "none" {
  switch (severity) {
    case Severity.CRITICAL:
      return "error";
    case Severity.HIGH:
      return "error";
    case Severity.MEDIUM:
      return "warning";
    case Severity.LOW:
      return "note";
    case Severity.INFO:
      return "none";
  }
}

/**
 * Convert an toolsurf ScanReport to SARIF v2.1.0 format.
 */
export function toSarif(report: ScanReport): SarifLog {
  // Build unique rules from findings
  const ruleMap = new Map<string, SarifRule>();
  const ruleIndexMap = new Map<string, number>();

  for (const finding of report.findings) {
    if (!ruleMap.has(finding.id)) {
      const ruleIndex = ruleMap.size;
      ruleIndexMap.set(finding.id, ruleIndex);
      ruleMap.set(finding.id, {
        id: finding.id,
        name: finding.title.replace(/[^a-zA-Z0-9]/g, ""),
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description },
        help: {
          text: finding.remediation,
          markdown: `**Remediation:** ${finding.remediation}`,
        },
        defaultConfiguration: {
          level: severityToLevel(finding.severity),
        },
        properties: {
          severity: finding.severity,
          module: finding.module,
          ...(finding.cweId ? { "security-severity": cweToScore(finding.cweId) } : {}),
          tags: (() => {
            const controls = finding.complianceControls ??
              (finding.cweId ? CWE_COMPLIANCE_MAP[finding.cweId] : undefined);
            return [
              "security",
              "mcp",
              finding.module,
              ...(finding.cweId ? [finding.cweId] : []),
              ...(controls?.map(c => `${c.framework}:${c.controlId}`) ?? []),
            ];
          })(),
        },
      });
    }
  }

  // Build results from findings
  const results: SarifResult[] = report.findings.map((finding) => ({
    ruleId: finding.id,
    ruleIndex: ruleIndexMap.get(finding.id) ?? 0,
    level: severityToLevel(finding.severity),
    message: {
      text: `${finding.title}: ${finding.description}`,
    },
    locations: [
      {
        logicalLocations: [
          {
            name: finding.toolName ?? report.server.serverInfo.name,
            kind: finding.toolName ? "mcpTool" : "mcpServer",
            fullyQualifiedName: finding.toolName
              ? `${report.server.serverInfo.name}/${finding.toolName}`
              : report.server.serverInfo.name,
          },
        ],
      },
    ],
    fixes: [
      {
        description: { text: finding.remediation },
      },
    ],
    properties: {
      severity: finding.severity,
      module: finding.module,
      evidence: finding.evidence,
    },
  }));

  // Calculate end time from start + duration
  const startTime = new Date(report.timestamp);
  const endTime = new Date(startTime.getTime() + report.durationMs);

  return {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "toolsurf",
            version: report.cliVersion,
            informationUri: "https://github.com/toolsurf/toolsurf",
            rules: [...ruleMap.values()],
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: report.timestamp,
            endTimeUtc: endTime.toISOString(),
            properties: {
              serverName: report.server.serverInfo.name,
              serverVersion: report.server.serverInfo.version,
              protocolVersion: report.server.protocolVersion,
              toolCount: report.server.tools.length,
              securityScore: report.summary.securityScore,
            },
          },
        ],
        properties: {
          securityScore: report.summary.securityScore,
          totalChecks: report.summary.totalChecks,
          transport: report.transport,
        },
      },
    ],
  };
}

/**
 * Map CWE IDs to approximate security-severity scores (0-10).
 * Used by GitHub Code Scanning to prioritize results.
 */
function cweToScore(cweId: string): string {
  const scores: Record<string, string> = {
    "CWE-918": "9.0",   // SSRF
    "CWE-78": "9.8",    // OS Command Injection
    "CWE-89": "9.8",    // SQL Injection
    "CWE-94": "9.8",    // Code Injection
    "CWE-74": "8.5",    // Injection (general, includes prompt injection)
    "CWE-22": "7.5",    // Path Traversal
    "CWE-79": "6.1",    // XSS
    "CWE-200": "5.3",   // Information Exposure
    "CWE-201": "5.3",   // Sensitive Data in Sent Data
    "CWE-250": "4.0",   // Unnecessary Privileges
    "CWE-269": "8.0",   // Improper Privilege Management
    "CWE-345": "6.5",   // Insufficient Verification of Data Authenticity
    "CWE-400": "5.3",   // Uncontrolled Resource Consumption
    "CWE-522": "7.0",   // Insufficiently Protected Credentials
    "CWE-710": "3.0",   // Improper Adherence to Coding Standards
    "CWE-732": "5.3",   // Incorrect Permission Assignment
    "CWE-757": "5.3",   // Less-Secure Algorithm Selection
    "CWE-862": "6.5",   // Missing Authorization
    "CWE-912": "7.5",   // Hidden Functionality
    "CWE-1188": "6.0",  // Hard-Coded Network Resource Init
    "CWE-20": "7.5",    // Improper Input Validation
  };
  return scores[cweId] ?? "5.0";
}
