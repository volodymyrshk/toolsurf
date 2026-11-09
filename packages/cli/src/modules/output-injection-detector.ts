import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
  type ToolInfo,
} from "../types/index.js";

/**
 * Output Injection Detector Module.
 *
 * Manual pentesters read tool responses carefully. The scanner's existing
 * modules only check tool descriptions (static analysis) and HTTP status
 * codes (active fuzzing). This module analyzes the *content* of tool
 * responses to detect:
 *
 * 1. Hidden instructions in output ("Note to LLM" in response data)
 * 2. Data leakage (sensitive data in error messages)
 * 3. Response poisoning (adversarial content returned to agent)
 * 4. Format confusion (JSON that looks like instructions)
 *
 * This is the active-scanning equivalent of description-injection-detector.
 * Where that module checks what the server TELLS the agent, this module
 * checks what the server RETURNS to the agent.
 *
 * Finding prefixes: OID-001 through OID-004
 */
export class OutputInjectionDetectorModule implements AuditModule {
  id = "output-injection-detector";
  name = "Output Injection Detector";
  description =
    "Analyzes tool responses for hidden instructions, data leakage, and adversarial content that could poison agent behavior";
  version = "1.0.0";
  mode = "active" as const;

  /** Patterns that indicate hidden instructions in tool output */
  private readonly OUTPUT_INJECTION_PATTERNS = [
    {
      id: "OID-001a",
      label: "note-to-llm-in-output",
      pattern: /NOTE\s+TO\s+(AI|LLM|ASSISTANT|CLAUDE|GPT|MODEL|AGENT)\s*:/i,
      severity: Severity.CRITICAL,
    },
    {
      id: "OID-001b",
      label: "important-instruction-in-output",
      pattern: /IMPORTANT\s*(?:FOR\s+(?:AI|LLM|ASSISTANT|MODEL|AGENT))?\s*:\s*(?:you\s+must|always|never|before|do\s+not)/i,
      severity: Severity.CRITICAL,
    },
    {
      id: "OID-001c",
      label: "system-prompt-in-output",
      pattern: /<(system|instructions?|context|rules?)[^>]*>[^<]*<\/\1>/i,
      severity: Severity.CRITICAL,
    },
    {
      id: "OID-001d",
      label: "ignore-previous-in-output",
      pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|guidelines?)/i,
      severity: Severity.CRITICAL,
    },
    {
      id: "OID-001e",
      label: "new-instructions-in-output",
      pattern: /new\s+instructions?\s*:\s*\n/i,
      severity: Severity.CRITICAL,
    },
    {
      id: "OID-001f",
      label: "hidden-directive-in-output",
      pattern: /<!--\s*(?:ignore|override|bypass|disregard|forget|NOTE\s+TO\s+AI)\s*[^]*?-->/i,
      severity: Severity.CRITICAL,
    },
  ];

  /** Patterns that indicate data leakage */
  private readonly DATA_LEAKAGE_PATTERNS = [
    {
      id: "OID-002a",
      label: "api-key-in-output",
      pattern: /(api[_-]?key|apikey)\s*[:=]\s*['"]?[a-zA-Z0-9_-]{16,64}['"]?/i,
      severity: Severity.CRITICAL,
    },
    {
      id: "OID-002b",
      label: "secret-token-in-output",
      pattern: /(secret|token|password|credential)\s*[:=]\s*['"]?[a-zA-Z0-9!@#$%^&*._-]{8,64}['"]?/i,
      severity: Severity.CRITICAL,
    },
    {
      id: "OID-002c",
      label: "jwt-in-output",
      pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/,
      severity: Severity.HIGH,
    },
    {
      id: "OID-002d",
      label: "internal-path-in-error",
      pattern: /(\/home\/|\/root\/|\/var\/|\/opt\/|\/usr\/|\/etc\/)[a-zA-Z0-9_\/.-]+/,
      severity: Severity.MEDIUM,
    },
    {
      id: "OID-002e",
      label: "stack-trace-in-output",
      pattern: /(at\s+[a-zA-Z0-9_$.]+\s*\(|Error:\s+.*\n.*at\s|Traceback\s)/,
      severity: Severity.MEDIUM,
    },
    {
      id: "OID-002f",
      label: "database-connection-string",
      pattern: /(mongodb|postgres|mysql|redis):\/\/[^\s"]+/i,
      severity: Severity.CRITICAL,
    },
  ];

  /** Patterns for response poisoning */
  private readonly POISONING_PATTERNS = [
    {
      id: "OID-003a",
      label: "json-with-instructions",
      pattern: /\{[^}]*"instructions?"\s*:\s*"[^"]*(?:ignore|override|call|send|include)[^"]*"[^}]*\}/i,
      severity: Severity.HIGH,
    },
    {
      id: "OID-003b",
      label: "markdown-injection-in-output",
      pattern: /```[\s\S]{20,}```/,
      severity: Severity.MEDIUM,
    },
  ];

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];

    if (!context.callTool || !context.activeMode) {
      checks.push({
        id: "OID-000",
        name: "Output Injection Detector (Active)",
        status: CheckStatus.SKIP,
        message: "Requires --active flag and callTool access",
      });
      return checks;
    }

    const { capabilities: { tools }, callTool } = context;
    const probeDelay = context.probeDelay ?? 100;

    for (const tool of tools) {
      const findings = await this.analyzeToolOutput(tool, callTool, probeDelay);

      if (findings.length > 0) {
        const hasCritical = findings.some((f) => f.severity === Severity.CRITICAL);
        const hasHigh = findings.some((f) => f.severity === Severity.HIGH);

        checks.push({
          id: `OID-MAIN-${tool.name}`,
          name: `Output analysis: ${tool.name}`,
          status: CheckStatus.FAIL,
          message: `${findings.length} output anomaly(ies) in ${tool.name}`,
          finding: {
            id: `OID-MAIN-${tool.name}`,
            module: this.id,
            severity: hasCritical ? Severity.CRITICAL : hasHigh ? Severity.HIGH : Severity.MEDIUM,
            title: `Output injection / leakage in "${tool.name}"`,
            description:
              `Tool "${tool.name}" returned ${findings.length} suspicious output pattern(s) ` +
              `that could poison the AI agent's behavior or leak sensitive data. ` +
              `Unlike static description analysis, this finding is based on actual tool execution ` +
              `and response content.`,
            evidence: {
              toolName: tool.name,
              findings: findings.map((f) => ({
                category: f.category,
                label: f.label,
                matched: f.matched.substring(0, 200),
                severity: f.severity,
              })),
            },
            remediation:
              "Sanitize all tool outputs before returning them to the AI agent. Remove or redact " +
              "sensitive data (credentials, paths, stack traces). Strip any instructions or " +
              "directives embedded in response content. Validate that JSON responses don't contain " +
              "unexpected fields that could be interpreted as agent instructions.",
            toolName: tool.name,
            cweId: "CWE-116", // Improper Encoding or Escaping of Output
            confidence: 0.8,
          },
        });
      }
    }

    if (checks.length === 0) {
      checks.push({
        id: "OID-000",
        name: "Output Injection Detector",
        status: CheckStatus.PASS,
        message: "No output injection or leakage patterns detected",
      });
    }

    return checks;
  }

  private async analyzeToolOutput(
    tool: ToolInfo,
    callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
    probeDelay: number
  ): Promise<Array<{ category: string; label: string; matched: string; severity: Severity }>> {
    const findings: Array<{ category: string; label: string; matched: string; severity: Severity }> = [];

    // Build a benign test payload
    const testPayload = this.buildBenignPayload(tool);
    if (!testPayload) return findings;

    try {
      const result = await callTool(tool.name, testPayload);
      const responseStr = typeof result === "string" ? result : JSON.stringify(result);

      // Check for output injection patterns
      for (const pattern of this.OUTPUT_INJECTION_PATTERNS) {
        const match = responseStr.match(pattern.pattern);
        if (match) {
          findings.push({
            category: "output-injection",
            label: pattern.label,
            matched: match[0],
            severity: pattern.severity,
          });
        }
      }

      // Check for data leakage
      for (const pattern of this.DATA_LEAKAGE_PATTERNS) {
        const match = responseStr.match(pattern.pattern);
        if (match) {
          findings.push({
            category: "data-leakage",
            label: pattern.label,
            matched: match[0],
            severity: pattern.severity,
          });
        }
      }

      // Check for response poisoning
      for (const pattern of this.POISONING_PATTERNS) {
        const match = responseStr.match(pattern.pattern);
        if (match) {
          findings.push({
            category: "response-poisoning",
            label: pattern.label,
            matched: match[0],
            severity: pattern.severity,
          });
        }
      }

      if (probeDelay > 0) await new Promise((r) => setTimeout(r, probeDelay));
    } catch {
      // Tool failed — check error for leakage too
    }

    return findings;
  }

  private buildBenignPayload(tool: ToolInfo): Record<string, unknown> | null {
    const schema = tool.inputSchema as Record<string, unknown> | undefined;
    if (!schema || !schema.properties) return null;

    const props = schema.properties as Record<string, Record<string, unknown>>;
    const payload: Record<string, unknown> = {};

    for (const [key, val] of Object.entries(props)) {
      const type = val.type as string;
      if (type === "string") {
        // Use a benign, realistic value
        if (key.includes("path") || key.includes("file")) payload[key] = "/tmp/test.txt";
        else if (key.includes("url") || key.includes("endpoint")) payload[key] = "https://example.com";
        else if (key.includes("query") || key.includes("search")) payload[key] = "test query";
        else if (key.includes("id") || key.includes("name")) payload[key] = "test-id-123";
        else payload[key] = "benign_test_value";
      } else if (type === "number" || type === "integer") {
        payload[key] = 1;
      } else if (type === "boolean") {
        payload[key] = false;
      } else if (type === "array") {
        payload[key] = [];
      } else if (type === "object") {
        payload[key] = {};
      }
    }

    return Object.keys(payload).length > 0 ? payload : null;
  }
}
