import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
  type ToolInfo,
} from "../types/index.js";
import {
  collectAllDescriptions,
  collectAllDefaults,
  findUnconstrainedObjects,
  findUnconstrainedArrays,
} from "../utils/schema-walker.js";

/**
 * Prompt injection indicators in tool descriptions.
 * These patterns suggest a tool description is trying to manipulate
 * the AI agent's behavior rather than describe the tool's functionality.
 */
const INJECTION_PATTERNS = [
  {
    pattern: /ignore\s+(previous|prior|above|all)\s+(instructions?|rules?|guidelines?)/i,
    severity: Severity.CRITICAL,
    category: "instruction-override",
    description: "Attempts to override agent instructions",
  },
  {
    pattern: /you\s+(must|should|shall|have\s+to|need\s+to)\s+(always|never|first|immediately)/i,
    severity: Severity.HIGH,
    category: "behavioral-directive",
    description: "Behavioral directive disguised as tool description",
  },
  {
    pattern: /(do\s+not|don't|never)\s+(tell|inform|notify|alert|warn)\s+(the\s+)?(user|human|person)/i,
    severity: Severity.CRITICAL,
    category: "concealment",
    description: "Attempts to hide behavior from the user",
  },
  {
    pattern: /before\s+(using|calling|running)\s+(any\s+)?(other|another)\s+tool/i,
    severity: Severity.HIGH,
    category: "execution-order",
    description: "Tries to manipulate tool execution order",
  },
  {
    pattern: /(silently|quietly|secretly|automatically)\s+(run|execute|call|invoke|send)/i,
    severity: Severity.CRITICAL,
    category: "covert-execution",
    description: "Instructs covert execution of actions",
  },
  {
    pattern: /this\s+tool\s+(is|has\s+been)\s+(safe|verified|trusted|approved|audited)/i,
    severity: Severity.MEDIUM,
    category: "trust-assertion",
    description: "Self-asserted trust claim in description",
  },
  {
    pattern: /system\s*:?\s*(prompt|message|instruction)/i,
    severity: Severity.HIGH,
    category: "system-prompt-injection",
    description: "Attempts to inject system-level instructions",
  },
  {
    pattern: /\<\/?[a-z]+[^>]*>/i,
    severity: Severity.MEDIUM,
    category: "markup-injection",
    description: "HTML/XML markup in tool description",
  },
  {
    pattern: /\{[%{].*[%}]\}/,
    severity: Severity.MEDIUM,
    category: "template-injection",
    description: "Template syntax in tool description",
  },
  {
    pattern: /password|secret|token|api[_-]?key|credential/i,
    severity: Severity.MEDIUM,
    category: "credential-request",
    description: "References credentials in tool description",
  },
];

/**
 * Suspicious schema patterns that could be used for data exfiltration
 * or unexpected behavior.
 */
const SUSPICIOUS_SCHEMA_PATTERNS = [
  {
    check: (schema: Record<string, unknown>) => {
      // Check for extremely permissive schemas
      const props = schema.properties as Record<string, unknown> | undefined;
      if (!props) return false;
      const requiredCount = (schema.required as string[] | undefined)?.length ?? 0;
      const totalProps = Object.keys(props).length;
      return totalProps > 10 && requiredCount === 0;
    },
    id: "excessive-optional-params",
    severity: Severity.MEDIUM,
    description: "Tool has many parameters with none required — may accept unexpected data",
  },
  {
    check: (schema: Record<string, unknown>) => {
      // Check for nested object parameters with no constraints
      const props = schema.properties as Record<string, Record<string, unknown>> | undefined;
      if (!props) return false;
      return Object.values(props).some(
        (p) => p.type === "object" && !p.properties && p.additionalProperties !== false
      );
    },
    id: "unconstrained-nested-objects",
    severity: Severity.MEDIUM,
    description: "Tool accepts unconstrained nested objects — arbitrary data injection possible",
  },
  {
    check: (schema: Record<string, unknown>) => {
      // Check for array parameters without item constraints
      const props = schema.properties as Record<string, Record<string, unknown>> | undefined;
      if (!props) return false;
      return Object.values(props).some(
        (p) => p.type === "array" && (!p.items || !p.maxItems)
      );
    },
    id: "unconstrained-arrays",
    severity: Severity.LOW,
    description: "Tool accepts arrays without item type constraints or size limits",
  },
];

/**
 * Schema Manipulation Module.
 *
 * Detects prompt injection patterns hidden in tool descriptions,
 * schema poisoning via malicious default values, and suspicious
 * schema structures that could be used for data exfiltration.
 *
 * This module addresses a core MCP attack vector: tool poisoning,
 * where a malicious server injects instructions into tool schemas
 * that manipulate the AI agent's behavior.
 */
export class SchemaManipulationModule implements AuditModule {
  id = "schema-manipulation";
  name = "Schema Manipulation & Prompt Injection";
  description =
    "Detects prompt injection in tool descriptions, schema poisoning, and data exfiltration patterns";
  version = "1.0.0";
  mode = "passive" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const { tools } = context.capabilities;

    // ── Check 1: Scan all tool descriptions for injection patterns ─────
    checks.push(...this.scanDescriptionsForInjection(tools));

    // ── Check 2: Check parameter descriptions for injection ────────────
    checks.push(...this.scanParamDescriptionsForInjection(tools));

    // ── Check 3: Check for suspicious default values ───────────────────
    checks.push(...this.checkSuspiciousDefaults(tools));

    // ── Check 4: Check for suspicious schema structures (recursive) ────
    checks.push(...this.checkSuspiciousSchemas(tools));

    // ── Check 5: Description length anomalies ──────────────────────────
    checks.push(this.checkDescriptionLengthAnomalies(tools));

    return checks;
  }

  private scanDescriptionsForInjection(tools: ToolInfo[]): CheckResult[] {
    const checks: CheckResult[] = [];
    const injections: Array<{
      tool: string;
      pattern: string;
      category: string;
      matched: string;
    }> = [];

    for (const tool of tools) {
      if (!tool.description) continue;

      for (const { pattern, category } of INJECTION_PATTERNS) {
        const match = pattern.exec(tool.description);
        if (match) {
          injections.push({
            tool: tool.name,
            pattern: pattern.source,
            category,
            matched: match[0],
          });
        }
      }
    }

    if (injections.length === 0) {
      checks.push({
        id: "SM-001",
        name: "Tool description injection scan",
        status: CheckStatus.PASS,
        message: "No injection patterns found in tool descriptions",
      });
    } else {
      // Group by severity
      const hasCritical = injections.some((i) =>
        INJECTION_PATTERNS.find(
          (p) => p.category === i.category && p.severity === Severity.CRITICAL
        )
      );

      const severity = hasCritical ? Severity.CRITICAL : Severity.HIGH;

      checks.push({
        id: "SM-001",
        name: "Tool description injection scan",
        status: CheckStatus.FAIL,
        message: `${injections.length} injection pattern(s) detected across ${new Set(injections.map((i) => i.tool)).size} tool(s)`,
        finding: {
          id: "SM-001",
          module: this.id,
          severity,
          title: "Prompt injection patterns in tool descriptions",
          description:
            `${injections.length} injection pattern(s) were found in tool descriptions. ` +
            "These patterns attempt to manipulate AI agent behavior through the tool schema, " +
            "a technique known as 'tool poisoning' or 'indirect prompt injection'. " +
            `Categories detected: ${[...new Set(injections.map((i) => i.category))].join(", ")}.`,
          evidence: {
            injections: injections.map((i) => ({
              tool: i.tool,
              category: i.category,
              matched: i.matched,
            })),
          },
          remediation:
            "Tool descriptions should only describe the tool's functionality, input parameters, " +
            "and expected output. Remove any behavioral directives, system instructions, or " +
            "manipulation attempts. AI agent clients should sanitize or flag tool descriptions " +
            "before including them in prompts.",
          cweId: "CWE-94",
        },
      });
    }

    return checks;
  }

  private scanParamDescriptionsForInjection(tools: ToolInfo[]): CheckResult[] {
    const checks: CheckResult[] = [];
    const paramInjections: Array<{
      tool: string;
      param: string;
      path: string;
      category: string;
      matched: string;
    }> = [];

    for (const tool of tools) {
      if (!tool.inputSchema) continue;

      // Recursively collect all descriptions at any nesting depth
      const allDescriptions = collectAllDescriptions(tool.inputSchema);

      for (const descInfo of allDescriptions) {
        for (const { pattern, category } of INJECTION_PATTERNS) {
          const match = pattern.exec(descInfo.description);
          if (match) {
            paramInjections.push({
              tool: tool.name,
              param: descInfo.name,
              path: descInfo.path,
              category,
              matched: match[0],
            });
          }
        }
      }
    }

    if (paramInjections.length === 0) {
      checks.push({
        id: "SM-002",
        name: "Parameter description injection scan",
        status: CheckStatus.PASS,
        message: "No injection patterns found in parameter descriptions",
      });
    } else {
      const hasCritical = paramInjections.some((i) =>
        INJECTION_PATTERNS.find(
          (p) => p.category === i.category && p.severity === Severity.CRITICAL
        )
      );

      checks.push({
        id: "SM-002",
        name: "Parameter description injection scan",
        status: CheckStatus.FAIL,
        message: `${paramInjections.length} injection pattern(s) in parameter descriptions`,
        finding: {
          id: "SM-002",
          module: this.id,
          severity: hasCritical ? Severity.CRITICAL : Severity.HIGH,
          title: "Prompt injection in parameter descriptions",
          description:
            "Injection patterns were detected in tool parameter descriptions. " +
            "Parameter descriptions are often included in AI agent prompts and " +
            "can be used to inject instructions that modify agent behavior.",
          evidence: {
            injections: paramInjections.map((i) => ({
              tool: i.tool,
              param: i.param,
              category: i.category,
              matched: i.matched,
            })),
          },
          remediation:
            "Parameter descriptions should only describe the expected input format and semantics. " +
            "Remove any behavioral directives or manipulation patterns.",
          cweId: "CWE-94",
        },
      });
    }

    return checks;
  }

  private checkSuspiciousDefaults(tools: ToolInfo[]): CheckResult[] {
    const checks: CheckResult[] = [];
    const suspiciousDefaults: Array<{
      tool: string;
      param: string;
      path: string;
      defaultValue: unknown;
      reason: string;
      benign?: boolean;
    }> = [];

    for (const tool of tools) {
      if (!tool.inputSchema) continue;

      // Recursively collect all default values at any nesting depth
      const allDefaults = collectAllDefaults(tool.inputSchema);

      for (const defInfo of allDefaults) {
        const defaultStr = String(defInfo.defaultValue);

        // Check for URLs in defaults (possible C2 beacon)
        if (/https?:\/\//.test(defaultStr)) {
          const isBenignUrl = /https?:\/\/(www\.)?(github\.com|example\.com|localhost|127\.0\.0\.1|raw\.githubusercontent\.com|cdn\.jsdelivr\.net|unpkg\.com)/i.test(defaultStr);
          suspiciousDefaults.push({
            tool: tool.name,
            param: defInfo.name,
            path: defInfo.path,
            defaultValue: defInfo.defaultValue,
            reason: isBenignUrl
              ? "URL in default value — points to well-known domain, low risk"
              : "URL in default value — possible C2 beacon or data exfiltration endpoint",
            benign: isBenignUrl,
          });
        }

        // Check for shell commands in defaults
        if (/[;&|`$()]/.test(defaultStr) && defaultStr.length > 5) {
          suspiciousDefaults.push({
            tool: tool.name,
            param: defInfo.name,
            path: defInfo.path,
            defaultValue: defInfo.defaultValue,
            reason: "Shell metacharacters in default value — possible command injection",
          });
        }

        // Check for encoded payloads
        if (/^[A-Za-z0-9+/]{20,}={0,2}$/.test(defaultStr)) {
          suspiciousDefaults.push({
            tool: tool.name,
            param: defInfo.name,
            path: defInfo.path,
            defaultValue: defInfo.defaultValue,
            reason: "Base64-encoded default value — possible obfuscated payload",
          });
        }
      }
    }

    if (suspiciousDefaults.length === 0) {
      checks.push({
        id: "SM-003",
        name: "Suspicious default values",
        status: CheckStatus.PASS,
        message: "No suspicious default values detected",
      });
    } else {
      checks.push({
        id: "SM-003",
        name: "Suspicious default values",
        status: CheckStatus.FAIL,
        message: `${suspiciousDefaults.length} suspicious default value(s) found`,
        finding: {
          id: "SM-003",
          module: this.id,
          severity: suspiciousDefaults.every((d) => (d as any).benign) ? Severity.LOW : Severity.HIGH,
          title: "Suspicious default values in tool schemas",
          description:
            "Tool parameters have default values that contain URLs, shell metacharacters, " +
            "or encoded payloads. These could be used to inject malicious behavior when " +
            "an AI agent calls a tool without explicitly providing all parameters.",
          evidence: { suspiciousDefaults },
          remediation:
            "Review all default values in tool schemas. Default values should be simple, " +
            "safe strings that don't contain URLs, shell commands, or encoded data. " +
            "Remove or replace suspicious defaults.",
          cweId: "CWE-1188",
        },
      });
    }

    return checks;
  }

  private checkSuspiciousSchemas(tools: ToolInfo[]): CheckResult[] {
    const checks: CheckResult[] = [];

    for (const tool of tools) {
      const schema = tool.inputSchema as Record<string, unknown>;
      if (!schema) continue;

      // ── Shallow check: excessive optional params at top level ──
      for (const schemaCheck of SUSPICIOUS_SCHEMA_PATTERNS) {
        if (schemaCheck.id === "excessive-optional-params" && schemaCheck.check(schema)) {
          checks.push({
            id: `SM-004-${tool.name}-${schemaCheck.id}`,
            name: `Schema structure: ${tool.name}`,
            status: CheckStatus.WARN,
            message: schemaCheck.description,
            finding: {
              id: `SM-004-${tool.name}-${schemaCheck.id}`,
              module: this.id,
              severity: schemaCheck.severity,
              title: `Suspicious schema structure in "${tool.name}": ${schemaCheck.id}`,
              description: `${schemaCheck.description}. This structural pattern in the tool's input schema ` +
                "may allow unexpected data to be passed to the tool.",
              evidence: { toolName: tool.name, checkId: schemaCheck.id },
              remediation:
                "Tighten the tool's input schema: require necessary fields, constrain nested objects " +
                "with explicit properties, add maxItems to arrays, and set additionalProperties to false.",
              toolName: tool.name,
              cweId: "CWE-20",
            },
          });
        }
      }

      // ── Recursive check: unconstrained nested objects at any depth ──
      const unconstrainedObjects = findUnconstrainedObjects(schema);
      if (unconstrainedObjects.length > 0) {
        const nestedCount = unconstrainedObjects.filter((o) => o.depth > 1).length;
        checks.push({
          id: `SM-004-${tool.name}-unconstrained-nested-objects`,
          name: `Schema structure: ${tool.name}`,
          status: CheckStatus.WARN,
          message: `${unconstrainedObjects.length} unconstrained nested object(s)${nestedCount > 0 ? ` (${nestedCount} deeply nested)` : ""}`,
          finding: {
            id: `SM-004-${tool.name}-unconstrained-nested-objects`,
            module: this.id,
            severity: Severity.MEDIUM,
            title: `Unconstrained nested objects in "${tool.name}"`,
            description: `Tool accepts ${unconstrainedObjects.length} object parameter(s) without explicit property definitions ` +
              `or additionalProperties: false. Arbitrary data injection is possible.` +
              (nestedCount > 0 ? ` ${nestedCount} found in deeply nested structures.` : ""),
            evidence: {
              toolName: tool.name,
              locations: unconstrainedObjects.map((o) => ({ name: o.name, path: o.path, depth: o.depth })),
            },
            remediation:
              "Define explicit properties for all nested objects and set additionalProperties to false. " +
              "Apply constraints at every nesting level.",
            toolName: tool.name,
            cweId: "CWE-20",
          },
        });
      }

      // ── Recursive check: unconstrained arrays at any depth ──
      const unconstrainedArrays = findUnconstrainedArrays(schema);
      if (unconstrainedArrays.length > 0) {
        checks.push({
          id: `SM-004-${tool.name}-unconstrained-arrays`,
          name: `Schema structure: ${tool.name}`,
          status: CheckStatus.WARN,
          message: `${unconstrainedArrays.length} unconstrained array(s)`,
          finding: {
            id: `SM-004-${tool.name}-unconstrained-arrays`,
            module: this.id,
            severity: Severity.LOW,
            title: `Unconstrained arrays in "${tool.name}"`,
            description: `Tool accepts ${unconstrainedArrays.length} array parameter(s) without item type constraints ` +
              `or size limits.`,
            evidence: {
              toolName: tool.name,
              locations: unconstrainedArrays.map((a) => ({ name: a.name, path: a.path, depth: a.depth })),
            },
            remediation:
              "Add 'items' schema to define expected array element types and 'maxItems' to limit size.",
            toolName: tool.name,
            cweId: "CWE-20",
          },
        });
      }
    }

    if (checks.length === 0 && tools.length > 0) {
      checks.push({
        id: "SM-004",
        name: "Schema structure analysis",
        status: CheckStatus.PASS,
        message: "No suspicious schema structures detected",
      });
    }

    return checks;
  }

  private checkDescriptionLengthAnomalies(tools: ToolInfo[]): CheckResult {
    if (tools.length === 0) {
      return {
        id: "SM-005",
        name: "Description length anomaly",
        status: CheckStatus.PASS,
        message: "No tools to check",
      };
    }

    const descriptions = tools
      .filter((t) => t.description)
      .map((t) => ({ name: t.name, length: t.description!.length }));

    if (descriptions.length === 0) {
      return {
        id: "SM-005",
        name: "Description length anomaly",
        status: CheckStatus.PASS,
        message: "No descriptions to analyze",
      };
    }

    const avgLength =
      descriptions.reduce((sum, d) => sum + d.length, 0) / descriptions.length;

    // Flag tools with descriptions >3x the average or >500 chars
    const anomalies = descriptions.filter(
      (d) => d.length > Math.max(avgLength * 3, 500)
    );

    if (anomalies.length === 0) {
      return {
        id: "SM-005",
        name: "Description length anomaly",
        status: CheckStatus.PASS,
        message: `Average description length: ${Math.round(avgLength)} chars`,
      };
    }

    return {
      id: "SM-005",
      name: "Description length anomaly",
      status: CheckStatus.WARN,
      message: `${anomalies.length} tool(s) have abnormally long descriptions`,
      finding: {
        id: "SM-005",
        module: this.id,
        severity: Severity.MEDIUM,
        title: "Abnormally long tool descriptions",
        description:
          `${anomalies.length} tool(s) have descriptions significantly longer than average ` +
          `(avg: ${Math.round(avgLength)} chars). Unusually long descriptions may contain ` +
          "hidden injection payloads, obfuscated instructions, or excessive content " +
          "designed to push other instructions out of context window.",
        evidence: {
          averageLength: Math.round(avgLength),
          anomalies: anomalies.map((a) => ({
            tool: a.name,
            length: a.length,
          })),
        },
        remediation:
          "Review long tool descriptions for hidden instructions. Keep descriptions concise " +
          "and focused on the tool's purpose. Consider length limits for tool descriptions.",
        cweId: "CWE-94",
      },
    };
  }
}
