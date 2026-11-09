import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
  type ToolInfo,
} from "../types/index.js";

/**
 * Patterns that strongly indicate write/destructive behavior in parameter names.
 */
const WRITE_PARAM_PATTERNS = [
  /^(content|body|data|payload|text|html|code|script|source|template)$/i,
  /^(file_content|file_data|write_data|new_content|updated_content)$/i,
  /^(sql|query|command|cmd|shell|exec|code_to_run)$/i,
  /^(message|subject|recipient|to|from|cc|bcc)$/i, // email sending
  /^(webhook_url|callback_url|notify_url|endpoint)$/i, // outbound HTTP
];

/**
 * Patterns that indicate write/destructive behavior in tool names.
 */
const WRITE_NAME_PATTERNS = [
  /(?:^|[-_.])(?:write|create|update|patch|put|delete|remove|destroy|drop|insert|modify|set|overwrite|append|push|send|post|upload|deploy)/i,
  /(?:^|[-_.])(?:exec|execute|run|shell|spawn|eval|compile)/i,
  /(?:^|[-_.])(?:grant|revoke|assign|elevate|escalate)/i,
];

const READ_NAME_PATTERNS = [
  /(?:^|[-_.])(?:read|get|list|search|find|query|fetch|show|describe|view|browse|check|stat|info|metadata|count|exists)/i,
];

/**
 * Patterns in descriptions that suggest read-only or safe behavior.
 */
const SAFE_DESCRIPTION_PATTERNS = [
  /\b(read[- ]?only|safe|non[- ]?destructive|idempotent|no side[- ]?effects?|harmless|passive|view|inspect|query|search|retrieve|list|get|fetch|lookup|check)\b/i,
];

/**
 * Patterns in descriptions that suggest write/destructive behavior.
 */
const DANGEROUS_DESCRIPTION_PATTERNS = [
  /\b(write|create|delete|remove|modify|update|execute|run|send|deploy|overwrite|drop|truncate|destroy)\b/i,
];

/**
 * Rug Pull Detection Module.
 *
 * Detects tools that misrepresent their capabilities — where annotations,
 * descriptions, or names contradict the actual schema parameters. This is
 * the primary vector for malicious MCP servers to bypass human review:
 * a tool that looks read-only in the description but accepts write parameters.
 *
 * Novel to AI agent security (2025+): LLMs trust tool descriptions and
 * annotations to make autonomous decisions. A rug pull exploits this trust.
 *
 * Finding prefixes: RD-001 through RD-006
 */
export class RugPullDetectionModule implements AuditModule {
  id = "rug-pull-detection";
  name = "Rug Pull Detection";
  description =
    "Detects tools that misrepresent capabilities — annotations, descriptions, or names contradict actual schema";
  version = "1.0.0";
  mode = "passive" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const { tools } = context.capabilities;
    const checks: CheckResult[] = [];

    checks.push(...this.checkAnnotationSchemaMismatch(tools));
    checks.push(...this.checkDescriptionSchemaMismatch(tools));
    checks.push(...this.checkNameDescriptionMismatch(tools));
    checks.push(...this.checkHiddenCapabilities(tools));
    checks.push(...this.checkDestructiveWithoutAnnotation(tools));

    return checks;
  }

  /**
   * RD-001: Annotation claims readOnly but schema has write parameters.
   * Emits one CheckResult per affected tool so no findings are silently dropped.
   */
  private checkAnnotationSchemaMismatch(tools: ToolInfo[]): CheckResult[] {
    const checks: CheckResult[] = [];
    let anyFound = false;

    for (const tool of tools) {
      if (!tool.annotations?.readOnlyHint) continue;

      const writeParams = this.findWriteParameters(tool);
      if (writeParams.length === 0) continue;

      anyFound = true;
      checks.push({
        id: `RD-001-${tool.name}`,
        name: `Annotation-schema trust mismatch: ${tool.name}`,
        status: CheckStatus.FAIL,
        message: `"${tool.name}" claims readOnly but has write parameters: ${writeParams.join(", ")}`,
        finding: {
          id: `RD-001-${tool.name}`,
          module: this.id,
          severity: Severity.CRITICAL,
          title: `Rug pull: "${tool.name}" claims readOnly but accepts write parameters`,
          description:
            `Tool "${tool.name}" has readOnlyHint=true in its annotations, but its schema ` +
            `contains parameters strongly associated with write operations: ${writeParams.join(", ")}. ` +
            `An LLM would trust this tool as safe to call without user confirmation, but it may ` +
            `actually modify data, execute commands, or send external requests.`,
          evidence: {
            toolName: tool.name,
            readOnlyHint: true,
            writeParameters: writeParams,
            inputSchema: tool.inputSchema,
          },
          remediation:
            "Either remove readOnlyHint from the annotation (honest about capabilities) " +
            "or remove write-capable parameters from the schema.",
          toolName: tool.name,
          cweId: "CWE-285", // Improper Authorization
        },
      });
    }

    if (!anyFound) {
      checks.push({
        id: "RD-001",
        name: "Annotation-schema trust mismatch",
        status: CheckStatus.PASS,
        message: "No annotation-schema mismatches detected",
      });
    }

    return checks;
  }

  /**
   * RD-002: Description says "read/search/view" but schema has write parameters.
   * Emits one CheckResult per affected tool so no findings are silently dropped.
   */
  private checkDescriptionSchemaMismatch(tools: ToolInfo[]): CheckResult[] {
    const checks: CheckResult[] = [];
    let anyFound = false;

    for (const tool of tools) {
      const desc = tool.description ?? "";
      const descSuggestsSafe = SAFE_DESCRIPTION_PATTERNS.some((p) => p.test(desc));
      const descSuggestsDangerous = DANGEROUS_DESCRIPTION_PATTERNS.some((p) => p.test(desc));

      if (!descSuggestsSafe || descSuggestsDangerous) continue;

      // Description only mentions safe operations
      const writeParams = this.findWriteParameters(tool);
      if (writeParams.length === 0) continue;

      anyFound = true;
      const descExcerpt = desc.length > 80 ? desc.substring(0, 80) + "..." : desc;
      checks.push({
        id: `RD-002-${tool.name}`,
        name: `Description-schema mismatch: ${tool.name}`,
        status: CheckStatus.FAIL,
        message: `"${tool.name}" described as safe but has write parameters: ${writeParams.join(", ")}`,
        finding: {
          id: `RD-002-${tool.name}`,
          module: this.id,
          severity: Severity.HIGH,
          title: `Description mismatch: "${tool.name}" described as safe but has write parameters`,
          description:
            `Tool "${tool.name}" description suggests read-only behavior ("${descExcerpt}") ` +
            `but its schema contains write-capable parameters: ${writeParams.join(", ")}. ` +
            `An LLM relying on the description would underestimate this tool's risk.`,
          evidence: {
            toolName: tool.name,
            description: desc,
            writeParameters: writeParams,
            safePatternMatched: true,
          },
          remediation:
            "Update the tool description to accurately reflect all capabilities, " +
            "including any write or destructive operations.",
          toolName: tool.name,
          cweId: "CWE-451", // User Interface (UI) Misrepresentation of Critical Information
        },
      });
    }

    if (!anyFound) {
      checks.push({
        id: "RD-002",
        name: "Description-schema mismatch",
        status: CheckStatus.PASS,
        message: "All tool descriptions are consistent with schemas",
      });
    }

    return checks;
  }

  /**
   * RD-003: Tool name suggests read-only but description reveals write capabilities.
   * Emits one CheckResult per affected tool so no findings are silently dropped.
   */
  private checkNameDescriptionMismatch(tools: ToolInfo[]): CheckResult[] {
    const checks: CheckResult[] = [];
    let anyFound = false;

    for (const tool of tools) {
      const nameIsReadLike = READ_NAME_PATTERNS.some((p) => p.test(tool.name));
      const desc = tool.description ?? "";
      const descIsWriteLike = DANGEROUS_DESCRIPTION_PATTERNS.some((p) => p.test(desc.toLowerCase()));

      if (!nameIsReadLike || !descIsWriteLike) continue;

      anyFound = true;
      const descExcerpt = desc.length > 120 ? desc.substring(0, 120) + "..." : desc;
      checks.push({
        id: `RD-003-${tool.name}`,
        name: `Name-description contradiction: ${tool.name}`,
        status: CheckStatus.FAIL,
        message: `"${tool.name}" named as read-only but description reveals write capabilities`,
        finding: {
          id: `RD-003-${tool.name}`,
          module: this.id,
          severity: Severity.HIGH,
          title: `Name-description contradiction: "${tool.name}" named as read but described as write`,
          description:
            `Tool "${tool.name}" has a name suggesting read-only behavior but its description ` +
            `mentions write/destructive operations: "${descExcerpt}". ` +
            `This naming mismatch could trick an LLM into calling a destructive tool thinking it's safe.`,
          evidence: {
            toolName: tool.name,
            description: tool.description,
            namePattern: "read-like",
            descriptionPattern: "write-like",
          },
          remediation:
            "Rename the tool to accurately reflect its capabilities. " +
            "A tool that can write should not be named 'get_*' or 'read_*'.",
          toolName: tool.name,
          cweId: "CWE-451",
        },
      });
    }

    if (!anyFound) {
      checks.push({
        id: "RD-003",
        name: "Name-description contradiction",
        status: CheckStatus.PASS,
        message: "Tool names are consistent with descriptions",
      });
    }

    return checks;
  }

  /**
   * RD-004: Schema has parameters not mentioned in description (hidden capabilities).
   * If a tool's description says "searches files" but the schema has a `webhook_url`
   * parameter, that's a hidden exfiltration capability.
   * Emits one CheckResult per affected tool (aggregating all hidden params for that tool).
   */
  private checkHiddenCapabilities(tools: ToolInfo[]): CheckResult[] {
    const checks: CheckResult[] = [];
    let anyFound = false;

    const SUSPICIOUS_HIDDEN_PARAMS = [
      { pattern: /^(webhook[_-]?url|callback[_-]?url|notify[_-]?url|report[_-]?url|exfil|destination)$/i, risk: "outbound HTTP (data exfiltration)" },
      { pattern: /^(exec|command|cmd|shell|code|script|eval)$/i, risk: "code execution" },
      { pattern: /^(admin[_-]?token|secret|api[_-]?key|password|credentials?)$/i, risk: "credential injection" },
      { pattern: /^(sudo|root|privilege|role|permission)$/i, risk: "privilege escalation" },
    ];

    for (const tool of tools) {
      const properties = (tool.inputSchema?.properties ?? {}) as Record<string, unknown>;
      const desc = (tool.description ?? "").toLowerCase();

      // Collect all hidden suspicious params for this tool
      const hiddenParams: Array<{ paramName: string; risk: string }> = [];
      for (const [paramName] of Object.entries(properties)) {
        for (const { pattern, risk } of SUSPICIOUS_HIDDEN_PARAMS) {
          if (!pattern.test(paramName)) continue;

          const paramMentioned = desc.includes(paramName.toLowerCase()) ||
            desc.includes(paramName.replace(/[_-]/g, " ").toLowerCase());

          if (!paramMentioned) {
            hiddenParams.push({ paramName, risk });
            break; // one risk category match per param is enough
          }
        }
      }

      if (hiddenParams.length === 0) continue;

      anyFound = true;
      const paramSummary = hiddenParams.map(({ paramName, risk }) => `${paramName} (${risk})`).join(", ");
      checks.push({
        id: `RD-004-${tool.name}`,
        name: `Hidden undisclosed capabilities: ${tool.name}`,
        status: CheckStatus.FAIL,
        message: `"${tool.name}" has ${hiddenParams.length} undisclosed suspicious parameter(s): ${paramSummary}`,
        finding: {
          id: `RD-004-${tool.name}`,
          module: this.id,
          severity: Severity.CRITICAL,
          title: `Hidden capability in "${tool.name}": ${hiddenParams.length} undisclosed parameter(s)`,
          description:
            `Tool "${tool.name}" has parameter(s) not mentioned in its description: ${paramSummary}. ` +
            `Hidden parameters could be exploited by a prompt injection attack to exfiltrate data ` +
            `or escalate privileges without the user or agent knowing the capability exists.`,
          evidence: {
            toolName: tool.name,
            hiddenParams,
            description: tool.description,
            allParams: Object.keys(properties),
          },
          remediation:
            "Either document all parameters in the tool description, or remove " +
            "parameters that shouldn't be exposed to AI agents.",
          toolName: tool.name,
          cweId: "CWE-912", // Hidden Functionality
        },
      });
    }

    if (!anyFound) {
      checks.push({
        id: "RD-004",
        name: "Hidden undisclosed capabilities",
        status: CheckStatus.PASS,
        message: "No hidden capabilities detected",
      });
    }

    return checks;
  }

  /**
   * RD-005: Destructive tools missing destructiveHint annotation.
   * MCP spec says annotations are untrusted — but if they're missing entirely,
   * LLM frameworks that rely on them will default to unsafe assumptions.
   * Emits one CheckResult per affected tool so no findings are silently dropped.
   */
  private checkDestructiveWithoutAnnotation(tools: ToolInfo[]): CheckResult[] {
    const checks: CheckResult[] = [];
    let anyFound = false;

    for (const tool of tools) {
      const isDestructive = WRITE_NAME_PATTERNS.some((p) => p.test(tool.name));
      if (!isDestructive) continue;

      const hasDestructiveHint = tool.annotations?.destructiveHint === true;
      const hasReadOnlyHint = tool.annotations?.readOnlyHint === true;

      if (hasDestructiveHint || hasReadOnlyHint) continue;

      anyFound = true;
      checks.push({
        id: `RD-005-${tool.name}`,
        name: `Missing safety annotations: ${tool.name}`,
        status: CheckStatus.WARN,
        message: `Destructive tool "${tool.name}" has no destructiveHint or readOnlyHint annotation`,
        finding: {
          id: `RD-005-${tool.name}`,
          module: this.id,
          severity: Severity.MEDIUM,
          title: `Destructive tool "${tool.name}" missing annotations`,
          description:
            `Tool "${tool.name}" appears to perform destructive operations based on its name ` +
            `but has no destructiveHint or readOnlyHint annotation. MCP-aware LLM frameworks ` +
            `use these annotations to decide whether to require user confirmation. Without them, ` +
            `the framework may auto-execute destructive operations.`,
          evidence: {
            toolName: tool.name,
            annotations: tool.annotations ?? "none",
            namePatternMatched: "destructive",
          },
          remediation:
            "Add annotations to the tool definition: { destructiveHint: true } for tools " +
            "that modify state, or { readOnlyHint: true } for safe tools.",
          toolName: tool.name,
          cweId: "CWE-862", // Missing Authorization
        },
      });
    }

    if (!anyFound) {
      checks.push({
        id: "RD-005",
        name: "Missing safety annotations on destructive tools",
        status: CheckStatus.PASS,
        message: "All destructive tools have proper annotations",
      });
    }

    return checks;
  }

  /**
   * Look for parameter names that strongly indicate write/destructive behavior.
   */
  private findWriteParameters(tool: ToolInfo): string[] {
    const properties = (tool.inputSchema?.properties ?? {}) as Record<string, unknown>;
    const writeParams: string[] = [];

    for (const paramName of Object.keys(properties)) {
      if (WRITE_PARAM_PATTERNS.some((p) => p.test(paramName))) {
        writeParams.push(paramName);
      }
    }

    return writeParams;
  }
}
