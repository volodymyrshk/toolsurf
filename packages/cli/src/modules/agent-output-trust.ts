import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
  type ToolInfo,
  type Finding,
} from "../types/index.js";

/**
 * Agent Output Trust Propagation Detection Module.
 *
 * Detects patterns where one agent's tool output feeds another agent's
 * decisions without explicit validation — creating implicit trust chains
 * that attackers can exploit via prompt injection or data manipulation.
 *
 * Attack surface (2025–2026):
 * Multi-agent architectures are increasingly common. When agent A calls
 * tool_fetch and passes the result to agent B's tool_process without
 * sanitisation, a malicious server response can inject instructions into
 * agent B's context. This is "second-order" prompt injection propagation.
 *
 * Detection logic:
 * 1. AOT-001: Relay/forwarding pattern in tool descriptions
 *    - Descriptions mentioning trusted_by, relay, forward, pass to, send to agent
 * 2. AOT-002: Schema-matched output→input trust chain
 *    - Tool A's output schema matches Tool B's input schema (same field names + types)
 *    - Indicates unvalidated data passing between tools
 * 3. AOT-003: Trust escalation via output forwarding
 *    - A tool explicitly describes forwarding output to another component that
 *      has elevated privileges (db write, file write, external API call)
 *
 * Finding prefixes: AOT-001 through AOT-003
 */
export class AgentOutputTrustModule implements AuditModule {
  id = "agent-output-trust";
  name = "Agent Output Trust Propagation";
  description =
    "Detects implicit trust chains where tool output feeds another tool's input without validation";
  version = "1.0.0";
  mode = "passive" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const { tools } = context.capabilities;
    const checks: CheckResult[] = [];

    checks.push(this.checkRelayPatterns(tools));
    checks.push(this.checkOutputInputSchemaChains(tools));
    checks.push(this.checkTrustEscalation(tools));

    return checks;
  }

  /**
   * AOT-001: Tool descriptions containing relay/forwarding language.
   *
   * Tools that explicitly describe passing output to other agents, services,
   * or downstream consumers create implicit trust propagation channels.
   */
  private checkRelayPatterns(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];

    const RELAY_PATTERNS = [
      { pattern: /\btrusted[_-]?by\b/i, label: "trusted_by relationship" },
      { pattern: /\brelay(?:s|ed|ing)?\b.*\b(?:to|output|result|response)\b/i, label: "relay pattern" },
      { pattern: /\bforward(?:s|ed|ing)?\b.*\b(?:to|output|result|message|data)\b/i, label: "forwarding pattern" },
      { pattern: /\bpass(?:es|ed|ing)?\b.*\b(?:to\s+(?:another|the\s+next)\s+(?:agent|tool|model|llm))\b/i, label: "inter-agent pass" },
      { pattern: /\bsend(?:s|ing)?\b.*\b(?:to\s+(?:another|the\s+next)\s+(?:agent|tool|model|llm))\b/i, label: "send to agent" },
      { pattern: /\bdownstream\s+(?:agent|tool|model|consumer)\b/i, label: "downstream agent reference" },
      { pattern: /\b(?:pipes?|chains?)\s+(?:output|result|response)\b/i, label: "output chaining" },
      { pattern: /(?:output|result)\s+is\s+(?:passed?|fed|sent)\s+(?:to|into)\b/i, label: "output injection point" },
    ];

    for (const tool of tools) {
      const desc = tool.description ?? "";
      if (!desc || desc.length < 20) continue;

      for (const { pattern, label } of RELAY_PATTERNS) {
        if (!pattern.test(desc)) continue;

        const matchedText = desc.match(pattern)?.[0];
        findings.push({
          id: `AOT-001-${tool.name}`,
          module: this.id,
          severity: Severity.HIGH,
          title: `Output relay pattern: "${tool.name}" — ${label}`,
          description:
            `Tool "${tool.name}" describes forwarding its output to another component ` +
            `("${matchedText}"). This creates an implicit trust propagation channel: ` +
            `a malicious or compromised server response injected into this tool's output ` +
            `will be trusted and processed by the downstream consumer without re-validation. ` +
            `In multi-agent architectures, this enables second-order prompt injection — ` +
            `an attacker controls the data source that this tool reads, and crafts a payload ` +
            `that persists through the relay and executes in the receiving agent's context.`,
          evidence: {
            toolName: tool.name,
            relayPattern: label,
            matchedText,
            descriptionExcerpt: desc.substring(0, 400),
          },
          remediation:
            "Treat all tool outputs as untrusted data. Before forwarding to another agent or tool, " +
            "validate and sanitise the output: strip unexpected fields, enforce schema constraints, " +
            "and check for prompt-injection patterns (instructions, role-play markers, system: prefixes). " +
            "Use explicit trust boundaries between agents.",
          toolName: tool.name,
          cweId: "CWE-346", // Origin Validation Error
          confidence: 0.75,
        });
        break;
      }
    }

    return {
      id: "AOT-001",
      name: "Output relay / forwarding patterns",
      status: findings.length > 0 ? CheckStatus.WARN : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} tool(s) describe output relay or forwarding behaviour`
        : "No output relay patterns detected",
      finding: findings[0],
    };
  }

  /**
   * AOT-002: Schema-matched output→input trust chain.
   *
   * When tool A's output schema structurally matches tool B's input schema
   * (same field names + compatible types), there is likely an undocumented
   * data pipeline between them. If A's output contains attacker-controlled
   * data, it flows directly into B's processing without validation.
   */
  private checkOutputInputSchemaChains(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];

    for (let i = 0; i < tools.length; i++) {
      const toolA = tools[i];
      const outputSchemaA = (toolA as ToolInfo & { outputSchema?: Record<string, unknown> }).outputSchema;
      if (!outputSchemaA) continue;

      const outputFieldsA = this.extractFieldNames(outputSchemaA);
      if (outputFieldsA.size < 2) continue; // need at least 2 fields for meaningful match

      for (let j = 0; j < tools.length; j++) {
        if (i === j) continue;
        const toolB = tools[j];
        const inputSchemaB = toolB.inputSchema;
        if (!inputSchemaB) continue;

        const inputFieldsB = this.extractFieldNames(inputSchemaB);
        if (inputFieldsB.size < 2) continue;

        const overlap = [...outputFieldsA].filter((f) => inputFieldsB.has(f));
        const similarityRatio = overlap.length / Math.max(outputFieldsA.size, inputFieldsB.size);

        if (similarityRatio >= 0.7 && overlap.length >= 2) {
          findings.push({
            id: `AOT-002-${toolA.name}-${toolB.name}`,
            module: this.id,
            severity: Severity.MEDIUM,
            title: `Implicit trust chain: "${toolA.name}" output → "${toolB.name}" input (${Math.round(similarityRatio * 100)}% schema overlap)`,
            description:
              `The output schema of "${toolA.name}" has ${Math.round(similarityRatio * 100)}% field overlap ` +
              `with the input schema of "${toolB.name}" (shared fields: ${overlap.slice(0, 5).join(", ")}` +
              `${overlap.length > 5 ? `, +${overlap.length - 5} more` : ""}). ` +
              `This structural similarity strongly suggests an undocumented data pipeline ` +
              `where "${toolA.name}"'s output feeds "${toolB.name}"'s input. ` +
              `If "${toolA.name}"'s data source is attacker-influenced, crafted field values ` +
              `will be processed by "${toolB.name}" as trusted input — a schema-level trust ` +
              `propagation vulnerability.`,
            evidence: {
              sourceToolName: toolA.name,
              sinkToolName: toolB.name,
              overlappingFields: overlap,
              similarityRatio: Math.round(similarityRatio * 100) + "%",
              sourceOutputFields: [...outputFieldsA],
              sinkInputFields: [...inputFieldsB],
            },
            remediation:
              "Document the data flow between these tools explicitly. " +
              "Add an explicit validation step between the tools that sanitises all fields. " +
              "Use different field names if the tools are not intentionally chained. " +
              "If chaining is intentional, add a schema validation step that rejects unexpected values.",
            toolName: `${toolA.name} → ${toolB.name}`,
            cweId: "CWE-20", // Improper Input Validation
            confidence: Math.min(0.5 + similarityRatio * 0.4, 0.9),
          });
        }
      }
    }

    // Deduplicate symmetric pairs (A→B and B→A same overlap)
    const seen = new Set<string>();
    const deduped = findings.filter((f) => {
      const key = (f.evidence as Record<string, unknown>);
      const pairKey = [key["sourceToolName"], key["sinkToolName"]].sort().join("|");
      if (seen.has(pairKey)) return false;
      seen.add(pairKey);
      return true;
    });

    return {
      id: "AOT-002",
      name: "Schema-matched output→input trust chains",
      status: deduped.length > 0 ? CheckStatus.WARN : CheckStatus.PASS,
      message: deduped.length > 0
        ? `${deduped.length} tool pair(s) have high schema overlap suggesting implicit trust chains`
        : "No schema-matched trust chains detected",
      finding: deduped[0],
    };
  }

  /**
   * AOT-003: Trust escalation via output forwarding to privileged operations.
   *
   * A tool whose description indicates its output is forwarded to a privileged
   * downstream operation (DB write, file write, external API, shell command)
   * creates a trust escalation path.
   */
  private checkTrustEscalation(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];

    const ESCALATION_TARGETS = [
      { pattern: /\b(?:write|save|store|insert|update|delete)\b.*\b(?:database|db|sql|table|record)\b/i, label: "database write" },
      { pattern: /\b(?:write|save|create|overwrite)\b.*\b(?:file|disk|filesystem|path)\b/i, label: "file write" },
      { pattern: /\b(?:execute|run|shell|bash|command|script)\b/i, label: "command execution" },
      { pattern: /\b(?:call|invoke|trigger)\b.*\b(?:external\s+api|webhook|endpoint|service)\b/i, label: "external API call" },
      { pattern: /\b(?:send|dispatch|emit)\b.*\b(?:email|notification|alert|webhook)\b/i, label: "notification/email dispatch" },
    ];

    const RELAY_CONTEXT = /(?:output|result|response|data)\s+(?:is\s+then\s+)?(?:passed?|fed|sent|forwarded?|relayed?)\s+(?:to|into)/i;

    for (const tool of tools) {
      const desc = tool.description ?? "";
      if (!desc || desc.length < 30) continue;

      if (!RELAY_CONTEXT.test(desc)) continue;

      for (const { pattern, label } of ESCALATION_TARGETS) {
        if (!pattern.test(desc)) continue;

        findings.push({
          id: `AOT-003-${tool.name}`,
          module: this.id,
          severity: Severity.CRITICAL,
          title: `Trust escalation: "${tool.name}" output forwarded to ${label}`,
          description:
            `Tool "${tool.name}" describes forwarding its output to a privileged operation: ` +
            `${label}. If the tool's output is derived from an attacker-controlled data source ` +
            `(e.g., web fetch, user input, database query), injected content in the output ` +
            `will be executed or persisted with elevated privileges. ` +
            `This is the classic "confused deputy" attack adapted for AI agent pipelines: ` +
            `the tool acts as a trusted intermediary that launders untrusted input into ` +
            `a privileged operation.`,
          evidence: {
            toolName: tool.name,
            escalationTarget: label,
            relayPattern: desc.match(RELAY_CONTEXT)?.[0],
            privilegedPattern: desc.match(pattern)?.[0],
            descriptionExcerpt: desc.substring(0, 400),
          },
          remediation:
            "Never directly pipe tool output into privileged operations without validation. " +
            "Add an explicit sanitisation layer between the data source and the privileged sink. " +
            "Use allowlist validation on all fields before writing to database/filesystem/shell. " +
            "Apply the principle of least privilege — separate the data-fetching tool from the " +
            "data-writing tool and require explicit user confirmation for privileged operations.",
          toolName: tool.name,
          cweId: "CWE-266", // Incorrect Privilege Assignment
          confidence: 0.8,
        });
        break;
      }
    }

    return {
      id: "AOT-003",
      name: "Trust escalation via output forwarding",
      status: findings.length > 0 ? CheckStatus.FAIL : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} tool(s) forward output to privileged operations without explicit validation`
        : "No trust escalation patterns detected",
      finding: findings[0],
    };
  }

  /**
   * Extract all field names from a JSON Schema object (top-level properties only).
   */
  private extractFieldNames(schema: Record<string, unknown>): Set<string> {
    const fields = new Set<string>();
    const props = schema.properties as Record<string, unknown> | undefined;
    if (props) {
      for (const key of Object.keys(props)) {
        fields.add(key.toLowerCase());
      }
    }
    return fields;
  }
}
