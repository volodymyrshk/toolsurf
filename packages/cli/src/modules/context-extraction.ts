import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
  type ToolInfo,
} from "../types/index.js";

/**
 * Token-based sink classification. Tool names are split on `_`, `-`, `/`,
 * `.`, and camelCase boundaries. `\b` does NOT split on `_` (it's a word
 * char), so the previous regex-based approach silently failed on names like
 * `write_file` or `post_to_slack`.
 *
 * `scope: "network"` sinks count toward the CE-003 exfil chain. `scope:
 * "local"` sinks do not — local writes by themselves are the *purpose* of a
 * filesystem MCP server, not exfiltration.
 */
type SinkScope = "network" | "local" | "ambiguous";
interface SinkPattern {
  keywords: ReadonlySet<string>;
  category: string;
  scope: SinkScope;
  description: string;
}

const EXFIL_SINK_PATTERNS: SinkPattern[] = [
  {
    keywords: new Set([
      "post", "upload", "submit", "publish", "dispatch", "forward", "relay",
      "transmit",
    ]),
    category: "outbound-data",
    scope: "network",
    description: "Tool sends data to external destinations",
  },
  {
    keywords: new Set([
      "email", "mail", "smtp", "notify", "alert", "slack", "webhook",
      "discord", "telegram", "sms", "pager",
    ]),
    category: "messaging",
    scope: "network",
    description: "Tool sends messages to external services",
  },
  {
    keywords: new Set(["send", "emit", "push"]),
    category: "outbound-data",
    // `send` / `push` are ambiguous — `send_email` is network, `push_branch`
    // is git. Resolved to "network" only if the schema also exposes a
    // URL/host/recipient parameter (see resolveSinkScope).
    scope: "ambiguous",
    description: "Tool sends or pushes data (scope ambiguous)",
  },
  {
    keywords: new Set([
      "log", "record", "track", "audit", "report", "telemetry", "analytics",
    ]),
    category: "logging",
    scope: "ambiguous",
    description: "Tool logs or records data (may be local or remote)",
  },
  {
    // Local writes — listed so the exfil-chain logic can skip them.
    // Match either the keyword on its own (`write`, `mkdir`) or with a `file`
    // / `directory` suffix in the next token via combinedTokens below.
    keywords: new Set([
      "writefile", "createfile", "createdirectory", "editfile", "movefile",
      "appendfile", "savetofile", "savetodisk", "mkdir", "touch",
    ]),
    category: "local-write",
    scope: "local",
    description: "Tool writes data to the local filesystem (not exfil unless paired with a read-back primitive)",
  },
  {
    // S3/GCS/blob storage — *is* network egress.
    keywords: new Set([
      "putobject", "uploadfile", "s3put", "gcsput", "blobput",
    ]),
    category: "object-store-write",
    scope: "network",
    description: "Tool uploads to object storage",
  },
];

/** Network-destination parameter names (used to upgrade ambiguous → network). */
const NETWORK_DESTINATION_PARAMS = new Set([
  "url", "uri", "endpoint", "webhook_url", "callback_url", "webhookurl",
  "callbackurl", "host", "hostname", "recipient", "to", "address", "email",
  "webhook",
]);

function tokenizeName(name: string): string[] {
  return name
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .split(/[_\-/.\s]+/)
    .filter(Boolean)
    .map((t) => t.toLowerCase());
}

/** Build a list of token candidates: each individual token plus the joined
 *  pair of every two consecutive tokens (so `write_file` → ["write", "file",
 *  "writefile"]). This lets us match multi-word keywords like `writefile`
 *  cleanly. */
function tokenCandidates(name: string): string[] {
  const tokens = tokenizeName(name);
  const candidates: string[] = [...tokens];
  for (let i = 0; i < tokens.length - 1; i++) {
    candidates.push(tokens[i] + tokens[i + 1]);
  }
  return candidates;
}

function nameMatchesPattern(name: string, pattern: SinkPattern): boolean {
  const candidates = tokenCandidates(name);
  return candidates.some((c) => pattern.keywords.has(c));
}

function hasNetworkDestinationParam(tool: ToolInfo): boolean {
  const properties = (tool.inputSchema as Record<string, unknown> | undefined)
    ?.properties as Record<string, unknown> | undefined;
  if (!properties) return false;
  return Object.keys(properties).some((p) => NETWORK_DESTINATION_PARAMS.has(p.toLowerCase()));
}

function resolveSinkScope(tool: ToolInfo, pattern: SinkPattern): SinkScope {
  if (pattern.scope !== "ambiguous") return pattern.scope;
  return hasNetworkDestinationParam(tool) ? "network" : "local";
}

/**
 * Patterns indicating a tool can access conversation context,
 * system prompts, or other sensitive AI agent state.
 */
const CONTEXT_ACCESS_PATTERNS = [
  {
    namePattern: /\b(context|conversation|history|chat|thread|memory)\b/i,
    category: "conversation-access",
    description: "Tool may access conversation history or context",
  },
  {
    namePattern: /\b(system[-_]?prompt|instruction|system[-_]?config)\b/i,
    category: "prompt-access",
    description: "Tool may access system prompts or agent instructions",
  },
  {
    namePattern: /\b(get[-_]?env|environment[-_]?var|read[-_]?secret|get[-_]?credential|get[-_]?token|read[-_]?key)\b/i,
    category: "credential-access",
    description: "Tool may access environment variables or credentials",
  },
];

/**
 * Parameter patterns that suggest data exfiltration capability.
 */
/**
 * Exfil-capable parameter patterns. Two tiers:
 *   - `unambiguous`: name alone is enough to flag (webhook_url, callback_url).
 *   - `ambiguous`: requires the host tool's *name* to also look like a network
 *     transmitter — `forward_data.destination` is exfil; `move_file.destination`
 *     is a local rename. See checkExfilParameters where this is resolved.
 */
const EXFIL_PARAM_PATTERNS = [
  { pattern: /^(webhook_url|callback_url|target_url|fetch_url|request_url|recipient_email|to_email|email_to|notify_url)$/i, risk: "destination-control" },
  { pattern: /^(destination|to|recipient|target|endpoint|dest|sink)$/i, risk: "destination-control-ambiguous" },
  { pattern: /^(body|content|message|payload|data|text|html)$/i, risk: "content-injection" },
  { pattern: /^(subject|title|header|metadata)$/i, risk: "metadata-injection" },
  { pattern: /^(attachment|file|upload)$/i, risk: "file-exfiltration" },
];

/**
 * Context Extraction Module.
 *
 * Identifies tools and tool combinations that could be used to:
 * 1. Extract conversation context or system prompts
 * 2. Exfiltrate data to external services
 * 3. Create covert channels via write + read tool chains
 *
 * This addresses the MCP attack vector where a malicious tool collects
 * sensitive context from the AI agent and sends it to an attacker.
 *
 * Key insight: The danger isn't a single tool — it's the COMBINATION
 * of a tool that can read context + a tool that can send data externally.
 */
export class ContextExtractionModule implements AuditModule {
  id = "context-extraction";
  name = "Context Extraction & Data Exfiltration";
  description =
    "Identifies tools that could exfiltrate conversation context, system prompts, or sensitive data";
  version = "1.0.0";
  mode = "passive" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const { tools } = context.capabilities;

    // ── Check 1: Identify outbound data sinks 
    checks.push(...this.identifyExfilSinks(tools));

    // ── Check 2: Identify context access tools 
    checks.push(...this.identifyContextAccess(tools));

    // ── Check 3: Cross-tool exfil chains 
    checks.push(this.detectExfilChains(tools));

    // ── Check 4: Exfil-capable parameters
    checks.push(...this.checkExfilParameters(tools));

    // ── Check 5: Prompt resource exposure
    checks.push(this.checkPromptExposure(context));

    return checks;
  }

  private identifyExfilSinks(tools: ToolInfo[]): CheckResult[] {
    const checks: CheckResult[] = [];
    const networkSinks: Array<{ tool: string; category: string; description: string }> = [];
    const localWrites: Array<{ tool: string; category: string; description: string }> = [];

    for (const tool of tools) {
      for (const pattern of EXFIL_SINK_PATTERNS) {
        if (!nameMatchesPattern(tool.name, pattern)) continue;
        const scope = resolveSinkScope(tool, pattern);
        const entry = { tool: tool.name, category: pattern.category, description: pattern.description };
        if (scope === "network") {
          networkSinks.push(entry);
        } else {
          localWrites.push(entry);
        }
        break;
      }
    }

    if (networkSinks.length === 0) {
      checks.push({
        id: "CE-001",
        name: "Outbound data sinks",
        status: CheckStatus.PASS,
        message:
          localWrites.length > 0
            ? `No network sinks detected (${localWrites.length} local-write tool(s) noted, not exfil-relevant in isolation)`
            : "No outbound data sink tools detected",
      });
    } else {
      const hasMessaging = networkSinks.some((s) => s.category === "messaging");
      const hasOutbound = networkSinks.some((s) => s.category === "outbound-data");

      checks.push({
        id: "CE-001",
        name: "Outbound data sinks",
        status: CheckStatus.WARN,
        message: `${networkSinks.length} tool(s) can send data externally: ${networkSinks.map((s) => s.tool).join(", ")}`,
        finding: {
          id: "CE-001",
          module: this.id,
          severity: hasMessaging || hasOutbound ? Severity.MEDIUM : Severity.LOW,
          title: "Tools capable of sending data to external destinations",
          description:
            `${networkSinks.length} tool(s) have names suggesting they can send data to network destinations. ` +
            "These tools could potentially be used by a manipulated AI agent to exfiltrate " +
            "conversation context, system prompts, or user data to an attacker-controlled endpoint.",
          evidence: { sinks: networkSinks, localWrites },
          remediation:
            "Restrict outbound tools to specific allowlisted destinations. " +
            "Implement content filtering to prevent sensitive data from being included in outbound payloads. " +
            "Require user confirmation for all data-sending operations.",
          cweId: "CWE-200",
        },
      });
    }

    return checks;
  }

  private identifyContextAccess(tools: ToolInfo[]): CheckResult[] {
    const checks: CheckResult[] = [];
    const accessTools: Array<{ tool: string; category: string; description: string }> = [];

    for (const tool of tools) {
      for (const { namePattern, category, description } of CONTEXT_ACCESS_PATTERNS) {
        if (namePattern.test(tool.name)) {
          accessTools.push({ tool: tool.name, category, description });
          break;
        }
        // Also check tool description for credential-access patterns
        if (category === "credential-access" && tool.description) {
          const desc = tool.description.toLowerCase();
          if (
            desc.includes("environment variable") ||
            desc.includes("secret") ||
            desc.includes("credential") ||
            desc.includes("api key")
          ) {
            accessTools.push({ tool: tool.name, category, description: "Tool description references credentials" });
            break;
          }
        }
      }
    }

    if (accessTools.length === 0) {
      checks.push({
        id: "CE-002",
        name: "Context access tools",
        status: CheckStatus.PASS,
        message: "No context-access tools detected",
      });
    } else {
      const hasCredentialAccess = accessTools.some(
        (t) => t.category === "credential-access"
      );
      const hasPromptAccess = accessTools.some(
        (t) => t.category === "prompt-access"
      );

      const severity = hasCredentialAccess
        ? Severity.HIGH
        : hasPromptAccess
          ? Severity.MEDIUM
          : Severity.LOW;

      checks.push({
        id: "CE-002",
        name: "Context access tools",
        status:
          severity === Severity.HIGH ? CheckStatus.FAIL : CheckStatus.WARN,
        message: `${accessTools.length} tool(s) may access sensitive context: ${accessTools.map((t) => t.tool).join(", ")}`,
        finding: {
          id: "CE-002",
          module: this.id,
          severity,
          title: "Tools that may access sensitive agent context",
          description:
            `${accessTools.length} tool(s) have names suggesting they can access conversation context, ` +
            "system prompts, environment variables, or credentials. These tools could be exploited " +
            "by a prompt injection attack to extract sensitive information from the AI agent's state.",
          evidence: { accessTools },
          remediation:
            "Minimize the context exposed to MCP tools. Never pass full system prompts or " +
            "conversation history to tool calls. Use scoped tokens instead of raw credentials. " +
            "Implement data loss prevention (DLP) checks on tool inputs and outputs.",
          cweId: hasCredentialAccess ? "CWE-522" : hasPromptAccess ? "CWE-200" : "CWE-200",
        },
      });
    }

    return checks;
  }

  /**
   * Detect cross-tool exfiltration chains:
   * A server with BOTH context-access tools AND outbound sinks
   * creates a complete exfiltration pipeline.
   */
  private detectExfilChains(tools: ToolInfo[]): CheckResult {
    const contextTools: string[] = [];
    const sinkTools: string[] = [];

    for (const tool of tools) {
      for (const { namePattern } of CONTEXT_ACCESS_PATTERNS) {
        if (namePattern.test(tool.name)) {
          contextTools.push(tool.name);
          break;
        }
      }
      for (const pattern of EXFIL_SINK_PATTERNS) {
        if (!nameMatchesPattern(tool.name, pattern)) continue;
        // Only network-scope sinks complete an exfil chain. A filesystem MCP
        // server with `write_file` + `read_file` does NOT constitute exfil —
        // both endpoints are inside the same sandbox.
        if (resolveSinkScope(tool, pattern) === "network") {
          sinkTools.push(tool.name);
        }
        break;
      }
    }

    if (contextTools.length === 0 || sinkTools.length === 0) {
      return {
        id: "CE-003",
        name: "Cross-tool exfiltration chains",
        status: CheckStatus.PASS,
        message: "No complete exfiltration chains detected",
      };
    }

    return {
      id: "CE-003",
      name: "Cross-tool exfiltration chains",
      status: CheckStatus.FAIL,
      message: `Exfiltration chain detected: ${contextTools.length} source(s) + ${sinkTools.length} sink(s)`,
      finding: {
        id: "CE-003",
        module: this.id,
        severity: Severity.HIGH,
        title: "Complete data exfiltration chain available",
        description:
          "The server exposes BOTH tools that access sensitive context AND tools that send data " +
          "externally. A prompt injection attack could chain these tools to: " +
          "(1) read conversation context or credentials, then " +
          "(2) send the extracted data to an attacker-controlled endpoint. " +
          `Sources: ${contextTools.join(", ")}. Sinks: ${sinkTools.join(", ")}.`,
        evidence: { contextTools, sinkTools },
        remediation:
          "Separate context-access tools and outbound tools into different server profiles. " +
          "Never expose both on the same MCP server. If both are required, implement " +
          "server-side data flow controls that prevent tool outputs from being passed as " +
          "inputs to outbound tools without user review.",
        cweId: "CWE-200",
      },
    };
  }

  private checkExfilParameters(tools: ToolInfo[]): CheckResult[] {
    const checks: CheckResult[] = [];
    const toolsWithExfilParams: Array<{
      tool: string;
      params: Array<{ name: string; risk: string }>;
    }> = [];

    for (const tool of tools) {
      const properties =
        (tool.inputSchema as Record<string, unknown>)?.properties as
        | Record<string, Record<string, unknown>>
        | undefined;

      if (!properties) continue;

      // Resolve ambiguous "destination"/"target"/"to" params: only count
      // them when the tool's *name* also looks like a network transmitter
      // (matches a network-scope sink pattern). Otherwise `move_file.
      // destination` and `git_create_branch.base_branch` are local.
      const toolLooksLikeNetworkSink = EXFIL_SINK_PATTERNS.some(
        (p) => p.scope === "network" && nameMatchesPattern(tool.name, p),
      );

      const dangerousParams: Array<{ name: string; risk: string }> = [];
      for (const paramName of Object.keys(properties)) {
        for (const { pattern, risk } of EXFIL_PARAM_PATTERNS) {
          if (pattern.test(paramName)) {
            // Drop ambiguous matches when the host tool isn't a network sink.
            if (risk === "destination-control-ambiguous" && !toolLooksLikeNetworkSink) {
              break;
            }
            // Normalize the risk label so downstream consumers see one value.
            const normalizedRisk = risk === "destination-control-ambiguous" ? "destination-control" : risk;
            dangerousParams.push({ name: paramName, risk: normalizedRisk });
            break;
          }
        }
      }

      if (dangerousParams.length > 0) {
        toolsWithExfilParams.push({ tool: tool.name, params: dangerousParams });
      }
    }

    if (toolsWithExfilParams.length === 0) {
      checks.push({
        id: "CE-004",
        name: "Exfiltration-capable parameters",
        status: CheckStatus.PASS,
        message: "No exfiltration-capable parameter patterns found",
      });
    } else {
      const hasDestination = toolsWithExfilParams.some((t) =>
        t.params.some((p) => p.risk === "destination-control")
      );

      checks.push({
        id: "CE-004",
        name: "Exfiltration-capable parameters",
        status: hasDestination ? CheckStatus.WARN : CheckStatus.PASS,
        message: `${toolsWithExfilParams.length} tool(s) have parameters suggesting data exfiltration capability`,
        finding: hasDestination
          ? {
            id: "CE-004",
            module: this.id,
            severity: Severity.MEDIUM,
            title: "Tools with user-controlled destination parameters",
            description:
              "Tools accept destination parameters (to, recipient, endpoint, webhook_url) that " +
              "allow AI agents to specify where data is sent. A prompt injection could redirect " +
              "sensitive data to attacker-controlled endpoints.",
            evidence: { toolsWithExfilParams },
            remediation:
              "Hardcode or allowlist permitted destinations. Never allow AI agents to " +
              "specify arbitrary URLs, email addresses, or endpoints for outbound data.",
            cweId: "CWE-201",
          }
          : undefined,
      });
    }

    return checks;
  }

  /**
   * Check if MCP prompts expose system-level instructions or templates
   * that could reveal internal architecture to an attacker.
   */
  private checkPromptExposure(context: ModuleContext): CheckResult {
    const { prompts } = context.capabilities;

    if (prompts.length === 0) {
      return {
        id: "CE-005",
        name: "Prompt exposure",
        status: CheckStatus.PASS,
        message: "No prompts exposed",
      };
    }

    // Check for prompts with suspicious names
    const sensitivePrompts = prompts.filter((p) =>
      /system|admin|internal|debug|config|secret|credential/i.test(p.name)
    );

    if (sensitivePrompts.length > 0) {
      return {
        id: "CE-005",
        name: "Prompt exposure",
        status: CheckStatus.WARN,
        message: `${sensitivePrompts.length} prompt(s) with sensitive-sounding names`,
        finding: {
          id: "CE-005",
          module: this.id,
          severity: Severity.MEDIUM,
          title: "Potentially sensitive prompts exposed",
          description:
            `${sensitivePrompts.length} MCP prompt(s) have names suggesting they contain ` +
            "system-level instructions, internal configuration, or debug information. " +
            "These prompts are accessible to any connected client and may reveal internal " +
            "architecture or security-sensitive information.",
          evidence: {
            prompts: sensitivePrompts.map((p) => ({
              name: p.name,
              description: p.description,
            })),
          },
          remediation:
            "Review all exposed prompts for sensitive information. Remove debug and admin " +
            "prompts from production server configurations. Use server-side access controls " +
            "to restrict prompt visibility.",
          cweId: "CWE-200",
        },
      };
    }

    return {
      id: "CE-005",
      name: "Prompt exposure",
      status: CheckStatus.PASS,
      message: `${prompts.length} prompt(s) exposed, none appear sensitive`,
    };
  }
}
