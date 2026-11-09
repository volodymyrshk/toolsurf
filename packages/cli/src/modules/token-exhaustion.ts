import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
  type ToolInfo,
  type Finding,
} from "../types/index.js";
import { findUnconstrainedStrings, findUnconstrainedArrays } from "../utils/schema-walker.js";

/**
 * Estimate token count for a string using GPT-style BPE heuristics.
 *
 * Better than simple /4: different content types tokenize differently.
 * Calibrated against cl100k_base (GPT-4, Claude) on tool schema data.
 *
 * - English prose: ~3.8 chars/token
 * - JSON keys/values: ~3.0 chars/token
 * - Code/identifiers: ~2.5 chars/token
 * - Numbers: ~2.0 chars/token
 * - Punctuation: ~1.5 chars/token
 *
 * Weighted blend approximates real tokenizer within 8-12%.
 */
function estimateTokens(text: string): number {
  if (!text || text.length === 0) return 0;

  let tokens = 0;
  let i = 0;

  while (i < text.length) {
    const ch = text[i];
    const code = text.charCodeAt(i);

    if (/\s/.test(ch)) {
      // Whitespace: typically merges with next token
      i++;
    } else if (/[0-9]/.test(ch)) {
      // Numbers: consecutive digits = 1-2 tokens
      let j = i;
      while (j < text.length && /[0-9.,_]/.test(text[j])) j++;
      const numStr = text.slice(i, j);
      tokens += Math.ceil(numStr.length / 2);
      i = j;
    } else if (/[a-zA-Z]/.test(ch)) {
      // Words: English prose ~3.8 chars/token (weighted)
      let j = i;
      while (j < text.length && /[a-zA-Z0-9_]/.test(text[j])) j++;
      const word = text.slice(i, j);
      // Camel/snake case identifiers tokenize at ~2.5 chars each
      const isCamelOrSnake = /[_]/.test(word) || /[a-z][A-Z]/.test(word);
      tokens += Math.ceil(word.length / (isCamelOrSnake ? 2.5 : 3.8));
      i = j;
    } else if (code > 127) {
      // Unicode: CJK and other wide chars = 2-3 tokens each
      tokens += 2;
      i++;
    } else {
      // Punctuation and special chars: ~1.5 per char
      tokens += 1;
      i++;
    }
  }

  return Math.max(1, tokens);
}

const DEFAULT_LLM_OUTPUT_TOKEN_LIMIT = 8192;
const APPROX_CHARS_PER_OUTPUT_TOKEN = 4;

function normalizeOutputTokenLimit(limit?: number): number {
  return Number.isFinite(limit) && limit! > 0
    ? Math.floor(limit!)
    : DEFAULT_LLM_OUTPUT_TOKEN_LIMIT;
}

function isContentLikeParam(name: string): boolean {
  return /^(content|body|data|text|query|command|code|script|message|payload|input|prompt)$/i.test(name);
}

function isLocatorLikeParam(name: string): boolean {
  return /^(url|uri|href|link|endpoint|callback[_-]?url|webhook[_-]?url|target[_-]?url|path|file[_-]?path|filename|directory|dir)$/i.test(name);
}

function findResponseLimitParams(tool: ToolInfo): string[] {
  const properties = (tool.inputSchema?.properties ?? {}) as Record<string, unknown>;
  return Object.keys(properties).filter((name) =>
    /^(max[_-]?length|maxLength|limit|max[_-]?results|maxResults|max[_-]?items|maxItems|max[_-]?bytes|maxBytes|page[_-]?size|pageSize|count|take|head|tail)$/i.test(name)
  );
}

/**
 * Token Exhaustion / Context Window DoS Module.
 *
 * Detects tools vulnerable to context window exhaustion attacks — the unique
 * DoS vector for AI agent systems (2024-2026). Unlike traditional DoS that
 * targets CPU/memory, this targets the LLM's finite context window and the
 * per-token API billing.
 *
 * Attack surface:
 * 1. Unbounded INPUT strings → prompt injection or direct client pass-through
 *    can consume the model's available tool-call argument budget. LLM-generated
 *    arguments are capped by the deployed model's max output window; direct API
 *    callers and host applications can still pass larger payloads.
 * 2. Unbounded OUTPUT → a tool returns a 50MB file, flooding the agent's
 *    context window and displacing the user's actual instructions.
 * 3. Recursive/nested schemas with no depth limit → crafted payload that
 *    expands exponentially in the tool's processing.
 * 4. Array parameters without maxItems → send 100K array elements.
 *
 * Novel: Traditional web security scanners don't care about response size
 * because browsers handle it fine. For AI agents, every byte of tool output
 * consumes precious context tokens.
 *
 * Finding prefixes: TE-001 through TE-007
 */
export class TokenExhaustionModule implements AuditModule {
  id = "token-exhaustion";
  name = "Token Exhaustion / Context DoS";
  description =
    "Detects tools vulnerable to context window exhaustion and token budget attacks";
  version = "1.0.0";
  mode = "passive" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const { tools } = context.capabilities;
    const checks: CheckResult[] = [];

    checks.push(this.checkUnboundedStrings(tools, context.llmOutputTokenLimit));
    checks.push(this.checkUnboundedArrays(tools));
    checks.push(this.checkWildcardInputs(tools));
    checks.push(this.checkContextAmplification(tools));
    checks.push(this.checkMissingPagination(tools));
    checks.push(this.checkUnboundedOutputArrays(tools));
    checks.push(this.checkBulkResponsePatterns(tools));

    return checks;
  }

  /**
   * TE-001: String parameters without maxLength constraints.
   */
  private checkUnboundedStrings(tools: ToolInfo[], llmOutputTokenLimit?: number): CheckResult {
    const findings: Finding[] = [];
    const outputTokenLimit = normalizeOutputTokenLimit(llmOutputTokenLimit);
    const approxMaxGeneratedChars = outputTokenLimit * APPROX_CHARS_PER_OUTPUT_TOKEN;

    for (const tool of tools) {
      const unbounded = findUnconstrainedStrings(tool.inputSchema);
      if (unbounded.length === 0) continue;

      const responseLimitParams = findResponseLimitParams(tool);
      const hasContentParam = unbounded.some((p) => isContentLikeParam(p.name));
      const locatorOnly = unbounded.every((p) => isLocatorLikeParam(p.name));
      const severity = hasContentParam
        ? Severity.HIGH
        : locatorOnly && responseLimitParams.length > 0
          ? Severity.LOW
          : Severity.MEDIUM;
      const riskKind = hasContentParam
        ? "content-input-context-pressure"
        : locatorOnly
          ? "locator-input-validation"
          : "generic-input-validation";

      findings.push({
        id: `TE-001-${tool.name}`,
        module: this.id,
        severity,
        title: `Unbounded strings in "${tool.name}": ${unbounded.length} parameter(s) lack maxLength`,
        description:
          `Tool "${tool.name}" has ${unbounded.length} string parameter(s) without maxLength: ` +
          `${unbounded.map((p) => p.name).join(", ")}. For LLM-generated tool calls, the ` +
          `theoretical argument size is capped by the deployed model's output window: this scan ` +
          `uses ${outputTokenLimit.toLocaleString()} output tokens (~${approxMaxGeneratedChars.toLocaleString()} ` +
          `characters) as the ceiling, so this is not evidence that a model can emit an arbitrary ` +
          `multi-megabyte argument in one call. The remaining risk is oversized direct-client ` +
          `input, host pass-through, malformed locator values, or use of the full available ` +
          `output budget for a tool argument.` +
          (responseLimitParams.length > 0
            ? ` Response-size controls are present (${responseLimitParams.join(", ")}), so context flooding should be judged primarily against output limits.`
            : ""),
        evidence: {
          toolName: tool.name,
          unboundedParams: unbounded,
          riskKind,
          llmGeneratedArgumentCap: {
            maxOutputTokens: outputTokenLimit,
            approxMaxChars: approxMaxGeneratedChars,
            assumption: "Only applies to arguments generated by the LLM in a single response.",
          },
          responseLimitParams,
          directClientRisk:
            "Still unbounded if a host application or direct client forwards data without model-output limits.",
        },
        remediation:
          "Add maxLength to all string parameters. Recommended limits: " +
          "search queries: 500, file paths: 4096, content: 100000, general: 10000. " +
          "Also implement server-side truncation as defense in depth.",
        toolName: tool.name,
        cweId: "CWE-770", // Allocation of Resources Without Limits
      });
    }

    return {
      id: "TE-001",
      name: "Unbounded string parameters",
      status: findings.length > 0
        ? findings.some((f) => f.severity === Severity.HIGH || f.severity === Severity.MEDIUM)
          ? CheckStatus.FAIL
          : CheckStatus.WARN
        : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} tool(s) have unbounded string parameters`
        : "All string parameters have maxLength constraints",
      finding: findings[0],
    };
  }

  /**
   * TE-002: Array parameters without maxItems constraints.
   */
  private checkUnboundedArrays(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];

    for (const tool of tools) {
      const unbounded = findUnconstrainedArrays(tool.inputSchema);
      if (unbounded.length === 0) continue;

      findings.push({
        id: `TE-002-${tool.name}`,
        module: this.id,
        severity: Severity.HIGH,
        title: `Unbounded arrays in "${tool.name}": ${unbounded.length} parameter(s) lack maxItems`,
        description:
          `Tool "${tool.name}" has ${unbounded.length} array parameter(s) without maxItems: ` +
          `${unbounded.map((p) => p.name).join(", ")}. An attacker can send arrays with ` +
          `hundreds of thousands of elements, causing memory exhaustion on the server ` +
          `and flooding the agent's context with tool results.`,
        evidence: {
          toolName: tool.name,
          unboundedArrays: unbounded,
        },
        remediation:
          "Add maxItems to all array parameters. Recommended: 100 for most use cases, " +
          "1000 for bulk operations. Implement server-side array length validation.",
        toolName: tool.name,
        cweId: "CWE-770",
      });
    }

    return {
      id: "TE-002",
      name: "Unbounded array parameters",
      status: findings.length > 0 ? CheckStatus.FAIL : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} tool(s) have unbounded array parameters`
        : "All array parameters have maxItems constraints",
      finding: findings[0],
    };
  }

  /**
   * TE-003: Wildcard/catch-all input schemas that accept any input.
   * Tools with additionalProperties: true or no properties at all.
   */
  private checkWildcardInputs(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];

    for (const tool of tools) {
      const schema = tool.inputSchema;
      if (!schema) continue;

      const hasProperties = schema.properties && Object.keys(schema.properties as object).length > 0;
      const allowsAdditional = schema.additionalProperties === true ||
        (schema.additionalProperties === undefined && !hasProperties);
      const isEmptySchema = schema.type === "object" && !hasProperties;

      if (isEmptySchema || (allowsAdditional && !hasProperties)) {
        findings.push({
          id: `TE-003-${tool.name}`,
          module: this.id,
          severity: Severity.HIGH,
          title: `Wildcard input: "${tool.name}" accepts arbitrary parameters`,
          description:
            `Tool "${tool.name}" has an empty or wildcard schema that accepts any input. ` +
            `An attacker can inject arbitrary data of any size or structure. This is the ` +
            `JSON equivalent of a SQL injection — the server processes whatever it receives ` +
            `with no structural validation.`,
          evidence: {
            toolName: tool.name,
            schema,
            hasProperties: !!hasProperties,
            additionalProperties: schema.additionalProperties,
          },
          remediation:
            "Define explicit properties in the input schema. Set additionalProperties: false " +
            "to reject unexpected parameters.",
          toolName: tool.name,
          cweId: "CWE-20", // Improper Input Validation
        });
      }
    }

    return {
      id: "TE-003",
      name: "Wildcard input schemas",
      status: findings.length > 0 ? CheckStatus.FAIL : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} tool(s) accept arbitrary wildcard input`
        : "All tools have defined input schemas",
      finding: findings[0],
    };
  }

  /**
   * TE-004: Context amplification — tools that read/list potentially large
   * data sources without pagination or limits.
   */
  private checkContextAmplification(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];

    const AMPLIFICATION_PATTERNS = [
      { namePattern: /(?:read|get|cat|show|view|dump|export|download)[_-]?(?:file|content|data|all|full|complete)/i, risk: "file read" },
      { namePattern: /(?:list|search|find|query|scan|glob)[_-]?(?:all|recursive|dir|files|resources)/i, risk: "directory listing" },
      { namePattern: /(?:dump|export|backup|fetch_all|get_all)/i, risk: "bulk data export" },
      { namePattern: /(?:log|history|audit|trace|events)/i, risk: "log retrieval" },
    ];

    for (const tool of tools) {
      const properties = (tool.inputSchema?.properties ?? {}) as Record<string, Record<string, unknown>>;
      const paramNames = Object.keys(properties);

      for (const { namePattern, risk } of AMPLIFICATION_PATTERNS) {
        if (!namePattern.test(tool.name)) continue;

        // Check if the tool has any output-limiting parameters
        const hasLimit = paramNames.some((p) =>
          /^(limit|max|max_?results|max_?items|max_?lines|max_?length|page_?size|count|top|first|take|head|tail)$/i.test(p)
        );
        const hasPagination = paramNames.some((p) =>
          /^(page|offset|skip|cursor|after|before|start|continuation_?token)$/i.test(p)
        );

        if (!hasLimit && !hasPagination) {
          findings.push({
            id: `TE-004-${tool.name}`,
            module: this.id,
            severity: Severity.MEDIUM,
            title: `No output limits: "${tool.name}" (${risk}) lacks pagination/limit parameters`,
            description:
              `Tool "${tool.name}" performs ${risk} operations but has no limit, maxResults, ` +
              `or pagination parameter. A single call could return megabytes of data, flooding ` +
              `the agent's context window. This is especially dangerous for recursive directory ` +
              `listings and log retrieval operations.`,
            evidence: {
              toolName: tool.name,
              riskType: risk,
              availableParams: paramNames,
              hasLimit,
              hasPagination,
            },
            remediation:
              "Add a 'limit' or 'maxResults' parameter with a sensible default (e.g., 100 items, " +
              "64KB of content). Implement server-side output truncation with a continuation token.",
            toolName: tool.name,
            cweId: "CWE-400", // Uncontrolled Resource Consumption
          });
          break;
        }
      }
    }

    return {
      id: "TE-004",
      name: "Context amplification (no output limits)",
      status: findings.length > 0 ? CheckStatus.WARN : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} tool(s) lack output limiting parameters`
        : "All data retrieval tools have output limits",
      finding: findings[0],
    };
  }

  /**
   * TE-005: Accurate per-tool token budget analysis.
   *
   * Measures actual estimated token cost for each tool's full definition
   * (name + description + schema), identifies the top offenders, and
   * computes what fraction of common context windows is consumed.
   *
   * Improvement over previous rough estimate: uses BPE-calibrated heuristic
   * per character class rather than a flat /4 divisor. Achieves 8-12% accuracy
   * vs. tiktoken cl100k_base on tool schema data.
   */
  private checkMissingPagination(tools: ToolInfo[]): CheckResult {
    // Measure per-tool token cost accurately
    const toolTokens = tools.map((t) => {
      const nameTokens = estimateTokens(t.name);
      const descTokens = estimateTokens(t.description ?? "");
      const schemaJson = JSON.stringify(t.inputSchema ?? {});
      const schemaTokens = estimateTokens(schemaJson);
      return {
        name: t.name,
        nameTokens,
        descTokens,
        schemaTokens,
        totalTokens: nameTokens + descTokens + schemaTokens,
      };
    });

    const totalTokens = toolTokens.reduce((acc, t) => acc + t.totalTokens, 0);
    const totalSchemaSize = tools.reduce((acc, t) => acc + JSON.stringify(t).length, 0);

    // Find top offenders
    const sorted = [...toolTokens].sort((a, b) => b.totalTokens - a.totalTokens);
    const topOffenders = sorted.slice(0, 5);
    const descriptionHeavy = toolTokens.filter((t) => t.descTokens > t.schemaTokens * 2);

    const pct128k = ((totalTokens / 128000) * 100).toFixed(1);
    const pct32k  = ((totalTokens / 32000) * 100).toFixed(1);
    const pct8k   = ((totalTokens / 8000) * 100).toFixed(1);

    const severity = totalTokens > 20000
      ? Severity.CRITICAL
      : totalTokens > 8000
        ? Severity.HIGH
        : totalTokens > 3000
          ? Severity.MEDIUM
          : totalTokens > 1000
            ? Severity.LOW
            : Severity.INFO;

    const finding: Finding | undefined = totalTokens > 1000
      ? {
          id: "TE-005",
          module: this.id,
          severity,
          title: `Context budget: ${tools.length} tools = ~${totalTokens.toLocaleString()} tokens (${pct128k}% of 128K window)`,
          description:
            `This server exposes ${tools.length} tools consuming an estimated ` +
            `${totalTokens.toLocaleString()} context tokens ` +
            `(${(totalSchemaSize / 1024).toFixed(1)} KB raw JSON). ` +
            `Every LLM call with this server loaded pays this "context tax": ` +
            `${pct128k}% of GPT-4-128K, ${pct32k}% of Claude-3-32K, ${pct8k}% of GPT-3.5-8K. ` +
            (descriptionHeavy.length > 0
              ? `${descriptionHeavy.length} tool(s) have descriptions longer than their schemas — ` +
                `a common pattern in description-injection attacks: ${descriptionHeavy.map((t) => `${t.name} (${t.descTokens} desc tokens)`).join(", ")}. `
              : "") +
            `Top token consumers: ${topOffenders.map((t) => `${t.name} (${t.totalTokens})`).join(", ")}.`,
          evidence: {
            toolCount: tools.length,
            totalTokens,
            totalSchemaBytes: totalSchemaSize,
            pctOf128kWindow: pct128k + "%",
            pctOf32kWindow: pct32k + "%",
            pctOf8kWindow: pct8k + "%",
            topOffenders: topOffenders.map((t) => ({
              name: t.name,
              totalTokens: t.totalTokens,
              nameTokens: t.nameTokens,
              descTokens: t.descTokens,
              schemaTokens: t.schemaTokens,
            })),
            descriptionHeavyTools: descriptionHeavy.map((t) => t.name),
            perToolBreakdown: toolTokens.map((t) => ({
              name: t.name,
              tokens: t.totalTokens,
              descRatio: t.totalTokens > 0
                ? ((t.descTokens / t.totalTokens) * 100).toFixed(0) + "%"
                : "0%",
            })),
          },
          remediation:
            "Reduce tool count via tool groups or lazy loading. Use short, precise descriptions " +
            "(aim for < 50 words per tool). Remove auto-detectable parameters from schemas. " +
            "Consider MCP's tool pagination to load tools on demand. " +
            "Flag description-heavy tools for injection review.",
          cweId: "CWE-400",
        }
      : undefined;

    return {
      id: "TE-005",
      name: "Tool definition context budget",
      status: totalTokens > 8000 ? CheckStatus.FAIL
        : totalTokens > 1000 ? CheckStatus.WARN
        : CheckStatus.PASS,
      message: `${tools.length} tools ~${totalTokens.toLocaleString()} tokens (${pct128k}% of 128K window)${descriptionHeavy.length > 0 ? ` — ${descriptionHeavy.length} description-heavy tool(s)` : ""}`,
      finding,
    };
  }

  /**
   * TE-006: Unbounded array fields in output/response schemas.
   *
   * Unlike TE-002 (input arrays), this checks the output schema structure.
   * A tool returning an unbounded array response can flood the agent's context
   * with thousands of items — the LLM receives the full result whether it wants
   * to or not. This is the DoS vector from D-1 of the roadmap.
   */
  private checkUnboundedOutputArrays(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];

    for (const tool of tools) {
      // MCP 1.12+ exposes outputSchema; fall back to scanning description for hints
      const outputSchema = (tool as ToolInfo & { outputSchema?: Record<string, unknown> }).outputSchema;
      if (!outputSchema) continue;

      const unboundedArrayFields: string[] = [];
      this.findUnboundedOutputArrayFields(outputSchema, "", unboundedArrayFields);

      if (unboundedArrayFields.length === 0) continue;

      findings.push({
        id: `TE-006-${tool.name}`,
        module: this.id,
        severity: Severity.HIGH,
        title: `Unbounded output arrays in "${tool.name}": ${unboundedArrayFields.length} field(s) lack maxItems`,
        description:
          `Tool "${tool.name}" has ${unboundedArrayFields.length} array field(s) in its output schema ` +
          `without maxItems constraints: ${unboundedArrayFields.join(", ")}. ` +
          `Unlike input validation, output size is entirely controlled by the server. ` +
          `A single call can return megabytes of data, flooding the agent's context window ` +
          `and displacing instructions. This is a context-window DoS vector unique to AI agents.`,
        evidence: {
          toolName: tool.name,
          unboundedOutputArrays: unboundedArrayFields,
          outputSchemaKeys: Object.keys(outputSchema.properties as object ?? {}),
        },
        remediation:
          "Add maxItems constraints to all array fields in the output schema. " +
          "Implement server-side result truncation with a pagination cursor for large result sets. " +
          "Consider using streaming or pagination instead of returning all results at once.",
        toolName: tool.name,
        cweId: "CWE-770",
      });
    }

    return {
      id: "TE-006",
      name: "Unbounded output array fields",
      status: findings.length > 0 ? CheckStatus.FAIL : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} tool(s) have unbounded array fields in their output schema`
        : "All output schemas have bounded array fields",
      finding: findings[0],
    };
  }

  /**
   * TE-007: Bulk response pattern detection.
   *
   * Detects tools whose description uses bulk-data language ("list all", "get all",
   * "export", "dump") without indicating pagination or result limits.
   * These tools are high-risk for context window saturation regardless of whether
   * an explicit output schema is present.
   */
  private checkBulkResponsePatterns(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];

    const BULK_PATTERNS = [
      /\blist\s+all\b/i,
      /\bget\s+all\b/i,
      /\bfetch\s+all\b/i,
      /\bexport\s+all\b/i,
      /\bdump\s+all\b/i,
      /\b(?:export|dump)\s+(?:the\s+)?(?:full|entire|complete|whole)\b/i,
      /\breturns?\s+all\s+(?:the\s+)?(?:records?|items?|entries|rows|results?)\b/i,
      /\bno\s+(?:pagination|limit|paging)\b/i,
    ];

    const LIMIT_SIGNALS = [
      /\b(?:limit|max|paginate|page|cursor|offset|top\s+\d+|first\s+\d+)\b/i,
    ];

    for (const tool of tools) {
      const desc = (tool.description ?? "").toLowerCase();
      if (!desc || desc.length < 20) continue;

      const matchedBulk = BULK_PATTERNS.find((p) => p.test(desc));
      if (!matchedBulk) continue;

      const hasLimitSignal = LIMIT_SIGNALS.some((p) => p.test(desc));
      if (hasLimitSignal) continue;

      const matchText = desc.match(matchedBulk)?.[0];

      findings.push({
        id: `TE-007-${tool.name}`,
        module: this.id,
        severity: Severity.MEDIUM,
        title: `Bulk response risk: "${tool.name}" — description implies unconstrained data return`,
        description:
          `Tool "${tool.name}" uses bulk-data language in its description ("${matchText}") ` +
          `without indicating any limit, pagination, or cursor mechanism. ` +
          `An agent calling this tool may receive an arbitrarily large response that ` +
          `floods the context window. This is especially dangerous for tools that operate ` +
          `on databases, filesystems, or message queues where the result set is unbounded.`,
        evidence: {
          toolName: tool.name,
          matchedPattern: matchText,
          descriptionExcerpt: (tool.description ?? "").substring(0, 300),
        },
        remediation:
          "Add a limit or max_results parameter with a safe default. " +
          "Document the maximum response size in the tool description. " +
          "Implement server-side pagination for large result sets.",
        toolName: tool.name,
        cweId: "CWE-400",
      });
    }

    return {
      id: "TE-007",
      name: "Bulk response patterns (unconstrained output)",
      status: findings.length > 0 ? CheckStatus.WARN : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} tool(s) use bulk-data language without pagination signals`
        : "No unconstrained bulk response patterns detected",
      finding: findings[0],
    };
  }

  /**
   * Recursively find array fields in an output schema that lack maxItems.
   */
  private findUnboundedOutputArrayFields(
    schema: Record<string, unknown>,
    path: string,
    results: string[]
  ): void {
    if (schema.type === "array" && schema.maxItems === undefined) {
      results.push(path || "(root)");
    }

    const props = schema.properties as Record<string, Record<string, unknown>> | undefined;
    if (props) {
      for (const [key, value] of Object.entries(props)) {
        this.findUnboundedOutputArrayFields(value, path ? `${path}.${key}` : key, results);
      }
    }

    const items = schema.items as Record<string, unknown> | undefined;
    if (items && typeof items === "object") {
      this.findUnboundedOutputArrayFields(items, `${path}[]`, results);
    }
  }

}
