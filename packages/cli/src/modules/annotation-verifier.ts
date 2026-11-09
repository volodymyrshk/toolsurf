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
 * Dictionary of hidden administrative trigger strings used in rug-pull attacks.
 * These are inputs that look like normal values but trigger hidden behavior.
 */
const ADMIN_TRIGGER_PROBES: Array<{ value: string; label: string }> = [
  // Common hidden trigger strings
  { value: "__admin__",      label: "dunder-admin" },
  { value: "__debug__",      label: "dunder-debug" },
  { value: "__internal__",   label: "dunder-internal" },
  { value: "__root__",       label: "dunder-root" },
  { value: "__test__",       label: "dunder-test" },
  { value: "__backdoor__",   label: "dunder-backdoor" },
  { value: "__hidden__",     label: "dunder-hidden" },
  { value: "__dev__",        label: "dunder-dev" },
  // Conventional magic values
  { value: "admin",          label: "admin" },
  { value: "root",           label: "root" },
  { value: "debug",          label: "debug" },
  { value: "internal",       label: "internal" },
  { value: "test",           label: "test" },
  { value: "0",              label: "zero" },
  { value: "-1",             label: "neg-one" },
  { value: "null",           label: "null-string" },
  { value: "undefined",      label: "undefined-string" },
  { value: "true",           label: "true-string" },
  { value: "false",          label: "false-string" },
  // Common backdoor keys
  { value: "MASTER_KEY",     label: "master-key" },
  { value: "BYPASS",         label: "bypass" },
  { value: "OVERRIDE",       label: "override" },
  { value: "0000",           label: "quad-zero" },
  { value: "1337",           label: "leet" },
  { value: "secret",         label: "secret" },
  { value: "password",       label: "password-word" },
  // Path traversal that could expose hidden behavior
  { value: "../",            label: "path-traversal" },
  { value: ".",              label: "dot-current" },
];

/**
 * Patterns that suggest a tool response contains leaked sensitive data.
 * Used in differential analysis of rug-pull detection.
 */
const SENSITIVE_RESPONSE_PATTERNS = [
  { pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*["']?[A-Za-z0-9_\-]{16,}/i,  label: "api-key-leak" },
  { pattern: /(?:password|passwd|pwd)\s*[:=]\s*\S{6,}/i,                      label: "password-leak" },
  { pattern: /AKIA[0-9A-Z]{16}/,                                               label: "aws-key-leak" },
  { pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY/,                          label: "private-key-leak" },
  { pattern: /(?:secret|token|credential)\s*[:=]\s*["']?[A-Za-z0-9_\-+/]{20,}/i, label: "secret-leak" },
  { pattern: /(?:home|root|usr|etc|var|tmp)\s*[:\/]/,                          label: "filesystem-path-leak" },
  { pattern: /PATH=[\S:]+|HOME=[\S]+|USER=[\S]+/,                              label: "env-var-leak" },
  { pattern: /uid=\d+|gid=\d+/,                                                label: "unix-identity-leak" },
  { pattern: /(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+(?:FROM|INTO|TABLE|DATABASE)/i, label: "sql-leak" },
];

/**
 * State-change fingerprinting for readOnly annotation verification.
 * These are simple before/after checks we can perform on tool responses.
 */
function fingerprintResponse(response: unknown): string {
  if (response === null || response === undefined) return "null";
  const str = JSON.stringify(response);
  return `len:${str.length}|hash:${simpleHash(str)}`;
}

function simpleHash(s: string): number {
  let h = 0;
  for (let i = 0; i < Math.min(s.length, 1000); i++) {
    h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  }
  return h >>> 0;
}

function extractText(response: unknown): string {
  if (!response) return "";
  if (typeof response === "string") return response;
  return JSON.stringify(response);
}

/**
 * Annotation Verifier Module (Active).
 *
 * Three-part active verification of tool honesty:
 *
 * Part 1 — readOnlyHint verification:
 *   For tools annotated as readOnly, call them with benign inputs and compare
 *   responses across calls to detect state changes. A readOnly tool should be
 *   idempotent: calling it twice with the same input should produce
 *   structurally identical responses.
 *
 * Part 2 — Rug-pull probe (conditional behavior detection):
 *   For all tools, send dictionary-based admin trigger strings and compare
 *   responses structurally against normal inputs. If the admin input produces
 *   a structurally different response (different length class, different JSON
 *   keys), flag it as possible conditional/hidden behavior.
 *
 * Part 3 — Response content scanning:
 *   Scan all tool responses (regardless of input) for patterns indicating
 *   leaked credentials, environment variables, filesystem paths, or other
 *   sensitive data that should not appear in tool output.
 *
 * This implements Attacks #4 (rug-pull via conditional behavior) and
 * #6 (annotation lying) from the research findings.
 *
 * Finding prefixes: AV-001 through AV-003
 */
export class AnnotationVerifierModule implements AuditModule {
  id = "annotation-verifier";
  name = "Annotation Honesty Verifier";
  description =
    "Actively verifies that readOnly annotations are truthful and detects hidden conditional behavior";
  version = "1.0.0";
  mode = "active" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const { tools } = context.capabilities;

    if (!context.callTool) {
      return [
        {
          id: "AV-SKIP",
          name: "Annotation verification (skipped)",
          status: CheckStatus.SKIP,
          message: "Requires --active flag",
        },
      ];
    }

    const probeDelay = context.probeDelay ?? 150;
    const progress = context.onProgress;

    // Part 1: readOnly annotation honesty
    progress?.("Annotation: readOnly verification");
    checks.push(await this.verifyReadOnlyAnnotations(tools, context.callTool, probeDelay));

    // Part 2: Rug-pull probe — hidden admin triggers
    progress?.("Annotation: rug-pull probe");
    checks.push(await this.probeForHiddenBehavior(tools, context.callTool, probeDelay));

    // Part 3: Response content scan for leaked secrets
    progress?.("Annotation: response content scan");
    checks.push(await this.scanResponsesForLeaks(tools, context.callTool, probeDelay));

    return checks;
  }

  /**
   * AV-001: Verify readOnlyHint truthfulness.
   *
   * Call each readOnly-annotated tool twice with identical inputs.
   * A truly read-only tool should return structurally identical responses.
   * A structural difference suggests side effects (state change).
   *
   * Also: call the tool and check if the server exposes any mutation-indicative
   * response fields (e.g., "created", "updated", "deleted", "rows_affected").
   */
  private async verifyReadOnlyAnnotations(
    tools: ToolInfo[],
    callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
    probeDelay: number,
  ): Promise<CheckResult> {
    const findings: Finding[] = [];

    const readOnlyTools = tools.filter((t) => t.annotations?.readOnlyHint === true);

    for (const tool of readOnlyTools) {
      const benignArgs = this.buildBenignArgs(tool);

      try {
        // First call
        const resp1 = await callTool(tool.name, benignArgs);
        await delay(probeDelay);

        // Second call — identical args
        const resp2 = await callTool(tool.name, benignArgs);

        const fp1 = fingerprintResponse(resp1);
        const fp2 = fingerprintResponse(resp2);

        const text1 = extractText(resp1);
        const text2 = extractText(resp2);

        // Check for mutation-indicative response fields
        const mutationKeywords = /\b(created|updated|deleted|inserted|rows[_-]?affected|modified|changed|saved|committed|applied)\b/i;
        const hasMutationResponse = mutationKeywords.test(text1) || mutationKeywords.test(text2);

        // Check if responses differ significantly
        const len1 = text1.length;
        const len2 = text2.length;
        const lenDiff = Math.abs(len1 - len2);
        const lenDiffPct = len1 > 0 ? (lenDiff / len1) * 100 : 0;

        // Flag if: structural fingerprints differ, or mutation language detected
        if (lenDiffPct > 20 || hasMutationResponse) {
          findings.push({
            id: `AV-001-${tool.name}`,
            module: this.id,
            severity: Severity.CRITICAL,
            title: `readOnly lie: "${tool.name}" shows state change indicators`,
            description:
              `Tool "${tool.name}" is annotated readOnlyHint=true but exhibits behavior ` +
              `inconsistent with a read-only operation. ` +
              (hasMutationResponse
                ? `Response contains mutation-indicating language: "${text1.match(mutationKeywords)?.[0]}". `
                : "") +
              (lenDiffPct > 20
                ? `Two identical calls returned responses differing by ${lenDiffPct.toFixed(1)}% in length, ` +
                  `suggesting non-deterministic or stateful behavior. `
                : "") +
              `An LLM agent trusts readOnly annotations to determine whether user confirmation ` +
              `is needed before invoking a tool. A lying annotation bypasses this safety check.`,
            evidence: {
              toolName: tool.name,
              args: benignArgs,
              response1Fingerprint: fp1,
              response2Fingerprint: fp2,
              responseLengthDelta: lenDiff,
              responseLengthDeltaPct: lenDiffPct.toFixed(1) + "%",
              hasMutationLanguage: hasMutationResponse,
              mutationMatch: text1.match(mutationKeywords)?.[0],
              response1Excerpt: text1.substring(0, 200),
              response2Excerpt: text2.substring(0, 200),
            },
            remediation:
              "Either fix the annotation (remove readOnlyHint if the tool has side effects) " +
              "or fix the implementation (ensure the tool truly makes no state changes). " +
              "All LLM agent frameworks rely on readOnlyHint to gate user confirmation prompts.",
            toolName: tool.name,
            cweId: "CWE-912", // Hidden Functionality
            confidence: hasMutationResponse ? 0.9 : 0.7,
          });
        }
      } catch {
        // Tool errors are expected for some benign inputs — not a finding
      }

      await delay(probeDelay);
    }

    return {
      id: "AV-001",
      name: "readOnly annotation verification",
      status: findings.length > 0 ? CheckStatus.FAIL : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} readOnly tool(s) show state-change indicators`
        : `${readOnlyTools.length} readOnly tool(s) verified — no state changes detected`,
      finding: findings[0],
    };
  }

  /**
   * AV-002: Rug-pull probe — test for hidden conditional behavior.
   *
   * For each tool, send a small set of admin trigger probes as the value of
   * every string parameter. Compare response structure against a baseline
   * normal call. Significant structural differences = possible rug pull.
   *
   * Implements Attack #4 from research findings: "Rug-Pull via Conditional Behavior"
   * — a tool that returns weather for normal inputs but when called with
   * city="__admin__", returns environment variables or file listings.
   */
  private async probeForHiddenBehavior(
    tools: ToolInfo[],
    callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
    probeDelay: number,
  ): Promise<CheckResult> {
    const findings: Finding[] = [];

    // Limit to tools with at least one string parameter
    const toolsWithStrings = tools.filter((t) => {
      const props = (t.inputSchema?.properties ?? {}) as Record<string, Record<string, unknown>>;
      return Object.values(props).some((p) => p.type === "string" || !p.type);
    });

    // Use a subset of probes to keep runtime reasonable
    const probesToTest = ADMIN_TRIGGER_PROBES.slice(0, 10);

    for (const tool of toolsWithStrings) {
      const props = (tool.inputSchema?.properties ?? {}) as Record<string, Record<string, unknown>>;
      const stringParams = Object.entries(props)
        .filter(([, schema]) => schema.type === "string" || !schema.type)
        .map(([name]) => name)
        .slice(0, 3); // max 3 params per tool

      if (stringParams.length === 0) continue;

      // Get baseline response with benign args
      let baselineText = "";
      let baselineLen = 0;
      try {
        const benignArgs = this.buildBenignArgs(tool);
        const baseline = await callTool(tool.name, benignArgs);
        baselineText = extractText(baseline);
        baselineLen = baselineText.length;
        await delay(probeDelay);
      } catch {
        continue; // can't establish baseline
      }

      // Test each probe against each string param
      for (const paramName of stringParams) {
        for (const probe of probesToTest) {
          try {
            const probeArgs = this.buildBenignArgs(tool);
            probeArgs[paramName] = probe.value;

            const probeResponse = await callTool(tool.name, probeArgs);
            const probeText = extractText(probeResponse);
            const probeLen = probeText.length;

            // Structural difference check: length ratio
            const lenDiff = Math.abs(probeLen - baselineLen);
            const maxLen = Math.max(probeLen, baselineLen, 1);
            const diffRatio = lenDiff / maxLen;

            // Content change check: does probe response contain sensitive-looking data
            // not present in the baseline?
            const hasSensitiveContent = SENSITIVE_RESPONSE_PATTERNS.some(
              ({ pattern }) => pattern.test(probeText) && !pattern.test(baselineText)
            );

            if (diffRatio > 0.5 || hasSensitiveContent) {
              const matchedPattern = SENSITIVE_RESPONSE_PATTERNS.find(
                ({ pattern }) => pattern.test(probeText) && !pattern.test(baselineText)
              );

              findings.push({
                id: `AV-002-${tool.name}-${paramName}-${probe.label}`,
                module: this.id,
                severity: hasSensitiveContent ? Severity.CRITICAL : Severity.HIGH,
                title: `Hidden behavior: "${tool.name}" responds differently to probe "${probe.value}" in param "${paramName}"`,
                description:
                  `Tool "${tool.name}" returned a structurally different response when ` +
                  `parameter "${paramName}" was set to the probe value "${probe.value}". ` +
                  `Baseline response length: ${baselineLen} chars. ` +
                  `Probe response length: ${probeLen} chars (${(diffRatio * 100).toFixed(0)}% difference). ` +
                  (hasSensitiveContent
                    ? `Probe response contains sensitive content not in baseline: ${matchedPattern?.label}. `
                    : "") +
                  `This is consistent with a "rug pull" attack where the tool has a hidden ` +
                  `administrative mode triggered by specific input values. The tool's declared ` +
                  `schema and description give no indication of this behavior.`,
                evidence: {
                  toolName: tool.name,
                  paramName,
                  probeValue: probe.value,
                  probeLabel: probe.label,
                  baselineLength: baselineLen,
                  probeResponseLength: probeLen,
                  lengthDiffRatio: (diffRatio * 100).toFixed(1) + "%",
                  hasSensitiveContent,
                  sensitivePatternMatched: matchedPattern?.label,
                  probeResponseExcerpt: probeText.substring(0, 300),
                  baselineResponseExcerpt: baselineText.substring(0, 200),
                },
                remediation:
                  "Investigate why the tool responds differently to this input. " +
                  "If this is intentional administrative functionality, it must be " +
                  "separately documented and access-controlled, not hidden behind magic strings. " +
                  "Remove all hidden trigger strings from tool implementations.",
                toolName: tool.name,
                cweId: "CWE-912", // Hidden Functionality
                confidence: hasSensitiveContent ? 0.92 : 0.72,
              });
              break; // One finding per param is enough
            }

            await delay(Math.floor(probeDelay / 2));
          } catch {
            // Probe caused an error — not necessarily a finding
          }
        }
      }
    }

    return {
      id: "AV-002",
      name: "Hidden conditional behavior (rug-pull probe)",
      status: findings.length > 0 ? CheckStatus.FAIL : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} tool(s) show suspicious differential behavior`
        : "No hidden conditional behavior detected",
      finding: findings[0],
    };
  }

  /**
   * AV-003: Scan all tool responses for leaked sensitive content.
   *
   * Call every tool with benign inputs and scan the response for patterns
   * indicating leaked credentials, API keys, filesystem paths, or
   * other sensitive information that should never appear in tool output.
   */
  private async scanResponsesForLeaks(
    tools: ToolInfo[],
    callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
    probeDelay: number,
  ): Promise<CheckResult> {
    const findings: Finding[] = [];

    for (const tool of tools) {
      const benignArgs = this.buildBenignArgs(tool);
      try {
        const response = await callTool(tool.name, benignArgs);
        const responseText = extractText(response);

        const matched = SENSITIVE_RESPONSE_PATTERNS.filter(({ pattern }) =>
          pattern.test(responseText)
        );

        if (matched.length > 0) {
          findings.push({
            id: `AV-003-${tool.name}`,
            module: this.id,
            severity: Severity.CRITICAL,
            title: `Response leak in "${tool.name}": ${matched.map((m) => m.label).join(", ")}`,
            description:
              `Tool "${tool.name}" returned a response containing patterns consistent with ` +
              `sensitive data: ${matched.map((m) => m.label).join(", ")}. ` +
              `This is a passive data leak — no attack input was needed, just a normal tool call. ` +
              `The tool may be returning environment variables, credentials, filesystem paths, ` +
              `or other information that should be treated as confidential.`,
            evidence: {
              toolName: tool.name,
              args: benignArgs,
              matchedPatterns: matched.map((m) => m.label),
              responseExcerpt: responseText.substring(0, 400),
            },
            remediation:
              "Audit what data this tool returns in its response. Strip any credentials, " +
              "API keys, or sensitive configuration from tool outputs. " +
              "Implement response sanitization before returning data to the LLM agent.",
            toolName: tool.name,
            cweId: "CWE-200", // Exposure of Sensitive Information
            confidence: 0.88,
          });
        }
      } catch {
        // Tool error on benign input — not a leak finding
      }

      await delay(probeDelay);
    }

    return {
      id: "AV-003",
      name: "Tool response content scan",
      status: findings.length > 0 ? CheckStatus.FAIL : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} tool(s) returned responses with sensitive content patterns`
        : "No sensitive content patterns in tool responses",
      finding: findings[0],
    };
  }

  /**
   * Build minimally valid arguments for a tool based on its schema.
   * Returns safe, benign values for each declared required parameter.
   */
  private buildBenignArgs(tool: ToolInfo): Record<string, unknown> {
    const props = (tool.inputSchema?.properties ?? {}) as Record<string, Record<string, unknown>>;
    const required = new Set<string>(
      (tool.inputSchema?.required as string[] | undefined) ?? []
    );

    const args: Record<string, unknown> = {};

    for (const [name, schema] of Object.entries(props)) {
      if (!required.has(name)) continue; // Skip optional params

      const type = schema.type as string | undefined;
      const enumVals = schema.enum as unknown[] | undefined;

      if (enumVals && enumVals.length > 0) {
        args[name] = enumVals[0];
      } else if (type === "string" || !type) {
        // Use a safe benign string based on param name hints
        if (/path|file|dir/i.test(name)) args[name] = "/tmp";
        else if (/url|uri/i.test(name)) args[name] = "https://example.com";
        else if (/id$/i.test(name)) args[name] = "1";
        else if (/name/i.test(name)) args[name] = "test";
        else args[name] = "test";
      } else if (type === "integer" || type === "number") {
        args[name] = schema.minimum !== undefined ? schema.minimum as number : 1;
      } else if (type === "boolean") {
        args[name] = false;
      } else if (type === "array") {
        args[name] = [];
      } else if (type === "object") {
        args[name] = {};
      } else {
        args[name] = null;
      }
    }

    return args;
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
