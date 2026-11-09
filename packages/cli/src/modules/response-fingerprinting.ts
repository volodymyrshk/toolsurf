import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
  type ToolInfo,
} from "../types/index.js";

/**
 * Response Fingerprinting Module (Active).
 *
 * Sends identical payloads to the same tool multiple times and detects
 * non-deterministic responses. Non-determinism can indicate:
 * - Hidden state being accumulated across calls
 * - Backdoor logic that activates after N calls
 * - Timing channels or covert communication
 * - Tool poisoning that evolves over time
 *
 * ACTIVE MODULE: makes tool calls to the server.
 *
 * CWE-656: Reliance on Security Through Obscurity
 */
export class ResponseFingerprintingModule implements AuditModule {
  id = "response-fingerprinting";
  name = "Response Fingerprinting";
  description =
    "Detects non-deterministic tool responses indicating hidden state or backdoors";
  version = "1.0.0";
  mode = "active" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const { tools } = context.capabilities;

    if (!context.callTool) {
      checks.push({
        id: "RF-001",
        name: "Response determinism analysis",
        status: CheckStatus.SKIP,
        message: "Requires --active flag",
      });
      checks.push({
        id: "RF-002",
        name: "Response timing variance",
        status: CheckStatus.SKIP,
        message: "Requires --active flag",
      });
      checks.push({
        id: "RF-003",
        name: "Stateful behavior detection",
        status: CheckStatus.SKIP,
        message: "Requires --active flag",
      });
      return checks;
    }

    const probeDelay = context.probeDelay ?? 100;
    const progress = context.onProgress;

    // Check 1: Response determinism — same input should give same output
    progress?.("Fingerprinting: Determinism");
    checks.push(
      ...await this.testDeterminism(tools, context.callTool, probeDelay, context.verbose)
    );

    // Check 2: Response timing variance — consistent timing expected
    progress?.("Fingerprinting: Timing variance");
    checks.push(
      ...await this.testTimingVariance(tools, context.callTool, probeDelay, context.verbose)
    );

    // Check 3: Stateful behavior — responses shouldn't change over repeated calls
    progress?.("Fingerprinting: Stateful behavior");
    checks.push(
      ...await this.testStatefulBehavior(tools, context.callTool, probeDelay, context.verbose)
    );

    return checks;
  }

  /**
   * Test if tools produce deterministic responses for identical inputs.
   * Send the same payload 3 times and compare responses.
   */
  private async testDeterminism(
    tools: ToolInfo[],
    callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
    probeDelay: number,
    verbose: boolean
  ): Promise<CheckResult[]> {
    const ROUNDS = 3;
    const nonDeterministic: Array<{
      tool: string;
      uniqueResponses: number;
      diffs: string[];
    }> = [];

    // Test up to 5 tools
    const candidates = tools.slice(0, 5);

    for (const tool of candidates) {
      const args = this.buildMinimalArgs(tool);
      const responses: string[] = [];

      for (let i = 0; i < ROUNDS; i++) {
        try {
          if (probeDelay > 0) await new Promise((r) => setTimeout(r, probeDelay));
          if (verbose) console.error(`[toolsurf:fingerprint] Determinism round ${i + 1}: ${tool.name}`);

          const result = await callTool(tool.name, args);
          const responseStr = typeof result === "string" ? result : JSON.stringify(result);
          responses.push(this.normalizeResponse(responseStr));
        } catch {
          responses.push("__ERROR__");
        }
      }

      const unique = new Set(responses);
      if (unique.size > 1) {
        // Find what changed between responses
        const diffs = this.describeDiffs(responses);
        nonDeterministic.push({
          tool: tool.name,
          uniqueResponses: unique.size,
          diffs,
        });
      }
    }

    if (nonDeterministic.length === 0) {
      return [{
        id: "RF-001",
        name: "Response determinism analysis",
        status: CheckStatus.PASS,
        message: `${candidates.length} tool(s) produce deterministic responses`,
      }];
    }

    return [{
      id: "RF-001",
      name: "Response determinism analysis",
      status: CheckStatus.WARN,
      message: `${nonDeterministic.length} tool(s) produce non-deterministic responses`,
      finding: {
        id: "RF-001",
        module: this.id,
        severity: Severity.MEDIUM,
        title: "Non-deterministic tool responses detected",
        description:
          `${nonDeterministic.length} tool(s) returned different responses for identical inputs ` +
          "across multiple calls. While some non-determinism is expected (timestamps, random IDs), " +
          "significant structural changes may indicate hidden state, progressive data collection, " +
          "or conditional backdoor logic that activates based on call patterns.",
        evidence: { nonDeterministic },
        remediation:
          "Audit tools that produce varying responses for the same input. " +
          "Ensure tools are stateless unless explicitly designed otherwise. " +
          "Document any expected sources of non-determinism (timestamps, random IDs). " +
          "Investigate structural response changes that go beyond expected variance.",
        cweId: "CWE-656",
      },
    }];
  }

  /**
   * Test timing variance across identical calls.
   * Abnormally high variance can indicate timing channels or conditional processing.
   */
  private async testTimingVariance(
    tools: ToolInfo[],
    callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
    probeDelay: number,
    verbose: boolean
  ): Promise<CheckResult[]> {
    const ROUNDS = 5;
    const suspicious: Array<{
      tool: string;
      timings: number[];
      coefficientOfVariation: number;
    }> = [];

    // Test up to 3 tools
    const candidates = tools.slice(0, 3);

    for (const tool of candidates) {
      const args = this.buildMinimalArgs(tool);
      const timings: number[] = [];

      for (let i = 0; i < ROUNDS; i++) {
        try {
          if (probeDelay > 0) await new Promise((r) => setTimeout(r, probeDelay));
          if (verbose) console.error(`[toolsurf:fingerprint] Timing round ${i + 1}: ${tool.name}`);

          const t0 = performance.now();
          await callTool(tool.name, args);
          timings.push(Math.round(performance.now() - t0));
        } catch {
          // Skip failed calls for timing analysis
        }
      }

      if (timings.length < 3) continue;

      const mean = timings.reduce((a, b) => a + b, 0) / timings.length;
      const variance = timings.reduce((sum, t) => sum + (t - mean) ** 2, 0) / timings.length;
      const stddev = Math.sqrt(variance);
      const cv = mean > 0 ? stddev / mean : 0;

      // CV > 0.5 (50% variation) is suspicious for identical inputs
      if (cv > 0.5 && mean > 100) {
        suspicious.push({
          tool: tool.name,
          timings,
          coefficientOfVariation: Math.round(cv * 100) / 100,
        });
      }
    }

    if (suspicious.length === 0) {
      return [{
        id: "RF-002",
        name: "Response timing variance",
        status: CheckStatus.PASS,
        message: `${candidates.length} tool(s) show consistent timing`,
      }];
    }

    return [{
      id: "RF-002",
      name: "Response timing variance",
      status: CheckStatus.WARN,
      message: `${suspicious.length} tool(s) show high timing variance`,
      finding: {
        id: "RF-002",
        module: this.id,
        severity: Severity.LOW,
        title: "High timing variance detected in tool responses",
        description:
          `${suspicious.length} tool(s) showed coefficient of variation > 50% in response times ` +
          "for identical inputs. While network jitter can cause some variance, extreme timing " +
          "differences may indicate conditional processing paths, timing channels, or " +
          "resource contention that could be exploited.",
        evidence: { suspicious },
        remediation:
          "Investigate tools with high timing variance for conditional logic paths. " +
          "Ensure constant-time processing for security-sensitive operations. " +
          "Consider rate limiting to prevent timing-based side channels.",
        cweId: "CWE-208",
      },
    }];
  }

  /**
   * Test for stateful behavior by calling a tool many times and checking
   * if responses evolve (e.g., growing response, changing behavior on Nth call).
   */
  private async testStatefulBehavior(
    tools: ToolInfo[],
    callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
    probeDelay: number,
    verbose: boolean
  ): Promise<CheckResult[]> {
    const ROUNDS = 6;
    const stateful: Array<{
      tool: string;
      pattern: string;
      responseLengths: number[];
    }> = [];

    // Test up to 3 tools
    const candidates = tools.slice(0, 3);

    for (const tool of candidates) {
      const args = this.buildMinimalArgs(tool);
      const responseLengths: number[] = [];
      const responses: string[] = [];

      for (let i = 0; i < ROUNDS; i++) {
        try {
          if (probeDelay > 0) await new Promise((r) => setTimeout(r, probeDelay));
          if (verbose) console.error(`[toolsurf:fingerprint] Stateful round ${i + 1}: ${tool.name}`);

          const result = await callTool(tool.name, args);
          const responseStr = typeof result === "string" ? result : JSON.stringify(result);
          responseLengths.push(responseStr.length);
          responses.push(this.normalizeResponse(responseStr));
        } catch {
          responseLengths.push(-1);
          responses.push("__ERROR__");
        }
      }

      // Detect monotonically growing response (data accumulation)
      const validLengths = responseLengths.filter((l) => l >= 0);
      if (validLengths.length >= 4) {
        const isGrowing = validLengths.every((l, i) =>
          i === 0 || l >= validLengths[i - 1]
        );
        const growthRatio = validLengths[validLengths.length - 1] / Math.max(validLengths[0], 1);

        if (isGrowing && growthRatio > 1.5) {
          stateful.push({
            tool: tool.name,
            pattern: "monotonic-growth",
            responseLengths: validLengths,
          });
          continue;
        }
      }

      // Detect sudden behavioral shift (first N responses same, then different)
      const normalized = responses.filter((r) => r !== "__ERROR__");
      if (normalized.length >= 4) {
        const firstResponse = normalized[0];
        const sameCount = normalized.filter((r) => r === firstResponse).length;
        const diffCount = normalized.length - sameCount;

        // If first responses match but later ones diverge
        if (sameCount >= 2 && diffCount >= 2) {
          const lastSameIndex = normalized.findIndex((r, i) =>
            i > 0 && r !== firstResponse
          );
          if (lastSameIndex > 0 && normalized.slice(lastSameIndex).every((r) => r !== firstResponse)) {
            stateful.push({
              tool: tool.name,
              pattern: "behavioral-shift",
              responseLengths: validLengths,
            });
          }
        }
      }
    }

    if (stateful.length === 0) {
      return [{
        id: "RF-003",
        name: "Stateful behavior detection",
        status: CheckStatus.PASS,
        message: `${candidates.length} tool(s) show no stateful behavior`,
      }];
    }

    return [{
      id: "RF-003",
      name: "Stateful behavior detection",
      status: CheckStatus.FAIL,
      message: `${stateful.length} tool(s) show stateful behavior patterns`,
      finding: {
        id: "RF-003",
        module: this.id,
        severity: Severity.HIGH,
        title: "Stateful tool behavior detected",
        description:
          `${stateful.length} tool(s) showed evolving responses for identical repeated inputs. ` +
          "Patterns detected include monotonically growing responses (data accumulation) " +
          "and sudden behavioral shifts after N calls (conditional backdoor). " +
          "MCP tools should be stateless unless explicitly designed otherwise.",
        evidence: { stateful },
        remediation:
          "Audit tools for hidden state or call counters. " +
          "Ensure tools do not accumulate data across calls without client awareness. " +
          "Document any intentional stateful behavior. " +
          "Implement call-count monitoring to detect anomalous behavior patterns.",
        cweId: "CWE-912",
      },
    }];
  }

  private buildMinimalArgs(tool: ToolInfo): Record<string, unknown> {
    const properties = (tool.inputSchema as Record<string, unknown>).properties as
      Record<string, Record<string, unknown>> | undefined;
    const required = ((tool.inputSchema as Record<string, unknown>).required ?? []) as string[];
    const args: Record<string, unknown> = {};

    for (const param of required) {
      const schema = properties?.[param];
      args[param] = this.getDefaultValue(schema?.type as string);
    }
    return args;
  }

  private getDefaultValue(type: string): unknown {
    switch (type) {
      case "string": return "test";
      case "number":
      case "integer": return 1;
      case "boolean": return true;
      case "array": return [];
      case "object": return {};
      default: return "test";
    }
  }

  /**
   * Normalize response by removing timestamps, UUIDs, and other expected variance.
   */
  private normalizeResponse(s: string): string {
    return s
      .replace(/\d{4}-\d{2}-\d{2}T[\d:.]+Z?/g, "TS")
      .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, "UUID")
      .replace(/\d{10,13}/g, "EPOCH")
      .replace(/"(modified|created|accessed)":\s*\d+/g, '"$1": TS');
  }

  /**
   * Describe the differences between responses for human review.
   */
  private describeDiffs(responses: string[]): string[] {
    const diffs: string[] = [];
    for (let i = 1; i < responses.length; i++) {
      if (responses[i] !== responses[0]) {
        const lenDiff = responses[i].length - responses[0].length;
        diffs.push(
          `Round ${i + 1}: length delta ${lenDiff > 0 ? "+" : ""}${lenDiff}`
        );
      }
    }
    return diffs;
  }
}
