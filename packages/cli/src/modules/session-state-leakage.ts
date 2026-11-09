import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
  type ToolInfo,
} from "../types/index.js";

/**
 * Session State Leakage Tester Module.
 *
 * Manual pentesters check if state from one tool call leaks into another.
 * This is critical for multi-turn agent security:
 *
 * - Does calling Tool A with malicious input affect Tool B's behavior?
 * - Does the server remember previous calls across the same connection?
 * - Can an attacker set state in one turn that is exploited in the next?
 *
 * This module tests state isolation by:
 * 1. Call Tool A with Input X (sets potential state)
 * 2. Call Tool A with Input Y (different input)
 * 3. Check if Y's output is contaminated by X
 *
 * Finding prefixes: SSL-001 through SSL-003
 */
export class SessionStateLeakageModule implements AuditModule {
  id = "session-state-leakage";
  name = "Session State Leakage Tester";
  description =
    "Tests if state from one tool call leaks into subsequent calls, enabling cross-turn attacks";
  version = "1.0.0";
  mode = "active" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];

    if (!context.callTool || !context.activeMode) {
      checks.push({
        id: "SSL-000",
        name: "Session State Leakage Tester (Active)",
        status: CheckStatus.SKIP,
        message: "Requires --active flag and callTool access",
      });
      return checks;
    }

    const { capabilities: { tools }, callTool } = context;
    const probeDelay = context.probeDelay ?? 100;

    for (const tool of tools) {
      const stringParam = this.findStringParam(tool);
      if (!stringParam) continue;

      // Test 1: Same-tool state leakage
      const sameToolLeakage = await this.testSameToolStateLeakage(
        tool,
        stringParam,
        callTool,
        probeDelay
      );
      if (sameToolLeakage) checks.push(sameToolLeakage);

      // Test 2: Cross-tool state leakage (if there are similar tools)
      const similarTools = tools.filter(
        (t: ToolInfo) => t.name !== tool.name && this.areToolsSimilar(t, tool)
      );
      for (const otherTool of similarTools.slice(0, 2)) {
        const crossToolLeakage = await this.testCrossToolStateLeakage(
          tool,
          otherTool,
          stringParam,
          this.findStringParam(otherTool) || stringParam,
          callTool,
          probeDelay
        );
        if (crossToolLeakage) checks.push(crossToolLeakage);
      }
    }

    if (checks.length === 0) {
      checks.push({
        id: "SSL-000",
        name: "Session State Leakage Tester",
        status: CheckStatus.PASS,
        message: "No session state leakage detected",
      });
    }

    return checks;
  }

  /**
   * SSL-001: Test if calling Tool A with Input X affects Tool A with Input Y.
   *
   * Example: A filesystem tool that caches the last accessed path.
   * Call 1: read_file("/etc/passwd") → returns file contents
   * Call 2: read_file("/tmp/test.txt") → should NOT contain /etc/passwd data
   */
  private async testSameToolStateLeakage(
    tool: ToolInfo,
    paramName: string,
    callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
    probeDelay: number
  ): Promise<CheckResult | null> {
    const markerA = `__session_test_a_${Date.now()}`;
    const markerB = `__session_test_b_${Date.now()}`;

    try {
      // Call 1: Set state with marker A
      await callTool(tool.name, { [paramName]: markerA });

      if (probeDelay > 0) await new Promise((r) => setTimeout(r, probeDelay));

      // Call 2: Call with marker B
      const resultB = await callTool(tool.name, { [paramName]: markerB });
      const responseB = typeof resultB === "string" ? resultB : JSON.stringify(resultB);

      // Check if response B contains marker A (state leakage)
      // Note: responseB will almost always contain markerB since that's the input,
      // so we check if A's marker appears in B's output (which shouldn't happen if stateless)
      if (responseB.includes(markerA)) {
        return {
          id: `SSL-001-${tool.name}`,
          name: `Same-tool state leakage: ${tool.name}`,
          status: CheckStatus.FAIL,
          message: `State from previous call leaked into subsequent call`,
          finding: {
            id: `SSL-001-${tool.name}`,
            module: this.id,
            severity: Severity.HIGH,
            title: `Session state leakage in "${tool.name}"`,
            description:
              `Tool "${tool.name}" retains state from previous invocations. When called with ` +
              `"${markerA}" then "${markerB}", the second response contained data from the first. ` +
              `This enables cross-turn attacks where an attacker sets malicious state in one ` +
              `turn that affects behavior in subsequent turns.`,
            evidence: {
              toolName: tool.name,
              firstCallInput: markerA,
              secondCallInput: markerB,
              secondCallOutput: responseB.substring(0, 300),
              leakedContent: markerA,
            },
            remediation:
              "Ensure each tool invocation is stateless and isolated. Clear any cached data, " +
              "temporary variables, or connection state between calls. Use fresh connections " +
              "or explicitly reset state before processing each request.",
            toolName: tool.name,
            cweId: "CWE-400", // Uncontrolled Resource Consumption (or CWE-664: Improper Control of a Resource Through its Lifetime)
            confidence: 0.85,
          },
        };
      }

      return null;
    } catch {
      return null;
    }
  }

  /**
   * SSL-002: Test if calling Tool A affects Tool B's behavior.
   *
   * Example: A database tool and an email tool that share a connection pool.
   * Call 1: db_query("SET SESSION AUTHORIZATION attacker") → sets DB session
   * Call 2: send_email() → uses the same connection, now with attacker's privileges
   */
  private async testCrossToolStateLeakage(
    toolA: ToolInfo,
    toolB: ToolInfo,
    paramA: string,
    paramB: string,
    callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
    probeDelay: number
  ): Promise<CheckResult | null> {
    const marker = `__cross_tool_test_${Date.now()}`;

    try {
      // Call Tool A with marker
      await callTool(toolA.name, { [paramA]: marker });

      if (probeDelay > 0) await new Promise((r) => setTimeout(r, probeDelay));

      // Call Tool B with benign input
      const resultB = await callTool(toolB.name, { [paramB]: "benign_test" });
      const responseB = typeof resultB === "string" ? resultB : JSON.stringify(resultB);

      // Check if Tool B's response contains marker from Tool A
      if (responseB.includes(marker)) {
        return {
          id: `SSL-002-${toolA.name}-${toolB.name}`,
          name: `Cross-tool state leakage: ${toolA.name} → ${toolB.name}`,
          status: CheckStatus.FAIL,
          message: `State leaked from ${toolA.name} into ${toolB.name}`,
          finding: {
            id: `SSL-002-${toolA.name}-${toolB.name}`,
            module: this.id,
            severity: Severity.CRITICAL,
            title: `Cross-tool state leakage: "${toolA.name}" → "${toolB.name}"`,
            description:
              `Tool "${toolB.name}" was affected by a previous call to "${toolA.name}". ` +
              `This indicates shared state between tools — a critical isolation failure. ` +
              `An attacker could use this to escalate privileges: set malicious state with ` +
              `one tool, then exploit it with another tool that has different permissions.`,
            evidence: {
              sourceTool: toolA.name,
              targetTool: toolB.name,
              markerSentToSource: marker,
              targetOutput: responseB.substring(0, 300),
            },
            remediation:
              "Isolate all tool invocations completely. Each tool should use independent " +
              "connections, sessions, and resources. Never share state between tools, " +
              "especially across different permission levels.",
            toolName: toolB.name,
            cweId: "CWE-284", // Improper Access Control
            confidence: 0.9,
          },
        };
      }

      return null;
    } catch {
      return null;
    }
  }

  /**
   * Check if two tools are similar enough to potentially share state.
   */
  private areToolsSimilar(a: ToolInfo, b: ToolInfo): boolean {
    const nameA = a.name.toLowerCase();
    const nameB = b.name.toLowerCase();
    const descA = (a.description ?? "").toLowerCase();
    const descB = (b.description ?? "").toLowerCase();

    // Same domain keywords
    const domains = ["file", "db", "query", "read", "write", "fetch", "send", "email", "auth"];
    const domainA = domains.find((d) => nameA.includes(d) || descA.includes(d));
    const domainB = domains.find((d) => nameB.includes(d) || descB.includes(d));

    return domainA === domainB && domainA !== undefined;
  }

  private findStringParam(tool: ToolInfo): string | null {
    const props = (tool.inputSchema as any)?.properties;
    if (!props) return null;
    for (const [key, val] of Object.entries(props)) {
      if ((val as any).type === "string") return key;
    }
    return null;
  }
}
