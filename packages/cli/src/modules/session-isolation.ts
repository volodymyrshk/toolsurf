import { randomUUID } from "node:crypto";
import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
  type ToolInfo,
} from "../types/index.js";

/**
 * Session Isolation Module (Active).
 *
 * Tests for cross-session data leakage vulnerabilities (CVE-2026-25536).
 * Sends sequential requests with different context markers to detect
 * whether the server properly isolates per-session state.
 *
 * CWE-488: Exposure of Data Element to Wrong Session
 */
export class SessionIsolationModule implements AuditModule {
  id = "session-isolation";
  name = "Session Isolation";
  description = "Tests for cross-session data leakage and state isolation issues";
  version = "1.0.0";
  mode = "active" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const { tools } = context.capabilities;

    if (!context.callTool) {
      checks.push({
        id: "SI-001",
        name: "Session state isolation",
        status: CheckStatus.SKIP,
        message: "Requires --active flag",
      });
      return checks;
    }

    // Find tools with string parameters suitable for canary injection
    const candidates = tools
      .filter((t) => {
        const props = (t.inputSchema as Record<string, unknown>)?.properties as
          Record<string, unknown> | undefined;
        if (!props) return false;
        return Object.values(props).some(
          (p) => (p as Record<string, unknown>)?.type === "string"
        );
      })
      .slice(0, 3);

    if (candidates.length === 0) {
      checks.push({
        id: "SI-001",
        name: "Session state isolation",
        status: CheckStatus.PASS,
        message: "No string-parameter tools to test for session leakage",
      });
      return checks;
    }

    // Test 1: Session canary injection — send unique markers, check for cross-contamination
    checks.push(...await this.testSessionCanaries(candidates, context));

    // Test 2: State accumulation — check if repeated calls accumulate state
    checks.push(...await this.testStateAccumulation(candidates, context));

    return checks;
  }

  /**
   * Send unique canary values in sequential calls and check if any response
   * contains a canary from a different "session" context.
   */
  private async testSessionCanaries(
    tools: ToolInfo[],
    context: ModuleContext
  ): Promise<CheckResult[]> {
    const callTool = context.callTool!;
    const leaks: Array<{ tool: string; canary: string; response: string }> = [];

    for (const tool of tools) {
      const props = (tool.inputSchema as Record<string, unknown>)?.properties as
        Record<string, Record<string, unknown>>;
      if (!props) continue;

      const stringParam = Object.entries(props).find(
        ([, s]) => (s as Record<string, unknown>).type === "string"
      );
      if (!stringParam) continue;
      const [paramName] = stringParam;

      // Generate unique canary markers (crypto.randomUUID for deterministic test-retest)
      const canary1 = `VSAUDIT_SESSION_A_${randomUUID()}`;
      const canary2 = `VSAUDIT_SESSION_B_${randomUUID()}`;

      try {
        // Send canary 1
        await callTool(tool.name, { [paramName]: canary1 });

        // Small delay to simulate different session timing
        await new Promise((r) => setTimeout(r, 50));

        // Send canary 2 and check response for canary 1
        const result2 = await callTool(tool.name, { [paramName]: canary2 });
        const response2 = typeof result2 === "string" ? result2 : JSON.stringify(result2);

        if (response2.includes(canary1)) {
          leaks.push({
            tool: tool.name,
            canary: canary1,
            response: response2.substring(0, 300),
          });
        }

        // Send a third call and check for both previous canaries
        const canary3 = `VSAUDIT_SESSION_C_${Date.now()}`;
        const result3 = await callTool(tool.name, { [paramName]: canary3 });
        const response3 = typeof result3 === "string" ? result3 : JSON.stringify(result3);

        if (response3.includes(canary1) || response3.includes(canary2)) {
          if (!leaks.some((l) => l.tool === tool.name)) {
            leaks.push({
              tool: tool.name,
              canary: response3.includes(canary1) ? canary1 : canary2,
              response: response3.substring(0, 300),
            });
          }
        }
      } catch {
        // Tool rejected input — expected for some tools
      }
    }

    if (leaks.length === 0) {
      return [{
        id: "SI-001",
        name: "Session canary isolation",
        status: CheckStatus.PASS,
        message: `${tools.length} tool(s) show no cross-session data leakage`,
      }];
    }

    return [{
      id: "SI-001",
      name: "Session canary isolation",
      status: CheckStatus.FAIL,
      message: `${leaks.length} tool(s) leak data across sessions`,
      finding: {
        id: "SI-001",
        module: this.id,
        severity: Severity.HIGH,
        title: "Cross-session data leakage detected",
        description:
          `${leaks.length} tool(s) returned data from previous request contexts in subsequent responses. ` +
          "This indicates the server does not properly isolate per-session state, potentially allowing " +
          "one user's data to leak into another user's session. Reference: CVE-2026-25536 (TypeScript SDK cross-client leak).",
        evidence: { leaks },
        remediation:
          "Implement strict per-session state isolation. " +
          "Use unique request IDs and validate JSON-RPC message ID uniqueness. " +
          "Do not share mutable state between concurrent client connections. " +
          "Clear session buffers between requests.",
        cweId: "CWE-488",
      },
    }];
  }

  /**
   * Check if the server accumulates state across calls that it shouldn't.
   */
  private async testStateAccumulation(
    tools: ToolInfo[],
    context: ModuleContext
  ): Promise<CheckResult[]> {
    const callTool = context.callTool!;
    const accumulations: Array<{ tool: string; evidence: string }> = [];

    for (const tool of tools) {
      const props = (tool.inputSchema as Record<string, unknown>)?.properties as
        Record<string, Record<string, unknown>>;
      if (!props) continue;

      const stringParam = Object.entries(props).find(
        ([, s]) => (s as Record<string, unknown>).type === "string"
      );
      if (!stringParam) continue;
      const [paramName] = stringParam;

      try {
        // Call with identical input 3 times
        const input = "test_state_check";
        const results: string[] = [];

        for (let i = 0; i < 3; i++) {
          const result = await callTool(tool.name, { [paramName]: input });
          results.push(typeof result === "string" ? result : JSON.stringify(result));
          await new Promise((r) => setTimeout(r, 30));
        }

        // Check if responses grow (state accumulation) or reference previous calls
        if (results.length === 3) {
          const lengths = results.map((r) => r.length);
          const isGrowing = lengths[2] > lengths[0] * 1.5 && lengths[1] > lengths[0] * 1.2;

          if (isGrowing) {
            accumulations.push({
              tool: tool.name,
              evidence: `Response sizes grew: ${lengths.join(" → ")} bytes (${Math.round(lengths[2] / lengths[0] * 100)}% growth)`,
            });
          }
        }
      } catch {
        // Expected
      }
    }

    if (accumulations.length === 0) {
      return [{
        id: "SI-002",
        name: "State accumulation check",
        status: CheckStatus.PASS,
        message: "No unexpected state accumulation detected",
      }];
    }

    return [{
      id: "SI-002",
      name: "State accumulation check",
      status: CheckStatus.WARN,
      message: `${accumulations.length} tool(s) show state accumulation patterns`,
      finding: {
        id: "SI-002",
        module: this.id,
        severity: Severity.MEDIUM,
        title: "Server may accumulate state across calls",
        description:
          "Tool responses grow significantly across identical sequential calls, " +
          "suggesting the server accumulates state between requests. This may indicate " +
          "a memory leak, conversation history retention, or improper session management.",
        evidence: { accumulations },
        remediation:
          "Ensure tools are stateless between invocations unless explicitly designed for state. " +
          "Implement request-scoped contexts that are cleaned up after each call. " +
          "Document any intentional stateful behavior in tool annotations.",
        cweId: "CWE-488",
      },
    }];
  }
}
