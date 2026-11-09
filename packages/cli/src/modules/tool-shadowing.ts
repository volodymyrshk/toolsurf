import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
  type ToolInfo,
} from "../types/index.js";

/**
 * Tool Shadowing Detection Module (Active).
 *
 * Detects tools whose *actual behavior* contradicts their declared metadata:
 * 1. Schema honesty: does the tool reject inputs that violate its declared schema?
 * 2. readOnlyHint honesty: does a "read-only" tool actually modify state?
 * 3. Side-channel detection: does a tool produce unexpected side effects?
 * 4. Description honesty: does the tool's response match what it claims to do?
 *
 * ACTIVE MODULE: makes tool calls to the server.
 *
 * CWE-912: Hidden Functionality
 */
export class ToolShadowingModule implements AuditModule {
  id = "tool-shadowing";
  name = "Tool Shadowing Detection";
  description =
    "Detects tools whose actual behavior contradicts their declared schema and annotations";
  version = "1.0.0";
  mode = "active" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const { tools } = context.capabilities;

    if (!context.callTool) {
      checks.push({
        id: "TS-001",
        name: "Schema honesty testing",
        status: CheckStatus.SKIP,
        message: "Requires --active flag",
      });
      checks.push({
        id: "TS-002",
        name: "Read-only annotation honesty",
        status: CheckStatus.SKIP,
        message: "Requires --active flag",
      });
      checks.push({
        id: "TS-003",
        name: "Undeclared parameter acceptance",
        status: CheckStatus.SKIP,
        message: "Requires --active flag",
      });
      return checks;
    }

    const probeDelay = context.probeDelay ?? 100;
    const progress = context.onProgress;

    // Check 1: Schema honesty — do tools reject invalid inputs?
    progress?.("Shadowing: Schema honesty");
    checks.push(...await this.testSchemaHonesty(tools, context.callTool, probeDelay, context.verbose));

    // Check 2: Read-only annotation honesty
    progress?.("Shadowing: Read-only honesty");
    checks.push(...await this.testReadOnlyHonesty(tools, context.callTool, probeDelay, context.verbose));

    // Check 3: Undeclared parameter acceptance
    progress?.("Shadowing: Undeclared params");
    checks.push(...await this.testUndeclaredParams(tools, context.callTool, probeDelay, context.verbose));

    return checks;
  }

  /**
   * Test if tools enforce their declared input schemas.
   * Send inputs that violate type constraints and see if they're accepted.
   */
  private async testSchemaHonesty(
    tools: ToolInfo[],
    callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
    probeDelay: number,
    verbose: boolean
  ): Promise<CheckResult[]> {
    const violations: Array<{
      tool: string;
      test: string;
      detail: string;
    }> = [];

    // Test up to 5 tools with required params
    const candidates = tools
      .filter((t) => {
        const required = (t.inputSchema as Record<string, unknown>)?.required;
        return Array.isArray(required) && required.length > 0;
      })
      .slice(0, 5);

    if (candidates.length === 0) {
      return [{
        id: "TS-001",
        name: "Schema honesty testing",
        status: CheckStatus.PASS,
        message: "No tools with required params to test",
      }];
    }

    for (const tool of candidates) {
      const required = (tool.inputSchema as Record<string, unknown>).required as string[];
      const properties = (tool.inputSchema as Record<string, unknown>).properties as
        Record<string, Record<string, unknown>> | undefined;

      if (!properties) continue;

      // Test 1: Call with missing required params (should fail)
      try {
        if (probeDelay > 0) await new Promise((r) => setTimeout(r, probeDelay));
        if (verbose) console.error(`[toolsurf:shadow] Schema test: ${tool.name} with empty args`);

        await callTool(tool.name, {});
        // If this succeeds, the tool doesn't enforce required params
        violations.push({
          tool: tool.name,
          test: "missing-required",
          detail: `Accepted call with no args despite requiring: ${required.join(", ")}`,
        });
      } catch {
        // Expected — tool correctly rejects missing params
      }

      // Test 2: Send wrong types for declared params
      for (const paramName of required.slice(0, 2)) {
        const paramSchema = properties[paramName];
        if (!paramSchema) continue;

        const wrongValue = this.getWrongTypeValue(paramSchema.type as string);
        if (wrongValue === undefined) continue;

        try {
          if (probeDelay > 0) await new Promise((r) => setTimeout(r, probeDelay));
          if (verbose) console.error(`[toolsurf:shadow] Type test: ${tool.name}.${paramName} expects ${paramSchema.type}, sending ${typeof wrongValue}`);

          await callTool(tool.name, { [paramName]: wrongValue });
          violations.push({
            tool: tool.name,
            test: "wrong-type",
            detail: `Param "${paramName}" accepts ${typeof wrongValue} despite declaring type "${paramSchema.type}"`,
          });
        } catch {
          // Expected
        }
      }
    }

    if (violations.length === 0) {
      return [{
        id: "TS-001",
        name: "Schema honesty testing",
        status: CheckStatus.PASS,
        message: `${candidates.length} tool(s) correctly enforce their declared schemas`,
      }];
    }

    return [{
      id: "TS-001",
      name: "Schema honesty testing",
      status: CheckStatus.FAIL,
      message: `${violations.length} schema violation(s) accepted`,
      finding: {
        id: "TS-001",
        module: this.id,
        severity: Severity.MEDIUM,
        title: "Tools do not enforce their declared input schemas",
        description:
          `${violations.length} tool(s) accepted inputs that violate their declared schemas. ` +
          "This indicates the schema is decorative rather than enforced, which means " +
          "input validation cannot be trusted and unexpected inputs may reach server logic.",
        evidence: { violations },
        remediation:
          "Enforce input validation matching the declared schema on the server side. " +
          "Reject calls with missing required parameters or wrong types. " +
          "Use runtime schema validation libraries (e.g., zod, ajv).",
        cweId: "CWE-20",
      },
    }];
  }

  /**
   * Test if tools marked readOnlyHint=true actually avoid mutation.
   * Call them and look for mutation signals in the response.
   */
  private async testReadOnlyHonesty(
    tools: ToolInfo[],
    callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
    probeDelay: number,
    verbose: boolean
  ): Promise<CheckResult[]> {
    const readOnlyTools = tools.filter((t) => t.annotations?.readOnlyHint === true);

    if (readOnlyTools.length === 0) {
      return [{
        id: "TS-002",
        name: "Read-only annotation honesty",
        status: CheckStatus.PASS,
        message: "No tools declare readOnlyHint",
      }];
    }

    const suspicious: Array<{
      tool: string;
      signals: string[];
    }> = [];

    const mutationSignals = [
      "created", "deleted", "removed", "modified", "updated",
      "written", "saved", "inserted", "dropped", "truncated",
      "moved", "renamed", "overwritten", "sent", "posted",
    ];

    for (const tool of readOnlyTools.slice(0, 5)) {
      const properties = (tool.inputSchema as Record<string, unknown>).properties as
        Record<string, Record<string, unknown>> | undefined;

      // Build minimal valid args
      const args: Record<string, unknown> = {};
      const required = ((tool.inputSchema as Record<string, unknown>).required ?? []) as string[];
      for (const param of required) {
        const schema = properties?.[param];
        args[param] = this.getDefaultValue(schema?.type as string);
      }

      try {
        if (probeDelay > 0) await new Promise((r) => setTimeout(r, probeDelay));
        if (verbose) console.error(`[toolsurf:shadow] ReadOnly test: ${tool.name}`);

        const result = await callTool(tool.name, args);
        const responseStr = typeof result === "string" ? result : JSON.stringify(result);
        const lower = responseStr.toLowerCase();

        const hitSignals = mutationSignals.filter((s) => lower.includes(s));
        if (hitSignals.length >= 2) {
          suspicious.push({ tool: tool.name, signals: hitSignals });
        }
      } catch {
        // Error is fine — tool rejected our minimal input
      }
    }

    if (suspicious.length === 0) {
      return [{
        id: "TS-002",
        name: "Read-only annotation honesty",
        status: CheckStatus.PASS,
        message: `${readOnlyTools.length} read-only tool(s) show no mutation signals`,
      }];
    }

    return [{
      id: "TS-002",
      name: "Read-only annotation honesty",
      status: CheckStatus.WARN,
      message: `${suspicious.length} read-only tool(s) show mutation signals`,
      finding: {
        id: "TS-002",
        module: this.id,
        severity: Severity.HIGH,
        title: "Read-only tools may perform mutations",
        description:
          `${suspicious.length} tool(s) annotated as readOnlyHint=true returned responses ` +
          "containing mutation signals (created, deleted, modified, etc.). " +
          "This could indicate the tool performs hidden write operations despite declaring read-only behavior.",
        evidence: { suspicious },
        remediation:
          "Audit tool implementations to ensure readOnlyHint accurately reflects behavior. " +
          "Read-only tools must never modify state. Remove the annotation if the tool performs writes.",
        cweId: "CWE-912",
      },
    }];
  }

  /**
   * Test if tools accept undeclared parameters not in their schema.
   * This can reveal hidden functionality or debug backdoors.
   */
  private async testUndeclaredParams(
    tools: ToolInfo[],
    callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
    probeDelay: number,
    verbose: boolean
  ): Promise<CheckResult[]> {
    const accepting: Array<{
      tool: string;
      param: string;
      response: string;
    }> = [];

    const suspiciousParams = [
      { name: "__debug", value: true },
      { name: "__admin", value: true },
      { name: "_internal", value: "1" },
      { name: "verbose", value: true },
      { name: "raw", value: true },
      { name: "bypass_auth", value: true },
    ];

    for (const tool of tools.slice(0, 5)) {
      const properties = (tool.inputSchema as Record<string, unknown>).properties as
        Record<string, Record<string, unknown>> | undefined;
      const declaredParams = new Set(Object.keys(properties ?? {}));

      // Build minimal valid args
      const required = ((tool.inputSchema as Record<string, unknown>).required ?? []) as string[];
      const baseArgs: Record<string, unknown> = {};
      for (const param of required) {
        const schema = properties?.[param];
        baseArgs[param] = this.getDefaultValue(schema?.type as string);
      }

      // Get baseline response
      let baselineResponse = "";
      try {
        const baseResult = await callTool(tool.name, baseArgs);
        baselineResponse = typeof baseResult === "string" ? baseResult : JSON.stringify(baseResult);
      } catch {
        continue; // Can't test if baseline fails
      }

      for (const probe of suspiciousParams) {
        if (declaredParams.has(probe.name)) continue; // Skip if declared

        try {
          if (probeDelay > 0) await new Promise((r) => setTimeout(r, probeDelay));
          if (verbose) console.error(`[toolsurf:shadow] Undeclared param: ${tool.name}.${probe.name}`);

          const result = await callTool(tool.name, { ...baseArgs, [probe.name]: probe.value });
          const responseStr = typeof result === "string" ? result : JSON.stringify(result);

          // If response differs significantly from baseline, the param had an effect
          if (this.responsesDiffer(baselineResponse, responseStr)) {
            accepting.push({
              tool: tool.name,
              param: probe.name,
              response: responseStr.substring(0, 200),
            });
            break; // One undeclared param per tool is enough
          }
        } catch {
          // Expected
        }
      }
    }

    if (accepting.length === 0) {
      return [{
        id: "TS-003",
        name: "Undeclared parameter acceptance",
        status: CheckStatus.PASS,
        message: "No tools accept undeclared debug/admin parameters",
      }];
    }

    return [{
      id: "TS-003",
      name: "Undeclared parameter acceptance",
      status: CheckStatus.FAIL,
      message: `${accepting.length} tool(s) accept undeclared parameters`,
      finding: {
        id: "TS-003",
        module: this.id,
        severity: Severity.HIGH,
        title: "Tools accept undeclared debug/admin parameters",
        description:
          `${accepting.length} tool(s) accepted parameters not declared in their schema, ` +
          "and the response changed. This may indicate hidden functionality, debug backdoors, " +
          "or admin override capabilities not exposed in the tool's public API.",
        evidence: { accepting },
        remediation:
          "Reject all parameters not declared in the tool's input schema. " +
          "Use strict schema validation (additionalProperties: false). " +
          "Remove debug/admin parameters from production builds.",
        cweId: "CWE-912",
      },
    }];
  }

  private getWrongTypeValue(declaredType: string): unknown {
    switch (declaredType) {
      case "string": return 99999;
      case "number":
      case "integer": return "not_a_number";
      case "boolean": return "not_a_bool";
      case "array": return "not_an_array";
      case "object": return "not_an_object";
      default: return undefined;
    }
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

  private responsesDiffer(a: string, b: string): boolean {
    if (a === b) return false;
    // Ignore minor differences (timestamps, IDs)
    const normalize = (s: string) =>
      s.replace(/\d{4}-\d{2}-\d{2}T[\d:.]+Z?/g, "TS")
       .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, "UUID");
    const na = normalize(a);
    const nb = normalize(b);
    if (na === nb) return false;
    // Length difference > 20% or structural difference
    const lenDiff = Math.abs(na.length - nb.length) / Math.max(na.length, 1);
    return lenDiff > 0.2 || na.length === 0 !== (nb.length === 0);
  }
}
