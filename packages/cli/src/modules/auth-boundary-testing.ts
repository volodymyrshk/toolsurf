import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
  type ToolInfo,
} from "../types/index.js";

/**
 * Auth Boundary Testing Module (Active).
 *
 * Probes whether tools enforce authorization scoping:
 * 1. Cross-tool data leakage: Can one tool's output reference another tool's scope?
 * 2. Privilege escalation: Can a read-only tool be tricked into write operations?
 * 3. Resource boundary: Can tools access resources outside their declared scope?
 * 4. Token/session confusion: Do tools properly isolate per-session state?
 *
 * ACTIVE MODULE: makes tool calls to the server.
 *
 * CWE-863: Incorrect Authorization
 */
export class AuthBoundaryTestingModule implements AuditModule {
  id = "auth-boundary-testing";
  name = "Auth Boundary Testing";
  description =
    "Probes whether tools enforce authorization scoping and access boundaries";
  version = "1.0.0";
  mode = "active" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const { tools } = context.capabilities;

    if (!context.callTool) {
      checks.push({
        id: "AB-001",
        name: "Cross-tool data leakage",
        status: CheckStatus.SKIP,
        message: "Requires --active flag",
      });
      checks.push({
        id: "AB-002",
        name: "Privilege escalation via annotations",
        status: CheckStatus.SKIP,
        message: "Requires --active flag",
      });
      checks.push({
        id: "AB-003",
        name: "Resource boundary enforcement",
        status: CheckStatus.SKIP,
        message: "Requires --active flag",
      });
      return checks;
    }

    const probeDelay = context.probeDelay ?? 100;
    const progress = context.onProgress;

    // Check 1: Cross-tool data leakage
    progress?.("Auth: Cross-tool leakage");
    checks.push(
      ...await this.testCrossToolLeakage(tools, context.callTool, probeDelay, context.verbose)
    );

    // Check 2: Privilege escalation via annotation mismatch
    progress?.("Auth: Privilege escalation");
    checks.push(
      ...await this.testPrivilegeEscalation(tools, context.callTool, probeDelay, context.verbose)
    );

    // Check 3: Resource boundary enforcement
    progress?.("Auth: Resource boundaries");
    checks.push(
      ...await this.testResourceBoundaries(tools, context.callTool, probeDelay, context.verbose)
    );

    // Check 4: Confused deputy detection
    progress?.("Auth: Confused deputy");
    checks.push(
      ...await this.testConfusedDeputy(tools, context.callTool, probeDelay, context.verbose)
    );

    return checks;
  }

  /**
   * Test if tools leak data from other tools' scopes.
   * Call tool A with references to tool B's namespace/data.
   */
  private async testCrossToolLeakage(
    tools: ToolInfo[],
    callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
    probeDelay: number,
    verbose: boolean
  ): Promise<CheckResult[]> {
    const leaks: Array<{
      sourceTool: string;
      targetTool: string;
      probe: string;
      response: string;
    }> = [];

    // Only test if there are multiple tools
    if (tools.length < 2) {
      return [{
        id: "AB-001",
        name: "Cross-tool data leakage",
        status: CheckStatus.PASS,
        message: "Fewer than 2 tools — cross-tool testing not applicable",
      }];
    }

    // Prepare candidates: tools with string params
    const candidates = tools.slice(0, 5)
      .map((tool) => {
        const properties = (tool.inputSchema as Record<string, unknown>).properties as
          Record<string, Record<string, unknown>> | undefined;
        if (!properties) return null;
        const stringParam = Object.entries(properties).find(
          ([, schema]) => (schema as Record<string, unknown>).type === "string"
        );
        if (!stringParam) return null;
        return { tool, paramName: stringParam[0] };
      })
      .filter((c): c is { tool: ToolInfo; paramName: string } => c !== null);

    // Build probe tasks for all candidate tool pairs
    const probeTasks: Array<{
      tool: ToolInfo;
      paramName: string;
      otherTool: ToolInfo;
      probes: string[];
    }> = [];
    for (const { tool, paramName } of candidates) {
      for (const otherTool of tools) {
        if (otherTool.name === tool.name) continue;
        probeTasks.push({
          tool, paramName, otherTool,
          probes: [
            `../../../${otherTool.name}`,
            `__tool__:${otherTool.name}`,
            `${otherTool.name}://internal`,
          ],
        });
      }
    }

    // Execute probe batches in parallel (batch size 4 to respect rate limits)
    const BATCH_SIZE = 4;
    for (let i = 0; i < probeTasks.length; i += BATCH_SIZE) {
      const batch = probeTasks.slice(i, i + BATCH_SIZE);
      if (probeDelay > 0) await new Promise((r) => setTimeout(r, probeDelay));

      await Promise.allSettled(
        batch.map(async ({ tool, paramName, otherTool, probes }) => {
          // Skip if we already found a leak for this source tool
          if (leaks.some((l) => l.sourceTool === tool.name)) return;

          for (const probe of probes) {
            try {
              if (verbose) console.error(`[toolsurf:auth] Cross-tool: ${tool.name} -> ${otherTool.name}`);
              const result = await callTool(tool.name, { [paramName]: probe });
              const responseStr = typeof result === "string" ? result : JSON.stringify(result);

              if (this.containsCrossToolData(responseStr, otherTool)) {
                leaks.push({
                  sourceTool: tool.name,
                  targetTool: otherTool.name,
                  probe,
                  response: responseStr.substring(0, 200),
                });
                break;
              }
            } catch {
              // Expected — tool rejected the cross-reference
            }
          }
        })
      );
    }

    if (leaks.length === 0) {
      return [{
        id: "AB-001",
        name: "Cross-tool data leakage",
        status: CheckStatus.PASS,
        message: `${candidates.length} tool(s) show no cross-tool data leakage`,
      }];
    }

    return [{
      id: "AB-001",
      name: "Cross-tool data leakage",
      status: CheckStatus.FAIL,
      message: `${leaks.length} cross-tool data leak(s) detected`,
      finding: {
        id: "AB-001",
        module: this.id,
        severity: Severity.HIGH,
        title: "Cross-tool data leakage detected",
        description:
          `${leaks.length} tool(s) leaked data from other tools' scopes when ` +
          "probed with cross-tool references. This indicates insufficient authorization " +
          "boundaries between tools, allowing one tool to access another's data.",
        evidence: { leaks },
        remediation:
          "Implement strict authorization boundaries between tools. " +
          "Each tool should only access its own designated resources. " +
          "Validate and sanitize all path-like inputs to prevent scope traversal. " +
          "Use namespace isolation to prevent cross-tool data access.",
        cweId: "CWE-863",
      },
    }];
  }

  /**
   * Test if read-only tools can be tricked into performing writes.
   * Send write-like commands through read-only tool parameters.
   */
  private async testPrivilegeEscalation(
    tools: ToolInfo[],
    callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
    probeDelay: number,
    verbose: boolean
  ): Promise<CheckResult[]> {
    const readOnlyTools = tools.filter((t) => t.annotations?.readOnlyHint === true);

    if (readOnlyTools.length === 0) {
      return [{
        id: "AB-002",
        name: "Privilege escalation via annotations",
        status: CheckStatus.PASS,
        message: "No read-only annotated tools to test",
      }];
    }

    const escalations: Array<{
      tool: string;
      probe: string;
      signals: string[];
    }> = [];

    const writeProbes = [
      { arg: "DELETE", signals: ["deleted", "removed", "dropped"] },
      { arg: "CREATE", signals: ["created", "inserted", "added"] },
      { arg: "UPDATE", signals: ["updated", "modified", "changed"] },
      { arg: "WRITE", signals: ["written", "saved", "stored"] },
    ];

    for (const tool of readOnlyTools.slice(0, 5)) {
      const properties = (tool.inputSchema as Record<string, unknown>).properties as
        Record<string, Record<string, unknown>> | undefined;
      if (!properties) continue;

      // Find a string parameter
      const stringParam = Object.entries(properties).find(
        ([, schema]) => (schema as Record<string, unknown>).type === "string"
      );
      if (!stringParam) continue;
      const [paramName] = stringParam;

      // Build base args with required params
      const required = ((tool.inputSchema as Record<string, unknown>).required ?? []) as string[];
      const args: Record<string, unknown> = {};
      for (const param of required) {
        if (param === paramName) continue;
        const schema = properties[param];
        args[param] = this.getDefaultValue((schema as Record<string, unknown>)?.type as string);
      }

      for (const probe of writeProbes) {
        try {
          if (probeDelay > 0) await new Promise((r) => setTimeout(r, probeDelay));
          if (verbose) console.error(`[toolsurf:auth] Privesc: ${tool.name} with ${probe.arg}`);

          const result = await callTool(tool.name, {
            ...args,
            [paramName]: probe.arg,
          });
          const responseStr = typeof result === "string" ? result : JSON.stringify(result);
          const lower = responseStr.toLowerCase();

          const hitSignals = probe.signals.filter((s) => lower.includes(s));
          if (hitSignals.length > 0) {
            escalations.push({
              tool: tool.name,
              probe: probe.arg,
              signals: hitSignals,
            });
            break;
          }
        } catch {
          // Expected
        }
      }
    }

    if (escalations.length === 0) {
      return [{
        id: "AB-002",
        name: "Privilege escalation via annotations",
        status: CheckStatus.PASS,
        message: `${readOnlyTools.length} read-only tool(s) resist privilege escalation`,
      }];
    }

    return [{
      id: "AB-002",
      name: "Privilege escalation via annotations",
      status: CheckStatus.WARN,
      message: `${escalations.length} read-only tool(s) show write-like behavior`,
      finding: {
        id: "AB-002",
        module: this.id,
        severity: Severity.HIGH,
        title: "Read-only tools may perform write operations",
        description:
          `${escalations.length} tool(s) annotated as read-only returned responses ` +
          "containing write-operation signals when probed with write-like inputs. " +
          "This may indicate that the read-only annotation is not enforced server-side.",
        evidence: { escalations },
        remediation:
          "Enforce read-only behavior at the implementation level, not just annotations. " +
          "Read-only tools should reject any input that could trigger mutations. " +
          "Implement RBAC (Role-Based Access Control) at the tool level.",
        cweId: "CWE-269",
      },
    }];
  }

  /**
   * Test if tools with file/path/URL params enforce boundary constraints.
   * Attempt to access resources outside the expected scope.
   */
  private async testResourceBoundaries(
    tools: ToolInfo[],
    callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
    probeDelay: number,
    verbose: boolean
  ): Promise<CheckResult[]> {
    const PATH_PARAM = /^(path|file|filepath|filename|dir|directory|folder|uri|url|location|resource)$/i;

    const candidates = tools.filter((t) => {
      const props = (t.inputSchema as Record<string, unknown>).properties as
        Record<string, unknown> | undefined;
      if (!props) return false;
      return Object.keys(props).some((k) => PATH_PARAM.test(k));
    }).slice(0, 5);

    if (candidates.length === 0) {
      return [{
        id: "AB-003",
        name: "Resource boundary enforcement",
        status: CheckStatus.PASS,
        message: "No tools with path/resource parameters found",
      }];
    }

    const violations: Array<{
      tool: string;
      param: string;
      probe: string;
      response: string;
    }> = [];

    const boundaryProbes = [
      "/etc/shadow",
      "/proc/self/environ",
      "file:///etc/hostname",
      "C:\\Windows\\System32\\config\\SAM",
      "~/.ssh/id_rsa",
    ];

    for (const tool of candidates) {
      const properties = (tool.inputSchema as Record<string, unknown>).properties as
        Record<string, Record<string, unknown>>;

      const pathParam = Object.entries(properties).find(
        ([key]) => PATH_PARAM.test(key)
      );
      if (!pathParam) continue;
      const [paramName] = pathParam;

      // Build base args with required params
      const required = ((tool.inputSchema as Record<string, unknown>).required ?? []) as string[];
      const args: Record<string, unknown> = {};
      for (const param of required) {
        if (param === paramName) continue;
        const schema = properties[param];
        args[param] = this.getDefaultValue(schema?.type as string);
      }

      for (const probe of boundaryProbes) {
        try {
          if (probeDelay > 0) await new Promise((r) => setTimeout(r, probeDelay));
          if (verbose) console.error(`[toolsurf:auth] Boundary: ${tool.name}.${paramName} = ${probe}`);

          const result = await callTool(tool.name, {
            ...args,
            [paramName]: probe,
          });
          const responseStr = typeof result === "string" ? result : JSON.stringify(result);

          // Check if the response contains actual file content (not just error messages)
          if (this.containsSensitiveContent(responseStr)) {
            violations.push({
              tool: tool.name,
              param: paramName,
              probe,
              response: responseStr.substring(0, 200),
            });
            break; // One violation per tool is enough
          }
        } catch {
          // Expected — tool properly rejects out-of-scope access
        }
      }
    }

    if (violations.length === 0) {
      return [{
        id: "AB-003",
        name: "Resource boundary enforcement",
        status: CheckStatus.PASS,
        message: `${candidates.length} tool(s) enforce resource boundaries`,
      }];
    }

    return [{
      id: "AB-003",
      name: "Resource boundary enforcement",
      status: CheckStatus.FAIL,
      message: `${violations.length} tool(s) allow out-of-scope resource access`,
      finding: {
        id: "AB-003",
        module: this.id,
        severity: Severity.CRITICAL,
        title: "Tools allow access to out-of-scope resources",
        description:
          `${violations.length} tool(s) returned content from sensitive system paths ` +
          "when probed with out-of-scope resource references. This indicates missing or " +
          "inadequate path validation and access control enforcement.",
        evidence: { violations },
        remediation:
          "Implement strict path canonicalization and boundary checking. " +
          "Maintain an allowlist of accessible paths/resources per tool. " +
          "Reject all path traversal patterns and absolute paths outside scope. " +
          "Use chroot or container isolation for file-system tools.",
        cweId: "CWE-22",
      },
    }];
  }

  /**
   * Test for confused deputy vulnerabilities where a tool acts on behalf of
   * a low-privileged caller but uses its own high-privileged credentials.
   *
   * The test probes tools with admin/root/system-level identifiers to see
   * if the tool performs privileged operations without validating caller authorization.
   *
   * CWE-441: Unintended Proxy or Intermediary (Confused Deputy)
   */
  private async testConfusedDeputy(
    tools: ToolInfo[],
    callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
    probeDelay: number,
    verbose: boolean
  ): Promise<CheckResult[]> {
    const deputyFindings: Array<{
      tool: string;
      probe: string;
      signals: string[];
    }> = [];

    // Focus on tools that likely interact with auth-gated resources
    const authTools = tools.filter((t) => {
      const name = t.name.toLowerCase();
      const desc = (t.description ?? "").toLowerCase();
      return /database|query|sql|api|admin|user|account|file|read|write|delete|create|execute/i.test(name + " " + desc);
    }).slice(0, 5);

    if (authTools.length === 0) {
      return [{
        id: "AB-004",
        name: "Confused deputy detection",
        status: CheckStatus.PASS,
        message: "No authority-sensitive tools found to test",
      }];
    }

    // Privilege escalation probes — attempt to invoke tools as admin/root
    const deputyProbes = [
      { args: { user: "admin", role: "administrator" }, desc: "admin role injection" },
      { args: { user_id: "1", admin: true }, desc: "admin flag injection" },
      { args: { scope: "admin:*", permission: "root" }, desc: "scope escalation" },
      { args: { __admin: true, sudo: true }, desc: "hidden admin parameter" },
      { args: { authorization: "Bearer admin", x_user_role: "superadmin" }, desc: "auth header injection" },
    ];

    for (const tool of authTools) {
      const properties = (tool.inputSchema as Record<string, unknown>).properties as
        Record<string, Record<string, unknown>> | undefined;
      if (!properties) continue;

      // Build base args with required params
      const required = ((tool.inputSchema as Record<string, unknown>).required ?? []) as string[];
      const baseArgs: Record<string, unknown> = {};
      for (const param of required) {
        const schema = properties[param];
        baseArgs[param] = this.getDefaultValue(schema?.type as string);
      }

      for (const probe of deputyProbes) {
        try {
          if (probeDelay > 0) await new Promise((r) => setTimeout(r, probeDelay));
          if (verbose) console.error(`[toolsurf:auth] Deputy: ${tool.name} with ${probe.desc}`);

          const result = await callTool(tool.name, { ...baseArgs, ...probe.args });
          const responseStr = typeof result === "string" ? result : JSON.stringify(result);
          const lower = responseStr.toLowerCase();

          // Check if the response indicates privileged access was granted
          const privilegeSignals = [
            "admin", "administrator", "superuser", "root access",
            "elevated", "privileged", "all permissions", "full access",
            "authorized as admin", "role: admin",
          ];

          const hitSignals = privilegeSignals.filter((s) => lower.includes(s));

          // Filter out error messages that just echo back our input
          const isError = lower.includes("error") || lower.includes("invalid") || lower.includes("denied");

          if (hitSignals.length > 0 && !isError) {
            deputyFindings.push({
              tool: tool.name,
              probe: probe.desc,
              signals: hitSignals,
            });
            break; // One finding per tool is enough
          }
        } catch {
          // Expected — tool rejected the probe
        }
      }
    }

    if (deputyFindings.length === 0) {
      return [{
        id: "AB-004",
        name: "Confused deputy detection",
        status: CheckStatus.PASS,
        message: `${authTools.length} tool(s) resist confused deputy probes`,
      }];
    }

    return [{
      id: "AB-004",
      name: "Confused deputy detection",
      status: CheckStatus.FAIL,
      message: `${deputyFindings.length} tool(s) may be vulnerable to confused deputy attacks`,
      finding: {
        id: "AB-004",
        module: this.id,
        severity: Severity.HIGH,
        title: "Confused deputy vulnerability detected",
        description:
          `${deputyFindings.length} tool(s) accepted privilege escalation parameters and returned ` +
          "responses indicating elevated access. This suggests the tool acts with its own elevated " +
          "credentials without validating the caller's authorization level (confused deputy pattern). " +
          "An LLM agent could be tricked into invoking these tools with injected admin parameters.",
        evidence: { deputyFindings },
        remediation:
          "Implement caller-level authorization validation in every tool. " +
          "Do not accept user/role/permission parameters from untrusted input. " +
          "Use the authenticated session's actual permissions, not client-supplied claims. " +
          "Apply the principle of least privilege to all tool operations.",
        cweId: "CWE-441",
      },
    }];
  }

  private containsCrossToolData(response: string, otherTool: ToolInfo): boolean {
    const lower = response.toLowerCase();
    const otherName = otherTool.name.toLowerCase();
    // Check if the response mentions the other tool's name in a data-like context
    return (
      lower.includes(`"${otherName}"`) ||
      lower.includes(`'${otherName}'`) ||
      lower.includes(`tool: ${otherName}`) ||
      lower.includes(`name: ${otherName}`)
    );
  }

  private containsSensitiveContent(response: string): boolean {
    const lower = response.toLowerCase();

    // First, check if this looks like an error/rejection response
    // Error messages that MENTION sensitive paths are not leaks
    const errorSignals = [
      "error", "denied", "not found", "not allowed", "permission",
      "forbidden", "cannot access", "no such file", "does not exist",
      "outside", "restricted", "unauthorized", "invalid path",
      "is not allowed", "access denied", "eacces", "enoent", "eperm",
    ];
    const isErrorResponse = errorSignals.some((s) => lower.includes(s));

    // If the response is just an error/rejection, it's NOT a leak
    // even if it mentions sensitive path names in the error message
    if (isErrorResponse && response.length < 500) {
      return false;
    }

    // Look for actual sensitive FILE CONTENT (not just path mentions)
    // /etc/passwd format: username:x:uid:gid:comment:home:shell
    // /etc/shadow format: username:$6$salt$hash:lastchange:min:max:warn:...
    const passwdLine = /^[a-z_][\w-]*:[^\n:]*:\d+:\d+:/m.test(response);
    // SSH private key content
    const sshKey = lower.includes("ssh-rsa aaaa") ||
      lower.includes("begin rsa private key") ||
      lower.includes("begin openssh private key");
    // Environment variable dump (KEY=value format, multiple lines)
    const envDump = (response.match(/^[A-Z_]+=.+$/gm) ?? []).length >= 3;
    // Windows SAM hive content
    const samContent = lower.includes("[boot loader]") && lower.includes("timeout=");
    // Actual credential values (not just field names)
    const credentialValues = /(?:password|secret|token|api.?key)\s*[=:]\s*[^\s]{8,}/i.test(response);

    return passwdLine || sshKey || envDump || samContent || credentialValues;
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
}
