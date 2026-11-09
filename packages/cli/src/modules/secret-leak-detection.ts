import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
  type ToolInfo,
} from "../types/index.js";

/**
 * Regex patterns for detecting leaked secrets in tool descriptions
 * and schema defaults/examples.
 */
const SECRET_PATTERNS = [
  {
    id: "api-key",
    label: "API Key",
    pattern: /(?:api[_-]?key|apikey)\s*[:=]\s*["']?[A-Za-z0-9_\-]{16,}["']?/i,
    severity: Severity.CRITICAL,
  },
  {
    id: "openai-project-key",
    label: "OpenAI Project Key",
    pattern: /\bsk-proj-[A-Za-z0-9]{20,}\b/,
    severity: Severity.CRITICAL,
  },
  {
    id: "openai-secret-key",
    label: "OpenAI Secret Key",
    pattern: /\bsk-(?:live|test)-[A-Za-z0-9]{20,}\b/i,
    severity: Severity.CRITICAL,
  },
  {
    id: "aws-access-key",
    label: "AWS Access Key",
    pattern: /AKIA[0-9A-Z]{16}/,
    severity: Severity.CRITICAL,
  },
  {
    id: "aws-secret-key",
    label: "AWS Secret Key",
    pattern: /(?:aws)?_?secret_?(?:access)?_?key\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?/i,
    severity: Severity.CRITICAL,
  },
  {
    id: "jwt",
    label: "JWT Token",
    pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-+/=]{10,}/,
    severity: Severity.HIGH,
  },
  {
    id: "github-token",
    label: "GitHub Token",
    pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/,
    severity: Severity.CRITICAL,
  },
  {
    id: "slack-token",
    label: "Slack Token",
    pattern: /xox[bporas]-[A-Za-z0-9\-]{10,}/,
    severity: Severity.HIGH,
  },
  {
    id: "private-key",
    label: "Private Key",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
    severity: Severity.CRITICAL,
  },
  {
    id: "bearer-token",
    label: "Bearer Token",
    pattern: /Bearer\s+[A-Za-z0-9_\-\.]{20,}/i,
    severity: Severity.HIGH,
  },
  {
    id: "password-assignment",
    label: "Hardcoded Password",
    pattern: /(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']/i,
    severity: Severity.HIGH,
  },
  {
    id: "connection-string",
    label: "Database Connection String",
    pattern: /(?:mongodb|postgres|mysql|redis|amqp):\/\/[^\s"']{10,}/i,
    severity: Severity.HIGH,
  },
  {
    id: "generic-secret",
    label: "Generic Secret",
    pattern: /(?:secret|token|credential)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']/i,
    severity: Severity.MEDIUM,
  },
];

/**
 * Secret Leak Detection Module.
 *
 * Passively scans MCP server metadata for accidentally exposed secrets:
 * 1. Tool descriptions containing API keys, tokens, or credentials
 * 2. Schema defaults/examples with hardcoded secrets
 * 3. Resource URIs with embedded credentials
 * 4. Prompt templates with leaked tokens
 *
 * CWE-798: Use of Hard-coded Credentials
 * CWE-200: Exposure of Sensitive Information
 */
export class SecretLeakDetectionModule implements AuditModule {
  id = "secret-leak-detection";
  name = "Secret & Token Leak Detection";
  description =
    "Scans tool schemas, descriptions, and resources for accidentally exposed secrets";
  version = "1.0.0";
  mode = "passive" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const { tools, resources, prompts } = context.capabilities;

    // Check 1: Scan tool descriptions and schemas for secrets
    checks.push(...this.scanToolSchemas(tools));

    // Check 2: Scan resource URIs for embedded credentials
    checks.push(this.scanResourceUris(resources));

    // Check 3: Scan prompt descriptions for leaked secrets
    checks.push(this.scanPromptDescriptions(prompts));

    // Check 4: Check for credential-bearing default values in schemas
    checks.push(this.scanSchemaDefaults(tools));

    return checks;
  }

  private scanToolSchemas(tools: ToolInfo[]): CheckResult[] {
    const leaks: Array<{
      tool: string;
      field: string;
      secretType: string;
      severity: Severity;
      snippet: string;
    }> = [];

    for (const tool of tools) {
      // Scan description
      if (tool.description) {
        for (const sp of SECRET_PATTERNS) {
          const match = sp.pattern.exec(tool.description);
          if (match) {
            leaks.push({
              tool: tool.name,
              field: "description",
              secretType: sp.label,
              severity: sp.severity,
              snippet: this.redact(match[0]),
            });
          }
        }
      }

      // Scan schema as string
      const schemaStr = JSON.stringify(tool.inputSchema);
      for (const sp of SECRET_PATTERNS) {
        const match = sp.pattern.exec(schemaStr);
        if (match) {
          // Avoid duplicating if already found in description
          const alreadyFound = leaks.some(
            (l) => l.tool === tool.name && l.secretType === sp.label
          );
          if (!alreadyFound) {
            leaks.push({
              tool: tool.name,
              field: "inputSchema",
              secretType: sp.label,
              severity: sp.severity,
              snippet: this.redact(match[0]),
            });
          }
        }
      }
    }

    if (leaks.length === 0) {
      return [
        {
          id: "SL-001",
          name: "Secret leak in tool schemas",
          status: CheckStatus.PASS,
          message: "No secrets detected in tool descriptions or schemas",
        },
      ];
    }

    const maxSeverity = this.maxSeverity(leaks.map((l) => l.severity));

    return [
      {
        id: "SL-001",
        name: "Secret leak in tool schemas",
        status:
          maxSeverity === Severity.CRITICAL || maxSeverity === Severity.HIGH
            ? CheckStatus.FAIL
            : CheckStatus.WARN,
        message: `${leaks.length} secret(s) detected in tool metadata`,
        finding: {
          id: "SL-001",
          module: this.id,
          severity: maxSeverity,
          title: "Secrets exposed in tool metadata",
          description:
            `${leaks.length} potential secret(s) found in tool descriptions or input schemas. ` +
            "These secrets are visible to any connected MCP client and could be harvested " +
            "by a malicious client or exposed through prompt injection attacks.",
          evidence: { leaks },
          remediation:
            "Remove all hardcoded secrets from tool descriptions and schemas. " +
            "Use environment variables or a secrets manager for credentials. " +
            "Audit server code for accidentally committed API keys.",
          cweId: "CWE-798",
        },
      },
    ];
  }

  private scanResourceUris(
    resources: Array<{ uri: string; name: string; description?: string }>
  ): CheckResult {
    const leaks: Array<{
      resource: string;
      secretType: string;
      snippet: string;
    }> = [];

    for (const resource of resources) {
      // Check URI for embedded credentials (e.g., postgres://user:pass@host)
      const credentialInUri =
        /(?:\/\/[^:]+:[^@]{4,}@)/.test(resource.uri);
      if (credentialInUri) {
        leaks.push({
          resource: resource.name,
          secretType: "Embedded Credentials in URI",
          snippet: this.redactUri(resource.uri),
        });
      }

      // Check description for secrets
      const combined = `${resource.uri} ${resource.description ?? ""}`;
      for (const sp of SECRET_PATTERNS) {
        if (sp.pattern.test(combined)) {
          leaks.push({
            resource: resource.name,
            secretType: sp.label,
            snippet: this.redact(combined.match(sp.pattern)![0]),
          });
        }
      }
    }

    if (leaks.length === 0) {
      return {
        id: "SL-002",
        name: "Secret leak in resource URIs",
        status: CheckStatus.PASS,
        message: "No secrets detected in resource URIs",
      };
    }

    return {
      id: "SL-002",
      name: "Secret leak in resource URIs",
      status: CheckStatus.FAIL,
      message: `${leaks.length} secret(s) detected in resource URIs`,
      finding: {
        id: "SL-002",
        module: this.id,
        severity: Severity.HIGH,
        title: "Credentials embedded in resource URIs",
        description:
          "Resource URIs contain embedded credentials or secrets. " +
          "These are visible to all MCP clients and may be logged in plaintext.",
        evidence: { leaks },
        remediation:
          "Remove credentials from resource URIs. Use server-side authentication " +
          "rather than embedding credentials in connection strings. " +
          "Configure resource access through environment variables.",
        cweId: "CWE-798",
      },
    };
  }

  private scanPromptDescriptions(
    prompts: Array<{ name: string; description?: string }>
  ): CheckResult {
    const leaks: Array<{
      prompt: string;
      secretType: string;
      snippet: string;
    }> = [];

    for (const prompt of prompts) {
      if (!prompt.description) continue;

      for (const sp of SECRET_PATTERNS) {
        const match = sp.pattern.exec(prompt.description);
        if (match) {
          leaks.push({
            prompt: prompt.name,
            secretType: sp.label,
            snippet: this.redact(match[0]),
          });
        }
      }
    }

    if (leaks.length === 0) {
      return {
        id: "SL-003",
        name: "Secret leak in prompt descriptions",
        status: CheckStatus.PASS,
        message: "No secrets detected in prompt descriptions",
      };
    }

    return {
      id: "SL-003",
      name: "Secret leak in prompt descriptions",
      status: CheckStatus.FAIL,
      message: `${leaks.length} secret(s) detected in prompt descriptions`,
      finding: {
        id: "SL-003",
        module: this.id,
        severity: Severity.HIGH,
        title: "Secrets exposed in prompt descriptions",
        description:
          "Prompt descriptions contain hardcoded secrets that are visible to all clients.",
        evidence: { leaks },
        remediation:
          "Remove all secrets from prompt metadata. " +
          "Use parameterized prompts with runtime credential injection instead.",
        cweId: "CWE-798",
      },
    };
  }

  private scanSchemaDefaults(tools: ToolInfo[]): CheckResult {
    const leaks: Array<{
      tool: string;
      param: string;
      field: string;
      secretType: string;
    }> = [];

    for (const tool of tools) {
      const properties = (tool.inputSchema as Record<string, unknown>)
        ?.properties as Record<string, Record<string, unknown>> | undefined;

      if (!properties) continue;

      for (const [paramName, schema] of Object.entries(properties)) {
        // Check default values and examples
        const valuesToCheck = [
          schema?.default,
          schema?.example,
          ...(Array.isArray(schema?.examples) ? schema.examples : []),
        ].filter((v) => typeof v === "string") as string[];

        for (const value of valuesToCheck) {
          for (const sp of SECRET_PATTERNS) {
            if (sp.pattern.test(value)) {
              leaks.push({
                tool: tool.name,
                param: paramName,
                field: schema?.default === value ? "default" : "example",
                secretType: sp.label,
              });
            }
          }
        }
      }
    }

    if (leaks.length === 0) {
      return {
        id: "SL-004",
        name: "Secret leak in schema defaults",
        status: CheckStatus.PASS,
        message: "No secrets detected in schema default/example values",
      };
    }

    return {
      id: "SL-004",
      name: "Secret leak in schema defaults",
      status: CheckStatus.FAIL,
      message: `${leaks.length} secret(s) in schema defaults/examples`,
      finding: {
        id: "SL-004",
        module: this.id,
        severity: Severity.HIGH,
        title: "Secrets in schema default or example values",
        description:
          "Tool input schemas contain hardcoded secrets in default or example values. " +
          "These are exposed to all connected clients via the tools/list endpoint.",
        evidence: { leaks },
        remediation:
          "Remove real credentials from schema defaults and examples. " +
          "Use placeholder values like 'YOUR_API_KEY' instead.",
        cweId: "CWE-798",
      },
    };
  }

  /** Redact the middle portion of a secret for safe display */
  private redact(value: string): string {
    if (value.length <= 8) return "****";
    return value.slice(0, 4) + "****" + value.slice(-4);
  }

  /** Redact credentials in a URI */
  private redactUri(uri: string): string {
    return uri.replace(
      /(\/\/[^:]+:)([^@]+)(@)/,
      "$1****$3"
    );
  }

  /** Get the highest severity from a list */
  private maxSeverity(severities: Severity[]): Severity {
    const order = [
      Severity.CRITICAL,
      Severity.HIGH,
      Severity.MEDIUM,
      Severity.LOW,
      Severity.INFO,
    ];
    for (const s of order) {
      if (severities.includes(s)) return s;
    }
    return Severity.INFO;
  }
}
