import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
  type ResourceInfo,
  type PromptInfo,
} from "../types/index.js";

/**
 * Resource & Prompt Audit Module.
 *
 * Analyzes MCP resources and prompts for security issues:
 * 1. Resources with overly-broad access patterns (wildcard URIs)
 * 2. Resources exposing sensitive file types or paths
 * 3. Prompts with unvalidated arguments that could enable injection
 * 4. Prompts that accept freeform instructions (prompt injection surface)
 * 5. Resource/prompt count anomalies (too many = larger attack surface)
 */
export class ResourcePromptAuditModule implements AuditModule {
  id = "resource-prompt-audit";
  name = "Resource & Prompt Auditing";
  description =
    "Analyzes resources and prompts for access control, injection, and exposure risks";
  version = "1.0.0";
  mode = "passive" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const { resources, prompts } = context.capabilities;

    // Check 1: Resource URI pattern analysis
    checks.push(this.checkResourcePatterns(resources));

    // Check 2: Sensitive resource exposure
    checks.push(this.checkSensitiveResources(resources));

    // Check 3: Prompt injection surface
    checks.push(this.checkPromptInjectionSurface(prompts));

    // Check 4: Unvalidated prompt arguments
    checks.push(this.checkPromptArguments(prompts));

    // Check 5: Attack surface size
    checks.push(this.checkAttackSurface(resources, prompts));

    return checks;
  }

  private checkResourcePatterns(resources: ResourceInfo[]): CheckResult {
    if (resources.length === 0) {
      return {
        id: "RP-001",
        name: "Resource URI patterns",
        status: CheckStatus.PASS,
        message: "No resources exposed",
      };
    }

    const wildcardResources = resources.filter(
      (r) =>
        r.uri.includes("*") ||
        r.uri.includes("{") ||
        r.uri.endsWith("/") ||
        /\/:?\w+$/.test(r.uri)
    );

    const broadPatterns = resources.filter(
      (r) =>
        r.uri === "file:///" ||
        r.uri === "file://**" ||
        /^file:\/\/\/?(\*|\.\.|\/)$/.test(r.uri) ||
        r.uri.includes("/**")
    );

    if (broadPatterns.length > 0) {
      return {
        id: "RP-001",
        name: "Resource URI patterns",
        status: CheckStatus.FAIL,
        message: `${broadPatterns.length} resource(s) with overly-broad access patterns`,
        finding: {
          id: "RP-001",
          module: this.id,
          severity: Severity.HIGH,
          title: "Resources with overly-broad access patterns",
          description:
            "Resources use wildcard or recursive patterns that grant access to " +
            "large portions of the filesystem or data store. This violates the " +
            "principle of least privilege and expands the attack surface.",
          evidence: {
            broadPatterns: broadPatterns.map((r) => ({
              name: r.name,
              uri: r.uri,
            })),
          },
          remediation:
            "Restrict resource URIs to specific paths and files. " +
            "Avoid wildcard patterns like '/**'. " +
            "Implement server-side path validation and allowlisting.",
          cweId: "CWE-732",
        },
      };
    }

    if (wildcardResources.length > 0) {
      return {
        id: "RP-001",
        name: "Resource URI patterns",
        status: CheckStatus.WARN,
        message: `${wildcardResources.length} resource(s) with parameterized or wildcard URIs`,
        finding: {
          id: "RP-001",
          module: this.id,
          severity: Severity.LOW,
          title: "Resources with parameterized URI patterns",
          description:
            `${wildcardResources.length} resource(s) use parameterized or wildcard URIs. ` +
            "Ensure server-side validation prevents path traversal and unauthorized access.",
          evidence: {
            wildcardResources: wildcardResources.map((r) => ({
              name: r.name,
              uri: r.uri,
            })),
          },
          remediation:
            "Validate all URI parameters server-side. " +
            "Canonicalize paths and reject traversal sequences.",
          cweId: "CWE-22",
        },
      };
    }

    return {
      id: "RP-001",
      name: "Resource URI patterns",
      status: CheckStatus.PASS,
      message: `${resources.length} resource(s) with specific URI patterns`,
    };
  }

  private checkSensitiveResources(resources: ResourceInfo[]): CheckResult {
    const sensitivePatterns = [
      { pattern: /\.env/i, type: "Environment file" },
      { pattern: /\.pem|\.key|\.cert|\.crt/i, type: "Certificate/Key file" },
      { pattern: /\.sql|\.db|\.sqlite/i, type: "Database file" },
      { pattern: /password|credential|secret|token/i, type: "Credential-related" },
      { pattern: /\/etc\/|\/proc\/|\/sys\//i, type: "System path" },
      { pattern: /\.ssh|\.gnupg|\.aws/i, type: "Security config" },
      { pattern: /\.git\//i, type: "Git repository metadata" },
      { pattern: /config\.json|settings\.json/i, type: "Configuration file" },
    ];

    const sensitiveResources: Array<{
      name: string;
      uri: string;
      type: string;
    }> = [];

    for (const resource of resources) {
      const combined = `${resource.uri} ${resource.name} ${resource.description ?? ""}`;
      for (const { pattern, type } of sensitivePatterns) {
        if (pattern.test(combined)) {
          sensitiveResources.push({
            name: resource.name,
            uri: resource.uri,
            type,
          });
          break;
        }
      }
    }

    if (sensitiveResources.length === 0) {
      return {
        id: "RP-002",
        name: "Sensitive resource exposure",
        status: CheckStatus.PASS,
        message: "No sensitive resources detected",
      };
    }

    return {
      id: "RP-002",
      name: "Sensitive resource exposure",
      status: CheckStatus.FAIL,
      message: `${sensitiveResources.length} sensitive resource(s) exposed`,
      finding: {
        id: "RP-002",
        module: this.id,
        severity: Severity.HIGH,
        title: "Sensitive resources exposed via MCP",
        description:
          "Resources expose access to sensitive files, credentials, or system paths. " +
          "A malicious or compromised client could read these resources to extract secrets.",
        evidence: { sensitiveResources },
        remediation:
          "Remove sensitive resources from the MCP server configuration. " +
          "Use scoped file access with explicit allowlists. " +
          "Never expose .env, private keys, or database files via MCP.",
        cweId: "CWE-200",
      },
    };
  }

  private checkPromptInjectionSurface(prompts: PromptInfo[]): CheckResult {
    if (prompts.length === 0) {
      return {
        id: "RP-003",
        name: "Prompt injection surface",
        status: CheckStatus.PASS,
        message: "No prompts exposed",
      };
    }

    // Prompts with freeform text arguments are injection surfaces
    const injectionSurface: Array<{
      prompt: string;
      args: string[];
    }> = [];

    for (const prompt of prompts) {
      if (!prompt.arguments || prompt.arguments.length === 0) continue;

      const freeformArgs = prompt.arguments.filter((arg) => {
        const name = arg.name.toLowerCase();
        return (
          /^(input|text|content|message|query|instruction|prompt|request|data|body|command)$/i.test(
            name
          ) ||
          (arg.description &&
            /free.?form|any|arbitrary|custom|user/i.test(arg.description))
        );
      });

      if (freeformArgs.length > 0) {
        injectionSurface.push({
          prompt: prompt.name,
          args: freeformArgs.map((a) => a.name),
        });
      }
    }

    if (injectionSurface.length === 0) {
      return {
        id: "RP-003",
        name: "Prompt injection surface",
        status: CheckStatus.PASS,
        message: `${prompts.length} prompt(s) with no freeform injection surface`,
      };
    }

    return {
      id: "RP-003",
      name: "Prompt injection surface",
      status: CheckStatus.WARN,
      message: `${injectionSurface.length} prompt(s) accept freeform text input`,
      finding: {
        id: "RP-003",
        module: this.id,
        severity: Severity.MEDIUM,
        title: "Prompts with freeform text injection surface",
        description:
          "Prompts accept freeform text arguments that could be used for prompt injection. " +
          "An attacker could craft input that causes the AI agent to execute unintended actions.",
        evidence: { injectionSurface },
        remediation:
          "Validate and sanitize all prompt arguments. " +
          "Use structured arguments with enumerated options where possible. " +
          "Implement input length limits and content filtering on prompt arguments.",
        cweId: "CWE-74",
      },
    };
  }

  private checkPromptArguments(prompts: PromptInfo[]): CheckResult {
    const noValidation: Array<{
      prompt: string;
      requiredCount: number;
      optionalCount: number;
    }> = [];

    for (const prompt of prompts) {
      if (!prompt.arguments || prompt.arguments.length === 0) continue;

      const required = prompt.arguments.filter((a) => a.required).length;
      const optional = prompt.arguments.length - required;

      // Flag prompts with many optional args (loose validation)
      if (optional > 3 || (prompt.arguments.length > 5 && required === 0)) {
        noValidation.push({
          prompt: prompt.name,
          requiredCount: required,
          optionalCount: optional,
        });
      }
    }

    if (noValidation.length === 0) {
      return {
        id: "RP-004",
        name: "Prompt argument validation",
        status: CheckStatus.PASS,
        message: "Prompt arguments appear properly structured",
      };
    }

    return {
      id: "RP-004",
      name: "Prompt argument validation",
      status: CheckStatus.WARN,
      message: `${noValidation.length} prompt(s) with loose argument validation`,
      finding: {
        id: "RP-004",
        module: this.id,
        severity: Severity.LOW,
        title: "Prompts with loose argument validation",
        description:
          "Prompts accept many optional arguments or have no required parameters, " +
          "suggesting insufficient input validation.",
        evidence: { noValidation },
        remediation:
          "Mark essential prompt arguments as required. " +
          "Reduce optional arguments to minimize the injection surface. " +
          "Document expected formats and constraints for each argument.",
        cweId: "CWE-20",
      },
    };
  }

  private checkAttackSurface(
    resources: ResourceInfo[],
    prompts: PromptInfo[]
  ): CheckResult {
    const total = resources.length + prompts.length;

    if (total === 0) {
      return {
        id: "RP-005",
        name: "Resource/prompt attack surface",
        status: CheckStatus.PASS,
        message: "No resources or prompts exposed",
      };
    }

    if (total > 20) {
      return {
        id: "RP-005",
        name: "Resource/prompt attack surface",
        status: CheckStatus.WARN,
        message: `Large attack surface: ${resources.length} resources + ${prompts.length} prompts`,
        finding: {
          id: "RP-005",
          module: this.id,
          severity: Severity.LOW,
          title: "Large resource and prompt attack surface",
          description:
            `Server exposes ${resources.length} resources and ${prompts.length} prompts ` +
            `(${total} total). A large attack surface increases the likelihood ` +
            "of misconfigured or vulnerable endpoints.",
          evidence: {
            resourceCount: resources.length,
            promptCount: prompts.length,
            total,
          },
          remediation:
            "Review all exposed resources and prompts. " +
            "Remove unused or development-only endpoints. " +
            "Apply the principle of least privilege to the server configuration.",
          cweId: "CWE-1059",
        },
      };
    }

    return {
      id: "RP-005",
      name: "Resource/prompt attack surface",
      status: CheckStatus.PASS,
      message: `Moderate attack surface: ${resources.length} resources + ${prompts.length} prompts`,
    };
  }
}
