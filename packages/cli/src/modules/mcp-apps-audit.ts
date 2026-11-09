import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
} from "../types/index.js";

/**
 * MCP Apps Extension Audit Module (Passive).
 *
 * Audits MCP server capabilities related to the MCP Apps Extension (SEP-1865).
 * MCP Apps allow servers to return interactive HTML interfaces rendered in
 * sandboxed iframes within the AI client's chat UI.
 *
 * Security concerns:
 * 1. XSS in HTML responses rendered in client
 * 2. iframe sandbox escape
 * 3. postMessage origin validation
 * 4. Clickjacking via embedded content
 * 5. Data exfiltration through embedded interfaces
 *
 * CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)
 */
export class McpAppsAuditModule implements AuditModule {
  id = "mcp-apps-audit";
  name = "MCP Apps Extension Audit";
  description = "Audits MCP Apps Extension (SEP-1865) capabilities for XSS, iframe, and postMessage risks";
  version = "1.0.0";
  mode = "passive" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const { tools, resources } = context.capabilities;

    // Check 1: Tools that return HTML content
    checks.push(this.checkHtmlReturningTools(tools));

    // Check 2: iframe/embed capability indicators
    checks.push(this.checkIframeCapabilities(tools, resources));

    // Check 3: postMessage usage in tool descriptions
    checks.push(this.checkPostMessagePatterns(tools));

    // Check 4: External resource loading indicators
    checks.push(this.checkExternalResourceLoading(tools));

    return checks;
  }

  private checkHtmlReturningTools(tools: ModuleContext["capabilities"]["tools"]): CheckResult {
    const htmlTools: Array<{ name: string; indicators: string[] }> = [];

    for (const tool of tools) {
      const indicators: string[] = [];
      const desc = (tool.description ?? "").toLowerCase();
      const schema = JSON.stringify(tool.inputSchema ?? {}).toLowerCase();

      // Check for HTML output indicators
      if (desc.includes("html") || desc.includes("render") || desc.includes("display")) {
        indicators.push("Description mentions HTML rendering");
      }
      if (desc.includes("iframe") || desc.includes("embed")) {
        indicators.push("Description mentions iframe/embed");
      }
      if (desc.includes("interactive") || desc.includes("dashboard") || desc.includes("widget")) {
        indicators.push("Description mentions interactive UI elements");
      }
      if (schema.includes("text/html") || schema.includes("content-type")) {
        indicators.push("Schema references HTML content type");
      }

      if (indicators.length > 0) {
        htmlTools.push({ name: tool.name, indicators });
      }
    }

    if (htmlTools.length === 0) {
      return {
        id: "MA-001",
        name: "HTML-returning tools",
        status: CheckStatus.PASS,
        message: "No tools appear to return HTML content (MCP Apps not in use)",
      };
    }

    return {
      id: "MA-001",
      name: "HTML-returning tools",
      status: CheckStatus.WARN,
      message: `${htmlTools.length} tool(s) may return HTML content via MCP Apps Extension`,
      finding: {
        id: "MA-001",
        module: this.id,
        severity: Severity.MEDIUM,
        title: "Tools returning HTML content detected (MCP Apps surface)",
        description:
          `${htmlTools.length} tool(s) appear to return HTML content that may be rendered ` +
          "in the AI client's chat UI via the MCP Apps Extension (SEP-1865). This creates " +
          "a potential XSS attack surface if HTML content is not properly sanitized. " +
          "Malicious tool responses could inject scripts that execute in the client context.",
        evidence: { htmlTools },
        remediation:
          "1) Sanitize all HTML output using a strict allowlist (DOMPurify or equivalent). " +
          "2) Ensure iframes use sandbox attribute with minimal permissions. " +
          "3) Set Content-Security-Policy headers on HTML responses. " +
          "4) Never include user-controlled data in HTML without encoding. " +
          "5) Validate postMessage origins strictly.",
        cweId: "CWE-79",
      },
    };
  }

  private checkIframeCapabilities(
    tools: ModuleContext["capabilities"]["tools"],
    resources: ModuleContext["capabilities"]["resources"]
  ): CheckResult {
    const combined = JSON.stringify([...tools, ...resources]).toLowerCase();
    const issues: string[] = [];

    if (combined.includes("allowfullscreen")) {
      issues.push("allowfullscreen attribute detected — potential for UI takeover");
    }
    if (combined.includes("allow-scripts") && combined.includes("allow-same-origin")) {
      issues.push("iframe with both allow-scripts and allow-same-origin — effectively no sandbox");
    }
    if (combined.includes("sandbox=\"\"") || combined.includes("sandbox=''")) {
      issues.push("Empty sandbox attribute — all restrictions applied (good)");
    }
    if (combined.includes("srcdoc")) {
      issues.push("srcdoc attribute usage — inline HTML in iframes");
    }

    if (issues.length === 0) {
      return {
        id: "MA-002",
        name: "iframe security analysis",
        status: CheckStatus.PASS,
        message: "No iframe security issues detected",
      };
    }

    return {
      id: "MA-002",
      name: "iframe security analysis",
      status: CheckStatus.WARN,
      message: `${issues.length} iframe security concern(s) found`,
      finding: {
        id: "MA-002",
        module: this.id,
        severity: Severity.HIGH,
        title: "Insecure iframe configuration in MCP Apps",
        description: "The server's MCP Apps configuration contains iframe security issues. " +
          issues.join(". ") + ".",
        evidence: { issues },
        remediation:
          "Use strict iframe sandbox attributes. Never combine allow-scripts with allow-same-origin. " +
          "Avoid allowfullscreen unless explicitly required. Prefer srcdoc over src for controlled content.",
        cweId: "CWE-1021",
      },
    };
  }

  private checkPostMessagePatterns(tools: ModuleContext["capabilities"]["tools"]): CheckResult {
    const concerns: string[] = [];
    const combined = JSON.stringify(tools).toLowerCase();

    if (combined.includes("postmessage")) {
      concerns.push("postMessage API usage detected — requires origin validation");
    }
    if (combined.includes("addeventlistener") && combined.includes("message")) {
      concerns.push("Message event listener detected — verify origin checking");
    }
    if (combined.includes("window.parent") || combined.includes("parent.postmessage")) {
      concerns.push("parent frame communication detected — cross-origin risk");
    }
    if (combined.includes("*") && combined.includes("postmessage")) {
      concerns.push("Wildcard (*) origin in postMessage — accepts messages from any origin");
    }

    if (concerns.length === 0) {
      return {
        id: "MA-003",
        name: "postMessage security",
        status: CheckStatus.PASS,
        message: "No postMessage security concerns detected",
      };
    }

    return {
      id: "MA-003",
      name: "postMessage security",
      status: CheckStatus.WARN,
      message: `${concerns.length} postMessage security concern(s) found`,
      finding: {
        id: "MA-003",
        module: this.id,
        severity: Severity.MEDIUM,
        title: "postMessage security concerns in MCP Apps",
        description: "The server configuration contains postMessage patterns that may be vulnerable " +
          "to cross-origin message injection. " + concerns.join(". ") + ".",
        evidence: { concerns },
        remediation:
          "Always validate event.origin in message event handlers. " +
          "Never use '*' as targetOrigin in postMessage calls. " +
          "Validate message data structure before processing.",
        cweId: "CWE-346",
      },
    };
  }

  private checkExternalResourceLoading(tools: ModuleContext["capabilities"]["tools"]): CheckResult {
    const risks: string[] = [];
    const combined = JSON.stringify(tools).toLowerCase();

    const externalPatterns = [
      { pattern: /https?:\/\/cdn\./i, desc: "External CDN resource loading" },
      { pattern: /https?:\/\/unpkg\.com/i, desc: "unpkg.com resource loading" },
      { pattern: /https?:\/\/cdnjs\./i, desc: "cdnjs resource loading" },
      { pattern: /<script\s+src=/i, desc: "External script tag detected" },
      { pattern: /<link\s+.*href=.*https?:/i, desc: "External stylesheet loading" },
    ];

    for (const { pattern, desc } of externalPatterns) {
      if (pattern.test(combined)) {
        risks.push(desc);
      }
    }

    if (risks.length === 0) {
      return {
        id: "MA-004",
        name: "External resource loading",
        status: CheckStatus.PASS,
        message: "No external resource loading detected in tool definitions",
      };
    }

    return {
      id: "MA-004",
      name: "External resource loading",
      status: CheckStatus.WARN,
      message: `${risks.length} external resource loading pattern(s) detected`,
      finding: {
        id: "MA-004",
        module: this.id,
        severity: Severity.MEDIUM,
        title: "External resources loaded in MCP Apps content",
        description:
          "Tool definitions reference external resources (CDNs, scripts, stylesheets) that could " +
          "be compromised or modified to inject malicious code into the MCP Apps UI.",
        evidence: { risks },
        remediation:
          "Use Subresource Integrity (SRI) for all external resources. " +
          "Prefer self-hosted resources over external CDNs. " +
          "Set strict Content-Security-Policy to limit resource origins.",
        cweId: "CWE-829",
      },
    };
  }
}
