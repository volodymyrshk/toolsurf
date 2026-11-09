import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
} from "../types/index.js";

/**
 * EU AI Act Article 15 Conformity Assessment Module (Passive).
 *
 * Evaluates AI agent tool interfaces against EU AI Act High-Risk AI requirements.
 * Enforcement date: August 2, 2026.
 *
 * Assessed requirements:
 *   Art. 9  — Risk management system
 *   Art. 10 — Data governance
 *   Art. 13 — Transparency
 *   Art. 14 — Human oversight
 *   Art. 15 — Accuracy, robustness, and cybersecurity
 *
 * Reference: DeepR_4 research report — OWASP/MITRE/NIST/EU AI Act Framework Analysis.
 */
export class EuAiActModule implements AuditModule {
  id = "eu-ai-act";
  name = "EU AI Act Conformity";
  description = "Assesses compliance with EU AI Act Article 15 requirements for high-risk AI systems";
  version = "1.0.0";
  mode = "passive" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const { capabilities } = context;
    const tools = capabilities.tools ?? [];
    const capStr = JSON.stringify(capabilities).toLowerCase();

    // Check 1: Risk Management (Art. 9)
    checks.push(this.checkRiskManagement(tools, capStr));

    // Check 2: Data governance (Art. 10)
    checks.push(this.checkDataGovernance(tools, capStr));

    // Check 3: Transparency (Art. 13)
    checks.push(this.checkTransparency(capabilities, tools));

    // Check 4: Human oversight (Art. 14)
    checks.push(this.checkHumanOversight(tools, capStr));

    // Check 5: Accuracy, robustness, cybersecurity (Art. 15)
    checks.push(this.checkAccuracyRobustness(tools, capStr));

    // Aggregate conformity status
    checks.push(this.aggregateConformity(checks));

    return checks;
  }

  /**
   * Art. 9 — Risk management system.
   * Checks for evidence of risk assessment in tool annotations, descriptions,
   * and capability declarations.
   */
  private checkRiskManagement(
    tools: ModuleContext["capabilities"]["tools"],
    capStr: string,
  ): CheckResult {
    const concerns: string[] = [];
    const evidence: string[] = [];

    // Check for destructive hints without risk annotations
    const DESTRUCTIVE_KEYWORDS = [
      "delete", "remove", "drop", "destroy", "kill", "terminate",
      "execute", "eval", "exec", "run", "shell", "command", "sql",
    ];
    const RISK_ANNOTATIONS = [
      "readonly", "readOnly", "read_only", "safe",
      "destructive", "idempotent", "risk",
    ];

    let destructiveToolCount = 0;
    let annotatedToolCount = 0;

    for (const tool of tools) {
      const desc = (tool.description ?? "").toLowerCase();
      const name = tool.name.toLowerCase();
      const annotations = JSON.stringify(tool.annotations ?? {}).toLowerCase();

      // Word-boundary match prevents false positives from negation phrases
      // like "(no eval)", "non-execute", "no-sql" — use \b boundaries.
      // Also honour explicit destructiveHint: false annotation.
      const explicitlySafe = tool.annotations?.destructiveHint === false;
      const isDestructive = !explicitlySafe && DESTRUCTIVE_KEYWORDS.some(
        (k) => new RegExp(`\\b${k}\\b`).test(desc) || new RegExp(`\\b${k}\\b`).test(name),
      );
      const hasRiskAnnotation = RISK_ANNOTATIONS.some(
        (k) => annotations.includes(k) || desc.includes(`[${k}]`),
      );

      if (isDestructive) {
        destructiveToolCount++;
        if (hasRiskAnnotation) {
          annotatedToolCount++;
        } else {
          concerns.push(
            `Tool "${tool.name}" has destructive capability without risk annotation`,
          );
        }
      }
    }

    if (destructiveToolCount > 0 && annotatedToolCount === 0) {
      concerns.push(
        `${destructiveToolCount} tool(s) with destructive capabilities lack any risk management annotations`,
      );
    }

    // Check if risk/safety keywords appear anywhere in capability metadata.
    // Explicit MCP readOnly/destructiveHint annotations also count as risk
    // evidence — the operator has declared the risk level via annotations.
    const hasExplicitAnnotations = tools.some(
      (t) => t.annotations?.readOnlyHint === true || t.annotations?.destructiveHint !== undefined,
    );
    const hasRiskMetadata =
      capStr.includes("risk") ||
      capStr.includes("safety") ||
      capStr.includes("hazard") ||
      hasExplicitAnnotations;
    if (!hasRiskMetadata) {
      concerns.push(
        "No evidence of risk management metadata in server capabilities",
      );
    } else {
      evidence.push("Risk/safety evidence found in capability metadata or annotations");
    }

    if (concerns.length === 0) {
      return {
        id: "EUAI-001",
        name: "Art. 9 Risk Management",
        status: CheckStatus.PASS,
        message: "Evidence of risk management practices found",
      };
    }

    return {
      id: "EUAI-001",
      name: "Art. 9 Risk Management",
      status: CheckStatus.WARN,
      message: `${concerns.length} risk management gap(s) — Art. 9 conformity uncertain`,
      finding: {
        id: "EUAI-001",
        module: this.id,
        severity: Severity.MEDIUM,
        title: "EU AI Act Art. 9: Missing risk management evidence",
        description:
          "The AI system does not provide sufficient evidence of a risk management system " +
          "as required by EU AI Act Article 9. High-risk AI systems must establish, implement, " +
          "document and maintain a continuous iterative risk management system. " +
          concerns.join(". ") + ".",
        evidence: { concerns, evidence, destructiveToolCount, annotatedToolCount },
        remediation:
          "Implement a risk management system covering: (1) identification and analysis of known " +
          "and reasonably foreseeable risks, (2) estimation and evaluation of risks that may emerge, " +
          "(3) adoption of appropriate risk management measures. Add risk annotations (readOnly, " +
          "destructive) to all tool declarations. Document risk assessments in server metadata.",
        cweId: "CWE-693",
      },
    };
  }

  /**
   * Art. 10 — Data governance.
   * Checks for data handling documentation, input validation evidence,
   * and data quality indicators.
   */
  private checkDataGovernance(
    tools: ModuleContext["capabilities"]["tools"],
    capStr: string,
  ): CheckResult {
    const concerns: string[] = [];

    // Check for input validation constraints in schemas
    let constrainedParams = 0;
    let totalParams = 0;

    for (const tool of tools) {
      const props = (tool.inputSchema?.properties ?? {}) as Record<string, any>;
      for (const [, schema] of Object.entries(props)) {
        totalParams++;
        if (
          schema?.enum ||
          schema?.pattern ||
          schema?.maxLength ||
          schema?.minimum !== undefined ||
          schema?.maximum !== undefined ||
          schema?.format
        ) {
          constrainedParams++;
        }
      }
    }

    const constraintRatio =
      totalParams > 0 ? constrainedParams / totalParams : 1;
    if (constraintRatio < 0.3 && totalParams > 0) {
      concerns.push(
        `Only ${Math.round(constraintRatio * 100)}% of input parameters have validation constraints ` +
        `(${constrainedParams}/${totalParams}) — insufficient data quality controls`,
      );
    }

    // Check for PII/sensitive data handling indicators
    const PII_KEYWORDS = [
      "email", "password", "ssn", "phone", "address", "credit_card",
      "token", "secret", "api_key", "personal", "private",
    ];
    const hasPiiFields = PII_KEYWORDS.some((k) => capStr.includes(k));
    const hasDataProtection =
      capStr.includes("encrypt") ||
      capStr.includes("mask") ||
      capStr.includes("redact") ||
      capStr.includes("anonymi");

    if (hasPiiFields && !hasDataProtection) {
      concerns.push(
        "Tool schemas reference PII/sensitive data fields without evidence of data protection measures",
      );
    }

    if (concerns.length === 0) {
      return {
        id: "EUAI-002",
        name: "Art. 10 Data Governance",
        status: CheckStatus.PASS,
        message: `Data governance adequate — ${Math.round(constraintRatio * 100)}% parameters constrained`,
      };
    }

    return {
      id: "EUAI-002",
      name: "Art. 10 Data Governance",
      status: CheckStatus.WARN,
      message: `${concerns.length} data governance gap(s) — Art. 10 conformity uncertain`,
      finding: {
        id: "EUAI-002",
        module: this.id,
        severity: Severity.MEDIUM,
        title: "EU AI Act Art. 10: Insufficient data governance",
        description:
          "The AI system's data governance practices do not fully meet EU AI Act Article 10 requirements. " +
          "Training, validation and testing data sets shall be subject to appropriate data governance " +
          "and management practices. " +
          concerns.join(". ") + ".",
        evidence: { concerns, constrainedParams, totalParams, constraintRatio },
        remediation:
          "Improve data governance by: (1) adding validation constraints (enum, pattern, maxLength) " +
          "to all input parameters, (2) implementing data protection measures for PII fields, " +
          "(3) documenting data quality requirements in tool descriptions, " +
          "(4) ensuring training data relevance and representativeness.",
        cweId: "CWE-20",
      },
    };
  }

  /**
   * Art. 13 — Transparency.
   * Checks for clear documentation, version information, usage instructions,
   * and known limitations.
   */
  private checkTransparency(
    capabilities: ModuleContext["capabilities"],
    tools: ModuleContext["capabilities"]["tools"],
  ): CheckResult {
    const concerns: string[] = [];
    const { serverInfo } = capabilities;

    // Server identity transparency
    if (!serverInfo.name || serverInfo.name.trim() === "") {
      concerns.push("Server name is not declared — users cannot identify the AI system");
    }
    if (!serverInfo.version || serverInfo.version.trim() === "") {
      concerns.push("Server version is not declared — users cannot determine which version they are interacting with");
    }

    // Tool documentation quality
    let undocumentedTools = 0;
    let poorlyDocumentedTools = 0;

    for (const tool of tools) {
      if (!tool.description || tool.description.trim() === "") {
        undocumentedTools++;
      } else if (tool.description.length < 20) {
        poorlyDocumentedTools++;
      }
    }

    if (undocumentedTools > 0) {
      concerns.push(
        `${undocumentedTools} tool(s) have no description — users cannot understand their function`,
      );
    }
    if (poorlyDocumentedTools > 0) {
      concerns.push(
        `${poorlyDocumentedTools} tool(s) have minimal descriptions (<20 chars) — insufficient for informed use`,
      );
    }

    // Check for limitations/warnings documentation
    const capStr = JSON.stringify(capabilities).toLowerCase();
    const hasLimitations =
      capStr.includes("limitation") ||
      capStr.includes("warning") ||
      capStr.includes("caveat") ||
      capStr.includes("known issue") ||
      capStr.includes("beta") ||
      capStr.includes("experimental");

    if (!hasLimitations && tools.length > 5) {
      concerns.push(
        "No evidence of documented limitations or known issues — Art. 13 requires disclosure of known limitations",
      );
    }

    if (concerns.length === 0) {
      return {
        id: "EUAI-003",
        name: "Art. 13 Transparency",
        status: CheckStatus.PASS,
        message: `Transparency requirements met — all ${tools.length} tools documented`,
      };
    }

    return {
      id: "EUAI-003",
      name: "Art. 13 Transparency",
      status: CheckStatus.WARN,
      message: `${concerns.length} transparency gap(s) — Art. 13 conformity uncertain`,
      finding: {
        id: "EUAI-003",
        module: this.id,
        severity: Severity.MEDIUM,
        title: "EU AI Act Art. 13: Insufficient transparency",
        description:
          "The AI system lacks sufficient transparency measures as required by EU AI Act Article 13. " +
          "High-risk AI systems shall be designed and developed in such a way as to ensure that their " +
          "operation is sufficiently transparent to enable deployers to interpret outputs and use them appropriately. " +
          concerns.join(". ") + ".",
        evidence: { concerns, undocumentedTools, poorlyDocumentedTools, serverName: serverInfo.name },
        remediation:
          "Improve transparency by: (1) providing complete server identification, " +
          "(2) adding detailed descriptions to all tools explaining purpose, inputs, and outputs, " +
          "(3) documenting known limitations, error conditions, and edge cases, " +
          "(4) declaring intended use cases and populations in server metadata.",
        cweId: "CWE-1059",
      },
    };
  }

  /**
   * Art. 14 — Human oversight.
   * Checks for mechanisms that enable human oversight of AI tool operations.
   */
  private checkHumanOversight(
    tools: ModuleContext["capabilities"]["tools"],
    capStr: string,
  ): CheckResult {
    const concerns: string[] = [];
    const evidence: string[] = [];

    // Check for human-in-the-loop indicators
    const hasConfirmation =
      capStr.includes("confirm") ||
      capStr.includes("approval") ||
      capStr.includes("human") ||
      capStr.includes("review") ||
      capStr.includes("elicitation");

    if (hasConfirmation) {
      evidence.push("Human confirmation/approval mechanisms referenced in capabilities");
    }

    // Check for audit logging indicators
    const hasAuditLog =
      capStr.includes("log") ||
      capStr.includes("audit") ||
      capStr.includes("trace") ||
      capStr.includes("history");

    if (hasAuditLog) {
      evidence.push("Audit logging/tracing capabilities detected");
    }

    // Check for annotation-based oversight hints
    let toolsWithAnnotations = 0;
    let destructiveWithoutConfirm = 0;

    for (const tool of tools) {
      const annotations = tool.annotations ?? {};
      if (Object.keys(annotations).length > 0) {
        toolsWithAnnotations++;
      }

      const desc = (tool.description ?? "").toLowerCase();
      const name = tool.name.toLowerCase();
      const isDestructive =
        desc.includes("delete") || desc.includes("write") ||
        desc.includes("execute") || desc.includes("modify") ||
        name.includes("delete") || name.includes("write") ||
        name.includes("execute") || name.includes("update");
      const hasConfirm =
        desc.includes("confirm") || desc.includes("approval") ||
        JSON.stringify(annotations).toLowerCase().includes("confirm");

      if (isDestructive && !hasConfirm) {
        destructiveWithoutConfirm++;
      }
    }

    // Only require human oversight evidence when the server has tools that
    // actually perform write/destructive operations. A fully read-only server
    // (all tools annotated readOnlyHint: true or no write keywords) does not
    // require confirmation workflows — flagging it is a false positive.
    const allToolsReadOnly = tools.length > 0 && tools.every(
      (t) => t.annotations?.readOnlyHint === true,
    );
    if (!hasConfirmation && !hasAuditLog && !allToolsReadOnly) {
      concerns.push(
        "No evidence of human oversight mechanisms (confirmation, audit logging, review workflows)",
      );
    }

    if (destructiveWithoutConfirm > 3) {
      concerns.push(
        `${destructiveWithoutConfirm} destructive tool(s) have no confirmation requirement — ` +
        "reduces ability for human oversight of irreversible actions",
      );
    }

    if (toolsWithAnnotations === 0 && tools.length > 0) {
      concerns.push(
        "No tools have MCP annotations — tool behavior annotations enable deployer oversight decisions",
      );
    }

    if (concerns.length === 0) {
      return {
        id: "EUAI-004",
        name: "Art. 14 Human Oversight",
        status: CheckStatus.PASS,
        message: "Human oversight mechanisms detected",
      };
    }

    return {
      id: "EUAI-004",
      name: "Art. 14 Human Oversight",
      status: CheckStatus.WARN,
      message: `${concerns.length} human oversight gap(s) — Art. 14 conformity uncertain`,
      finding: {
        id: "EUAI-004",
        module: this.id,
        severity: Severity.HIGH,
        title: "EU AI Act Art. 14: Insufficient human oversight",
        description:
          "The AI system does not provide sufficient mechanisms for human oversight as required by " +
          "EU AI Act Article 14. High-risk AI systems shall be designed and developed so that they " +
          "can be effectively overseen by natural persons during their period of use. " +
          concerns.join(". ") + ".",
        evidence: { concerns, evidence, destructiveWithoutConfirm, toolsWithAnnotations },
        remediation:
          "Enable human oversight by: (1) implementing confirmation flows for destructive operations, " +
          "(2) adding audit logging for all tool invocations, (3) using MCP annotations to declare " +
          "tool behavior (readOnly, destructive, idempotent), (4) providing a mechanism for human " +
          "operators to interrupt or override AI tool usage, (5) implementing the MCP elicitation " +
          "capability for out-of-band human approval on sensitive actions.",
        cweId: "CWE-693",
      },
    };
  }

  /**
   * Art. 15 — Accuracy, robustness, and cybersecurity.
   * Checks for input validation, error handling, and security measures.
   */
  private checkAccuracyRobustness(
    tools: ModuleContext["capabilities"]["tools"],
    capStr: string,
  ): CheckResult {
    const concerns: string[] = [];

    // Input validation (robustness)
    let toolsWithRequired = 0;
    for (const tool of tools) {
      const required = tool.inputSchema?.required;
      if (Array.isArray(required) && required.length > 0) {
        toolsWithRequired++;
      }
    }

    if (tools.length > 0 && toolsWithRequired / tools.length < 0.5) {
      concerns.push(
        `Only ${Math.round((toolsWithRequired / tools.length) * 100)}% of tools declare required fields — ` +
        "insufficient input validation for robustness",
      );
    }

    // Transport security (cybersecurity)
    const hasHttpsOrStdio =
      capStr.includes("https") ||
      capStr.includes("stdio") ||
      capStr.includes("localhost");
    const hasPlainHttp =
      capStr.includes("http://") && !capStr.includes("http://localhost");

    if (hasPlainHttp && !hasHttpsOrStdio) {
      concerns.push(
        "Server may use unencrypted HTTP transport — fails Art. 15 cybersecurity requirement",
      );
    }

    // Error handling indicators
    const hasErrorHandling =
      capStr.includes("error") ||
      capStr.includes("exception") ||
      capStr.includes("fallback") ||
      capStr.includes("retry");

    if (!hasErrorHandling && tools.length > 5) {
      concerns.push(
        "No evidence of error handling or fallback mechanisms in tool declarations",
      );
    }

    // Schema completeness (accuracy)
    let toolsWithoutSchema = 0;
    for (const tool of tools) {
      const props = tool.inputSchema?.properties ?? {};
      if (Object.keys(props).length === 0 && tool.inputSchema?.type !== "object") {
        toolsWithoutSchema++;
      }
    }
    if (toolsWithoutSchema > 0) {
      concerns.push(
        `${toolsWithoutSchema} tool(s) lack input schema definitions — cannot validate input accuracy`,
      );
    }

    if (concerns.length === 0) {
      return {
        id: "EUAI-005",
        name: "Art. 15 Accuracy & Robustness",
        status: CheckStatus.PASS,
        message: "Accuracy, robustness, and cybersecurity measures adequate",
      };
    }

    return {
      id: "EUAI-005",
      name: "Art. 15 Accuracy & Robustness",
      status: CheckStatus.WARN,
      message: `${concerns.length} accuracy/robustness gap(s) — Art. 15 conformity uncertain`,
      finding: {
        id: "EUAI-005",
        module: this.id,
        severity: Severity.HIGH,
        title: "EU AI Act Art. 15: Insufficient accuracy, robustness, or cybersecurity",
        description:
          "The AI system may not meet the accuracy, robustness, and cybersecurity requirements of " +
          "EU AI Act Article 15. High-risk AI systems shall be designed and developed in such a way " +
          "that they achieve an appropriate level of accuracy, robustness and cybersecurity, and " +
          "perform consistently in those respects throughout their lifecycle. " +
          concerns.join(". ") + ".",
        evidence: { concerns, toolsWithRequired, toolsWithoutSchema, totalTools: tools.length },
        remediation:
          "Improve accuracy and robustness by: (1) declaring required fields in all tool schemas, " +
          "(2) using HTTPS/TLS for all transport, (3) implementing error handling with graceful " +
          "degradation, (4) providing complete input schemas with validation constraints, " +
          "(5) implementing rate limiting and resource bounds, (6) conducting regular cybersecurity " +
          "assessments as per ENISA guidelines.",
        cweId: "CWE-693",
      },
    };
  }

  /**
   * Aggregate conformity status across all Article checks.
   * Outputs overall CONFORMANT / NON-CONFORMANT / REQUIRES-ASSESSMENT verdict.
   */
  private aggregateConformity(articleChecks: CheckResult[]): CheckResult {
    const failCount = articleChecks.filter(
      (c) => c.status === CheckStatus.FAIL,
    ).length;
    const warnCount = articleChecks.filter(
      (c) => c.status === CheckStatus.WARN,
    ).length;
    const passCount = articleChecks.filter(
      (c) => c.status === CheckStatus.PASS,
    ).length;

    let conformity: "CONFORMANT" | "NON-CONFORMANT" | "REQUIRES-ASSESSMENT";
    let severity: Severity;

    if (failCount > 0) {
      conformity = "NON-CONFORMANT";
      severity = Severity.CRITICAL;
    } else if (warnCount > 2) {
      conformity = "NON-CONFORMANT";
      severity = Severity.HIGH;
    } else if (warnCount > 0) {
      conformity = "REQUIRES-ASSESSMENT";
      severity = Severity.MEDIUM;
    } else {
      conformity = "CONFORMANT";
      return {
        id: "EUAI-000",
        name: "EU AI Act Overall Conformity",
        status: CheckStatus.PASS,
        message: `CONFORMANT — all ${passCount} Article requirements satisfied (enforcement: 2026-08-02)`,
      };
    }

    return {
      id: "EUAI-000",
      name: "EU AI Act Overall Conformity",
      status: conformity === "NON-CONFORMANT" ? CheckStatus.FAIL : CheckStatus.WARN,
      message: `${conformity} — ${passCount} pass, ${warnCount} warn, ${failCount} fail (enforcement: 2026-08-02)`,
      finding: {
        id: "EUAI-000",
        module: this.id,
        severity,
        title: `EU AI Act Conformity: ${conformity}`,
        description:
          `The AI system's overall EU AI Act conformity status is ${conformity}. ` +
          `${passCount} article(s) satisfied, ${warnCount} article(s) with gaps, ` +
          `${failCount} article(s) non-compliant. ` +
          "EU AI Act enforcement for high-risk AI systems begins August 2, 2026. " +
          "Non-compliant systems may face fines up to €35 million or 7% of global annual turnover.",
        evidence: { conformity, passCount, warnCount, failCount, enforcementDate: "2026-08-02" },
        remediation:
          "Address all findings from EUAI-001 through EUAI-005 to achieve conformity. " +
          "Engage a qualified EU AI Act conformity assessment body for formal evaluation. " +
          "Maintain documentation of all risk management, data governance, transparency, " +
          "human oversight, and robustness measures as required by Articles 9-15.",
        cweId: "CWE-693",
      },
    };
  }
}
