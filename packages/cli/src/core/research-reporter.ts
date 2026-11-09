/**
 * Research-grade output formats for academic papers and datasets.
 * Generates LaTeX tables, CSV datasets, pgfplots data, and JSON with research metadata.
 *
 * Designed for LTJournalArticle LaTeX class with booktabs, longtable, xcolor, listings, tcolorbox.
 */

import type { ScanReport } from "../types/index.js";
import { Severity } from "../types/index.js";
import { scoreToGrade, SCORING_FORMULA_VERSION, computeECE, computeBrierScore } from "./scorer.js";
import { escapeLatex } from "../utils/latex.js";

/**
 * Escape CSV fields per RFC 4180.
 */
function escapeCsv(field: string): string {
  if (field.includes(",") || field.includes('"') || field.includes("\n")) {
    return `"${field.replace(/"/g, '""')}"`;
  }
  return field;
}

/**
 * Map severity to LaTeX cell color.
 */
function severityToLatexColor(severity: string | Severity): string {
  const sev = String(severity);
  switch (sev) {
    case "CRITICAL":
      return "red!20";
    case "HIGH":
      return "orange!20";
    case "MEDIUM":
      return "yellow!20";
    case "LOW":
      return "blue!10";
    case "INFO":
      return "gray!10";
    default:
      return "white";
  }
}

/**
 * Format a number with thousands separator.
 */
function formatNumber(n: number): string {
  return n.toLocaleString("en-US");
}

// ─── Main Export Functions ──────────────────────────────────────────────────

/**
 * Generate LaTeX content for inclusion in an LTJournalArticle document.
 * Produces finding tables, score boxes, module effectiveness, and compliance mappings.
 */
export function outputLatex(report: ScanReport): string {
  const lines: string[] = [];
  const serverName = escapeLatex(report.server.serverInfo.name);
  const score = report.summary.securityScore;
  const grade = scoreToGrade(score);

  // ── Score Summary Box ──────────────────────────────────────────────────
  lines.push("% ─── Security Assessment Summary ───");
  lines.push("\\begin{tcolorbox}[colback=gray!5, colframe=gray!50, title={Security Assessment: \\texttt{" + serverName + "}}]");
  lines.push(`\\textbf{Score:} ${score}/100 (Grade: ${grade}) \\\\`);
  lines.push(`\\textbf{Protocol:} ${escapeLatex(report.transport.protocol ?? "unknown")} \\\\`);
  lines.push(
    `\\textbf{Tools:} ${report.server.tools.length} \\quad \\textbf{Resources:} ${report.server.resources.length} \\quad \\textbf{Prompts:} ${report.server.prompts.length} \\\\`
  );

  const s = report.summary.findingsBySeverity;
  lines.push(
    `\\textbf{Findings:} ${s[Severity.CRITICAL] ?? 0} Critical, ${s[Severity.HIGH] ?? 0} High, ${s[Severity.MEDIUM] ?? 0} Medium, ${s[Severity.LOW] ?? 0} Low \\\\`
  );
  lines.push(`\\textbf{Scan Duration:} ${formatNumber(report.durationMs)}ms`);
  lines.push("\\end{tcolorbox}");
  lines.push("");

  // ── Findings Table (longtable with booktabs) ────────────────────────────
  if (report.findings.length > 0) {
    lines.push("% ─── Security Findings Table ───");
    lines.push("\\begin{longtable}{llllp{5cm}}");
    lines.push(`\\caption{Security findings for \\texttt{${serverName}} (Score: ${score}/100, Grade: ${grade})}`);
    lines.push(`\\label{tab:findings-${report.server.serverInfo.name.toLowerCase().replace(/[^a-z0-9]/g, "")}}`);
    lines.push("\\\\");
    lines.push("\\toprule");
    lines.push("ID & Severity & Module & CWE & Description \\\\");
    lines.push("\\midrule");
    lines.push("\\endfirsthead");
    lines.push("\\multicolumn{5}{c}{\\textit{(continued)}} \\\\");
    lines.push("\\toprule");
    lines.push("ID & Severity & Module & CWE & Description \\\\");
    lines.push("\\midrule");
    lines.push("\\endhead");
    lines.push("\\midrule");
    lines.push("\\multicolumn{5}{r}{\\textit{(continued on next page)}} \\\\");
    lines.push("\\endfoot");
    lines.push("\\bottomrule");
    lines.push("\\endlastfoot");

    for (const finding of report.findings) {
      const color = severityToLatexColor(finding.severity);
      const cweId = finding.cweId ?? "---";
      const desc = escapeLatex(finding.description.substring(0, 100));
      lines.push(
        `${escapeLatex(finding.id)} & \\cellcolor{${color}}${finding.severity} & ${escapeLatex(finding.module)} & ${cweId} & ${desc} \\\\`
      );
    }

    lines.push("\\end{longtable}");
    lines.push("");
  }

  // ── Module Effectiveness Table ─────────────────────────────────────────
  lines.push("% ─── Module Effectiveness ───");
  lines.push("\\begin{table}[htbp]");
  lines.push(`\\caption{Module effectiveness for \\texttt{${serverName}}}`);
  lines.push(
    `\\label{tab:modules-${report.server.serverInfo.name.toLowerCase().replace(/[^a-z0-9]/g, "")}}`
  );
  lines.push("\\centering");
  lines.push("\\begin{tabular}{lrrrr}");
  lines.push("\\toprule");
  lines.push("Module & Checks & Pass & Fail & Duration (ms) \\\\");
  lines.push("\\midrule");

  for (const mod of report.modules) {
    const checks = mod.checks.length;
    const passed = mod.checks.filter((c) => c.status === "PASS").length;
    const failed = mod.checks.filter((c) => c.status === "FAIL").length;
    lines.push(
      `${escapeLatex(mod.moduleName)} & ${checks} & ${passed} & ${failed} & ${mod.durationMs} \\\\`
    );
  }

  lines.push("\\bottomrule");
  lines.push("\\end{tabular}");
  lines.push("\\end{table}");
  lines.push("");

  // ── Compliance Mapping (if available) ──────────────────────────────────
  if (report.compliance && Object.keys(report.compliance.nist).length > 0) {
    lines.push("% ─── Compliance Control Mapping ───");
    lines.push("\\begin{table}[htbp]");
    lines.push(`\\caption{Compliance control mapping for \\texttt{${serverName}}}`);
    lines.push(
      `\\label{tab:compliance-${report.server.serverInfo.name.toLowerCase().replace(/[^a-z0-9]/g, "")}}`
    );
    lines.push("\\centering");
    lines.push("\\begin{tabular}{lrr}");
    lines.push("\\toprule");
    lines.push("Framework & Control & Findings \\\\");
    lines.push("\\midrule");

    const frameworks = [
      { name: "NIST SP 800-171", controls: report.compliance.nist },
      { name: "SOC 2 TSC", controls: report.compliance.soc2 },
      { name: "OWASP ASVS v4.0", controls: report.compliance.asvs },
    ];

    for (const fw of frameworks) {
      const controls = Object.entries(fw.controls).sort((a, b) => b[1] - a[1]);
      for (const [control, count] of controls) {
        lines.push(`${fw.name} & ${escapeLatex(control)} & ${count} \\\\`);
      }
    }

    lines.push("\\bottomrule");
    lines.push("\\end{tabular}");
    lines.push("\\end{table}");
    lines.push("");
  }

  // ── Per-Finding Details (for appendix) ──────────────────────────────────
  if (report.findings.length > 0) {
    lines.push("% ─── Detailed Finding Descriptions (Appendix Material) ───");
    lines.push("");

    for (const finding of report.findings) {
      const safeId = finding.id.replace(/[^a-z0-9-]/gi, "");
      const safeName = report.server.serverInfo.name.toLowerCase().replace(/[^a-z0-9]/g, "");
      lines.push(`\\paragraph{${escapeLatex(finding.id)}: ${escapeLatex(finding.title)}}`);
      lines.push(`\\label{finding:${safeId}-${safeName}}`);
      lines.push("");
      lines.push(
        `\\textbf{Severity:} ${finding.severity} \\quad \\textbf{CWE:} ${finding.cweId ?? "N/A"} \\quad \\textbf{Confidence:} ${(finding.confidence ?? 0).toFixed(2)} \\\\`
      );
      if (finding.toolName) {
        lines.push(`\\textbf{Tool:} \\texttt{${escapeLatex(finding.toolName)}} \\\\`);
      }
      lines.push("");
      lines.push(`\\textbf{Description:} ${escapeLatex(finding.description)}`);
      lines.push("");

      // Evidence as code block
      if (Object.keys(finding.evidence).length > 0) {
        const evidenceJson = JSON.stringify(finding.evidence, null, 2);
        lines.push("\\textbf{Evidence:}");
        lines.push("\\begin{lstlisting}[language=json, basicstyle=\\ttfamily\\small]");
        lines.push(escapeLatex(evidenceJson));
        lines.push("\\end{lstlisting}");
        lines.push("");
      }

      lines.push(`\\textbf{Remediation:} ${escapeLatex(finding.remediation)}`);
      lines.push("");
    }
  }

  return lines.join("\n");
}

/**
 * Generate pgfplots data file content for severity distribution charts.
 * Format: space-separated columns suitable for bar/column charts.
 */
export function outputPgfplotsData(report: ScanReport): string {
  const lines: string[] = [];
  const serverName = report.server.serverInfo.name;

  // ── Header ──────────────────────────────────────────────────────────────
  lines.push(`% toolsurf pgfplots data`);
  lines.push(`% Target: ${serverName} | Protocol: ${report.transport.protocol ?? "unknown"} | Score: ${report.summary.securityScore}/100`);
  lines.push(`% Format: severity count percentage`);
  lines.push("");

  // ── Severity Distribution ──────────────────────────────────────────────
  const s = report.summary.findingsBySeverity;
  const total =
    (s[Severity.CRITICAL] ?? 0) +
    (s[Severity.HIGH] ?? 0) +
    (s[Severity.MEDIUM] ?? 0) +
    (s[Severity.LOW] ?? 0);
  const data: Array<[string, number]> = [
    ["CRITICAL", s[Severity.CRITICAL] ?? 0],
    ["HIGH", s[Severity.HIGH] ?? 0],
    ["MEDIUM", s[Severity.MEDIUM] ?? 0],
    ["LOW", s[Severity.LOW] ?? 0],
  ];

  lines.push("Severity Count Percentage");
  for (const [severity, count] of data) {
    const pct = total > 0 ? ((count / total) * 100).toFixed(1) : "0.0";
    lines.push(`${severity} ${count} ${pct}`);
  }
  lines.push("");

  // ── Module effectiveness data ──────────────────────────────────────────
  lines.push("% Module effectiveness data");
  lines.push("% Format: module_name pass_count fail_count skip_count");
  lines.push("");

  for (const mod of report.modules) {
    const passed = mod.checks.filter((c) => c.status === "PASS").length;
    const failed = mod.checks.filter((c) => c.status === "FAIL").length;
    const skipped = mod.checks.filter((c) => c.status === "SKIP").length;
    lines.push(`${mod.moduleName} ${passed} ${failed} ${skipped}`);
  }

  return lines.join("\n");
}

/**
 * Generate CSV output with comprehensive finding and metadata columns.
 * RFC 4180 compliant (proper quoting of fields with commas/quotes/newlines).
 */
export function outputResearchCsv(report: ScanReport): string {
  const lines: string[] = [];

  // ── CSV Header ──────────────────────────────────────────────────────────
  const headers = [
    "target_name",
    "target_version",
    "protocol",
    "protocol_version",
    "tool_count",
    "resource_count",
    "prompt_count",
    "finding_id",
    "severity",
    "module",
    "check_name",
    "cwe_id",
    "tool_name",
    "confidence",
    "description",
    "remediation",
    "scan_date",
    "scan_duration_ms",
    "security_score",
    "grade",
  ];
  lines.push(headers.map(escapeCsv).join(","));

  // ── Data rows ───────────────────────────────────────────────────────────
  const targetName = report.server.serverInfo.name;
  const targetVersion = report.server.serverInfo.version;
  const protocol = report.transport.protocol ?? "unknown";
  const protocolVersion = report.server.protocolVersion;
  const toolCount = report.server.tools.length;
  const resourceCount = report.server.resources.length;
  const promptCount = report.server.prompts.length;
  const scanDate = new Date(report.timestamp).toISOString();
  const scanDuration = report.durationMs;
  const score = report.summary.securityScore;
  const grade = scoreToGrade(score);

  if (report.findings.length === 0) {
    // No findings: one row with target metadata only
    const row = [
      escapeCsv(targetName),
      escapeCsv(targetVersion),
      escapeCsv(protocol),
      escapeCsv(protocolVersion),
      String(toolCount),
      String(resourceCount),
      String(promptCount),
      "", // finding_id
      "", // severity
      "", // module
      "", // check_name
      "", // cwe_id
      "", // tool_name
      "", // confidence
      "", // description
      "", // remediation
      escapeCsv(scanDate),
      String(scanDuration),
      String(score),
      escapeCsv(grade),
    ];
    lines.push(row.join(","));
  } else {
    // One row per finding
    for (const finding of report.findings) {
      const row = [
        escapeCsv(targetName),
        escapeCsv(targetVersion),
        escapeCsv(protocol),
        escapeCsv(protocolVersion),
        String(toolCount),
        String(resourceCount),
        String(promptCount),
        escapeCsv(finding.id),
        escapeCsv(String(finding.severity)),
        escapeCsv(finding.module),
        escapeCsv(finding.title), // check_name
        escapeCsv(finding.cweId ?? ""),
        escapeCsv(finding.toolName ?? ""),
        String(finding.confidence ?? 0),
        escapeCsv(finding.description),
        escapeCsv(finding.remediation),
        escapeCsv(scanDate),
        String(scanDuration),
        String(score),
        escapeCsv(grade),
      ];
      lines.push(row.join(","));
    }
  }

  return lines.join("\n");
}

/**
 * Generate enhanced JSON with research-specific metadata fields.
 * Adds protocol type, corpus ID, scan profile, and dataset version.
 */
interface ResearchScanReport extends ScanReport {
  researchMetadata: Record<string, unknown>;
}

export function outputResearchJson(report: ScanReport): string {
  // ── Research metadata — all hardening labels (INSTRUMENT-HARDENING-REPORT §LEAD)
  // Protocol-agnostic: applies equally to MCP, OpenAI Functions, LangChain,
  // REST API, GraphQL, and gRPC scans — all produce the same ScanReport shape.
  const timedOutModules = report.modules
    .filter((m) => m.error?.includes("timed out"))
    .map((m) => m.moduleId);

  const researchMetadata = {
    protocol: report.transport.protocol ?? "unknown",
    corpusId: report.server.serverInfo.name.toLowerCase().replace(/[^a-z0-9-]/g, "-"),
    scanProfile: report.modules.length >= 10 ? "enterprise" : report.modules.length >= 6 ? "standard" : "quick",
    // #08 — formula version from named constant (not hardcoded string)
    scoringVersion: SCORING_FORMULA_VERSION,
    // #09 — git commit for exact reproducibility
    scannerCommit: report.scannerCommit ?? "unknown",
    // P0-02/P1-03 — scan mode distinguishes active fuzzing from passive-only
    scanMode: report.scanMode ?? "unknown",
    // P0-01 — scan tier from riskProfile for research stratification
    scanTier: report.riskProfile?._scanTier ?? "unknown",
    // #10 — calibration gate
    calibrationStatus: report.calibrationStatus ?? "PRE-CALIBRATION",
    datasetVersion: "2026-03-25",
    generatedAt: new Date().toISOString(),
    scannerVersion: report.cliVersion,
    slim: false,
    // §Topic 9 — W3C PROV-DM provenance for IEEE S&P artifact evaluation
    ...(report.provenance ? { provenance: report.provenance } : {}),
    // #11 — surface timed-out modules so consumers know coverage is partial
    ...(timedOutModules.length > 0 ? { notAssessedModules: timedOutModules } : {}),
    // §REPRO / DeepR_7 — per-scan confidence calibration metrics.
    // Uses finding.confidence as predicted probability and severity (CRITICAL|HIGH) as
    // proxy for actual outcome. Cross-server ECE requires fleet-research-reporter.
    calibrationMetrics: (() => {
      const predictions = report.findings.map((f) => ({
        predicted: f.confidence ?? 0.5,
        actual: (f.severity === Severity.CRITICAL || f.severity === Severity.HIGH) ? 1 : 0 as 0 | 1,
      }));
      if (predictions.length === 0) {
        return { note: "No findings — calibration metrics not applicable", sampleSize: 0 };
      }
      const ece = computeECE(predictions);
      const brier = computeBrierScore(predictions);
      return {
        note: "Single-scan confidence calibration proxy. Cross-server ECE requires fleet-research-reporter.",
        sampleSize: predictions.length,
        ece: Math.round(ece * 10000) / 10000,
        brier: {
          brier: Math.round(brier.brier * 10000) / 10000,
          reliability: Math.round(brier.reliability * 10000) / 10000,
          resolution: Math.round(brier.resolution * 10000) / 10000,
          uncertainty: Math.round(brier.uncertainty * 10000) / 10000,
        },
      };
    })(),
    // #16 — [LEGACY] label on securityScore for all research consumers
    legacyScoreNote:
      "[LEGACY] securityScore (0-100) is a backwards-compatible penalty-deduction " +
      "metric. Use riskProfile.compositeRiskScore (CRS) and riskProfile.umriScalar " +
      "for all research analysis. The legacy score will be removed in a future version.",
    // #05 — score=100 ≠ secure; applies to every protocol adapter
    securityScoreInterpretation:
      "[KNOWN LIMIT #05] securityScore=100 means no passive findings were detected. " +
      "It does NOT mean the target is secure. A server that hides dangerous capabilities " +
      "behind non-keyword tool names scores 100 passively. Always use --active and treat " +
      "score=100 as 'no passive signals', not 'absence of risk'. " +
      "Applies to MCP, REST, GraphQL, gRPC, OpenAI Functions, LangChain, and all other protocols.",
    // #13 — passive DC detection bypass (keyword-based)
    // #15 — out-of-scope coverage gaps
    detectionLimitations: {
      passiveBypass:
        "[KNOWN LIMIT #13] DC-001/002/003 (arbitrary SQL/code/shell) detection is " +
        "keyword-based on tool names and descriptions. A tool named 'process_workflow' " +
        "that internally runs shell commands will not be flagged passively. " +
        "--active mode partially mitigates this for all supported protocols.",
      authorizationCoverage:
        "[OUT OF SCOPE #15] No auth/authorization assessment. A server requiring " +
        "bearer tokens is not distinguished from an unauthenticated server. " +
        "Affects REST, GraphQL, gRPC, and MCP transports equally.",
      rateLimitCoverage:
        "[OUT OF SCOPE #15] No rate-limit detection. Especially relevant for " +
        "REST API, GraphQL, and gRPC targets.",
      schemaDriftCoverage:
        "[OUT OF SCOPE #15] Cross-scan schema-drift is not enforced automatically. " +
        "The schemaHash field enables external diffing between runs.",
      tlsCertificateValidation:
        "[OUT OF SCOPE #15] TLS usage is checked but certificate trust chains are not validated.",
    },
  };

  const researchReport: ResearchScanReport = { ...report, researchMetadata };
  return JSON.stringify(researchReport, null, 2);
}

// ─── Slim Output Mode ─────────────────────────────────────────────────────────

/**
 * Truncate array-valued evidence fields to at most maxItems entries.
 * Replaces long arrays with { _truncated: true, count: N, sample: [...first N] }.
 * Non-array values pass through unchanged.
 *
 * Why: Some modules store 100+ matched-tool lists in evidence (e.g. SM-002 stores
 * 124 tool names = 16KB per finding). For the paper's analysis we only need the
 * count and a representative sample.
 */
function truncateEvidence(
  evidence: Record<string, unknown>,
  maxItems = 10,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(evidence)) {
    if (Array.isArray(value) && value.length > maxItems) {
      result[key] = {
        _truncated: true,
        count: value.length,
        sample: value.slice(0, maxItems),
      };
    } else {
      result[key] = value;
    }
  }
  return result;
}

/**
 * Produce a slim version of a ScanReport for storage-efficient fleet runs.
 *
 * What is stripped (and why):
 *
 * 1. `server.tools`  (avg 40% of file = raw OpenAPI/MCP tool schemas)
 *    → Identical across all 5 runs of the same target. Replaced by `toolCount`.
 *      Full schemas live in the fixture files if ever needed.
 *
 * 2. `modules[].findings`  (avg 25% of file = full finding objects duplicated per module)
 *    → Already present in the top-level `findings[]` array. Removed from each module.
 *
 * 3. `modules[].checks[].finding`  (the embedded finding object on each CheckResult)
 *    → Same data, third copy. Removed; keep only `id`, `name`, `status`, `message`.
 *
 * 4. `findings[].evidence` arrays > 10 items
 *    → Truncated to { _truncated, count, sample[0..9] }.
 *
 * What is preserved (everything the analysis scripts actually read):
 *   - All findings with id, severity, module, cweId, confidence, toolName, title, description, remediation
 *   - All module-level check status counts (pass/fail/skip per module)
 *   - Full summary (securityScore, rawScore, penaltyPoints, findingsBySeverity)
 *   - Full transport, compliance, researchMetadata blocks
 *
 * Typical size reduction: ~85% (1.5MB → ~180-200KB for a REST fleet target).
 */
export function slimifyReport(report: ScanReport): Record<string, unknown> {
  // Slim server block: drop tools[], keep everything else + add toolCount
  const slimServer = {
    serverInfo: report.server.serverInfo,
    protocolVersion: report.server.protocolVersion,
    capabilities: report.server.capabilities,
    // toolCount replaces the full tools[] array
    toolCount: report.server.tools.length,
    resourceCount: report.server.resources.length,
    promptCount: report.server.prompts.length,
    // Keep resources + prompts (they're small and contain research-relevant data)
    resources: report.server.resources,
    prompts: report.server.prompts,
  };

  // Slim modules: remove embedded findings and strip finding objects from checks
  const slimModules = report.modules.map((mod) => ({
    moduleId: mod.moduleId,
    moduleName: mod.moduleName,
    moduleVersion: mod.moduleVersion,
    durationMs: mod.durationMs,
    error: mod.error,
    // Summarise check outcomes without embedding full finding objects
    checks: mod.checks.map((c) => ({
      id: c.id,
      name: c.name,
      status: c.status,
      ...(c.message ? { message: c.message } : {}),
      // omit c.finding — already in top-level findings[]
    })),
    // omit mod.findings — already in top-level findings[]
  }));

  // Slim findings: truncate over-sized evidence arrays
  const slimFindings = report.findings.map((f) => ({
    ...f,
    evidence: truncateEvidence(f.evidence),
  }));

  return {
    version: report.version,
    id: report.id,
    timestamp: report.timestamp,
    durationMs: report.durationMs,
    cliVersion: report.cliVersion,
    scannerCommit: report.scannerCommit ?? "unknown",
    scanMode: report.scanMode ?? "unknown",
    scoringFormulaVersion: report.scoringFormulaVersion ?? SCORING_FORMULA_VERSION,
    calibrationStatus: report.calibrationStatus ?? "PRE-CALIBRATION",
    transport: report.transport,
    server: slimServer,
    modules: slimModules,
    findings: slimFindings,
    summary: report.summary,
    // Preserve riskProfile (UMRI, CRS, SSVC) — critical for research analysis
    ...(report.riskProfile ? { riskProfile: report.riskProfile } : {}),
    ...(report.schemaHash ? { schemaHash: report.schemaHash } : {}),
    ...(report.provenance ? { provenance: report.provenance } : {}),
    ...(report.peavReport ? { peavReport: report.peavReport } : {}),
    ...(report.chamberReachability ? { chamberReachability: report.chamberReachability } : {}),
    ...(report.chamberSummary ? { chamberSummary: report.chamberSummary } : {}),
    ...(report.killChainSummary ? { killChainSummary: report.killChainSummary } : {}),
    ...(report.chamberProofBundle ? { chamberProofBundle: report.chamberProofBundle } : {}),
    ...(report.compliance ? { compliance: report.compliance } : {}),
    researchMetadata: {
      protocol: report.transport.protocol ?? "unknown",
      corpusId: report.server.serverInfo.name.toLowerCase().replace(/[^a-z0-9-]/g, "-"),
      scanProfile: report.modules.length >= 10 ? "enterprise" : report.modules.length >= 6 ? "standard" : "quick",
      scoringVersion: SCORING_FORMULA_VERSION,
      scannerCommit: report.scannerCommit ?? "unknown",
      calibrationStatus: report.calibrationStatus ?? "PRE-CALIBRATION",
      datasetVersion: "2026-03-25",
      generatedAt: new Date().toISOString(),
      scannerVersion: report.cliVersion,
      slim: true,
      // §Topic 9 — W3C PROV-DM provenance for IEEE S&P artifact evaluation
      ...(report.provenance ? { provenance: report.provenance } : {}),
      ...(report.modules.filter((m) => m.error?.includes("timed out")).length > 0
        ? { notAssessedModules: report.modules.filter((m) => m.error?.includes("timed out")).map((m) => m.moduleId) }
        : {}),
      legacyScoreNote:
        "[LEGACY] securityScore (0-100) is a backwards-compatible penalty-deduction " +
        "metric. Use riskProfile.compositeRiskScore (CRS) and riskProfile.umriScalar " +
        "for all research analysis.",
      securityScoreInterpretation:
        "[KNOWN LIMIT #05] securityScore=100 means no passive findings were detected, " +
        "NOT that the target is secure. Applies to all protocol adapters.",
      detectionLimitations: {
        passiveBypass:
          "[KNOWN LIMIT #13] DC-001/002/003 detection is keyword-based and bypassable " +
          "via non-keyword tool naming. Use --active to partially mitigate.",
        authorizationCoverage: "[OUT OF SCOPE #15] No auth/authorization assessment.",
        rateLimitCoverage: "[OUT OF SCOPE #15] No rate-limit detection.",
        schemaDriftCoverage: "[OUT OF SCOPE #15] Cross-scan schema-drift not enforced automatically.",
        tlsCertificateValidation: "[OUT OF SCOPE #15] TLS usage checked; cert trust chains are not.",
      },
    },
  };
}

/**
 * Generate a slim research-JSON output.
 * Use --format research-json-slim (or pass --slim with --format research-json
 * via the scan command) to get ~85% smaller files suitable for fleet scanning.
 */
export function outputResearchJsonSlim(report: ScanReport): string {
  return JSON.stringify(slimifyReport(report), null, 2);
}
