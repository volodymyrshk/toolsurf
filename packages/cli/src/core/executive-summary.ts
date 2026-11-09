import chalk from "chalk";
import type { ScanReport, Finding } from "../types/index.js";
import { scoreToGrade } from "./scorer.js";

/**
 * Executive Summary Generator.
 *
 * Produces a concise, non-technical summary of audit results
 * suitable for CISOs, VPs, and compliance stakeholders.
 * Written in business language, not engineering jargon.
 */

export interface ExecutiveSummary {
  /** One-paragraph risk assessment */
  riskAssessment: string;
  /** Risk level classification */
  riskLevel: "critical" | "high" | "moderate" | "low" | "minimal";
  /** Key takeaways (3-5 bullet points) */
  keyTakeaways: string[];
  /** Recommended immediate actions */
  immediateActions: string[];
  /** Overall posture statement */
  postureStatement: string;
}

/**
 * Generate an executive summary from scan results.
 */
export function generateExecutiveSummary(report: ScanReport): ExecutiveSummary {
  const { summary, findings, server } = report;
  const score = summary.securityScore;
  const grade = scoreToGrade(score);

  const critCount = summary.findingsBySeverity.CRITICAL;
  const highCount = summary.findingsBySeverity.HIGH;
  const medCount = summary.findingsBySeverity.MEDIUM;
  const lowCount = summary.findingsBySeverity.LOW;
  const totalFindings = findings.length;

  // Determine risk level
  const riskLevel = riskLevelFromReport(report, {
    critCount,
    highCount,
    medCount,
    totalFindings,
  });

  // Build risk assessment paragraph
  const riskAssessment = buildRiskAssessment(
    server.serverInfo.name,
    server.serverInfo.version,
    server.tools.length,
    score, grade,
    critCount, highCount, medCount, lowCount,
    totalFindings, riskLevel,
    findings
  );

  // Build key takeaways
  const keyTakeaways = buildKeyTakeaways(
    score, critCount, highCount, medCount, totalFindings,
    summary.passed, summary.totalChecks, findings
  );

  // Build immediate actions
  const immediateActions = buildImmediateActions(
    critCount, highCount, medCount, findings
  );

  // Posture statement
  const postureStatement = buildPostureStatement(score, grade, riskLevel);

  return {
    riskAssessment,
    riskLevel,
    keyTakeaways,
    immediateActions,
    postureStatement,
  };
}

// ─── Builders ───────────────────────────────────────────────────────────────

function buildRiskAssessment(
  serverName: string, version: string, toolCount: number,
  score: number, grade: string,
  critCount: number, highCount: number, medCount: number, lowCount: number,
  totalFindings: number, riskLevel: string,
  findings: Finding[]
): string {
  const serverDesc = `"${serverName}" (v${version}, ${toolCount} tools)`;

  if (riskLevel === "critical") {
    const critFinding = findings.find((f) => f.severity === "CRITICAL");
    return (
      `The MCP server ${serverDesc} presents CRITICAL security risk. ` +
      `The audit identified ${totalFindings} security finding(s), including ${critCount} critical-severity issue(s) ` +
      `that could allow direct exploitation. ` +
      (critFinding ? `Most notably, ${summarizeFinding(critFinding)}. ` : "") +
      `The overall security score of ${score}/100 (Grade ${grade}) indicates this server ` +
      `is NOT ready for production deployment without immediate remediation.`
    );
  }

  if (riskLevel === "high") {
    if (critCount > 0) {
      return (
        `The MCP server ${serverDesc} presents elevated security risk. ` +
        `The audit identified ${totalFindings} finding(s), including ${critCount} critical-severity and ` +
        `${highCount} high-severity issue(s). The calibrated CRS model classifies the aggregate target risk as HIGH, ` +
        `but the critical findings still require immediate remediation. ` +
        `The security score of ${score}/100 (Grade ${grade}) suggests significant hardening is needed.`
      );
    }

    return (
      `The MCP server ${serverDesc} presents elevated security risk. ` +
      `The audit identified ${totalFindings} finding(s), including ${highCount} high-severity issue(s) ` +
      `that require prompt attention. ` +
      `While no critical vulnerabilities were found, the combination of high-severity issues ` +
      `could be chained to compromise server integrity. ` +
      `The security score of ${score}/100 (Grade ${grade}) suggests significant hardening is needed.`
    );
  }

  if (riskLevel === "moderate") {
    return (
      `The MCP server ${serverDesc} has a moderate security posture. ` +
      `The audit identified ${totalFindings} finding(s): ${highCount} high, ${medCount} medium, and ${lowCount} low-severity. ` +
      `No critical vulnerabilities were detected, but medium-priority improvements ` +
      `would strengthen the server's defense-in-depth. ` +
      `The security score of ${score}/100 (Grade ${grade}) is acceptable for staging environments ` +
      `but should be improved before production deployment.`
    );
  }

  if (riskLevel === "low") {
    return (
      `The MCP server ${serverDesc} demonstrates a solid security posture. ` +
      `The audit identified ${totalFindings} minor finding(s) with no critical or high-severity issues. ` +
      `The security score of ${score}/100 (Grade ${grade}) indicates the server follows ` +
      `most security best practices. Minor improvements are recommended for defense-in-depth.`
    );
  }

  return (
    `The MCP server ${serverDesc} demonstrates excellent security posture. ` +
    `No security findings were identified across ${totalFindings === 0 ? "all" : totalFindings} checks. ` +
    `The security score of ${score}/100 (Grade ${grade}) indicates the server meets ` +
    `or exceeds security best practices for MCP deployments.`
  );
}

function riskLevelFromReport(
  report: ScanReport,
  counts: { critCount: number; highCount: number; medCount: number; totalFindings: number },
): ExecutiveSummary["riskLevel"] {
  if (report.riskProfile?.riskLevel) {
    const level = report.riskProfile.riskLevel.toLowerCase();
    if (
      level === "critical" ||
      level === "high" ||
      level === "medium" ||
      level === "low" ||
      level === "minimal"
    ) {
      return level === "medium" ? "moderate" : level;
    }
  }

  return counts.critCount > 0 ? "critical"
    : counts.highCount > 2 ? "high"
    : counts.highCount > 0 || counts.medCount > 5 ? "moderate"
    : counts.totalFindings > 0 ? "low"
    : "minimal";
}

function buildKeyTakeaways(
  score: number, critCount: number, highCount: number, _medCount: number,
  totalFindings: number, passed: number, totalChecks: number,
  findings: Finding[]
): string[] {
  const takeaways: string[] = [];
  const passRate = totalChecks > 0 ? Math.round((passed / totalChecks) * 100) : 100;

  takeaways.push(
    `Security score: ${score}/100 — ${passRate}% of ${totalChecks} security checks passed.`
  );

  if (critCount > 0) {
    takeaways.push(
      `${critCount} CRITICAL finding(s) require immediate remediation before any production use.`
    );
  }

  if (highCount > 0) {
    takeaways.push(
      `${highCount} HIGH-severity finding(s) should be addressed within the current sprint.`
    );
  }

  // Group findings by category for a high-level view
  const categories = new Map<string, number>();
  for (const f of findings) {
    const cat = categorizeFinding(f);
    categories.set(cat, (categories.get(cat) ?? 0) + 1);
  }

  if (categories.size > 0) {
    const topCategories = Array.from(categories.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([cat, count]) => `${cat} (${count})`)
      .join(", ");
    takeaways.push(`Primary risk areas: ${topCategories}.`);
  }

  if (totalFindings === 0) {
    takeaways.push(
      "No security vulnerabilities detected — the server follows MCP security best practices."
    );
  }

  return takeaways;
}

function buildImmediateActions(
  critCount: number, highCount: number, medCount: number,
  findings: Finding[]
): string[] {
  const actions: string[] = [];

  if (critCount > 0) {
    actions.push("URGENT: Remediate all critical findings before next deployment.");
    const critFindings = findings.filter((f) => f.severity === "CRITICAL");
    for (const f of critFindings.slice(0, 2)) {
      actions.push(`Fix: ${summarizeFinding(f)}`);
    }
  }

  if (highCount > 0) {
    const highFindings = findings.filter((f) => f.severity === "HIGH");
    actions.push(`Schedule remediation for ${highCount} high-severity finding(s) this sprint.`);
    if (highFindings.length > 0 && critCount === 0) {
      actions.push(`Priority: ${summarizeFinding(highFindings[0])}`);
    }
  }

  if (medCount > 0 && critCount === 0 && highCount === 0) {
    actions.push(`Plan improvements for ${medCount} medium-severity finding(s) in upcoming sprints.`);
  }

  if (actions.length === 0) {
    actions.push("No immediate actions required. Continue regular security scanning.");
    actions.push("Consider running scans with --active flag for deeper analysis.");
  }

  return actions;
}

function buildPostureStatement(score: number, grade: string, riskLevel: string): string {
  const levelStr = riskLevel.toUpperCase();
  const recommendation =
    riskLevel === "critical" ? "Deployment should be BLOCKED until critical issues are resolved."
    : riskLevel === "high" ? "Production deployment is NOT recommended without remediation."
    : riskLevel === "moderate" ? "Acceptable for staging; remediate before production promotion."
    : riskLevel === "low" ? "Ready for production with minor improvements recommended."
    : "Fully ready for production deployment.";

  return `Risk Level: ${levelStr} | Score: ${score}/100 (${grade}) | ${recommendation}`;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function summarizeFinding(f: Finding): string {
  // Create a concise business-readable summary
  const tool = f.toolName ? ` in "${f.toolName}"` : "";
  const cwe = f.cweId ? ` (${f.cweId})` : "";

  // Simplify technical titles to business language
  if (f.cweId === "CWE-78") return `command injection vulnerability${tool}`;
  if (f.cweId === "CWE-89") return `SQL injection vulnerability${tool}`;
  if (f.cweId === "CWE-22") return `path traversal allowing unauthorized file access${tool}`;
  if (f.cweId === "CWE-79") return `cross-site scripting (XSS) vulnerability${tool}`;
  if (f.cweId === "CWE-918") return `server-side request forgery (SSRF)${tool}`;
  if (f.cweId === "CWE-798") return `hardcoded credentials detected${tool}`;
  if (f.cweId === "CWE-912") return `hidden functionality detected${tool}`;

  return `${f.title.toLowerCase()}${cwe}`;
}

function categorizeFinding(f: Finding): string {
  if (f.cweId === "CWE-78" || f.cweId === "CWE-89" || f.cweId === "CWE-79") return "injection attacks";
  if (f.cweId === "CWE-22") return "path traversal";
  if (f.cweId === "CWE-918") return "SSRF";
  if (f.cweId === "CWE-798") return "credential exposure";
  if (f.cweId === "CWE-176" || f.cweId === "CWE-20") return "input validation";
  if (f.cweId === "CWE-400") return "resource limits";
  if (f.cweId === "CWE-912") return "hidden functionality";
  if (f.cweId === "CWE-863" || f.cweId === "CWE-269") return "authorization";
  if (f.cweId === "CWE-1357" || f.cweId === "CWE-250") return "supply chain";
  if (f.module === "tool-permissions") return "permissions";
  if (f.module === "transport-security") return "transport config";
  if (f.module === "schema-manipulation") return "schema integrity";
  if (f.module === "context-extraction") return "data exfiltration";
  return "security";
}

// ─── Terminal Output ────────────────────────────────────────────────────────

/**
 * Output executive summary to terminal.
 */
export function outputExecutiveSummary(es: ExecutiveSummary): void {
  const riskColors: Record<string, (s: string) => string> = {
    critical: chalk.bgRed.white.bold,
    high: chalk.red.bold,
    moderate: chalk.yellow.bold,
    low: chalk.green,
    minimal: chalk.green.bold,
  };
  const riskColor = riskColors[es.riskLevel] ?? chalk.white;

  console.log();
  console.log(chalk.bold.cyan("  ╭─────────────────────────────────────────────────────────────╮"));
  console.log(chalk.bold.cyan("  │") + chalk.bold("  EXECUTIVE SUMMARY") + chalk.dim("  — for leadership & compliance   ") + chalk.bold.cyan("  │"));
  console.log(chalk.bold.cyan("  ╰─────────────────────────────────────────────────────────────╯"));
  console.log();

  // Risk level badge
  console.log(`  ${chalk.bold("Risk Level:")} ${riskColor(` ${es.riskLevel.toUpperCase()} `)}`);
  console.log();

  // Risk assessment paragraph
  const words = es.riskAssessment.split(" ");
  let line = "  ";
  for (const word of words) {
    if (line.length + word.length + 1 > 78) {
      console.log(line);
      line = "  " + word;
    } else {
      line += (line.length > 2 ? " " : "") + word;
    }
  }
  if (line.trim()) console.log(line);
  console.log();

  // Key takeaways
  console.log(chalk.bold("  Key Takeaways:"));
  for (const t of es.keyTakeaways) {
    console.log(chalk.dim("    •") + ` ${t}`);
  }
  console.log();

  // Immediate actions
  console.log(chalk.bold("  Recommended Actions:"));
  for (let i = 0; i < es.immediateActions.length; i++) {
    const action = es.immediateActions[i];
    const prefix = action.startsWith("URGENT")
      ? chalk.red(`  ${i + 1}.`)
      : chalk.cyan(`  ${i + 1}.`);
    console.log(`${prefix} ${action}`);
  }
  console.log();

  // Posture statement
  console.log(chalk.dim("  ─".repeat(33)));
  console.log(`  ${chalk.bold(es.postureStatement)}`);
  console.log();
}

/**
 * Format executive summary as markdown for reports.
 */
export function executiveSummaryToMarkdown(es: ExecutiveSummary): string {
  const lines: string[] = [];

  lines.push("## Executive Summary");
  lines.push("");
  lines.push(`**Risk Level:** ${es.riskLevel.toUpperCase()}`);
  lines.push("");
  lines.push(es.riskAssessment);
  lines.push("");
  lines.push("### Key Takeaways");
  for (const t of es.keyTakeaways) {
    lines.push(`- ${t}`);
  }
  lines.push("");
  lines.push("### Recommended Actions");
  for (let i = 0; i < es.immediateActions.length; i++) {
    lines.push(`${i + 1}. ${es.immediateActions[i]}`);
  }
  lines.push("");
  lines.push(`> ${es.postureStatement}`);
  lines.push("");

  return lines.join("\n");
}

/**
 * Format executive summary as HTML for reports.
 */
export function executiveSummaryToHtml(es: ExecutiveSummary): string {
  const riskColors: Record<string, string> = {
    critical: "#ef4444", high: "#f97316", moderate: "#eab308",
    low: "#22c55e", minimal: "#22c55e",
  };
  const color = riskColors[es.riskLevel] ?? "#6b7280";

  return `
<div class="executive-summary" style="background:#0a0a0a;border:1px solid #171717;border-radius:4px;padding:1.5rem 2rem;margin-bottom:2rem">
  <h2 style="color:#22d3ee;margin-bottom:1rem;font-size:1.1rem;text-transform:uppercase;letter-spacing:0.05em">Executive Summary</h2>
  <div style="display:inline-block;padding:4px 12px;border-radius:2px;font-weight:700;color:#fff;background:${color};margin-bottom:1rem;text-transform:uppercase;font-size:0.75rem">${es.riskLevel}</div>
  <p style="color:#d4d4d4;line-height:1.6;margin-bottom:1rem">${es.riskAssessment}</p>
  <h3 style="color:#a3a3a3;font-size:0.9rem;margin-bottom:0.5rem">Key Takeaways</h3>
  <ul style="color:#d4d4d4;font-size:0.85rem;margin-bottom:1rem">${es.keyTakeaways.map((t) => `<li>${t}</li>`).join("")}</ul>
  <h3 style="color:#a3a3a3;font-size:0.9rem;margin-bottom:0.5rem">Recommended Actions</h3>
  <ol style="color:#d4d4d4;font-size:0.85rem;margin-bottom:1rem">${es.immediateActions.map((a) => `<li>${a}</li>`).join("")}</ol>
  <div style="border-top:1px solid #262626;padding-top:0.75rem;color:#737373;font-size:0.8rem;font-weight:600">${es.postureStatement}</div>
</div>`;
}
