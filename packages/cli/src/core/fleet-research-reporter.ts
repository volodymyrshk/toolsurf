/**
 * Fleet-level research output for cross-protocol security analysis.
 * Generates LaTeX tables for multi-target comparisons, heatmaps, and statistical summaries.
 *
 * Suitable for corpus-wide analysis in academic papers.
 */

import type { ScanReport } from "../types/index.js";
import { Severity } from "../types/index.js";
import { scoreToGrade } from "./scorer.js";
import { escapeLatex } from "../utils/latex.js";

/**
 * Calculate mean of a numeric array.
 */
function mean(arr: number[]): number {
  if (arr.length === 0) return 0;
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

/**
 * Calculate median of a numeric array.
 */
function median(arr: number[]): number {
  const sorted = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? (sorted[mid - 1] + sorted[mid]) / 2
    : sorted[mid];
}

/**
 * Calculate standard deviation.
 */
function stdDev(arr: number[]): number {
  if (arr.length < 2) return 0;
  const m = mean(arr);
  const variance =
    arr.reduce((sum, val) => sum + Math.pow(val - m, 2), 0) / arr.length;
  return Math.sqrt(variance);
}

// ─── Main Export Functions ──────────────────────────────────────────────────

/**
 * Generate cross-protocol comparison LaTeX tables and statistical summaries.
 */
export function outputFleetLatex(reports: ScanReport[]): string {
  const lines: string[] = [];

  if (reports.length === 0) {
    return "% No reports to generate fleet summary";
  }

  // Group by protocol
  interface ProtocolGroup {
    protocol: string;
    reports: ScanReport[];
  }

  const protocolMap = new Map<string, ScanReport[]>();
  for (const report of reports) {
    const proto = report.transport.protocol ?? "unknown";
    if (!protocolMap.has(proto)) {
      protocolMap.set(proto, []);
    }
    protocolMap.get(proto)!.push(report);
  }

  const protocolGroups: ProtocolGroup[] = Array.from(protocolMap.entries())
    .map(([protocol, reports]) => ({ protocol, reports }))
    .sort((a, b) => a.protocol.localeCompare(b.protocol));

  // ── Cross-Protocol Comparison Table ────────────────────────────────────
  lines.push("% ─── Cross-Protocol Security Assessment Results ───");
  lines.push("\\begin{table*}[htbp]");
  lines.push(`\\caption{Cross-protocol security assessment results (N=${reports.length})}\\label{tab:cross-protocol}`);
  lines.push("\\centering");
  lines.push("\\begin{tabular}{lrrrrrrr}");
  lines.push("\\toprule");
  lines.push(
    "Protocol & Targets & Avg Score & Critical & High & Medium & Low & Total Findings \\\\"
  );
  lines.push("\\midrule");

  for (const group of protocolGroups) {
    const scores = group.reports.map((r) => r.summary.securityScore);
    const avgScore = mean(scores).toFixed(1);

    let totalCritical = 0,
      totalHigh = 0,
      totalMedium = 0,
      totalLow = 0;
    for (const report of group.reports) {
      const s = report.summary.findingsBySeverity;
      totalCritical += s[Severity.CRITICAL] ?? 0;
      totalHigh += s[Severity.HIGH] ?? 0;
      totalMedium += s[Severity.MEDIUM] ?? 0;
      totalLow += s[Severity.LOW] ?? 0;
    }
    const totalFindings = totalCritical + totalHigh + totalMedium + totalLow;

    lines.push(
      `${escapeLatex(group.protocol)} & ${group.reports.length} & ${avgScore} & ${totalCritical} & ${totalHigh} & ${totalMedium} & ${totalLow} & ${totalFindings} \\\\`
    );
  }

  lines.push("\\bottomrule");
  lines.push("\\end{tabular}");
  lines.push("\\end{table*}");
  lines.push("");

  // ── Statistical Summary Table ──────────────────────────────────────────
  lines.push("% ─── Descriptive Statistics ───");
  lines.push("\\begin{table}[htbp]");
  lines.push("\\caption{Descriptive statistics of security scores across protocols}");
  lines.push("\\label{tab:statistics}");
  lines.push("\\centering");
  lines.push("\\begin{tabular}{lrrrrrr}");
  lines.push("\\toprule");
  lines.push("Protocol & N & Mean & Median & Std Dev & Min & Max \\\\");
  lines.push("\\midrule");

  for (const group of protocolGroups) {
    const scores = group.reports.map((r) => r.summary.securityScore);
    const m = mean(scores);
    const med = median(scores);
    const sd = stdDev(scores);
    const minScore = Math.min(...scores);
    const maxScore = Math.max(...scores);

    lines.push(
      `${escapeLatex(group.protocol)} & ${scores.length} & ${m.toFixed(1)} & ${med.toFixed(1)} & ${sd.toFixed(2)} & ${minScore} & ${maxScore} \\\\`
    );
  }

  lines.push("\\bottomrule");
  lines.push("\\end{tabular}");
  lines.push("\\end{table}");
  lines.push("");

  // ── Worst Targets (Pentest Candidates) ─────────────────────────────────
  const sortedByScore = [...reports].sort((a, b) => a.summary.securityScore - b.summary.securityScore);
  const worstTargets = sortedByScore.slice(0, Math.min(10, reports.length));

  if (worstTargets.length > 0) {
    lines.push("% ─── Lowest-Scoring Targets (Pentest Candidates) ───");
    lines.push("\\begin{table}[htbp]");
    lines.push("\\caption{Lowest-scoring targets for focused testing}");
    lines.push("\\label{tab:worst-targets}");
    lines.push("\\centering");
    lines.push("\\begin{tabular}{lllrrr}");
    lines.push("\\toprule");
    lines.push("Rank & Target & Protocol & Score & Grade & Critical Findings \\\\");
    lines.push("\\midrule");

    for (let i = 0; i < worstTargets.length; i++) {
      const report = worstTargets[i];
      const grade = scoreToGrade(report.summary.securityScore);
      const criticalCount = report.summary.findingsBySeverity.CRITICAL ?? 0;
      lines.push(
        `${i + 1} & \\texttt{${escapeLatex(report.server.serverInfo.name)}} & ${escapeLatex(report.transport.protocol ?? "unknown")} & ${report.summary.securityScore} & ${grade} & ${criticalCount} \\\\`
      );
    }

    lines.push("\\bottomrule");
    lines.push("\\end{tabular}");
    lines.push("\\end{table}");
    lines.push("");
  }

  // ── Framework-Level Finding Correlation Table ──────────────────────────────
  const correlation = computeFindingCorrelation(reports);
  if (correlation.frameworkLevel.length > 0) {
    lines.push("% ─── Framework-Level Findings (present in ≥50% of targets) ───");
    lines.push("\\begin{table}[htbp]");
    lines.push("\\caption{Framework-level findings across the corpus}");
    lines.push("\\label{tab:framework-findings}");
    lines.push("\\centering");
    lines.push("\\begin{tabular}{llrr}");
    lines.push("\\toprule");
    lines.push("Finding ID & Max Severity & Servers & Prevalence \\\\");
    lines.push("\\midrule");

    for (const f of correlation.frameworkLevel.slice(0, 15)) {
      lines.push(
        `\\texttt{${escapeLatex(f.findingId)}} & ${f.maxSeverity} & ${f.serverCount}/${reports.length} & ${f.prevalencePercent}\\% \\\\`
      );
    }

    lines.push("\\bottomrule");
    lines.push("\\end{tabular}");
    lines.push("\\end{table}");
    lines.push("");
  }

  return lines.join("\n");
}

/**
 * Generate pgfplots data for score distribution histogram.
 * Format: bucketed score ranges for visualization.
 */
export function outputScoreDistributionData(reports: ScanReport[]): string {
  const lines: string[] = [];

  lines.push("% Fleet score distribution");
  lines.push("% Bucket ScoreRange Count");
  lines.push("");

  // Create buckets: 0-9, 10-19, ..., 90-99, 100
  const buckets: Record<number, number> = {};
  for (let i = 0; i <= 10; i++) {
    buckets[i] = 0;
  }

  for (const report of reports) {
    const score = report.summary.securityScore;
    const bucket = score === 100 ? 10 : Math.floor(score / 10);
    buckets[bucket]++;
  }

  for (let i = 0; i <= 10; i++) {
    const rangeStart = i * 10;
    const rangeEnd = i === 10 ? 100 : (i + 1) * 10 - 1;
    const label = i === 10 ? "100" : `${rangeStart}-${rangeEnd}`;
    lines.push(`${i} ${label} ${buckets[i]}`);
  }

  return lines.join("\n");
}

/**
 * Generate heatmap data for findings per module per protocol.
 * Format: space-separated columns (protocol as header, module rows).
 */
export function outputHeatmapData(reports: ScanReport[]): string {
  const lines: string[] = [];

  lines.push("% Heatmap: findings per module per protocol");
  lines.push("% module mcp openai langchain rest graphql grpc");
  lines.push("");

  // Group by protocol
  const protocolMap = new Map<string, ScanReport[]>();
  for (const report of reports) {
    const proto = report.transport.protocol ?? "unknown";
    if (!protocolMap.has(proto)) {
      protocolMap.set(proto, []);
    }
    protocolMap.get(proto)!.push(report);
  }

  // Collect all modules
  const moduleSet = new Set<string>();
  for (const report of reports) {
    for (const mod of report.modules) {
      moduleSet.add(mod.moduleName);
    }
  }

  const modules = Array.from(moduleSet).sort();
  const protocols = Array.from(protocolMap.keys()).sort();

  // Build data grid
  for (const moduleName of modules) {
    const row = [moduleName];
    for (const protocol of protocols) {
      const protocolReports = protocolMap.get(protocol)!;
      let findingCount = 0;
      for (const report of protocolReports) {
        const moduleResult = report.modules.find((m) => m.moduleName === moduleName);
        if (moduleResult) {
          findingCount += moduleResult.findings.length;
        }
      }
      row.push(String(findingCount));
    }
    lines.push(row.join(" "));
  }

  return lines.join("\n");
}

/**
 * Generate CSV of all targets with metadata for corpus analysis.
 */
export function outputFleetCsv(reports: ScanReport[]): string {
  const lines: string[] = [];

  // Header
  const headers = [
    "rank",
    "target_name",
    "protocol",
    "security_score",
    "grade",
    "tool_count",
    "resource_count",
    "prompt_count",
    "critical_findings",
    "high_findings",
    "medium_findings",
    "low_findings",
    "total_findings",
    "scan_duration_ms",
    "scan_date",
  ];
  lines.push(headers.join(","));

  // Data rows, sorted by score
  const sorted = [...reports].sort(
    (a, b) => b.summary.securityScore - a.summary.securityScore
  );

  for (let i = 0; i < sorted.length; i++) {
    const report = sorted[i];
    const grade = scoreToGrade(report.summary.securityScore);
    const s = report.summary.findingsBySeverity;

    const row = [
      String(i + 1),
      report.server.serverInfo.name.replace(/,/g, ";"), // Escape commas
      report.transport.protocol ?? "unknown",
      String(report.summary.securityScore),
      grade,
      String(report.server.tools.length),
      String(report.server.resources.length),
      String(report.server.prompts.length),
      String(s[Severity.CRITICAL] ?? 0),
      String(s[Severity.HIGH] ?? 0),
      String(s[Severity.MEDIUM] ?? 0),
      String(s[Severity.LOW] ?? 0),
      String(report.findings.length),
      String(report.durationMs),
      new Date(report.timestamp).toISOString(),
    ];
    lines.push(row.join(","));
  }

  return lines.join("\n");
}

/**
 * Generate JSON with aggregated fleet statistics.
 */
export function outputFleetJson(reports: ScanReport[]): string {
  // Group by protocol
  interface ProtocolStats {
    protocol: string;
    targetCount: number;
    averageScore: number;
    medianScore: number;
    scores: number[];
    criticalFindings: number;
    highFindings: number;
    mediumFindings: number;
    lowFindings: number;
    totalFindings: number;
  }

  const protocolMap = new Map<string, ScanReport[]>();
  for (const report of reports) {
    const proto = report.transport.protocol ?? "unknown";
    if (!protocolMap.has(proto)) {
      protocolMap.set(proto, []);
    }
    protocolMap.get(proto)!.push(report);
  }

  const protocolStats: ProtocolStats[] = [];

  for (const [protocol, protocolReports] of protocolMap) {
    const scores = protocolReports.map((r) => r.summary.securityScore);
    let critical = 0, high = 0, medium = 0, low = 0;

    for (const report of protocolReports) {
      const s = report.summary.findingsBySeverity;
      critical += s[Severity.CRITICAL] ?? 0;
      high += s[Severity.HIGH] ?? 0;
      medium += s[Severity.MEDIUM] ?? 0;
      low += s[Severity.LOW] ?? 0;
    }

    protocolStats.push({
      protocol,
      targetCount: protocolReports.length,
      averageScore: Math.round(mean(scores) * 10) / 10,
      medianScore: median(scores),
      scores,
      criticalFindings: critical,
      highFindings: high,
      mediumFindings: medium,
      lowFindings: low,
      totalFindings: critical + high + medium + low,
    });
  }

  const allScores = reports.map((r) => r.summary.securityScore);

  // ── Multi-server finding correlation ────────────────────────────────────
  // Identify findings that appear across many servers — these are likely
  // framework-level issues (e.g., the MCP SDK itself, a common middleware)
  // rather than server-specific vulnerabilities.
  const findingPrevalence = computeFindingCorrelation(reports);

  const fleetJson = {
    summary: {
      scanCount: reports.length,
      generatedAt: new Date().toISOString(),
      fleetStatistics: {
        averageScore: Math.round(mean(allScores) * 10) / 10,
        medianScore: median(allScores),
        stdDev: Math.round(stdDev(allScores) * 100) / 100,
        minScore: Math.min(...allScores),
        maxScore: Math.max(...allScores),
      },
      protocolBreakdown: protocolStats,
      findingCorrelation: findingPrevalence,
    },
    targets: reports.map((r) => ({
      name: r.server.serverInfo.name,
      protocol: r.transport.protocol ?? "unknown",
      score: r.summary.securityScore,
      grade: scoreToGrade(r.summary.securityScore),
      toolCount: r.server.tools.length,
      findingCount: r.findings.length,
      findings: r.findings.map((f) => ({
        id: f.id,
        severity: f.severity,
        title: f.title,
      })),
    })),
  };

  return JSON.stringify(fleetJson, null, 2);
}

// ─── Multi-Server Finding Correlation ─────────────────────────────────────

interface CorrelatedFinding {
  /** Finding check ID (e.g., "TP-005", "SM-001") */
  findingId: string;
  /** How many servers this finding appears on */
  serverCount: number;
  /** Percentage of servers affected */
  prevalencePercent: number;
  /** Whether this is likely a framework/SDK issue vs server-specific */
  classification: "framework-level" | "common" | "server-specific";
  /** Highest severity seen for this finding across servers */
  maxSeverity: string;
  /** Servers affected */
  affectedServers: string[];
}

/**
 * Compute cross-server finding correlation.
 * Findings appearing in >=50% of servers are classified as "framework-level",
 * >=20% as "common", and the rest as "server-specific".
 */
function computeFindingCorrelation(reports: ScanReport[]): {
  frameworkLevel: CorrelatedFinding[];
  common: CorrelatedFinding[];
  totalUniqueFindingIds: number;
} {
  if (reports.length < 2) {
    return { frameworkLevel: [], common: [], totalUniqueFindingIds: 0 };
  }

  // Map: findingId -> { servers: Set<string>, maxSeverity }
  const findingMap = new Map<string, { servers: Set<string>; maxSeverity: string }>();

  const severityRank: Record<string, number> = {
    CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1,
  };

  for (const report of reports) {
    const serverName = report.server.serverInfo.name;
    for (const finding of report.findings) {
      const existing = findingMap.get(finding.id);
      if (existing) {
        existing.servers.add(serverName);
        if ((severityRank[finding.severity] ?? 0) > (severityRank[existing.maxSeverity] ?? 0)) {
          existing.maxSeverity = finding.severity;
        }
      } else {
        findingMap.set(finding.id, {
          servers: new Set([serverName]),
          maxSeverity: finding.severity,
        });
      }
    }
  }

  const total = reports.length;
  const frameworkLevel: CorrelatedFinding[] = [];
  const common: CorrelatedFinding[] = [];

  for (const [findingId, data] of findingMap) {
    const prevalence = (data.servers.size / total) * 100;
    const correlated: CorrelatedFinding = {
      findingId,
      serverCount: data.servers.size,
      prevalencePercent: Math.round(prevalence * 10) / 10,
      classification: prevalence >= 50 ? "framework-level" : prevalence >= 20 ? "common" : "server-specific",
      maxSeverity: data.maxSeverity,
      affectedServers: Array.from(data.servers).sort(),
    };

    if (correlated.classification === "framework-level") {
      frameworkLevel.push(correlated);
    } else if (correlated.classification === "common") {
      common.push(correlated);
    }
  }

  // Sort by prevalence descending
  frameworkLevel.sort((a, b) => b.serverCount - a.serverCount);
  common.sort((a, b) => b.serverCount - a.serverCount);

  return {
    frameworkLevel,
    common,
    totalUniqueFindingIds: findingMap.size,
  };
}
