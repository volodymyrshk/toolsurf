import chalk from "chalk";
import {
  Severity,
  CheckStatus,
  type ScanReport,
  type Finding,
  type ModuleResult,
  type ReportSummary,
} from "../types/index.js";
import { scoreToGrade, scoreToColor } from "./scorer.js";
import {
  outputLatex,
  outputPgfplotsData,
  outputResearchCsv,
  outputResearchJson,
  outputResearchJsonSlim,
} from "./research-reporter.js";

export type OutputFormat =
  | "terminal"
  | "json"
  | "html"
  | "markdown"
  | "latex"
  | "csv"
  | "research-json"
  | "research-json-slim"
  | "pgfplots";

// ─── ASCII Art Logo ──────────────────────────────────────────────────────────

const LOGO = `
█████  ███   ███  █      ████ █   █ ████  █████
  █   █   █ █   █ █     █     █   █ █   █ █    
  █   █   █ █   █ █      ███  █   █ ████  ████ 
  █   █   █ █   █ █         █ █   █ █  █  █    
  █    ███   ███  █████ ████   ███  █   █ █    
`;

/**
 * Print the ASCII banner with optional subtitle.
 * Reusable across all commands for consistent branding.
 */
export function printBanner(subtitle?: string): void {
  console.log(chalk.cyan(LOGO));
  console.log(chalk.dim(`  ── ${subtitle ?? "Security audits for AI agents"} ──`));
  console.log();
}

/** Severity rank for filtering */
const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

/** Options for report output */
export interface OutputOptions {
  minSeverity?: string;
  writer?: (content: string) => void;
}

/**
 * Format and output a scan report.
 */
export function outputReport(report: ScanReport, format: OutputFormat, options?: OutputOptions): void {
  switch (format) {
    case "json":
      outputJson(report);
      break;
    case "html":
      outputHtml(report);
      break;
    case "markdown":
      outputMarkdown(report, options?.writer);
      break;
    case "latex":
      console.log(outputLatex(report));
      break;
    case "csv":
      console.log(outputResearchCsv(report));
      break;
    case "research-json":
      console.log(outputResearchJson(report));
      break;
    case "research-json-slim":
      console.log(outputResearchJsonSlim(report));
      break;
    case "pgfplots":
      console.log(outputPgfplotsData(report));
      break;
    case "terminal":
    default:
      outputTerminal(report, options);
      break;
  }
}

// ─── JSON Output ───────────────────────────────────────────────────────────────

function outputJson(report: ScanReport): void {
  // Clean JSON output to stdout (no ANSI codes, no extra text)
  console.log(JSON.stringify(report, null, 2));
}

// ─── Terminal Output ───────────────────────────────────────────────────────────

function outputTerminal(report: ScanReport, options?: OutputOptions): void {
  const minRank = SEVERITY_RANK[options?.minSeverity ?? ""] ?? 0;

  outputCompactHeader(report, options?.minSeverity);
  outputRiskOverview(report);
  outputSummary(report.summary);

  // Detonation chamber panel — recorded callbacks, sample bodies, IPI proof.
  // This is the most important visual block in a chamber-backed scan because
  // chamber findings are the strongest evidence class the scanner produces.
  outputChamberPanel(report);
  outputEgressMatrix(report);
  outputKillChainPanel(report);

  outputTopFindings(report.findings, minRank);
  outputModuleRollup(report.modules, minRank);

  // Compliance mapping
  outputCompliance(report);

  // Security score gauge
  outputScore(report.summary.securityScore, report.summary);

  // Traction footer
  outputFooter();
}

function outputCompactHeader(report: ScanReport, minSeverity?: string): void {
  const { server } = report;
  console.log();
  console.log(chalk.bold.cyan("ToolSurf"));
  console.log(chalk.dim("─".repeat(72)));
  console.log(`${chalk.bold("Target:")} ${server.serverInfo.name} v${server.serverInfo.version}`);
  console.log(
    `${chalk.bold("Protocol:")} ${server.protocolVersion}` +
      chalk.dim(`  (${report.transport.protocol ?? server.protocol ?? "mcp"} / ${report.transport.type})`),
  );
  console.log(
    `${chalk.bold("Surface:")} ${server.tools.length} tools, ${server.resources.length} resources, ${server.prompts.length} prompts` +
      chalk.dim(`  Duration: ${formatDuration(report.durationMs)}`),
  );
  if (minSeverity) {
    console.log(chalk.dim(`Filter: ${minSeverity} and above`));
  }
  console.log(chalk.dim("─".repeat(72)));
}

function formatDuration(durationMs: number): string {
  if (durationMs >= 60000) return `${(durationMs / 60000).toFixed(1)}m (${durationMs}ms)`;
  if (durationMs >= 1000) return `${(durationMs / 1000).toFixed(1)}s (${durationMs}ms)`;
  return `${durationMs}ms`;
}

function outputRiskOverview(report: ScanReport): void {
  const risk = report.riskProfile;
  const riskLabel = risk?.riskLevel ?? "UNKNOWN";
  const ssvc = risk?.ssvcLabel ? `  SSVC: ${risk.ssvcLabel}` : "";
  const crs = risk ? risk.compositeRiskScore.toFixed(3) : "n/a";
  const umri = risk ? risk.umriScalar.toFixed(2) : "n/a";

  console.log();
  console.log(chalk.bold("Risk Overview"));
  console.log(
    `  ${riskLevelColor(riskLabel)(riskLabel.padEnd(8))}` +
      `  CRS: ${chalk.bold(crs)}` +
      `  UMRI: ${chalk.bold(umri)}` +
      `  Legacy score: ${chalk.bold(`${report.summary.securityScore}/100`)}` +
      chalk.dim(ssvc),
  );

  const s = report.summary.findingsBySeverity;
  console.log(
    "  " +
      [
        chalk.bgRed.white(` CRIT ${s[Severity.CRITICAL]} `),
        chalk.red(`HIGH ${s[Severity.HIGH]}`),
        chalk.yellow(`MED ${s[Severity.MEDIUM]}`),
        chalk.cyan(`LOW ${s[Severity.LOW]}`),
        chalk.dim(`INFO ${s[Severity.INFO]}`),
      ].join("  "),
  );
}

function riskLevelColor(level: string): (s: string) => string {
  if (level === "CRITICAL") return chalk.bgRed.white;
  if (level === "HIGH") return chalk.red.bold;
  if (level === "MEDIUM") return chalk.yellow.bold;
  if (level === "LOW") return chalk.cyan.bold;
  return chalk.dim;
}

function outputTopFindings(findings: Finding[], minRank: number): void {
  const visible = findings
    .filter((f) => (SEVERITY_RANK[f.severity] ?? 0) >= minRank)
    .sort((a, b) => {
      const sevDelta = (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
      if (sevDelta !== 0) return sevDelta;
      return (b.confidence ?? 0) - (a.confidence ?? 0);
    });

  console.log();
  console.log(chalk.bold("Top Findings"));
  if (visible.length === 0) {
    console.log(chalk.dim("  No findings at the selected severity threshold."));
    return;
  }

  for (const finding of visible.slice(0, 8)) {
    const badge = severityColor(finding.severity)(`[${finding.severity}]`);
    const tool = finding.toolName ? chalk.dim(`  tool: ${finding.toolName}`) : "";
    const affected = finding.affectedCount && finding.affectedCount > 1
      ? chalk.dim(`  affected: ${finding.affectedCount}`)
      : "";
    const confidence = typeof finding.confidence === "number"
      ? chalk.dim(`  confidence: ${Math.round(finding.confidence * 100)}%`)
      : "";

    console.log(`  ${badge} ${chalk.bold(truncate(finding.title, 96))}`);
    console.log(chalk.dim(`      ${finding.id}  ${finding.module}`) + tool + affected + confidence);
  }

  if (visible.length > 8) {
    console.log(chalk.dim(`  ... ${visible.length - 8} more finding(s) hidden in compact terminal output.`));
  }
}

function outputModuleRollup(modules: ModuleResult[], minRank: number): void {
  type Rollup = {
    name: string;
    failed: number;
    warnings: number;
    errors: number;
    skipped: number;
    findings: number;
    durationMs: number;
    error?: string;
  };

  const rollups: Rollup[] = modules.map((mod) => {
    const failed = mod.checks.filter((c) => c.status === CheckStatus.FAIL).length;
    const warnings = mod.checks.filter((c) => c.status === CheckStatus.WARN).length;
    const errors = mod.checks.filter((c) => c.status === CheckStatus.ERROR).length + (mod.error ? 1 : 0);
    const skipped = mod.checks.filter((c) => c.status === CheckStatus.SKIP).length;
    const findings = mod.findings.filter((f) => (SEVERITY_RANK[f.severity] ?? 0) >= minRank).length;
    return {
      name: mod.moduleName,
      failed,
      warnings,
      errors,
      skipped,
      findings,
      durationMs: mod.durationMs,
      error: mod.error,
    };
  });

  const interesting = rollups
    .filter((r) => r.findings > 0 || r.failed > 0 || r.warnings > 0 || r.errors > 0)
    .sort((a, b) => b.findings - a.findings || b.failed - a.failed || b.warnings - a.warnings);

  console.log();
  console.log(chalk.bold("Module Rollup"));
  if (interesting.length === 0) {
    console.log(chalk.dim(`  ${modules.length} module(s) completed with no reportable findings.`));
    return;
  }

  for (const r of interesting.slice(0, 12)) {
    const status = r.errors > 0
      ? chalk.bgMagenta.white(" ERR ")
      : r.failed > 0
        ? chalk.bgRed.white(" FAIL ")
        : chalk.bgYellow.black(" WARN ");
    console.log(
      `  ${status} ${truncate(r.name, 34).padEnd(34)} ` +
        chalk.dim(`${r.durationMs}ms`) +
        `  findings:${r.findings} fail:${r.failed} warn:${r.warnings} skip:${r.skipped}`,
    );
    if (r.error) console.log(chalk.red(`       ${truncate(r.error, 110)}`));
  }

  if (interesting.length > 12) {
    console.log(chalk.dim(`  ... ${interesting.length - 12} more module(s) with findings/check warnings.`));
  }
}

/**
 * Detonation chamber panel.
 *
 * Surfaces the chamber-backed evidence prominently. Renders nothing when no
 * chamber capture findings are present (so non-chamber scans look unchanged).
 *
 * Sources:
 *   - findings[] — module emits with id starting with `CHAMBER-` or `AF-CHAMBER-`
 *   - module evidence on `chamber-evidence` and `active-fuzzer` modules
 *   - raw capture file paths from those findings' evidence
 */
function outputChamberPanel(report: ScanReport): void {
  const findings = report.findings ?? [];
  const chamberFindings = findings.filter(
    (f) => f.id.startsWith("CHAMBER-") || f.id.startsWith("AF-CHAMBER"),
  );
  const reach = report.chamberReachability;

  // Render the panel whenever a chamber was wired in — even without chamber
  // findings — so operators always see the reachability verdict that gates
  // vendor-report emission.
  if (chamberFindings.length === 0 && !reach) return;

  console.log();
  console.log(chalk.bold(chalk.red("Detonation Chamber")));
  console.log(chalk.dim("  ─".repeat(36)));
  console.log();

  if (reach) {
    const status = reach.status;
    const tag =
      status === "verified"
        ? chalk.bgGreen.black(" VERIFIED ")
        : status === "unverified"
        ? chalk.bgYellow.black(" UNVERIFIED ")
        : status === "not-testable"
        ? chalk.bgBlue.white(" NOT-TESTABLE ")
        : chalk.bgRed.white(` ${status.toUpperCase()} `);
    console.log(`  ${chalk.bold("Reachability:")} ${tag}  ${chalk.dim(`via ${reach.method}`)}`);
    if (reach.toolName && reach.paramName) {
      console.log(chalk.dim(`    probe → ${reach.toolName}(${reach.paramName})`));
    }
    if (typeof reach.beforeCount === "number" && typeof reach.afterCount === "number") {
      console.log(
        chalk.dim(`    fake-http capture lines: ${reach.beforeCount} → ${reach.afterCount}`),
      );
    }
    console.log(chalk.dim(`    ${reach.reason}`));
    console.log();
  }

  if (chamberFindings.length === 0) return;

  // Tally by sink (HTTP / DNS / SMTP / metadata / netflow) by reading the
  // chamber-evidence module's check messages for capture counts.
  type SinkTally = { sink: string; events: number; severity: string; title: string; sample: string };
  const tallies: SinkTally[] = [];
  const ipiHits: Array<{ tool: string; poison: string; excerpt: string }> = [];
  const exfilHits: Array<{ id: string; tool: string; payload: string; sink: string }> = [];

  for (const f of chamberFindings) {
    const ev = (f.evidence ?? {}) as Record<string, unknown>;
    if (f.id === "CHAMBER-IPI-RELAY-001") {
      const hits = (ev.hits as Array<{ tool: string; poisonToken: string; excerpt: string }>) ?? [];
      for (const h of hits) {
        ipiHits.push({ tool: h.tool, poison: h.poisonToken, excerpt: (h.excerpt ?? "").slice(0, 220) });
      }
    } else if (f.id.startsWith("AF-CHAMBER-")) {
      const captures = (ev.captures as Array<{ tool: string; payload: string; sink: string }>) ?? [];
      for (const c of captures.slice(0, 3)) {
        exfilHits.push({ id: f.id, tool: c.tool, payload: c.payload, sink: c.sink });
      }
    } else if (f.id.startsWith("CHAMBER-")) {
      const eventCount = (ev.eventCount as number) ?? (ev.suspiciousFlowCount as number) ?? 0;
      const sample = ev.sample as Array<Record<string, unknown>> | undefined;
      const sampleLine = sample && sample[0] ? formatChamberSample(sample[0]) : "";
      tallies.push({
        sink: idToSink(f.id),
        events: eventCount,
        severity: f.severity,
        title: f.title,
        sample: sampleLine,
      });
    }
  }

  // Capture summary line
  const capturePathRoot = inferCaptureRoot(chamberFindings);
  if (tallies.length > 0) {
    console.log(chalk.bold("  Captures recorded:"));
    for (const t of tallies) {
      const sevColor = severityColor(t.severity);
      console.log(
        `    ${sevColor(`[${t.severity}]`)} ${chalk.cyan(t.sink.padEnd(8))} ${t.events} event(s)  ${chalk.dim(t.title)}`,
      );
      if (t.sample) console.log(chalk.dim(`             ${t.sample}`));
    }
    console.log();
  }

  // Confirmed exploits via active probes
  if (exfilHits.length > 0) {
    console.log(chalk.bold("  Confirmed exploits via active probes:"));
    for (const e of exfilHits.slice(0, 6)) {
      console.log(
        `    ${chalk.red("→")} ${chalk.cyan(e.tool)} (${e.sink})  ${chalk.dim(truncate(e.payload, 90))}`,
      );
    }
    console.log();
  }

  // IPI relay — the strongest evidence: poison token echoed back into agent context
  if (ipiHits.length > 0) {
    console.log(chalk.bold(chalk.yellow("  IPI Relay (poison echoed into agent context):")));
    for (const h of ipiHits.slice(0, 3)) {
      console.log(`    ${chalk.cyan(h.tool)}  ${chalk.dim("→")}  ${chalk.green(h.poison)}`);
      console.log(chalk.dim(`      ${truncate(h.excerpt.replace(/\n/g, " ⏎ "), 200)}`));
    }
    console.log();
  }

  if (capturePathRoot) {
    console.log(chalk.dim(`  Full captures: ${capturePathRoot}`));
    console.log();
  }
}

function outputEgressMatrix(report: ScanReport): void {
  const matrix = report.egressMatrix;
  if (!matrix) return;

  console.log();
  console.log(chalk.bold("Egress Matrix"));
  console.log(chalk.dim("  ─".repeat(36)));
  console.log(
    chalk.dim(
      `  ${matrix.verifiedCellCount} verified cell(s)  ` +
        `reached: ${matrix.reachedDestinations.length || 0} destination class(es)  ` +
        `active sinks: ${matrix.activeSinks.length || 0}`,
    ),
  );
  console.log();

  // Compute column widths so the grid stays aligned even with long sink names.
  const sinkLabels = matrix.sinks.map(formatEgressSinkLabel);
  const destWidth = Math.max(
    ...matrix.destinations.map((d) => formatEgressDestinationLabel(d).length),
    "Destination".length,
  );
  const cellWidth = Math.max(...sinkLabels.map((l) => l.length), 11);

  const header = [
    chalk.bold("Destination".padEnd(destWidth)),
    ...sinkLabels.map((l) => chalk.bold(l.padEnd(cellWidth))),
  ].join("  ");
  console.log(`  ${header}`);
  console.log(`  ${chalk.dim("─".repeat(destWidth + (cellWidth + 2) * sinkLabels.length))}`);

  for (let i = 0; i < matrix.destinations.length; i++) {
    const destLabel = formatEgressDestinationLabel(matrix.destinations[i]);
    const row = matrix.cells[i];
    // Skip wholly-empty unclassified row to keep output tight.
    if (matrix.destinations[i] === "unclassified" && row.every((c) => !c.verified)) {
      continue;
    }
    const cellTexts = row.map((cell) => {
      if (!cell.verified) return chalk.dim("Blocked".padEnd(cellWidth));
      const tag = chalk.green("Verified");
      return `${tag.padEnd(cellWidth + (chalk.green("Verified").length - "Verified".length))}`;
    });
    console.log(`  ${destLabel.padEnd(destWidth)}  ${cellTexts.join("  ")}`);

    // For verified cells, append canary IDs on a continuation line.
    for (let j = 0; j < row.length; j++) {
      const cell = row[j];
      if (!cell.verified) continue;
      if (cell.canaries.length === 0) continue;
      const canarySample = cell.canaries.slice(0, 2).join(", ");
      const more = cell.canaries.length > 2 ? ` (+${cell.canaries.length - 2} more)` : "";
      console.log(
        chalk.dim(
          `    ${" ".repeat(destWidth)}  ${sinkLabels[j]}: canary ${canarySample}${more}`,
        ),
      );
    }
  }
  console.log();
}

function formatEgressDestinationLabel(d: string): string {
  switch (d) {
    case "chamber-direct": return "Chamber-Direct";
    case "localhost": return "Localhost";
    case "rfc1918": return "RFC1918/Internal";
    case "cloud-metadata": return "Cloud Metadata";
    case "public-internet": return "Public Internet";
    case "dns": return "DNS";
    case "unclassified": return "Unclassified";
    default: return d;
  }
}

function formatEgressSinkLabel(s: string): string {
  switch (s) {
    case "http": return "fake-http";
    case "metadata": return "fake-metadata";
    case "dns": return "fake-dns";
    case "smtp": return "fake-smtp";
    case "netflow": return "netflow";
    default: return s;
  }
}

function outputKillChainPanel(report: ScanReport): void {
  const summary = report.killChainSummary;
  if (!summary || summary.total === 0) return;

  console.log();
  console.log(chalk.bold("Kill Chains"));
  console.log(chalk.dim("  ─".repeat(36)));
  console.log(
    chalk.dim(
      `  complete ${summary.completed}  partial ${summary.partial}  blocked ${summary.blocked}  proofs: ${summary.proofTypes.join(", ") || "none"}`,
    ),
  );
  if (report.chamberProofBundle) {
    const bundle = report.chamberProofBundle;
    const missing =
      bundle.missingArtifactCount > 0
        ? `  missing artifacts: ${bundle.missingArtifactCount}`
        : "";
    console.log(
      chalk.dim(
        `  proof bundle: ${truncate(bundle.proofFile, 106)}  records: ${bundle.proofCount}${missing}`,
      ),
    );
  }
  console.log();

  for (const chain of summary.chains.slice(0, 5)) {
    const status = killChainStatusBadge(chain.status);
    const sev = severityColor(chain.severity)(`[${chain.severity}]`);
    const tools = chain.toolNames.length > 0
      ? chalk.dim(`  tools: ${chain.toolNames.slice(0, 4).join(", ")}${chain.toolNames.length > 4 ? "..." : ""}`)
      : "";
    console.log(`  ${status} ${sev} ${chalk.bold(truncate(chain.title, 86))}${tools}`);
    const confidence =
      typeof chain.confidence === "number"
        ? `  confidence: ${Math.round(chain.confidence * 100)}%`
        : "";
    console.log(chalk.dim(`      ${chain.id}  impact: ${chain.impact}${confidence}`));

    const proof = chain.stages.find((stage) => stage.kind === "proof");
    if (proof) {
      console.log(chalk.dim(`      proof: ${truncate(proof.label, 110)}`));
    }
    if (chain.proofArtifacts.length > 0) {
      console.log(chalk.dim(`      artifact: ${truncate(chain.proofArtifacts[0].path, 110)}`));
    }
  }

  if (summary.chains.length > 5) {
    console.log(chalk.dim(`  ... ${summary.chains.length - 5} more chain(s) hidden in compact output.`));
  }
}

function killChainStatusBadge(status: string): string {
  if (status === "complete") return chalk.bgGreen.black(" COMPLETE ");
  if (status === "partial") return chalk.bgYellow.black(" PARTIAL ");
  return chalk.bgBlue.white(" BLOCKED ");
}

function idToSink(id: string): string {
  if (id.includes("HTTP")) return "http";
  if (id.includes("DNS")) return "dns";
  if (id.includes("SMTP")) return "smtp";
  if (id.includes("METADATA")) return "metadata";
  if (id.includes("NETFLOW")) return "netflow";
  if (id.includes("IPI")) return "ipi-relay";
  return "?";
}

function severityColor(sev: string): (s: string) => string {
  if (sev === Severity.CRITICAL) return chalk.bgRed.white;
  if (sev === Severity.HIGH) return chalk.red;
  if (sev === Severity.MEDIUM) return chalk.yellow;
  if (sev === Severity.LOW) return chalk.cyan;
  return chalk.dim;
}

function formatChamberSample(s: Record<string, unknown>): string {
  // Best-effort one-line summary for any of HTTP / DNS / SMTP / metadata / netflow rows.
  if (s.method && s.path) return `${s.method} ${s.path}  from ${s.client ?? "?"}`;
  if (s.qname) return `DNS  ${s.qname}  →  ${s.answer ?? "?"}`;
  if (s.dst) return `${s.proto ?? "ip"}  ${s.src}:${s.sport} → ${s.dst}:${s.dport}`;
  if (s.lines) return `SMTP  ${(s.lines as string[]).slice(0, 2).join(" / ")}`;
  return "";
}

function inferCaptureRoot(findings: Finding[]): string | undefined {
  for (const f of findings) {
    const ev = (f.evidence ?? {}) as Record<string, unknown>;
    const cf = (ev.captureFile as string | undefined) ?? undefined;
    if (cf) {
      // strip the trailing `<sink>/<file>.jsonl` to get the run dir
      const slash = cf.lastIndexOf("/captures/");
      if (slash !== -1) return cf.slice(0, slash + "/captures".length);
    }
  }
  return undefined;
}

function truncate(s: string, n: number): string {
  return s.length <= n ? s : s.slice(0, n) + "…";
}

function outputSummary(summary: ReportSummary): void {
  console.log();
  console.log(chalk.bold("Check Summary"));
  console.log(
    `  ${chalk.green(`pass ${summary.passed}`)}  ` +
      `${chalk.yellow(`warn ${summary.warnings}`)}  ` +
      `${chalk.red(`fail ${summary.checksWithFailStatus}`)}  ` +
      `${chalk.magenta(`error ${summary.errors}`)}  ` +
      `${chalk.dim(`skip ${summary.skipped}`)}  ` +
      chalk.dim(`total ${summary.totalChecks}`),
  );
}

function outputCompliance(report: ScanReport): void {
  const compliance = report.compliance;
  if (!compliance) return;

  const frameworks: Array<[string, Record<string, number>]> = [
    ["NIST", compliance.nist],
    ["SOC2", compliance.soc2],
    ["ASVS", compliance.asvs],
    ["HIPAA", compliance.hipaa],
    ["PCI", compliance.pciDss],
    ["ISO27001", compliance.iso27001],
    ["FedRAMP", compliance.fedramp],
    ["GDPR", compliance.gdpr],
  ];

  const controls = frameworks.flatMap(([framework, values]) =>
    Object.entries(values).map(([control, count]) => ({ framework, control, count })),
  ).sort((a, b) => b.count - a.count);

  if (controls.length === 0) return;

  console.log();
  console.log(chalk.bold("Compliance Mapping"));
  console.log(chalk.dim(`  ${compliance.mappedFindings} mapped finding(s), ${compliance.unmappedFindings} unmapped.`));
  for (const row of controls.slice(0, 10)) {
    console.log(`  ${chalk.cyan(row.framework.padEnd(8))} ${row.control.padEnd(12)} ${row.count} finding(s)`);
  }
  if (controls.length > 10) {
    console.log(chalk.dim(`  ... ${controls.length - 10} more mapped control(s).`));
  }
}

function outputScore(score: number, summary: ScanReport["summary"]): void {
  const grade = scoreToGrade(score);
  const color = scoreToColor(score);
  const colorFn =
    color === "green" ? chalk.green : color === "yellow" ? chalk.yellow : chalk.red;

  // Score header
  console.log();
  console.log(chalk.bold("Legacy Score Gauge"));
  console.log();

  // Visual gauge bar (30 chars wide)
  const BAR_WIDTH = 30;
  const filled = Math.round((score / 100) * BAR_WIDTH);
  const empty = BAR_WIDTH - filled;
  const bar = colorFn("█".repeat(filled)) + chalk.dim("░".repeat(empty));
  const scoreDisplay = colorFn.bold(`${score}/100`);
  const gradeDisplay = colorFn.bold(`Grade: ${grade}`);

  console.log(`  ${bar}  ${scoreDisplay}  ${gradeDisplay}`);
  console.log();

  // Inline severity summary
  const s = summary.findingsBySeverity;
  const parts = [
    chalk.red(`  CRITICAL: ${s[Severity.CRITICAL]}`),
    chalk.red(`  HIGH: ${s[Severity.HIGH]}`),
    chalk.yellow(`  WARN: ${summary.warnings}`),
    chalk.green(`  PASS: ${summary.passed}`),
  ];
  console.log(`  ` + parts.join("  "));
  console.log(chalk.dim(`  Raw score: ${summary.rawScore}; penalty points: ${summary.penaltyPoints}. Prefer CRS for research comparisons.`));
}

function outputFooter(): void {
  console.log();
  console.log(chalk.dim("─".repeat(72)));
  console.log(chalk.dim("Report complete. Use --format research-json for the full machine-readable artifact."));
  console.log();
}

// ─── Markdown Output ─────────────────────────────────────────────────────────

function outputMarkdown(report: ScanReport, writer?: (content: string) => void): void {
  const { server, modules, summary } = report;
  const score = summary.securityScore;
  const grade = scoreToGrade(score);

  const lines: string[] = [];

  lines.push("# ToolSurf Report");
  lines.push("");
  lines.push(`**Server:** ${escMd(server.serverInfo.name)} v${escMd(server.serverInfo.version)}`);
  lines.push(`**Protocol:** ${escMd(server.protocolVersion)}`);
  lines.push(`**Capabilities:** ${server.tools.length} tools, ${server.resources.length} resources, ${server.prompts.length} prompts`);
  lines.push(`**Scan Duration:** ${report.durationMs}ms`);
  lines.push(`**Date:** ${new Date(report.timestamp).toLocaleString()}`);
  lines.push("");

  // Score
  lines.push("## Security Score");
  lines.push("");
  lines.push(`**${score}/100** (Grade: ${grade})`);
  lines.push("");
  const s = summary.findingsBySeverity;
  lines.push(`| Metric | Count |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Total Checks | ${summary.totalChecks} |`);
  lines.push(`| Passed | ${summary.passed} |`);
  lines.push(`| Warnings | ${summary.warnings} |`);
  lines.push(`| Failed checks | ${summary.checksWithFailStatus} |`);
  lines.push(`| Critical | ${s.CRITICAL} |`);
  lines.push(`| High | ${s.HIGH} |`);
  lines.push("");

  if (report.killChainSummary && report.killChainSummary.total > 0) {
    lines.push("## Kill Chains");
    lines.push("");
    lines.push(`Completed: ${report.killChainSummary.completed}; Partial: ${report.killChainSummary.partial}; Blocked: ${report.killChainSummary.blocked}`);
    if (report.chamberProofBundle) {
      lines.push(`Proof bundle: \`${escMd(report.chamberProofBundle.proofFile)}\` (${report.chamberProofBundle.proofCount} record(s), ${report.chamberProofBundle.missingArtifactCount} missing artifact(s))`);
    }
    lines.push("");
    for (const chain of report.killChainSummary.chains.slice(0, 8)) {
      lines.push(`### \`${chain.status.toUpperCase()}\` ${escMd(chain.title)}`);
      lines.push("");
      lines.push(escMd(chain.summary));
      lines.push("");
      lines.push(`**Impact:** ${escMd(chain.impact)}`);
      lines.push(`**Severity:** ${escMd(chain.severity)}`);
      if (typeof chain.confidence === "number") {
        lines.push(`**Confidence:** ${Math.round(chain.confidence * 100)}%`);
      }
      if (chain.toolNames.length > 0) {
        lines.push(`**Tools:** ${escMd(chain.toolNames.join(", "))}`);
      }
      if (chain.findingIds.length > 0) {
        lines.push(`**Findings:** ${escMd(chain.findingIds.join(", "))}`);
      }
      if (chain.proofArtifacts.length > 0) {
        lines.push(`**Proof Artifacts:** ${escMd(chain.proofArtifacts.map((a) => `${a.proofId}: ${a.path}`).join("; "))}`);
      }
      lines.push("");
    }
  }

  // Module results
  lines.push("## Module Results");
  lines.push("");

  for (const mod of modules) {
    lines.push(`### ${mod.error ? "❌" : "✅"} ${escMd(mod.moduleName)} (v${mod.moduleVersion}, ${mod.durationMs}ms)`);
    lines.push("");

    if (mod.error) {
      lines.push(`> **Error:** ${escMd(mod.error)}`);
      lines.push("");
      continue;
    }

    if (mod.checks.length > 0) {
      lines.push("| Status | Check | Details |");
      lines.push("|--------|-------|---------|");
      for (const check of mod.checks) {
        const msg = check.message ? escMd(check.message).replace(/\|/g, "\\|") : "";
        lines.push(`| ${check.status} | ${escMd(check.name)} | ${msg} |`);
      }
      lines.push("");
    }
  }

  // Key findings
  const keyFindings = report.findings.filter(
    (f) => f.severity === "CRITICAL" || f.severity === "HIGH" || f.severity === "MEDIUM"
  );
  if (keyFindings.length > 0) {
    lines.push("## Key Findings");
    lines.push("");

    for (const f of keyFindings) {
      lines.push(`### \`${f.severity}\` ${escMd(f.title)}`);
      lines.push("");
      lines.push(escMd(f.description));
      lines.push("");
      if (f.cweId) lines.push(`**CWE:** ${escMd(f.cweId)}`);
      if (f.toolName) lines.push(`**Tool:** ${escMd(f.toolName)}`);
      lines.push(`**Remediation:** ${escMd(f.remediation)}`);
      lines.push("");
    }
  }

  // Compliance
  if (report.compliance) {
    lines.push("## Compliance Mapping");
    lines.push("");
    for (const [framework, controls] of Object.entries({
      "NIST SP 800-171": report.compliance.nist,
      "SOC 2 TSC": report.compliance.soc2,
      "OWASP ASVS v4.0": report.compliance.asvs,
    })) {
      if (Object.keys(controls).length > 0) {
        lines.push(`### ${framework}`);
        lines.push("");
        for (const [id, count] of Object.entries(controls).sort(
          (a, b) => b[1] - a[1]
        )) {
          lines.push(`- **${id}** (${count} finding${count > 1 ? "s" : ""})`);
        }
        lines.push("");
      }
    }
  }

  // Footer
  lines.push("---");
  lines.push(`Generated by [toolsurf](https://github.com/toolsurf/toolsurf) v${report.cliVersion}`);

  (writer ?? console.log)(lines.join("\n"));
}

// ─── HTML Output ─────────────────────────────────────────────────────────────

function outputHtml(report: ScanReport): void {
  const { server, modules, summary } = report;
  const score = summary.securityScore;
  const grade = scoreToGrade(score);
  const scoreColor = score >= 80 ? "#22c55e" : score >= 50 ? "#eab308" : "#ef4444";

  const checksHtml = modules.map((mod) => {
    const checks = mod.checks.map((c) => {
      const colors: Record<string, string> = {
        PASS: "#22c55e", WARN: "#eab308", FAIL: "#ef4444", SKIP: "#6b7280", ERROR: "#a855f7",
      };
      const bg = colors[c.status] ?? "#6b7280";
      return `<div class="check"><span class="badge" style="background:${bg}">${c.status}</span> <span class="check-name">${esc(c.name)}</span>${c.message ? `<span class="check-msg"> &mdash; ${esc(c.message)}</span>` : ""}</div>`;
    }).join("\n");
    const icon = mod.error ? "&#10007;" : "&#10003;";
    return `<div class="module"><h3>${icon} ${esc(mod.moduleName)} <span class="version">v${mod.moduleVersion} (${mod.durationMs}ms)</span></h3>${mod.error ? `<div class="error">${esc(mod.error)}</div>` : checks}</div>`;
  }).join("\n");

  const findingsHtml = report.findings
    .filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH" || f.severity === "MEDIUM")
    .map((f) => {
      const colors: Record<string, string> = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#eab308", LOW: "#6b7280", INFO: "#3b82f6" };
      return `<div class="finding"><span class="badge" style="background:${colors[f.severity] ?? "#6b7280"}">${f.severity}</span> <strong>${esc(f.title)}</strong><p>${esc(f.description)}</p>${f.cweId ? `<span class="cwe">${f.cweId}</span>` : ""}${f.toolName ? ` <span class="tool">Tool: ${esc(f.toolName)}</span>` : ""}<p class="remediation">${esc(f.remediation)}</p></div>`;
    }).join("\n");

  const complianceHtml = report.compliance ? `
    <div class="compliance">
      <h2>Compliance Mapping</h2>
      ${Object.entries({ "NIST SP 800-171": report.compliance.nist, "SOC 2 TSC": report.compliance.soc2, "OWASP ASVS v4.0": report.compliance.asvs })
        .filter(([, controls]) => Object.keys(controls).length > 0)
        .map(([framework, controls]) => `<h3>${framework}</h3><div class="controls">${Object.entries(controls).sort((a, b) => b[1] - a[1]).map(([id, count]) => `<span class="control">${id} <em>(${count})</em></span>`).join(" ")}</div>`).join("\n")}
      <p class="dim">${report.compliance.mappedFindings} mapped, ${report.compliance.unmappedFindings} unmapped</p>
    </div>` : "";

  const html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:;">
<title>ToolSurf Report &mdash; ${esc(server.serverInfo.name)}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#030303;color:#d4d4d4;padding:2rem;max-width:960px;margin:0 auto}
h1{font-size:2rem;color:#22d3ee;margin-bottom:.5rem;font-weight:800;letter-spacing:-0.025em}
h2{font-size:1.1rem;margin:2rem 0 1rem;border-bottom:1px solid #262626;padding-bottom:.5rem;text-transform:uppercase;letter-spacing:0.05em;color:#737373}
h3{font-size:1rem;margin:1rem 0 .5rem;color:#a3a3a3}
.header{background:#0a0a0a;border:1px solid #171717;border-radius:4px;padding:1.5rem 2rem;margin-bottom:2rem}
.meta{color:#525252;font-size:.8rem;margin-top:.5rem}
.score-card{display:flex;align-items:center;gap:2rem;background:#0a0a0a;border:1px solid #171717;border-radius:4px;padding:1.5rem 2rem;margin-bottom:2rem}
.score-ring{position:relative;width:120px;height:120px;flex-shrink:0}
.score-ring svg{transform:rotate(-90deg)}
.score-ring .label{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.score-ring .num{font-size:2rem;font-weight:700;color:${scoreColor}}
.score-ring .grade{font-size:.85rem;color:#737373}
.stats{display:flex;gap:1.5rem;flex-wrap:wrap}
.stat{text-align:center}
.stat .n{font-size:1.5rem;font-weight:700}
.stat .l{font-size:.7rem;color:#525252;text-transform:uppercase;letter-spacing:0.05em}
.module{background:#111;border:1px solid #171717;border-radius:4px;padding:1rem 1.5rem;margin-bottom:1rem}
.check{padding:4px 0;font-size:.85rem;border-bottom:1px solid #171717}
.check:last-child{border-bottom:none}
.badge{display:inline-block;padding:1px 6px;border-radius:2px;font-size:.65rem;font-weight:700;color:#fff;min-width:44px;text-align:center;text-transform:uppercase}
.check-name{font-weight:500;margin-left:8px}
.check-msg{color:#525252}
.version{font-weight:400;color:#404040;font-size:.75rem;margin-left:8px}
.finding{background:#0a0a0a;border-left:3px solid #ef4444;border-radius:2px;padding:1rem 1.5rem;margin-bottom:.75rem}
.finding p{margin:.5rem 0;font-size:.85rem;color:#a3a3a3}
.remediation{color:#22c55e;font-size:.8rem;margin-top:.5rem;background:#052e16;padding:8px;border-radius:2px}
.cwe{background:#171717;padding:2px 6px;border-radius:2px;font-size:.75rem;color:#737373}
.tool{color:#525252;font-size:.75rem}
.compliance{background:#0a0a0a;border:1px solid #171717;border-radius:4px;padding:1rem 1.5rem;margin-bottom:1rem}
.controls{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.5rem}
.control{background:#171717;padding:3px 8px;border-radius:2px;font-size:.75rem;color:#d4d4d4;border:1px solid #262626}
.control em{color:#525252;font-style:normal;margin-left:4px}
.dim{color:#404040;font-size:.8rem;margin-top:.75rem}
.footer{text-align:center;margin-top:3rem;padding:1.5rem;border-top:1px solid #171717;color:#404040;font-size:.8rem}
.footer a{color:#22d3ee;text-decoration:none}
</style></head><body>
<div class="header"><h1>ToolSurf Report</h1>
<div class="meta">${esc(server.serverInfo.name)} v${esc(server.serverInfo.version)} &bull; Protocol ${esc(server.protocolVersion)} &bull; ${server.tools.length} tools, ${server.resources.length} resources, ${server.prompts.length} prompts &bull; ${report.durationMs}ms</div></div>
<div class="score-card"><div class="score-ring"><svg viewBox="0 0 120 120"><circle cx="60" cy="60" r="52" fill="none" stroke="#334155" stroke-width="10"/><circle cx="60" cy="60" r="52" fill="none" stroke="${scoreColor}" stroke-width="10" stroke-dasharray="${(score / 100) * 327} 327" stroke-linecap="round"/></svg><div class="label"><span class="num">${score}</span><span class="grade">Grade ${grade}</span></div></div>
<div class="stats"><div class="stat"><div class="n" style="color:#22c55e">${summary.passed}</div><div class="l">Passed</div></div><div class="stat"><div class="n" style="color:#eab308">${summary.warnings}</div><div class="l">Warnings</div></div><div class="stat"><div class="n" style="color:#ef4444">${summary.checksWithFailStatus}</div><div class="l">Failed checks</div></div><div class="stat"><div class="n">${summary.totalChecks}</div><div class="l">Total</div></div></div></div>
<h2>Module Results</h2>
${checksHtml}
${findingsHtml.length > 0 ? `<h2>Key Findings</h2>${findingsHtml}` : ""}
${complianceHtml}
<div class="footer">Generated by <a href="https://github.com/toolsurf/toolsurf">toolsurf</a> v${esc(report.cliVersion)} on ${new Date(report.timestamp).toLocaleString()}</div>
</body></html>`;

  console.log(html);
}

/** Escape HTML entities */
function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/**
 * Escape untrusted strings for safe embedding in Markdown output.
 * Neutralizes: links, images, HTML tags, heading injection, and code fences.
 * Server-controlled data (tool names, descriptions, finding titles) MUST go
 * through this before interpolation into markdown reports.
 */
function escMd(s: string): string {
  return s
    .replace(/</g, "&lt;")           // HTML tags
    .replace(/>/g, "&gt;")
    .replace(/\[/g, "\\[")           // Markdown links/images
    .replace(/\]/g, "\\]")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)")
    .replace(/^(#{1,6})\s/gm, "\\$1 ") // Heading injection
    .replace(/```/g, "\\`\\`\\`");    // Code fence injection
}

/**
 * Format findings for detailed output used in verbose mode.
 */
export function formatFinding(finding: Finding): string {
  const severityColor = {
    [Severity.CRITICAL]: chalk.bgRed.white,
    [Severity.HIGH]: chalk.red,
    [Severity.MEDIUM]: chalk.yellow,
    [Severity.LOW]: chalk.dim,
    [Severity.INFO]: chalk.blue,
  };

  const lines = [
    `${severityColor[finding.severity](` ${finding.severity} `)} ${chalk.bold(finding.title)}`,
    chalk.dim(`  ID: ${finding.id} | Module: ${finding.module}`),
    `  ${finding.description}`,
  ];

  if (finding.toolName) {
    lines.push(chalk.dim(`  Tool: ${finding.toolName}`));
  }

  lines.push(chalk.green(`  Remediation: ${finding.remediation}`));

  return lines.join("\n");
}
