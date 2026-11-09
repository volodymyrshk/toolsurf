import { existsSync, readFileSync } from "node:fs";
import chalk from "chalk";
import type { AuditModule, ChamberProbeConfig, ModuleResult, ReportSummary } from "../types/index.js";
import { scoreToGrade, scoreToColor, type RiskProfile } from "./scorer.js";

/**
 * Interactive TUI Dashboard — live module progress, findings stream,
 * and animated score reveal. Enterprise-grade visual output.
 */

// ─── Box drawing characters ─────────────────────────────────────────────────

const BOX = {
  tl: "╭", tr: "╮", bl: "╰", br: "╯",
  h: "─", v: "│",
  lt: "├", rt: "┤", mt: "┬", mb: "┴",
};

const WIDTH = 78;

function hLine(left: string, right: string, fill = BOX.h): string {
  return left + fill.repeat(WIDTH - 2) + right;
}

function padRow(content: string, rawLen: number): string {
  const padding = WIDTH - 2 - rawLen;
  return `${BOX.v} ${content}${" ".repeat(Math.max(0, padding - 1))}${BOX.v}`;
}

// ─── Live Progress Renderer ─────────────────────────────────────────────────

interface ModuleStatus {
  id: string;
  name: string;
  mode: string;
  status: "pending" | "running" | "done" | "error";
  durationMs?: number;
  checkCount?: number;
  findingCount?: number;
  detailMessage?: string;
}

export interface TuiDashboardOptions {
  targetName?: string;
  protocol?: string;
  transport?: string;
  scanMode?: string;
  chamber?: ChamberProbeConfig;
}

type CaptureKey = "http" | "dns" | "smtp" | "metadata" | "netflow";
type CaptureCounts = Record<CaptureKey, number>;

export class TuiDashboard {
  private modules: ModuleStatus[] = [];
  private startTime = 0;
  private liveFindings: Array<{ id: string; module: string; severity: string; title: string; tool?: string }> = [];
  private intervalId: ReturnType<typeof setInterval> | null = null;
  private rendered = false;
  private lastLineCount = 0;
  private options: TuiDashboardOptions = {};
  private chamberCaptureCache?: { readAtMs: number; counts: CaptureCounts };
  private finalSummary?: ReportSummary;

  /**
   * Initialize dashboard with module list.
   */
  init(modules: AuditModule[], options: TuiDashboardOptions = {}): void {
    this.startTime = performance.now();
    this.options = options;
    this.modules = modules.map((m) => ({
      id: m.id,
      name: m.name,
      mode: m.mode,
      status: "pending",
    }));
    this.liveFindings = [];
    this.rendered = false;
    this.lastLineCount = 0;
    this.chamberCaptureCache = undefined;
    this.finalSummary = undefined;

    // Render initial state
    this.render();

    // Start live refresh
    this.intervalId = setInterval(() => this.render(), 250);
  }

  /**
   * Mark a module as started.
   */
  onModuleStart(moduleId: string): void {
    const mod = this.modules.find((m) => m.id === moduleId);
    if (mod) {
      mod.status = "running";
      mod.detailMessage = undefined;
    }
  }

  /**
   * Update the detail message for the currently running module.
   */
  onDetailProgress(message: string): void {
    const running = this.modules.find((m) => m.status === "running");
    if (running) {
      running.detailMessage = message;
    }
  }

  /**
   * Mark a module as complete with results.
   */
  onModuleComplete(moduleId: string, result: ModuleResult): void {
    const mod = this.modules.find((m) => m.id === moduleId);
    if (mod) {
      mod.status = result.error ? "error" : "done";
      mod.durationMs = result.durationMs;
      mod.checkCount = result.checks.length;
      mod.findingCount = result.findings.length;
      mod.detailMessage = undefined;

      // Stream findings to live feed
      for (const f of result.findings) {
        this.liveFindings.push({
          id: f.id,
          module: f.module,
          severity: f.severity,
          title: f.title.substring(0, 60),
          tool: f.toolName,
        });
      }
    }
  }

  /**
   * Finalize dashboard and show final score.
   */
  finalize(summary: ReportSummary, riskProfile?: RiskProfile): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    this.finalSummary = summary;
    this.render();
    this.renderScoreReveal(summary, riskProfile);
  }

  /**
   * Stop the dashboard (cleanup).
   */
  stop(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }

  // ─── Rendering ──────────────────────────────────────────────────────────

  private render(): void {
    const elapsed = Math.round((performance.now() - this.startTime) / 1000);
    const done = this.modules.filter((m) => m.status === "done" || m.status === "error").length;
    const total = this.modules.length;
    const running = this.modules.filter((m) => m.status === "running");
    const pending = this.modules.filter((m) => m.status === "pending").length;
    const errors = this.modules.filter((m) => m.status === "error").length;
    const activeTotal = this.modules.filter((m) => m.mode === "active").length;
    const activeDone = this.modules.filter((m) => m.mode === "active" && (m.status === "done" || m.status === "error")).length;
    const passiveTotal = total - activeTotal;
    const passiveDone = done - activeDone;

    // Clear previous render
    if (this.rendered) {
      const lineCount = this.getRenderedLineCount();
      process.stderr.write(`\x1b[${lineCount}A\x1b[J`);
    }

    const lines: string[] = [];

    const addRow = (content: string): void => {
      const rawLen = this.stripAnsi(content).length;
      const visible = rawLen > WIDTH - 3 ? chalk.dim(this.truncate(this.stripAnsi(content), WIDTH - 4)) : content;
      const visibleLen = this.stripAnsi(visible).length;
      lines.push(chalk.dim(BOX.v) + ` ${visible}${" ".repeat(Math.max(0, WIDTH - visibleLen - 3))}` + chalk.dim(BOX.v));
    };

    // Header
    lines.push(chalk.dim(hLine(BOX.tl, BOX.tr)));
    const target = this.options.targetName ? `  ${this.options.targetName}` : "";
    const headerText = ` MCP Audit Live${target}  ${done}/${total} modules  ${elapsed}s`;
    lines.push(chalk.dim(padRow(chalk.bold.cyan(headerText), headerText.length)));
    lines.push(chalk.dim(hLine(BOX.lt, BOX.rt)));

    // Progress bar
    const barWidth = 48;
    const progress = total > 0 ? done / total : 0;
    const filled = Math.round(progress * barWidth);
    const empty = barWidth - filled;
    const barStr = chalk.cyan("█".repeat(filled)) + chalk.dim("░".repeat(empty));
    const pctStr = `${Math.round(progress * 100)}%`;
    addRow(`${barStr} ${chalk.bold(pctStr)}  ${chalk.dim(`pending ${pending}`)}  ${errors > 0 ? chalk.red(`errors ${errors}`) : chalk.dim("errors 0")}`);
    addRow(
      `${chalk.bold("Modes")}  ` +
        chalk.dim(`passive ${passiveDone}/${passiveTotal}`) +
        `  ${activeTotal > 0 ? chalk.red(`active ${activeDone}/${activeTotal}`) : chalk.dim("active 0/0")}` +
        `  ${chalk.dim(`${this.options.protocol ?? "mcp"}/${this.options.transport ?? "stdio"}`)}` +
        (this.options.scanMode ? `  ${chalk.dim(this.options.scanMode)}` : ""),
    );
    if (this.options.chamber) {
      const counts = this.readChamberCaptureCounts();
      const confirmed = this.liveFindings.filter((f) => f.id.startsWith("CHAMBER-") || f.id.startsWith("AF-CHAMBER")).length;
      addRow(
        `${chalk.bold.red("Chamber")} ` +
          chalk.red("armed") +
          `  ${chalk.dim(`net ${this.options.chamber.networkName ?? "unknown"}`)}` +
          `  ${confirmed > 0 ? chalk.red(`confirmed ${confirmed}`) : chalk.dim("confirmed 0")}`,
      );
      addRow(
        `  ${chalk.dim("captures")} ` +
          `http ${counts.http}  dns ${counts.dns}  smtp ${counts.smtp}  meta ${counts.metadata}  flow ${counts.netflow}`,
      );
    }
    lines.push(chalk.dim(hLine(BOX.lt, BOX.rt)));

    // Current work and recent completions. This keeps the TUI stable even with
    // many modules: users need the current probe and recent findings, not a
    // scrolling wall of every completed PASS.
    if (running.length > 0) {
      addRow(chalk.bold("Running"));
      for (const mod of running.slice(0, 3)) {
        const badge = mod.mode === "active" ? chalk.red("active") : chalk.dim("passive");
        const detail = mod.detailMessage ? chalk.dim(` - ${this.truncate(mod.detailMessage, 42)}`) : "";
        addRow(`  ${this.statusIcon(mod.status)} ${this.truncate(mod.name, 32).padEnd(32)} ${badge}${detail}`);
      }
      if (running.length > 3) addRow(chalk.dim(`  ... ${running.length - 3} more running module(s)`));
    } else {
      addRow(chalk.dim("Running  none"));
    }

    const recent = this.modules
      .filter((m) => m.status === "done" || m.status === "error")
      .slice(-5);
    if (recent.length > 0) {
      addRow(chalk.bold("Recent Modules"));
      for (const mod of recent) {
        const counts = mod.checkCount !== undefined
          ? chalk.dim(` ${mod.checkCount} checks / ${mod.findingCount} findings`)
          : "";
        const timing = mod.durationMs !== undefined ? chalk.dim(` ${mod.durationMs}ms`) : "";
        addRow(`  ${this.statusIcon(mod.status)} ${this.truncate(mod.name, 36).padEnd(36)}${timing}${counts}`);
      }
    }

    // Live findings feed (last 4)
    if (this.liveFindings.length > 0) {
      lines.push(chalk.dim(hLine(BOX.lt, BOX.rt)));
      const counts = this.findingCounts();
      addRow(
        `${chalk.bold.yellow("Findings")}  ` +
          chalk.red(`crit ${counts.CRITICAL}`) +
          `  ${chalk.red(`high ${counts.HIGH}`)}` +
          `  ${chalk.yellow(`med ${counts.MEDIUM}`)}` +
          `  ${chalk.dim(`low ${counts.LOW}`)}`,
      );

      const recentFindings = this.liveFindings.slice(-4);
      for (const f of recentFindings) {
        const sevColor = f.severity === "CRITICAL" ? chalk.bgRed.white
          : f.severity === "HIGH" ? chalk.red
          : f.severity === "MEDIUM" ? chalk.yellow
          : chalk.dim;
        const sev = sevColor(`[${f.severity.padEnd(8)}]`);
        const tool = f.tool ? chalk.dim(` [${f.tool}]`) : "";
        addRow(`  ${sev} ${this.truncate(f.title, 46)}${tool}`);
      }

      if (this.liveFindings.length > 4) {
        addRow(chalk.dim(`  ... and ${this.liveFindings.length - 4} more`));
      }
    }

    // Footer
    lines.push(chalk.dim(hLine(BOX.bl, BOX.br)));

    process.stderr.write(lines.join("\n") + "\n");
    this.rendered = true;
    this.lastLineCount = lines.length;
  }

  private renderScoreReveal(summary: ReportSummary, riskProfile?: RiskProfile): void {
    const score = summary.securityScore;
    const grade = scoreToGrade(score);
    const color = scoreToColor(score);
    const riskLevel = riskProfile?.riskLevel ?? "UNKNOWN";
    const riskScore = riskProfile?.compositeRiskScore;
    const colorFn = riskProfile
      ? this.riskColor(riskLevel)
      : color === "green"
        ? chalk.green
        : color === "yellow"
          ? chalk.yellow
          : chalk.red;

    console.log();
    console.log(chalk.dim(hLine(BOX.tl, BOX.tr)));

    // Risk-first display. CRS is the primary research metric; legacy score is
    // retained for operator familiarity.
    const scoreStr = riskProfile
      ? `  RISK: ${riskLevel}  CRS: ${riskScore!.toFixed(3)}  SCORE: ${score}/100  `
      : `  SECURITY SCORE: ${score}/100  GRADE: ${grade}  `;
    const scorePad = Math.floor((WIDTH - 2 - scoreStr.length) / 2);
    console.log(
      chalk.dim(BOX.v) +
      " ".repeat(scorePad) +
      chalk.bold(colorFn(scoreStr)) +
      " ".repeat(Math.max(0, WIDTH - 2 - scorePad - scoreStr.length)) +
      chalk.dim(BOX.v)
    );

    // Score bar
    const barWidth = WIDTH - 8;
    const filled = Math.round((riskProfile ? riskScore! : score / 100) * barWidth);
    const empty = barWidth - filled;
    const bar = colorFn("█".repeat(filled)) + chalk.dim("░".repeat(empty));
    console.log(chalk.dim(BOX.v) + `  ${bar}  ` + chalk.dim(BOX.v));

    // Severity breakdown
    const s = summary.findingsBySeverity;
    const parts = [
      chalk.red(`CRIT:${s.CRITICAL}`),
      chalk.red(`HIGH:${s.HIGH}`),
      chalk.yellow(`MED:${s.MEDIUM}`),
      chalk.dim(`LOW:${s.LOW}`),
      chalk.green(`PASS:${summary.passed}`),
      chalk.yellow(`WARN:${summary.warnings}`),
      chalk.red(`FAIL:${summary.checksWithFailStatus}`),
    ];
    const breakdownStr = parts.join("  ");
    const rawLen = this.stripAnsi(breakdownStr).length;
    const breakdownPad = Math.floor((WIDTH - 2 - rawLen) / 2);
    console.log(
      chalk.dim(BOX.v) +
      " ".repeat(breakdownPad) +
      breakdownStr +
      " ".repeat(Math.max(0, WIDTH - 2 - breakdownPad - rawLen)) +
      chalk.dim(BOX.v)
    );

    console.log(chalk.dim(hLine(BOX.bl, BOX.br)));
    console.log();
  }

  private getRenderedLineCount(): number {
    return this.lastLineCount;
  }

  private statusIcon(status: ModuleStatus["status"]): string {
    switch (status) {
      case "pending": return chalk.dim("○");
      case "running": return chalk.cyan("◉");
      case "done": return chalk.green("●");
      case "error": return chalk.red("✗");
    }
  }

  private riskColor(level: string): (s: string) => string {
    if (level === "CRITICAL") return chalk.bgRed.white;
    if (level === "HIGH") return chalk.red;
    if (level === "MEDIUM") return chalk.yellow;
    if (level === "LOW") return chalk.cyan;
    return chalk.dim;
  }

  private stripAnsi(s: string): string {
    return s.replace(/\x1b\[[0-9;]*m/g, "");
  }

  private truncate(s: string, max: number): string {
    return s.length <= max ? s : s.slice(0, Math.max(0, max - 1)) + "…";
  }

  private findingCounts(): Record<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW", number> {
    if (this.finalSummary) {
      return {
        CRITICAL: this.finalSummary.findingsBySeverity.CRITICAL,
        HIGH: this.finalSummary.findingsBySeverity.HIGH,
        MEDIUM: this.finalSummary.findingsBySeverity.MEDIUM,
        LOW: this.finalSummary.findingsBySeverity.LOW,
      };
    }

    return this.liveFindings.reduce<Record<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW", number>>(
      (acc, f) => {
        if (f.severity === "CRITICAL" || f.severity === "HIGH" || f.severity === "MEDIUM" || f.severity === "LOW") {
          acc[f.severity]++;
        }
        return acc;
      },
      { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
    );
  }

  private readChamberCaptureCounts(): CaptureCounts {
    const now = performance.now();
    if (this.chamberCaptureCache && now - this.chamberCaptureCache.readAtMs < 1000) {
      return this.chamberCaptureCache.counts;
    }

    const captures = this.options.chamber?.captures;
    const counts: CaptureCounts = {
      http: this.countJsonlRows(captures?.http),
      dns: this.countJsonlRows(captures?.dns),
      smtp: this.countJsonlRows(captures?.smtp),
      metadata: this.countJsonlRows(captures?.metadata),
      netflow: this.countJsonlRows(captures?.netflow),
    };
    this.chamberCaptureCache = { readAtMs: now, counts };
    return counts;
  }

  private countJsonlRows(path: string | undefined): number {
    if (!path || !existsSync(path)) return 0;
    try {
      const raw = readFileSync(path, "utf-8").trim();
      if (!raw) return 0;
      return raw.split("\n").filter((line) => line.trim().length > 0).length;
    } catch {
      return 0;
    }
  }
}
