/**
 * SARIF Diff Command.
 *
 * Compares two SARIF files (or JSON scan reports) and shows
 * new, fixed, and unchanged findings.
 *
 * Usage:
 *   toolsurf diff baseline.sarif current.sarif
 */

import { readFileSync } from "node:fs";
import chalk from "chalk";
import type { Finding } from "../types/index.js";

interface DiffResult {
  newFindings: FindingSummary[];
  fixedFindings: FindingSummary[];
  unchangedFindings: FindingSummary[];
}

interface FindingSummary {
  id: string;
  title: string;
  severity: string;
  module: string;
  toolName?: string;
}

/**
 * Extract findings from a file (supports JSON report and SARIF).
 */
function extractFindings(filePath: string): FindingSummary[] {
  const content = readFileSync(filePath, "utf-8");
  const data = JSON.parse(content);

  // JSON scan report format
  if (data.findings) {
    return (data.findings as Finding[]).map((f) => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      module: f.module,
      toolName: f.toolName,
    }));
  }

  // SARIF format
  if (data.runs?.[0]?.results) {
    return data.runs[0].results.map(
      (r: Record<string, unknown>) => ({
        id: r.ruleId as string,
        title: ((r.message as Record<string, string>)?.text ?? "").split(":")[0],
        severity: ((r.properties as Record<string, string>)?.severity ?? "MEDIUM"),
        module: ((r.properties as Record<string, string>)?.module ?? "unknown"),
        toolName: (
          (r.locations as Array<Record<string, unknown>>)?.[0] as
            Record<string, unknown> | undefined
        )?.logicalLocations
          ? (
              (
                (r.locations as Array<Record<string, unknown>>)[0]
                  .logicalLocations as Array<Record<string, string>>
              )?.[0]?.name
            )
          : undefined,
      })
    );
  }

  throw new Error(`Unrecognized file format: ${filePath}`);
}

function computeDiff(
  baselineFindings: FindingSummary[],
  currentFindings: FindingSummary[]
): DiffResult {
  const baselineIds = new Set(baselineFindings.map((f) => f.id));
  const currentIds = new Set(currentFindings.map((f) => f.id));

  const newFindings = currentFindings.filter((f) => !baselineIds.has(f.id));
  const fixedFindings = baselineFindings.filter((f) => !currentIds.has(f.id));
  const unchangedFindings = currentFindings.filter((f) => baselineIds.has(f.id));

  return { newFindings, fixedFindings, unchangedFindings };
}

export function executeDiff(baselinePath: string, currentPath: string): void {
  try {
    const baselineFindings = extractFindings(baselinePath);
    const currentFindings = extractFindings(currentPath);
    const diff = computeDiff(baselineFindings, currentFindings);

    console.log();
    console.log(chalk.bold("  SARIF Diff Report"));
    console.log(chalk.dim("  ─".repeat(30)));
    console.log();

    // New findings (regressions)
    if (diff.newFindings.length > 0) {
      console.log(
        chalk.red.bold(`  + ${diff.newFindings.length} New Finding(s):`)
      );
      for (const f of diff.newFindings) {
        const sev = severityBadge(f.severity);
        console.log(`    ${sev} ${f.title}${f.toolName ? chalk.dim(` [${f.toolName}]`) : ""}`);
      }
      console.log();
    }

    // Fixed findings (improvements)
    if (diff.fixedFindings.length > 0) {
      console.log(
        chalk.green.bold(`  - ${diff.fixedFindings.length} Fixed Finding(s):`)
      );
      for (const f of diff.fixedFindings) {
        const sev = severityBadge(f.severity);
        console.log(`    ${sev} ${chalk.strikethrough(f.title)}${f.toolName ? chalk.dim(` [${f.toolName}]`) : ""}`);
      }
      console.log();
    }

    // Unchanged
    if (diff.unchangedFindings.length > 0) {
      console.log(
        chalk.dim(
          `  = ${diff.unchangedFindings.length} Unchanged Finding(s)`
        )
      );
      console.log();
    }

    // Summary
    console.log(chalk.dim("  ─".repeat(30)));
    console.log(
      `  Baseline: ${baselineFindings.length} finding(s)  →  Current: ${currentFindings.length} finding(s)`
    );

    const delta = currentFindings.length - baselineFindings.length;
    if (delta > 0) {
      console.log(chalk.red(`  Net: +${delta} (regression)`));
    } else if (delta < 0) {
      console.log(chalk.green(`  Net: ${delta} (improvement)`));
    } else {
      console.log(chalk.dim(`  Net: 0 (no change)`));
    }
    console.log();

    // Exit code: non-zero if new findings
    if (diff.newFindings.length > 0) {
      process.exitCode = 1;
    }
  } catch (err) {
    console.error(
      `Error: ${err instanceof Error ? err.message : String(err)}`
    );
    process.exitCode = 4;
  }
}

function severityBadge(severity: string): string {
  switch (severity) {
    case "CRITICAL":
      return chalk.bgRed.white(" CRIT ");
    case "HIGH":
      return chalk.red(" HIGH ");
    case "MEDIUM":
      return chalk.yellow(" MED  ");
    case "LOW":
      return chalk.dim(" LOW  ");
    default:
      return chalk.dim(" INFO ");
  }
}
