#!/usr/bin/env node

import { promises as fs } from "node:fs";
import path from "node:path";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

async function main() {
  const args = process.argv.slice(2).filter((arg) => arg !== "--");
  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    printUsage();
    process.exit(args.length === 0 ? 1 : 0);
  }

  const files = [];
  for (const arg of args) {
    const resolved = path.resolve(arg);
    await collectJsonFiles(resolved, files);
  }

  files.sort();

  let checked = 0;
  let mismatched = 0;
  let parseErrors = 0;
  const aggregateFindings = zeroCounts();
  const aggregateSummary = zeroCounts();
  const rows = [];

  for (const file of files) {
    let report;
    try {
      report = JSON.parse(await fs.readFile(file, "utf8"));
    } catch (error) {
      parseErrors++;
      rows.push({
        file,
        status: "PARSE_ERROR",
        detail: error instanceof Error ? error.message : String(error),
      });
      continue;
    }

    if (!report || typeof report !== "object" || !Array.isArray(report.findings)) {
      rows.push({
        file,
        status: "SKIP",
        detail: "Not a scan report with top-level findings[]",
      });
      continue;
    }

    checked++;
    const findingsCounts = countFindings(report.findings);
    const summaryCounts = readSummaryCounts(report.summary?.findingsBySeverity);
    addCounts(aggregateFindings, findingsCounts);
    addCounts(aggregateSummary, summaryCounts);

    const mismatch = !sameCounts(findingsCounts, summaryCounts);
    if (mismatch) mismatched++;

    rows.push({
      file,
      status: mismatch ? "MISMATCH" : "OK",
      findingsCounts,
      summaryCounts,
    });
  }

  for (const row of rows) {
    if (row.status === "OK") continue;
    if (row.status === "MISMATCH") {
      console.log([
        row.status,
        row.file,
        `findings=${formatCounts(row.findingsCounts)}`,
        `summary=${formatCounts(row.summaryCounts)}`,
      ].join("\t"));
    } else {
      console.log([row.status, row.file, row.detail].join("\t"));
    }
  }

  console.log([
    "SUMMARY",
    `files=${files.length}`,
    `checked=${checked}`,
    `mismatched=${mismatched}`,
    `parseErrors=${parseErrors}`,
    `findings=${formatCounts(aggregateFindings)}`,
    `summary=${formatCounts(aggregateSummary)}`,
  ].join("\t"));

  process.exit(mismatched > 0 || parseErrors > 0 ? 1 : 0);
}

function printUsage() {
  console.error("Usage: node scripts/validate-scan-reports.mjs <file-or-dir> [...]");
  console.error("Validates summary.findingsBySeverity against grouped top-level findings[].severity.");
}

async function collectJsonFiles(target, files) {
  const stat = await fs.stat(target);
  if (stat.isDirectory()) {
    const entries = await fs.readdir(target, { withFileTypes: true });
    for (const entry of entries) {
      await collectJsonFiles(path.join(target, entry.name), files);
    }
    return;
  }

  if (stat.isFile() && target.endsWith(".json")) {
    files.push(target);
  }
}

function zeroCounts() {
  return Object.fromEntries(SEVERITIES.map((severity) => [severity, 0]));
}

function countFindings(findings) {
  const counts = zeroCounts();
  for (const finding of findings) {
    const severity = typeof finding?.severity === "string" ? finding.severity.toUpperCase() : "";
    if (severity in counts) counts[severity]++;
  }
  return counts;
}

function readSummaryCounts(summary) {
  const counts = zeroCounts();
  for (const severity of SEVERITIES) {
    const value = summary?.[severity];
    counts[severity] = Number.isFinite(value) ? value : 0;
  }
  return counts;
}

function addCounts(target, source) {
  for (const severity of SEVERITIES) {
    target[severity] += source[severity] ?? 0;
  }
}

function sameCounts(a, b) {
  return SEVERITIES.every((severity) => (a[severity] ?? 0) === (b[severity] ?? 0));
}

function formatCounts(counts) {
  const total = SEVERITIES.reduce((sum, severity) => sum + (counts[severity] ?? 0), 0);
  return `${total}(${SEVERITIES.map((severity) => `${severity[0]}=${counts[severity] ?? 0}`).join(",")})`;
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack : String(error));
  process.exit(1);
});
