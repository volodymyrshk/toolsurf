import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import chalk from "chalk";
import {
  renderAgentJuiceShopMarkdown,
  runAgentJuiceShopBenchmark,
  type AgentJuiceShopReport,
} from "../core/agent-juice-shop.js";

export interface AgentJuiceShopOptions {
  format?: "terminal" | "json" | "markdown";
  output?: string;
  failOnMiss?: boolean;
  includeFindings?: boolean;
}

export async function executeAgentJuiceShop(options: AgentJuiceShopOptions = {}): Promise<AgentJuiceShopReport> {
  const format = options.format ?? "terminal";
  if (!["terminal", "json", "markdown"].includes(format)) {
    throw new Error(`Unsupported Agent Juice Shop format: ${format}`);
  }

  const report = await runAgentJuiceShopBenchmark({
    includeFindings: options.includeFindings ?? format === "json",
  });
  const output = renderReport(report, format);

  if (options.output) {
    mkdirSync(dirname(options.output), { recursive: true });
    writeFileSync(options.output, output, "utf-8");
  } else {
    console.log(output);
  }

  if (options.failOnMiss && report.summary.failedScenarios > 0) {
    process.exitCode = 1;
  }

  return report;
}

function renderReport(report: AgentJuiceShopReport, format: "terminal" | "json" | "markdown"): string {
  if (format === "json") {
    return JSON.stringify(report, null, 2);
  }
  if (format === "markdown") {
    return renderAgentJuiceShopMarkdown(report);
  }
  return renderTerminalReport(report);
}

function renderTerminalReport(report: AgentJuiceShopReport): string {
  const lines: string[] = [
    chalk.bold("Agent Juice Shop Benchmark"),
    chalk.dim(`version ${report.version} | module catalog ${report.moduleCatalogVersion}`),
    "",
    `${statusColor(report.summary.failedScenarios === 0)("PASS")} ${report.summary.passedScenarios}/${report.summary.totalScenarios} scenarios passed`,
    `${report.summary.detectedExpectedSignals}/${report.summary.expectedSignals} expected signals detected (${(report.summary.detectionRate * 100).toFixed(1)}%)`,
    `Protocols: ${report.summary.coveredProtocols.join(", ")}`,
    "",
  ];

  for (const scenario of report.scenarios) {
    const marker = scenario.status === "PASS" ? chalk.green("PASS") : chalk.red("FAIL");
    lines.push(
      `${marker} ${scenario.scenarioId}`,
      `  ${scenario.title}`,
      `  expected: ${scenario.expectedFindingPrefixes.join(", ")}`,
      `  detected: ${scenario.detectedExpectedPrefixes.join(", ") || "none"}`,
    );
    if (scenario.missingExpectedPrefixes.length > 0) {
      lines.push(`  missing:  ${chalk.red(scenario.missingExpectedPrefixes.join(", "))}`);
    }
  }

  lines.push(
    "",
    chalk.bold("Competitor comparison"),
    chalk.dim("Documentation-based unless pinned third-party command transcripts are attached."),
  );

  for (const row of report.competitorMatrix) {
    lines.push(
      `  - ${row.scanner}: source/runtime diff=${row.coverage.sourceRuntimeDiff}, ` +
      `multiprotocol=${row.coverage.multiprotocolContracts}, ` +
      `runtime enforcement=${row.coverage.runtimePolicyEnforcement}`,
    );
  }

  return lines.join("\n");
}

function statusColor(pass: boolean): (text: string) => string {
  return pass ? chalk.green : chalk.red;
}
