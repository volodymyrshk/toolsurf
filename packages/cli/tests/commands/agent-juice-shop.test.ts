import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { executeAgentJuiceShop } from "../../src/commands/agent-juice-shop.js";

const TMP_DIR = join(import.meta.dir, ".tmp-agent-juice-shop");

afterEach(() => {
  rmSync(TMP_DIR, { recursive: true, force: true });
});

async function captureOutput(format: "terminal" | "json" | "markdown") {
  const originalLog = console.log;
  const originalExitCode = process.exitCode;
  let output = "";

  console.log = (message?: unknown) => {
    output += String(message ?? "") + "\n";
  };

  try {
    const report = await executeAgentJuiceShop({ format, failOnMiss: true });
    return { output, report, exitCode: process.exitCode };
  } finally {
    console.log = originalLog;
    process.exitCode = originalExitCode ?? 0;
  }
}

describe("agent-juice-shop command", () => {
  test("prints JSON report with all scenarios passing", async () => {
    const { output, report, exitCode } = await captureOutput("json");
    const parsed = JSON.parse(output);

    expect(parsed.summary.failedScenarios).toBe(0);
    expect(parsed.summary.totalScenarios).toBe(report.summary.totalScenarios);
    expect(exitCode ?? 0).toBe(0);
  });

  test("writes markdown output to a nested file path", async () => {
    const outputPath = join(TMP_DIR, "data", "agent-juice-shop", "report.md");

    const report = await executeAgentJuiceShop({
      format: "markdown",
      output: outputPath,
      failOnMiss: true,
    });

    expect(existsSync(outputPath)).toBe(true);
    const markdown = readFileSync(outputPath, "utf-8");
    expect(markdown).toContain("# Agent Juice Shop Benchmark");
    expect(markdown).toContain("Competitor Matrix");
    expect(report.summary.failedScenarios).toBe(0);
  });

  test("terminal output includes benchmark and comparison summary", async () => {
    const { output } = await captureOutput("terminal");

    expect(output).toContain("Agent Juice Shop Benchmark");
    expect(output).toContain("Competitor comparison");
    expect(output).toContain("Snyk Agent Scan");
  });
});
