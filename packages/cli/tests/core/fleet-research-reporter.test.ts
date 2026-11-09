import { describe, test, expect } from "bun:test";
import {
  outputFleetLatex,
  outputScoreDistributionData,
  outputHeatmapData,
} from "../../src/core/fleet-research-reporter.js";
import type { ScanReport, Finding } from "../../src/types/index.js";
import { Severity } from "../../src/types/index.js";

function makeReport(
  name: string,
  score: number,
  protocol: string = "stdio",
  findings: Partial<Finding>[] = []
): ScanReport {
  const fullFindings: Finding[] = findings.map((f, i) => ({
    id: f.id ?? `F-${i}`,
    module: f.module ?? "test-module",
    severity: f.severity ?? Severity.MEDIUM,
    title: f.title ?? "Test finding",
    description: f.description ?? "A test finding",
    evidence: {},
    remediation: "Fix it",
    ...f,
  }));

  return {
    version: "1.0.0",
    id: `report-${name}`,
    timestamp: new Date().toISOString(),
    durationMs: 1000,
    cliVersion: "0.1.0-alpha.1",
    scannerCommit: "test",
    transport: { type: "stdio", command: "test", args: [], protocol },
    server: {
      serverInfo: { name, version: "1.0.0" },
      protocolVersion: "2025-11-05",
      capabilities: {},
      tools: [],
      resources: [],
      prompts: [],
    },
    modules: [],
    findings: fullFindings,
    summary: {
      totalChecks: 10,
      passed: 8,
      warnings: 1,
      failed: 1,
      skipped: 0,
      errors: 0,
      findingsBySeverity: {
        CRITICAL: fullFindings.filter((f) => f.severity === Severity.CRITICAL).length,
        HIGH: fullFindings.filter((f) => f.severity === Severity.HIGH).length,
        MEDIUM: fullFindings.filter((f) => f.severity === Severity.MEDIUM).length,
        LOW: fullFindings.filter((f) => f.severity === Severity.LOW).length,
        INFO: 0,
      },
      securityScore: score,
      checksWithFailStatus: 1,
    },
  } as ScanReport;
}

// ─── outputFleetLatex ───────────────────────────────────────────────────────

describe("outputFleetLatex", () => {
  test("returns comment for empty fleet", () => {
    const result = outputFleetLatex([]);
    expect(result).toBe("% No reports to generate fleet summary");
  });

  test("generates valid LaTeX for single-server fleet", () => {
    const report = makeReport("my-server", 85, "mcp");
    const result = outputFleetLatex([report]);
    expect(result).toContain("\\begin{table*}");
    expect(result).toContain("\\end{table*}");
    expect(result).toContain("mcp");
    expect(result).toContain("85.0");
    expect(result).toContain("N=1");
  });

  test("groups by protocol correctly", () => {
    const reports = [
      makeReport("server-a", 90, "mcp"),
      makeReport("server-b", 70, "mcp"),
      makeReport("server-c", 60, "rest"),
    ];
    const result = outputFleetLatex(reports);
    expect(result).toContain("N=3");
    expect(result).toContain("mcp");
    expect(result).toContain("rest");
  });

  test("handles all-zero scores", () => {
    const reports = [
      makeReport("server-a", 0, "mcp"),
      makeReport("server-b", 0, "mcp"),
    ];
    const result = outputFleetLatex(reports);
    expect(result).toContain("0.0");
  });

  test("handles maximum scores", () => {
    const report = makeReport("perfect-server", 100, "mcp");
    const result = outputFleetLatex([report]);
    expect(result).toContain("100.0");
  });

  test("counts findings by severity", () => {
    const report = makeReport("vuln-server", 30, "mcp", [
      { id: "C-001", severity: Severity.CRITICAL },
      { id: "C-002", severity: Severity.CRITICAL },
      { id: "H-001", severity: Severity.HIGH },
    ]);
    const result = outputFleetLatex([report]);
    // Cross-protocol table includes severity counts
    expect(result).toContain("2"); // 2 criticals
  });

  test("escapes LaTeX special characters in server names", () => {
    const report = makeReport("server_with_underscores", 50, "mcp");
    const result = outputFleetLatex([report]);
    expect(result).toContain("server\\_with\\_underscores");
  });

  test("includes worst targets table", () => {
    const reports = [
      makeReport("good-server", 95, "mcp"),
      makeReport("bad-server", 20, "mcp"),
    ];
    const result = outputFleetLatex(reports);
    expect(result).toContain("Lowest-scoring");
    expect(result).toContain("bad-server");
  });

  test("includes statistics table with std dev", () => {
    const reports = [
      makeReport("a", 80, "mcp"),
      makeReport("b", 60, "mcp"),
      makeReport("c", 40, "mcp"),
    ];
    const result = outputFleetLatex(reports);
    expect(result).toContain("Descriptive statistics");
    expect(result).toContain("Std Dev");
  });
});

// ─── outputScoreDistributionData ────────────────────────────────────────────

describe("outputScoreDistributionData", () => {
  test("creates 11 buckets for empty fleet", () => {
    const result = outputScoreDistributionData([]);
    const dataLines = result.split("\n").filter((l) => !l.startsWith("%") && l.trim());
    expect(dataLines.length).toBe(11); // 0-9, 10-19, ..., 90-99, 100
  });

  test("places score 100 in last bucket", () => {
    const report = makeReport("perfect", 100, "mcp");
    const result = outputScoreDistributionData([report]);
    const lines = result.split("\n").filter((l) => !l.startsWith("%") && l.trim());
    const lastLine = lines[lines.length - 1];
    expect(lastLine).toContain("100");
    expect(lastLine).toEndWith("1");
  });

  test("places score 0 in first bucket", () => {
    const report = makeReport("zero", 0, "mcp");
    const result = outputScoreDistributionData([report]);
    const lines = result.split("\n").filter((l) => !l.startsWith("%") && l.trim());
    expect(lines[0]).toEndWith("1");
  });
});

// ─── outputHeatmapData ──────────────────────────────────────────────────────

describe("outputHeatmapData", () => {
  test("returns header for empty fleet", () => {
    const result = outputHeatmapData([]);
    expect(result).toContain("Heatmap");
  });

  test("includes protocol columns", () => {
    const reports = [
      makeReport("a", 80, "mcp"),
      makeReport("b", 70, "rest"),
    ];
    const result = outputHeatmapData(reports);
    expect(result).toContain("mcp");
    expect(result).toContain("rest");
  });
});
