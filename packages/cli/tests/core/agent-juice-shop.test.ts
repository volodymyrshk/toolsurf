import { describe, expect, test } from "bun:test";
import {
  AGENT_JUICE_SHOP_SCENARIOS,
  COMPETITOR_MATRIX,
  renderAgentJuiceShopMarkdown,
  runAgentJuiceShopBenchmark,
} from "../../src/core/agent-juice-shop.js";

describe("Agent Juice Shop benchmark", () => {
  test("passes every built-in scenario and covers the intended protocols", async () => {
    const report = await runAgentJuiceShopBenchmark({
      generatedAt: "2026-05-01T00:00:00.000Z",
      includeFindings: false,
    });

    expect(report.summary.totalScenarios).toBe(AGENT_JUICE_SHOP_SCENARIOS.length);
    expect(report.summary.failedScenarios).toBe(0);
    expect(report.summary.detectionRate).toBe(1);
    expect(report.summary.coveredProtocols).toEqual([
      "a2a",
      "graphql",
      "grpc",
      "langchain-tools",
      "mcp",
      "openai-functions",
      "rest-api",
      "typescript",
    ]);
    expect(report.summary.crossProtocolScenarios).toBeGreaterThanOrEqual(2);
  });

  test("source/runtime scenario emits drift findings as benchmark signals", async () => {
    const report = await runAgentJuiceShopBenchmark({ includeFindings: true });
    const scenario = report.scenarios.find((item) => item.scenarioId === "source-runtime-drift");

    expect(scenario).toBeDefined();
    expect(scenario?.detectedExpectedPrefixes).toEqual([
      "SRC-AST-001",
      "SRC-AST-002",
      "SRC-AST-003",
    ]);
    expect(scenario?.findings.some((finding) => finding.id.startsWith("SRC-AST-003-read_invoice"))).toBe(true);
  });

  test("comparison matrix is careful about documentation-based claims", () => {
    const scanners = new Set(COMPETITOR_MATRIX.map((entry) => entry.scanner));

    expect(scanners.has("Snyk Agent Scan")).toBe(true);
    expect(scanners.has("MCPShield / mcp-shield")).toBe(true);
    expect(scanners.has("Microsoft Agent Governance Toolkit")).toBe(true);
    expect(scanners.has("Invariant MCP-Scan")).toBe(true);

    for (const entry of COMPETITOR_MATRIX.filter((row) => row.scanner !== "toolsurf / Agent Juice Shop")) {
      expect(entry.evidenceBasis).toContain("no tool execution transcript");
      expect(entry.sourceUrls.length).toBeGreaterThan(0);
    }
  });

  test("markdown report includes scenario status and non-overclaim caveat", async () => {
    const report = await runAgentJuiceShopBenchmark({
      generatedAt: "2026-05-01T00:00:00.000Z",
      includeFindings: false,
    });
    const markdown = renderAgentJuiceShopMarkdown(report);

    expect(markdown).toContain("# Agent Juice Shop Benchmark");
    expect(markdown).toContain("PASS - A2A delegates to MCP, MCP reads file, REST exfiltrates");
    expect(markdown).toContain("Do not publish superiority claims from this table alone.");
    expect(markdown).toContain("https://github.com/snyk/agent-scan");
  });
});
