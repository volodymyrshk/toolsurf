import { describe, test, expect } from "bun:test";
import { toSarif } from "../../src/core/sarif.js";
import { Severity, CheckStatus } from "../../src/types/index.js";
import type { ScanReport } from "../../src/types/index.js";

function makeReport(
  overrides: Partial<ScanReport> = {}
): ScanReport {
  return {
    version: "1.0.0",
    id: "test-report-id",
    timestamp: "2026-03-10T12:00:00.000Z",
    durationMs: 5000,
    cliVersion: "0.1.0-alpha.1",
    transport: {
      type: "stdio",
      command: "npx",
      args: ["-y", "@test/server"],
    },
    server: {
      serverInfo: { name: "test-server", version: "1.0.0" },
      protocolVersion: "2025-11-05",
      capabilities: {},
      tools: [],
      resources: [],
      prompts: [],
    },
    modules: [],
    findings: [],
    summary: {
      totalChecks: 10,
      passed: 8,
      warnings: 1,
      failed: 1,
      skipped: 0,
      errors: 0,
      findingsBySeverity: {
        CRITICAL: 0,
        HIGH: 1,
        MEDIUM: 0,
        LOW: 0,
        INFO: 0,
      },
      securityScore: 85,
    },
    ...overrides,
  };
}

describe("SARIF Output", () => {
  test("produces valid SARIF v2.1.0 structure", () => {
    const report = makeReport();
    const sarif = toSarif(report);

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toContain("sarif-schema-2.1.0");
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe("toolsurf");
  });

  test("maps findings to SARIF results", () => {
    const report = makeReport({
      findings: [
        {
          id: "TP-003-cmd",
          module: "tool-permissions",
          severity: Severity.HIGH,
          title: "Command execution tool detected",
          description: "Tool allows arbitrary command execution",
          evidence: { tool: "execute_command" },
          remediation: "Restrict command execution",
          toolName: "execute_command",
        },
        {
          id: "SM-001",
          module: "schema-manipulation",
          severity: Severity.CRITICAL,
          title: "Prompt injection in description",
          description: "Tool description contains injection pattern",
          evidence: { matched: "ignore previous" },
          remediation: "Remove injection patterns",
        },
      ],
    });

    const sarif = toSarif(report);
    const run = sarif.runs[0];

    expect(run.results).toHaveLength(2);
    expect(run.tool.driver.rules).toHaveLength(2);
  });

  test("maps severity to correct SARIF levels", () => {
    const report = makeReport({
      findings: [
        {
          id: "F1",
          module: "m",
          severity: Severity.CRITICAL,
          title: "Critical",
          description: "d",
          evidence: {},
          remediation: "r",
        },
        {
          id: "F2",
          module: "m",
          severity: Severity.HIGH,
          title: "High",
          description: "d",
          evidence: {},
          remediation: "r",
        },
        {
          id: "F3",
          module: "m",
          severity: Severity.MEDIUM,
          title: "Medium",
          description: "d",
          evidence: {},
          remediation: "r",
        },
        {
          id: "F4",
          module: "m",
          severity: Severity.LOW,
          title: "Low",
          description: "d",
          evidence: {},
          remediation: "r",
        },
        {
          id: "F5",
          module: "m",
          severity: Severity.INFO,
          title: "Info",
          description: "d",
          evidence: {},
          remediation: "r",
        },
      ],
    });

    const sarif = toSarif(report);
    const results = sarif.runs[0].results;

    expect(results[0].level).toBe("error"); // CRITICAL
    expect(results[1].level).toBe("error"); // HIGH
    expect(results[2].level).toBe("warning"); // MEDIUM
    expect(results[3].level).toBe("note"); // LOW
    expect(results[4].level).toBe("none"); // INFO
  });

  test("includes tool name in logical locations", () => {
    const report = makeReport({
      findings: [
        {
          id: "F1",
          module: "m",
          severity: Severity.HIGH,
          title: "T",
          description: "d",
          evidence: {},
          remediation: "r",
          toolName: "dangerous_tool",
        },
      ],
    });

    const sarif = toSarif(report);
    const location = sarif.runs[0].results[0].locations[0];

    expect(location.logicalLocations![0].name).toBe("dangerous_tool");
    expect(location.logicalLocations![0].kind).toBe("mcpTool");
    expect(location.logicalLocations![0].fullyQualifiedName).toBe(
      "test-server/dangerous_tool"
    );
  });

  test("includes CWE security-severity when present", () => {
    const report = makeReport({
      findings: [
        {
          id: "SSRF-010",
          module: "ssrf-detection",
          severity: Severity.CRITICAL,
          title: "SSRF",
          description: "d",
          evidence: {},
          remediation: "r",
          cweId: "CWE-918",
        },
      ],
    });

    const sarif = toSarif(report);
    const rule = sarif.runs[0].tool.driver.rules[0];

    expect((rule.properties as Record<string, unknown>)["security-severity"]).toBe("9.0");
  });

  test("includes invocation metadata", () => {
    const report = makeReport();
    const sarif = toSarif(report);
    const invocation = sarif.runs[0].invocations[0];

    expect(invocation.executionSuccessful).toBe(true);
    expect(invocation.startTimeUtc).toBe("2026-03-10T12:00:00.000Z");
    expect((invocation.properties as Record<string, unknown>).securityScore).toBe(85);
    expect((invocation.properties as Record<string, unknown>).serverName).toBe("test-server");
  });

  test("handles empty findings", () => {
    const report = makeReport({ findings: [] });
    const sarif = toSarif(report);

    expect(sarif.runs[0].results).toHaveLength(0);
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(0);
  });

  test("includes remediation in fixes", () => {
    const report = makeReport({
      findings: [
        {
          id: "F1",
          module: "m",
          severity: Severity.MEDIUM,
          title: "T",
          description: "d",
          evidence: {},
          remediation: "Apply the fix here",
        },
      ],
    });

    const sarif = toSarif(report);
    const fix = sarif.runs[0].results[0].fixes![0];
    expect(fix.description.text).toBe("Apply the fix here");
  });
});
