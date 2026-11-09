import { describe, test, expect } from "bun:test";
import {
  generateExecutiveSummary,
  executiveSummaryToMarkdown,
  executiveSummaryToHtml,
} from "../../src/core/executive-summary.js";
import { Severity } from "../../src/types/index.js";
import type { ScanReport, Finding, ReportSummary } from "../../src/types/index.js";

function makeFinding(overrides: Partial<Finding>): Finding {
  return {
    id: "TEST-001",
    module: "test-module",
    severity: Severity.MEDIUM,
    title: "Test finding",
    description: "A test finding",
    evidence: {},
    remediation: "Fix it",
    ...overrides,
  };
}

function makeReport(
  findings: Finding[],
  summaryOverrides: Partial<ReportSummary> = {}
): ScanReport {
  const crit = findings.filter((f) => f.severity === Severity.CRITICAL).length;
  const high = findings.filter((f) => f.severity === Severity.HIGH).length;
  const med = findings.filter((f) => f.severity === Severity.MEDIUM).length;
  const low = findings.filter((f) => f.severity === Severity.LOW).length;

  return {
    version: "1.0.0",
    id: "test-report-id",
    timestamp: new Date().toISOString(),
    durationMs: 1000,
    cliVersion: "0.1.0-alpha.1",
    transport: { type: "stdio", command: "test", args: [] },
    server: {
      serverInfo: { name: "test-server", version: "1.0.0" },
      protocolVersion: "2025-11-05",
      capabilities: {},
      tools: [
        { name: "tool_a", inputSchema: { type: "object", properties: {} } },
        { name: "tool_b", inputSchema: { type: "object", properties: {} } },
      ],
      resources: [],
      prompts: [],
    },
    modules: [],
    findings,
    summary: {
      totalChecks: 20,
      passed: 15,
      warnings: 3,
      failed: 2,
      skipped: 0,
      errors: 0,
      findingsBySeverity: {
        CRITICAL: crit,
        HIGH: high,
        MEDIUM: med,
        LOW: low,
        INFO: 0,
      },
      securityScore: 70,
      ...summaryOverrides,
    },
  };
}

describe("Executive Summary Generator", () => {
  describe("risk level classification", () => {
    test("critical when CRITICAL findings exist", () => {
      const report = makeReport(
        [makeFinding({ severity: Severity.CRITICAL, cweId: "CWE-78" })],
        { securityScore: 20 }
      );
      const summary = generateExecutiveSummary(report);
      expect(summary.riskLevel).toBe("critical");
    });

    test("high when multiple HIGH findings exist", () => {
      const report = makeReport(
        [
          makeFinding({ id: "H1", severity: Severity.HIGH }),
          makeFinding({ id: "H2", severity: Severity.HIGH }),
          makeFinding({ id: "H3", severity: Severity.HIGH }),
        ],
        { securityScore: 45 }
      );
      const summary = generateExecutiveSummary(report);
      expect(summary.riskLevel).toBe("high");
    });

    test("moderate when some HIGH findings exist", () => {
      const report = makeReport(
        [makeFinding({ severity: Severity.HIGH })],
        { securityScore: 65 }
      );
      const summary = generateExecutiveSummary(report);
      expect(summary.riskLevel).toBe("moderate");
    });

    test("low when only minor findings", () => {
      const report = makeReport(
        [makeFinding({ severity: Severity.LOW })],
        { securityScore: 90 }
      );
      const summary = generateExecutiveSummary(report);
      expect(summary.riskLevel).toBe("low");
    });

    test("minimal when no findings", () => {
      const report = makeReport([], { securityScore: 100 });
      const summary = generateExecutiveSummary(report);
      expect(summary.riskLevel).toBe("minimal");
    });

    test("uses CRS riskProfile when present so executive summary matches the scanner headline", () => {
      const report = makeReport(
        [makeFinding({ severity: Severity.CRITICAL })],
        { securityScore: 0 }
      );
      report.riskProfile = {
        exposure: 0.3,
        exploitChainDepth: 0.6,
        severityDensity: 0.4,
        capabilityRisk: 0.5,
        trustViolation: 0.2,
        compositeRiskScore: 0.555,
        umriScalar: 40.07,
        riskLevel: "HIGH",
        ssvcLabel: "Attend",
        _scanTier: "schema-rich",
        _inputs: {
          toolCount: 1,
          totalParams: 1,
          unconstrainedParams: 1,
          chainFindings: 1,
          dualUseFindings: 1,
          capConcentrationFindings: 0,
          dangerousCapabilities: [],
          rugPullCriticals: 0,
          rugPullHighs: 0,
          descInjectionFindings: 0,
          ipiFindings: 0,
          namespacePoisoningFindings: 0,
          findingsBySeverity: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
          weightedFindingSum: 1,
          cwas: 1,
          totalToolRisk: 1,
        },
      };

      const summary = generateExecutiveSummary(report);
      expect(summary.riskLevel).toBe("high");
      expect(summary.riskAssessment).toContain("calibrated CRS model");
    });
  });

  describe("risk assessment", () => {
    test("includes server name and score", () => {
      const report = makeReport([], { securityScore: 100 });
      const summary = generateExecutiveSummary(report);
      expect(summary.riskAssessment).toContain("test-server");
      expect(summary.riskAssessment).toContain("100/100");
    });

    test("mentions NOT ready for production on critical risk", () => {
      const report = makeReport(
        [makeFinding({ severity: Severity.CRITICAL })],
        { securityScore: 15 }
      );
      const summary = generateExecutiveSummary(report);
      expect(summary.riskAssessment).toContain("NOT ready for production");
    });

    test("mentions excellent posture on minimal risk", () => {
      const report = makeReport([], { securityScore: 100 });
      const summary = generateExecutiveSummary(report);
      expect(summary.riskAssessment).toContain("excellent");
    });
  });

  describe("key takeaways", () => {
    test("includes security score and pass rate", () => {
      const report = makeReport([], {
        securityScore: 100,
        totalChecks: 20,
        passed: 20,
      });
      const summary = generateExecutiveSummary(report);
      expect(summary.keyTakeaways.length).toBeGreaterThan(0);
      expect(summary.keyTakeaways[0]).toContain("100/100");
    });

    test("mentions CRITICAL findings when present", () => {
      const report = makeReport(
        [makeFinding({ severity: Severity.CRITICAL })],
        { securityScore: 15 }
      );
      const summary = generateExecutiveSummary(report);
      const critTakeaway = summary.keyTakeaways.find((t) =>
        t.includes("CRITICAL")
      );
      expect(critTakeaway).toBeDefined();
    });

    test("mentions no vulnerabilities when clean", () => {
      const report = makeReport([], { securityScore: 100 });
      const summary = generateExecutiveSummary(report);
      const cleanTakeaway = summary.keyTakeaways.find((t) =>
        t.includes("No security vulnerabilities")
      );
      expect(cleanTakeaway).toBeDefined();
    });
  });

  describe("immediate actions", () => {
    test("includes URGENT for critical findings", () => {
      const report = makeReport(
        [makeFinding({ severity: Severity.CRITICAL, cweId: "CWE-78" })],
        { securityScore: 15 }
      );
      const summary = generateExecutiveSummary(report);
      const urgentAction = summary.immediateActions.find((a) =>
        a.startsWith("URGENT")
      );
      expect(urgentAction).toBeDefined();
    });

    test("suggests active scanning when no actions needed", () => {
      const report = makeReport([], { securityScore: 100 });
      const summary = generateExecutiveSummary(report);
      const activeHint = summary.immediateActions.find((a) =>
        a.includes("--active")
      );
      expect(activeHint).toBeDefined();
    });
  });

  describe("posture statement", () => {
    test("includes risk level and score", () => {
      const report = makeReport([], { securityScore: 95 });
      const summary = generateExecutiveSummary(report);
      expect(summary.postureStatement).toContain("MINIMAL");
      expect(summary.postureStatement).toContain("95/100");
    });

    test("says BLOCKED for critical risk", () => {
      const report = makeReport(
        [makeFinding({ severity: Severity.CRITICAL })],
        { securityScore: 10 }
      );
      const summary = generateExecutiveSummary(report);
      expect(summary.postureStatement).toContain("BLOCKED");
    });

    test("says ready for production on minimal risk", () => {
      const report = makeReport([], { securityScore: 100 });
      const summary = generateExecutiveSummary(report);
      expect(summary.postureStatement).toContain("production");
    });
  });

  describe("markdown output", () => {
    test("generates valid markdown", () => {
      const report = makeReport(
        [makeFinding({ severity: Severity.HIGH })],
        { securityScore: 65 }
      );
      const summary = generateExecutiveSummary(report);
      const md = executiveSummaryToMarkdown(summary);

      expect(md).toContain("## Executive Summary");
      expect(md).toContain("**Risk Level:**");
      expect(md).toContain("### Key Takeaways");
      expect(md).toContain("### Recommended Actions");
    });
  });

  describe("HTML output", () => {
    test("generates valid HTML", () => {
      const report = makeReport(
        [makeFinding({ severity: Severity.HIGH })],
        { securityScore: 65 }
      );
      const summary = generateExecutiveSummary(report);
      const html = executiveSummaryToHtml(summary);

      expect(html).toContain("executive-summary");
      expect(html).toContain("<h2");
      expect(html).toContain("Key Takeaways");
      expect(html).toContain("Recommended Actions");
    });

    test("uses correct color for risk level", () => {
      const report = makeReport(
        [makeFinding({ severity: Severity.CRITICAL })],
        { securityScore: 10 }
      );
      const summary = generateExecutiveSummary(report);
      const html = executiveSummaryToHtml(summary);
      // Critical risk uses red (#ef4444)
      expect(html).toContain("#ef4444");
    });
  });
});
