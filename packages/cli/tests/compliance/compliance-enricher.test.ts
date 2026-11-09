import { describe, test, expect } from "bun:test";
import { enrichFindings, generateComplianceSummary } from "../../src/compliance/compliance-enricher.js";
import { Severity } from "../../src/types/index.js";
import type { Finding } from "../../src/types/index.js";

describe("Compliance Enricher", () => {
  const baseFinding: Finding = {
    id: "TEST-001",
    module: "test",
    severity: Severity.HIGH,
    title: "Test finding",
    description: "Test",
    evidence: {},
    remediation: "Fix it",
  };

  test("enriches finding with known CWE mapping", () => {
    const findings = [{ ...baseFinding, cweId: "CWE-918" }];
    const enriched = enrichFindings(findings);

    expect(enriched[0].complianceControls).toBeDefined();
    expect(enriched[0].complianceControls!.length).toBeGreaterThan(0);

    const frameworks = enriched[0].complianceControls!.map((c) => c.framework);
    expect(frameworks).toContain("NIST SP 800-171");
    expect(frameworks).toContain("SOC 2 TSC");
    expect(frameworks).toContain("OWASP ASVS");
  });

  test("leaves finding without CWE unmapped", () => {
    const findings = [baseFinding];
    const enriched = enrichFindings(findings);

    expect(enriched[0].complianceControls).toBeUndefined();
  });

  test("leaves finding with unknown CWE unmapped", () => {
    const findings = [{ ...baseFinding, cweId: "CWE-99999" }];
    const enriched = enrichFindings(findings);

    expect(enriched[0].complianceControls).toBeUndefined();
  });

  test("generates correct compliance summary", () => {
    const findings = [
      { ...baseFinding, cweId: "CWE-918" },
      { ...baseFinding, id: "TEST-002", cweId: "CWE-78" },
      { ...baseFinding, id: "TEST-003" }, // no CWE
    ];

    const enriched = enrichFindings(findings);
    const summary = generateComplianceSummary(enriched);

    expect(summary.mappedFindings).toBe(2);
    expect(summary.unmappedFindings).toBe(1);
    // Both CWE-918 and CWE-78 should map to NIST SP 800-171 controls
    expect(Object.keys(summary.nist).length).toBeGreaterThan(0);
    expect(Object.keys(summary.soc2).length).toBeGreaterThan(0);
    expect(Object.keys(summary.asvs).length).toBeGreaterThan(0);
  });

  test("handles empty findings list", () => {
    const enriched = enrichFindings([]);
    const summary = generateComplianceSummary(enriched);

    expect(summary.mappedFindings).toBe(0);
    expect(summary.unmappedFindings).toBe(0);
    expect(Object.keys(summary.nist)).toHaveLength(0);
  });

  test("complianceControls have correct structure", () => {
    const findings = [{ ...baseFinding, cweId: "CWE-78" }];
    const enriched = enrichFindings(findings);

    const controls = enriched[0].complianceControls!;
    for (const control of controls) {
      expect(control.framework).toBeTruthy();
      expect(control.controlId).toBeTruthy();
      expect(control.controlTitle).toBeTruthy();
      expect(control.requirement).toBeTruthy();
    }
  });
});
