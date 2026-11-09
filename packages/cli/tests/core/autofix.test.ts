import { describe, test, expect } from "bun:test";
import { generateFixSuggestions, type FixSuggestion } from "../../src/core/autofix.js";
import { Severity } from "../../src/types/index.js";
import type { ScanReport, Finding } from "../../src/types/index.js";

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

function makeReport(findings: Finding[]): ScanReport {
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
      tools: [],
      resources: [],
      prompts: [],
    },
    modules: [],
    findings,
    summary: {
      totalChecks: 10,
      passed: 8,
      warnings: 1,
      failed: 1,
      skipped: 0,
      errors: 0,
      findingsBySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 1, LOW: 0, INFO: 0 },
      securityScore: 85,
    },
  };
}

describe("Auto-Fix Suggestion Engine", () => {
  test("returns empty array when no findings match", () => {
    const report = makeReport([
      makeFinding({ id: "UNKNOWN-001" }),
    ]);
    const fixes = generateFixSuggestions(report);
    expect(fixes).toEqual([]);
  });

  test("generates fix for TP-004 (schema constraints)", () => {
    const report = makeReport([
      makeFinding({ id: "TP-004", toolName: "read_file" }),
    ]);
    const fixes = generateFixSuggestions(report);
    expect(fixes.length).toBe(1);
    expect(fixes[0].findingId).toBe("TP-004");
    expect(fixes[0].category).toBe("schema");
    expect(fixes[0].effort).toBe("easy");
    expect(fixes[0].patch).toBeDefined();
    expect(fixes[0].patch!).toContain("maxLength");
  });

  test("generates fix for TP-003 (destructive hint)", () => {
    const report = makeReport([
      makeFinding({ id: "TP-003", toolName: "delete_file" }),
    ]);
    const fixes = generateFixSuggestions(report);
    expect(fixes.length).toBe(1);
    expect(fixes[0].title).toBe("Add destructiveHint annotation");
    expect(fixes[0].patch!).toContain("destructiveHint");
  });

  test("generates fix for secret leaks (SL-*)", () => {
    const report = makeReport([
      makeFinding({ id: "SL-001" }),
    ]);
    const fixes = generateFixSuggestions(report);
    expect(fixes.length).toBe(1);
    expect(fixes[0].title).toBe("Remove hardcoded secrets");
    expect(fixes[0].category).toBe("code");
    expect(fixes[0].patch!).toContain("process.env");
  });

  test("generates fix for SSRF findings", () => {
    const report = makeReport([
      makeFinding({ id: "SSRF-001" }),
    ]);
    const fixes = generateFixSuggestions(report);
    expect(fixes.length).toBe(1);
    expect(fixes[0].title).toBe("Add URL allowlist validation");
    expect(fixes[0].patch!).toContain("ALLOWED_HOSTS");
  });

  test("generates fix for AB-003 (resource boundaries)", () => {
    const report = makeReport([
      makeFinding({ id: "AB-003" }),
    ]);
    const fixes = generateFixSuggestions(report);
    expect(fixes.length).toBe(1);
    expect(fixes[0].title).toBe("Implement path boundary enforcement");
    expect(fixes[0].priority).toBe(1);
  });

  test("generates fix for AF-009 (mutation-based)", () => {
    const report = makeReport([
      makeFinding({ id: "AF-009" }),
    ]);
    const fixes = generateFixSuggestions(report);
    expect(fixes.length).toBe(1);
    expect(fixes[0].title).toBe("Switch from blocklist to allowlist validation");
    expect(fixes[0].category).toBe("architecture");
  });

  test("deduplicates fixes by findingId", () => {
    const report = makeReport([
      makeFinding({ id: "SL-001", toolName: "tool_a" }),
      makeFinding({ id: "SL-002", toolName: "tool_b" }),
    ]);
    const fixes = generateFixSuggestions(report);
    // SL-001 and SL-002 both match SL-* but have different IDs, so both should be present
    expect(fixes.length).toBe(2);
  });

  test("sorts by priority (lower first)", () => {
    const report = makeReport([
      makeFinding({ id: "TP-004" }),  // priority 3
      makeFinding({ id: "AB-003" }),  // priority 1
      makeFinding({ id: "TP-003" }),  // priority 2
    ]);
    const fixes = generateFixSuggestions(report);
    expect(fixes.length).toBe(3);
    expect(fixes[0].priority).toBeLessThanOrEqual(fixes[1].priority);
    expect(fixes[1].priority).toBeLessThanOrEqual(fixes[2].priority);
  });

  test("handles multiple different finding types", () => {
    const report = makeReport([
      makeFinding({ id: "TS-001" }),
      makeFinding({ id: "TS-003" }),
      makeFinding({ id: "CE-001" }),
      makeFinding({ id: "AF-007", toolName: "fetch_url" }),
    ]);
    const fixes = generateFixSuggestions(report);
    expect(fixes.length).toBe(4);

    const ids = fixes.map((f) => f.findingId);
    expect(ids).toContain("TS-001");
    expect(ids).toContain("TS-003");
    expect(ids).toContain("CE-001");
    expect(ids).toContain("AF-007");
  });

  test("generates fix for TS-004 (dynamic registration)", () => {
    const report = makeReport([
      makeFinding({ id: "TS-004" }),
    ]);
    const fixes = generateFixSuggestions(report);
    expect(fixes.length).toBe(1);
    expect(fixes[0].title).toBe("Disable dynamic tool registration");
    expect(fixes[0].category).toBe("config");
  });

  test("returns empty for report with no findings", () => {
    const report = makeReport([]);
    const fixes = generateFixSuggestions(report);
    expect(fixes).toEqual([]);
  });
});
