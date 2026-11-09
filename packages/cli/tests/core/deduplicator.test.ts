import { describe, test, expect } from "bun:test";
import { deduplicateFindings } from "../../src/core/deduplicator.js";
import { calculateScore } from "../../src/core/scorer.js";
import type { Finding, ModuleResult } from "../../src/types/index.js";
import { Severity } from "../../src/types/index.js";

// ── Helpers ──────────────────────────────────────────────────────────────────

function makeFinding(
  id: string,
  severity: Severity,
  toolName?: string,
  confidence = 0.8
): Finding {
  return {
    id,
    module: id.split("-")[0].toLowerCase(),
    severity,
    confidence,
    title: `Test finding ${id}`,
    description: `Description for ${id}`,
    evidence: {},
    remediation: "Fix it.",
    cweId: "CWE-000",
    ...(toolName ? { toolName } : {}),
  };
}

function makeModuleResult(findings: Finding[]): ModuleResult {
  return {
    moduleId: "test-module",
    moduleName: "Test Module",
    status: "complete",
    checks: findings.map((f) => ({
      id: f.id,
      name: f.title,
      status: "FAIL" as const,
      message: f.description,
      finding: f,
    })),
    findings,
  };
}

// ── Empty / trivial cases ─────────────────────────────────────────────────────

describe("deduplicateFindings — empty and trivial", () => {
  test("empty array returns empty result", () => {
    const result = deduplicateFindings([]);
    expect(result.primary).toHaveLength(0);
    expect(result.supporting).toHaveLength(0);
    expect(result.stats.totalBefore).toBe(0);
    expect(result.stats.totalAfter).toBe(0);
    expect(result.stats.groupsCollapsed).toBe(0);
  });

  test("single finding passes through unchanged", () => {
    const f = makeFinding("TP-005-read_file", Severity.HIGH, "read_file");
    const result = deduplicateFindings([f]);
    expect(result.primary).toHaveLength(1);
    expect(result.supporting).toHaveLength(0);
    expect(result.stats.groupsCollapsed).toBe(0);
  });

  test("two findings with distinct prefixes are both primary", () => {
    const f1 = makeFinding("DC-001-run_sql", Severity.CRITICAL, "run_sql");
    const f2 = makeFinding("SL-001-config_read", Severity.HIGH, "config_read");
    const result = deduplicateFindings([f1, f2]);
    expect(result.primary).toHaveLength(2);
    expect(result.supporting).toHaveLength(0);
  });
});

// ── Pass 1: same-check dedup ──────────────────────────────────────────────────

describe("deduplicateFindings — pass 1: same root cause across tools", () => {
  test("collapses two TP-005 findings into one primary + one supporting", () => {
    const f1 = makeFinding("TP-005-read_file", Severity.HIGH, "read_file", 0.8);
    const f2 = makeFinding("TP-005-write_file", Severity.HIGH, "write_file", 0.8);
    const result = deduplicateFindings([f1, f2]);

    expect(result.primary).toHaveLength(1);
    expect(result.supporting).toHaveLength(1);
    expect(result.stats.groupsCollapsed).toBe(1);
    expect(result.stats.totalBefore).toBe(2);
    expect(result.stats.totalAfter).toBe(1);
  });

  test("primary finding has aggregated affectedTools", () => {
    const f1 = makeFinding("TP-005-read_file", Severity.HIGH, "read_file", 0.8);
    const f2 = makeFinding("TP-005-write_file", Severity.HIGH, "write_file", 0.8);
    const result = deduplicateFindings([f1, f2]);

    const primary = result.primary[0];
    expect(primary.affectedCount).toBe(2);
    expect(primary.affectedTools).toContain("read_file");
    expect(primary.affectedTools).toContain("write_file");
  });

  test("collapses 5 findings of same type — primary keeps highest severity", () => {
    const findings = [
      makeFinding("TP-005-tool_a", Severity.HIGH, "tool_a", 0.7),
      makeFinding("TP-005-tool_b", Severity.CRITICAL, "tool_b", 0.9),
      makeFinding("TP-005-tool_c", Severity.MEDIUM, "tool_c", 0.6),
      makeFinding("TP-005-tool_d", Severity.HIGH, "tool_d", 0.8),
      makeFinding("TP-005-tool_e", Severity.LOW, "tool_e", 0.5),
    ];
    const result = deduplicateFindings(findings);

    expect(result.primary).toHaveLength(1);
    expect(result.supporting).toHaveLength(4);
    // Lead should be the CRITICAL one
    expect(result.primary[0].severity).toBe(Severity.CRITICAL);
    expect(result.primary[0].affectedCount).toBe(5);
  });

  test("stats.totalAfter equals primary.length", () => {
    const f1 = makeFinding("TP-005-a", Severity.HIGH, "tool_a");
    const f2 = makeFinding("TP-005-b", Severity.HIGH, "tool_b");
    const f3 = makeFinding("DC-001-c", Severity.CRITICAL, "tool_c");
    const result = deduplicateFindings([f1, f2, f3]);

    expect(result.stats.totalAfter).toBe(result.primary.length);
    expect(result.stats.totalBefore).toBe(3);
  });
});

// ── No false dedup: distinct root causes with different prefixes ──────────────

describe("deduplicateFindings — no false dedup", () => {
  test("TP-005 and DC-001 on the same tool are NOT collapsed (distinct root causes)", () => {
    const f1 = makeFinding("TP-005-run_sql", Severity.HIGH, "run_sql");
    const f2 = makeFinding("DC-001-run_sql", Severity.CRITICAL, "run_sql");
    const result = deduplicateFindings([f1, f2]);

    // Both have different prefixes — should not be deduped in pass 1
    // (pass 2 cross-module overlap may demote one, but both should be present initially)
    const totalVisible = result.primary.length + result.supporting.length;
    expect(totalVisible).toBe(2);
  });

  test("two findings with same prefix but numerically distinct check types stay separate", () => {
    // TP-001 and TP-002 have different numeric IDs — different root causes
    const f1 = makeFinding("TP-001-tool_a", Severity.HIGH, "tool_a");
    const f2 = makeFinding("TP-002-tool_a", Severity.MEDIUM, "tool_a");
    const result = deduplicateFindings([f1, f2]);

    // TP-001 and TP-002 are distinct group keys → both primary
    expect(result.primary).toHaveLength(2);
    expect(result.supporting).toHaveLength(0);
  });

  test("findings without toolName that share a prefix are still deduped", () => {
    // Server-level findings (no tool suffix) with same check type
    const f1 = makeFinding("HF-001", Severity.HIGH);
    const f2 = makeFinding("HF-001", Severity.HIGH);
    const result = deduplicateFindings([f1, f2]);
    // Same group key → collapsed
    expect(result.primary).toHaveLength(1);
    expect(result.supporting).toHaveLength(1);
  });
});

// ── Pass 2: cross-module overlap demotion ─────────────────────────────────────

describe("deduplicateFindings — pass 2: cross-module overlap", () => {
  test("TP-005 (passive) demoted when AF-001 (active, higher confidence) targets same tool", () => {
    const passive = makeFinding("TP-005-exec_cmd", Severity.HIGH, "exec_cmd", 0.6);
    const active = makeFinding("AF-001-exec_cmd", Severity.CRITICAL, "exec_cmd", 0.95);
    const result = deduplicateFindings([passive, active]);

    // AF-001 should win (higher confidence + severity)
    expect(result.primary.some((f) => f.id.startsWith("AF-001"))).toBe(true);
    expect(result.supporting.some((f) => f.id.startsWith("TP-005"))).toBe(true);
  });

  test("DC-001 (passive) demoted when AF-003 (active, higher confidence) targets same tool", () => {
    const passive = makeFinding("DC-001-run_query", Severity.CRITICAL, "run_query", 0.7);
    const active = makeFinding("AF-003-run_query", Severity.CRITICAL, "run_query", 0.95);
    const result = deduplicateFindings([passive, active]);

    // AF-003 has higher confidence → DC-001 demoted
    expect(result.primary.some((f) => f.id.startsWith("AF-003"))).toBe(true);
    expect(result.supporting.some((f) => f.id.startsWith("DC-001"))).toBe(true);
  });

  test("no cross-module demotion when findings target DIFFERENT tools", () => {
    const passive = makeFinding("TP-005-tool_a", Severity.HIGH, "tool_a", 0.6);
    const active = makeFinding("AF-001-tool_b", Severity.CRITICAL, "tool_b", 0.95);
    const result = deduplicateFindings([passive, active]);

    // Different tools — no demotion, both should be primary
    expect(result.primary).toHaveLength(2);
    expect(result.supporting).toHaveLength(0);
  });

  test("cross-module demotion groupsCollapsed increases", () => {
    const passive = makeFinding("TP-005-exec_cmd", Severity.HIGH, "exec_cmd", 0.6);
    const active = makeFinding("AF-002-exec_cmd", Severity.CRITICAL, "exec_cmd", 0.95);
    const result = deduplicateFindings([passive, active]);

    expect(result.stats.groupsCollapsed).toBeGreaterThan(0);
  });

  test("annotation-only SC-003 is demoted when TP-006 covers the same root cause", () => {
    const tp006 = makeFinding("TP-006", Severity.LOW, undefined, 0.7);
    const sc003 = makeFinding("SC-003", Severity.MEDIUM, undefined, 0.7);
    sc003.evidence = {
      issues: ["No tool annotations declared — server provides no safety metadata"],
    };

    const result = deduplicateFindings([tp006, sc003]);

    expect(result.primary.some((f) => f.id === "TP-006")).toBe(true);
    expect(result.primary.some((f) => f.id === "SC-003")).toBe(false);
    expect(result.supporting.some((f) => f.id === "SC-003")).toBe(true);
  });

  test("SC-003 stays primary when capability sprawl has non-annotation issues", () => {
    const tp006 = makeFinding("TP-006", Severity.LOW, undefined, 0.7);
    const sc003 = makeFinding("SC-003", Severity.MEDIUM, undefined, 0.7);
    sc003.evidence = {
      issues: [
        "No tool annotations declared — server provides no safety metadata",
        "Large attack surface: 60 total capabilities",
      ],
    };

    const result = deduplicateFindings([tp006, sc003]);

    expect(result.primary.some((f) => f.id === "TP-006")).toBe(true);
    expect(result.primary.some((f) => f.id === "SC-003")).toBe(true);
  });
});

// ── Score impact ──────────────────────────────────────────────────────────────

describe("deduplicateFindings — score impact", () => {
  test("dedup reduces score penalty (fewer primary findings = higher securityScore)", () => {
    // 5 identical TP-005 findings on different tools
    const findings: Finding[] = [
      makeFinding("TP-005-a", Severity.HIGH, "tool_a"),
      makeFinding("TP-005-b", Severity.HIGH, "tool_b"),
      makeFinding("TP-005-c", Severity.HIGH, "tool_c"),
      makeFinding("TP-005-d", Severity.HIGH, "tool_d"),
      makeFinding("TP-005-e", Severity.HIGH, "tool_e"),
    ];

    const before = deduplicateFindings(findings);
    const beforeMod = makeModuleResult(before.primary);
    const scoreBefore = calculateScore([beforeMod]);

    // If we pretend no dedup happened (all 5 as separate findings)
    const noDedupMod = makeModuleResult(findings);
    const scoreNoDeDup = calculateScore([noDedupMod]);

    // After dedup there is 1 primary finding, before dedup there are 5
    // Score should be higher (less penalty) after dedup
    expect(scoreBefore.securityScore).toBeGreaterThanOrEqual(scoreNoDeDup.securityScore);
  });

  test("cross-module demotion does not increase total visible penalty beyond the dominant finding", () => {
    const passive = makeFinding("TP-005-exec_cmd", Severity.HIGH, "exec_cmd", 0.6);
    const active = makeFinding("AF-001-exec_cmd", Severity.CRITICAL, "exec_cmd", 0.95);
    const deduped = deduplicateFindings([passive, active]);

    // Only AF-001 should be primary
    expect(deduped.primary).toHaveLength(1);
    expect(deduped.primary[0].severity).toBe(Severity.CRITICAL);
  });
});
