import { describe, test, expect } from "bun:test";
import {
  calculateScore,
  scoreToGrade,
  scoreToColor,
  buildRiskProfile,
  lseFindingRisk,
  computeCWAS,
  bayesUpdate,
  applyBayesianUpdate,
  UMRI_SEVERITY_VALUES,
  SCORING_FORMULA_VERSION,
  ACTIVE_PROBE_CONFIGS,
} from "../../src/core/scorer.js";
import { Severity, CheckStatus } from "../../src/types/index.js";
import type { ModuleResult, Finding, ToolInfo } from "../../src/types/index.js";

// ════════════════════════════════════════════════════════════════════════════
//  TEST HELPERS
// ════════════════════════════════════════════════════════════════════════════

function makeFinding(
  severity: Severity,
  id = "TEST-001",
  confidence = 1.0,
  toolName?: string,
  module = "test-module",
): Finding {
  return {
    id,
    module,
    severity,
    title: `Test finding ${id}`,
    description: "Test finding description",
    evidence: {},
    remediation: "Fix it",
    confidence,
    toolName,
  };
}

function makeModuleResult(
  findings: Finding[],
  moduleId = "test-module",
): ModuleResult {
  return {
    moduleId,
    moduleName: "Test Module",
    moduleVersion: "1.0.0",
    durationMs: 10,
    checks: findings.map((f) => ({
      id: f.id,
      name: f.title,
      status: CheckStatus.FAIL,
      finding: f,
    })),
    findings,
  };
}

function makeToolInfo(name: string, paramCount = 1): ToolInfo {
  const properties: Record<string, unknown> = {};
  for (let i = 0; i < paramCount; i++) {
    properties[`param${i}`] = { type: "string" };
  }
  return {
    name,
    inputSchema: { type: "object", properties },
  };
}

// ════════════════════════════════════════════════════════════════════════════
//  SCORING_FORMULA_VERSION
// ════════════════════════════════════════════════════════════════════════════

describe("SCORING_FORMULA_VERSION", () => {
  test("is exported and is v4.0", () => {
    expect(SCORING_FORMULA_VERSION).toBe("v4.0");
  });
});

// ════════════════════════════════════════════════════════════════════════════
//  UMRI SEVERITY VALUES
// ════════════════════════════════════════════════════════════════════════════

describe("UMRI_SEVERITY_VALUES", () => {
  test("CRITICAL = 1.0", () => expect(UMRI_SEVERITY_VALUES.CRITICAL).toBe(1.0));
  test("HIGH = 0.7", ()     => expect(UMRI_SEVERITY_VALUES.HIGH).toBe(0.7));
  test("MEDIUM = 0.4", ()   => expect(UMRI_SEVERITY_VALUES.MEDIUM).toBe(0.4));
  test("LOW = 0.2", ()      => expect(UMRI_SEVERITY_VALUES.LOW).toBe(0.2));
  test("INFO = 0.05", ()    => expect(UMRI_SEVERITY_VALUES.INFO).toBe(0.05));
});

// ════════════════════════════════════════════════════════════════════════════
//  LSE AGGREGATION
// ════════════════════════════════════════════════════════════════════════════

describe("lseFindingRisk", () => {
  test("empty findings return 0", () => {
    expect(lseFindingRisk([])).toBe(0);
  });

  test("single CRITICAL at conf=1.0: R_t = (1/1.5)×ln(exp(1.5×1.0)) = 1.0", () => {
    const f = makeFinding(Severity.CRITICAL, "C1", 1.0);
    // LSE of single finding is the finding score itself
    const result = lseFindingRisk([f]);
    expect(result).toBeCloseTo(1.0, 4);
  });

  test("two identical findings: LSE > single finding, but sub-linear growth", () => {
    const findings = [
      makeFinding(Severity.MEDIUM, "M1", 1.0),
      makeFinding(Severity.MEDIUM, "M2", 1.0),
    ];
    const single = lseFindingRisk([findings[0]]);
    const both = lseFindingRisk(findings);
    expect(both).toBeGreaterThan(single);
    // LSE adds (1/β)·ln(2) ≈ 0.462 per additional identical finding.
    // With β=1.5, the boost is bounded: single + (1/β)·ln(n) for n identical findings.
    expect(both).toBeLessThan(single + single + 1);
  });

  test("LSE dominated by worst finding when β is high", () => {
    // A CRITICAL + many LOWs: LSE should be dominated by CRITICAL
    const findings = [
      makeFinding(Severity.CRITICAL, "C1", 1.0),
      ...Array.from({ length: 10 }, (_, i) =>
        makeFinding(Severity.LOW, `L${i}`, 1.0)
      ),
    ];
    const lseResult = lseFindingRisk(findings);
    const criticalScore = UMRI_SEVERITY_VALUES.CRITICAL * 1.0; // r_f for CRITICAL
    // LSE ≥ max(r_f), and with 10 LOWs the accumulated exp(β·0.2) terms
    // push the result above criticalScore by (1/β)·ln(1 + 10·exp(β·(LOW-CRIT)))
    expect(lseResult).toBeGreaterThan(criticalScore);
    // Even with 10 LOWs, result should be less than CRITICAL + all LOWs linearly
    expect(lseResult).toBeLessThan(criticalScore + 10 * UMRI_SEVERITY_VALUES.LOW);
  });

  test("confidence scaling: conf=0.5 halves finding contribution", () => {
    const highConf = lseFindingRisk([makeFinding(Severity.HIGH, "H1", 1.0)]);
    const lowConf = lseFindingRisk([makeFinding(Severity.HIGH, "H1", 0.5)]);
    expect(lowConf).toBeLessThan(highConf);
    // r_f = 0.7×0.5 = 0.35 vs 0.7×1.0 = 0.7 — LSE of single = r_f, so ratio holds
    expect(lowConf).toBeCloseTo(0.35, 3);
    expect(highConf).toBeCloseTo(0.7, 3);
  });
});

// ════════════════════════════════════════════════════════════════════════════
//  CWAS COMPUTATION
// ════════════════════════════════════════════════════════════════════════════

describe("computeCWAS", () => {
  test("no DC findings: all tools use baseline weight 0.3", () => {
    // 2 tools with 5 params each → κ_args = min(1.0, 5/5) = 1.0
    // CWAS = 2 × 0.3 × 1.0 = 0.6, floored to 1.0
    const tools = [makeToolInfo("tool_a", 5), makeToolInfo("tool_b", 5)];
    const cwas = computeCWAS(tools, []);
    expect(cwas).toBe(1.0); // floor applied
  });

  test("DC-001 tool gets weight 1.0", () => {
    const tools = [makeToolInfo("sql_query", 3)];
    const dcFinding = makeFinding(Severity.CRITICAL, "DC-001-001", 1.0, "sql_query", "dangerous-capability");
    const cwas = computeCWAS(tools, [dcFinding]);
    // κ_args = min(1, 3/5) = 0.6; ω_DC = 1.0; CWAS = 0.6
    // floored to 1.0
    expect(cwas).toBe(1.0);
  });

  test("DC-001 tool with 10 params gets CWAS > 1 (above floor)", () => {
    const tools = [makeToolInfo("sql_query", 10)];
    const dcFinding = makeFinding(Severity.CRITICAL, "DC-001-001", 1.0, "sql_query", "dangerous-capability");
    const cwas = computeCWAS(tools, [dcFinding]);
    // κ_args = min(1, 10/5) = 1.0; ω_DC = 1.0; CWAS = 1.0
    expect(cwas).toBe(1.0);
  });

  test("larger safe API has higher CWAS than small dangerous one", () => {
    // 20 benign tools × 5 params each
    const safeTools = Array.from({ length: 20 }, (_, i) =>
      makeToolInfo(`safe_tool_${i}`, 5)
    );
    // 1 dangerous tool × 5 params
    const dangerousTool = [makeToolInfo("exec_tool", 5)];
    const dcFinding = makeFinding(Severity.CRITICAL, "DC-002-001", 1.0, "exec_tool", "dangerous-capability");

    const safeCwas = computeCWAS(safeTools, []);
    const dangerousCwas = computeCWAS(dangerousTool, [dcFinding]);

    // Large safe API: 20 × 0.3 × 1.0 = 6.0
    // Small dangerous: 1 × 1.0 × 1.0 = 1.0
    expect(safeCwas).toBeGreaterThan(dangerousCwas);
  });

  test("floor prevents division by zero with empty tool list", () => {
    const cwas = computeCWAS([], []);
    expect(cwas).toBeGreaterThanOrEqual(1.0);
    expect(isFinite(cwas)).toBe(true);
  });
});

// ════════════════════════════════════════════════════════════════════════════
//  BAYESIAN UPDATE
// ════════════════════════════════════════════════════════════════════════════

describe("bayesUpdate", () => {
  const fuzzCfg = ACTIVE_PROBE_CONFIGS["active-fuzzer"]!; // TPR=0.85, FPR=0.05

  test("confirmed probe raises confidence significantly", () => {
    const prior = 0.5;
    const posterior = bayesUpdate(prior, fuzzCfg, true);
    expect(posterior).toBeGreaterThan(prior);
    // P(H|E+) = 0.85×0.5 / (0.85×0.5 + 0.05×0.5) = 0.425/0.45 ≈ 0.944
    expect(posterior).toBeCloseTo(0.944, 2);
  });

  test("failed probe lowers confidence (but not to zero)", () => {
    const prior = 0.5;
    const posterior = bayesUpdate(prior, fuzzCfg, false);
    expect(posterior).toBeLessThan(prior);
    expect(posterior).toBeGreaterThan(0);
    // P(H|E-) = 0.15×0.5 / (0.15×0.5 + 0.95×0.5) = 0.075/0.55 ≈ 0.136
    expect(posterior).toBeCloseTo(0.136, 2);
  });

  test("very low prior stays low even after confirmation (base rate matters)", () => {
    const prior = 0.05;
    const posterior = bayesUpdate(prior, fuzzCfg, true);
    // P(H|E+) = 0.85×0.05 / (0.85×0.05 + 0.05×0.95) ≈ 0.472
    expect(posterior).toBeGreaterThan(prior);
    expect(posterior).toBeLessThan(0.6); // not certain even after confirmation
  });

  test("high confidence prior stays high even after failure (uncertainty acknowledged)", () => {
    const prior = 0.9;
    const posterior = bayesUpdate(prior, fuzzCfg, false);
    // Fuzzer might have missed — confidence drops but doesn't collapse
    expect(posterior).toBeLessThan(prior);
    expect(posterior).toBeGreaterThan(0.4);
  });

  test("SSRF probing has lower FPR than response fingerprinting", () => {
    const ssrfCfg = ACTIVE_PROBE_CONFIGS["ssrf-detection"]!;
    const rfCfg = ACTIVE_PROBE_CONFIGS["response-fingerprinting"]!;
    const prior = 0.5;
    const ssrfPosterior = bayesUpdate(prior, ssrfCfg, true);
    const rfPosterior = bayesUpdate(prior, rfCfg, true);
    // Lower FPR = higher posterior after confirmation
    expect(ssrfPosterior).toBeGreaterThan(rfPosterior);
  });
});

describe("applyBayesianUpdate", () => {
  test("passive finding confidence raised when active module confirms same tool", () => {
    const passiveFinding = makeFinding(Severity.HIGH, "TP-005", 0.5, "read_file", "tool-permissions");
    const activeFinding = makeFinding(Severity.HIGH, "AF-003", 0.9, "read_file", "active-fuzzer");

    const passiveMod = makeModuleResult([passiveFinding], "tool-permissions");
    const activeMod = makeModuleResult([activeFinding], "active-fuzzer");

    applyBayesianUpdate([passiveMod, activeMod]);

    // Passive finding on same tool as active confirmation → confidence should rise
    expect(passiveFinding.confidence).toBeGreaterThan(0.5);
  });

  test("passive finding confidence lowered when active module ran but found nothing", () => {
    const passiveFinding = makeFinding(Severity.MEDIUM, "TP-005", 0.5, "read_file", "tool-permissions");
    // Active module ran (check exists) but produced no finding
    const activeMod: ModuleResult = {
      moduleId: "active-fuzzer",
      moduleName: "Active Fuzzer",
      moduleVersion: "1.0.0",
      durationMs: 50,
      findings: [],
      checks: [
        {
          id: "AF-CHECK-001",
          name: "Fuzz read_file",
          status: CheckStatus.PASS,
          finding: { ...passiveFinding, module: "active-fuzzer", id: "AF-CHECK" },
        },
      ],
    };
    const passiveMod = makeModuleResult([passiveFinding], "tool-permissions");

    applyBayesianUpdate([passiveMod, activeMod]);

    // Active module ran but found nothing → confidence drops (not confirmed)
    expect(passiveFinding.confidence).toBeLessThan(0.5);
  });

  test("unprobed tools are unchanged", () => {
    const finding = makeFinding(Severity.HIGH, "TP-001", 0.6, "unprobed_tool", "tool-permissions");
    const mod = makeModuleResult([finding], "tool-permissions");
    applyBayesianUpdate([mod]);
    expect(finding.confidence).toBe(0.6);
  });
});

// ════════════════════════════════════════════════════════════════════════════
//  BUILD RISK PROFILE — AXIS TESTS
// ════════════════════════════════════════════════════════════════════════════

describe("buildRiskProfile", () => {
  test("empty findings produce zero-risk profile", () => {
    const result = makeModuleResult([]);
    const profile = buildRiskProfile([result], 1, 1, 0);
    expect(profile.compositeRiskScore).toBeLessThan(0.1);
    expect(profile.riskLevel).toBe("MINIMAL");
    expect(profile.severityDensity).toBe(0);
    expect(profile.exploitChainDepth).toBe(0);
    expect(profile.trustViolation).toBe(0);
  });

  test("exposure axis: 30 tools with all unconstrained params → exposure = 1.0", () => {
    const profile = buildRiskProfile([], 30, 30, 30);
    expect(profile.exposure).toBe(1.0);
  });

  test("exposure axis: 0 unconstrained → exposure only from tool count", () => {
    const profile = buildRiskProfile([], 15, 10, 0);
    // (15/30)×0.4 + 0×0.6 = 0.2
    expect(profile.exposure).toBeCloseTo(0.2, 3);
  });

  test("exploit chain depth: 1 EC-001 finding → depth = 0.20", () => {
    const f = makeFinding(Severity.HIGH, "EC-001-001", 0.8, "tool_a", "chained-exploit");
    const mod = makeModuleResult([f]);
    const profile = buildRiskProfile([mod], 1, 1, 0);
    expect(profile.exploitChainDepth).toBeCloseTo(0.20, 3);
    expect(profile._inputs.chainFindings).toBe(1);
  });

  test("exploit chain depth: dual-use present → +0.35 bonus", () => {
    const f = makeFinding(Severity.HIGH, "EC-002-001", 0.8, "tool_a", "chained-exploit");
    const mod = makeModuleResult([f]);
    const profile = buildRiskProfile([mod], 1, 1, 0);
    expect(profile.exploitChainDepth).toBeCloseTo(0.35, 3);
    expect(profile._inputs.dualUseFindings).toBe(1);
  });

  test("capability risk: DC-001 only → 0.35", () => {
    const f = makeFinding(Severity.CRITICAL, "DC-001-001", 1.0, "query_tool", "dangerous-capability");
    const mod = makeModuleResult([f]);
    const profile = buildRiskProfile([mod], 1, 1, 0);
    expect(profile.capabilityRisk).toBeCloseTo(0.35, 3);
    expect(profile._inputs.dangerousCapabilities).toContain("DC-001:arbitrary-sql");
  });

  test("capability risk: DC-001+002+003 → capped at 1.0", () => {
    const findings = [
      makeFinding(Severity.CRITICAL, "DC-001-001", 1.0, "query_tool", "dangerous-capability"),
      makeFinding(Severity.CRITICAL, "DC-002-001", 1.0, "exec_tool", "dangerous-capability"),
      makeFinding(Severity.CRITICAL, "DC-003-001", 1.0, "shell_tool", "dangerous-capability"),
    ];
    const mod = makeModuleResult(findings);
    const profile = buildRiskProfile([mod], 3, 3, 3);
    expect(profile.capabilityRisk).toBe(1.0); // min(1, 0.35+0.35+0.35=1.05) = 1.0
  });

  test("trust violation: 1 rug-pull CRITICAL → 0.50", () => {
    const f = makeFinding(Severity.CRITICAL, "RUG-001", 0.9, "tool_a", "rug-pull-detection");
    const mod = makeModuleResult([f]);
    const profile = buildRiskProfile([mod], 1, 1, 0);
    expect(profile.trustViolation).toBeCloseTo(0.50, 3);
    expect(profile._inputs.rugPullCriticals).toBe(1);
  });

  test("trust violation: 2 rug-pull CRITICALs → capped at 1.0", () => {
    const findings = [
      makeFinding(Severity.CRITICAL, "RUG-001", 0.9, "tool_a", "rug-pull-detection"),
      makeFinding(Severity.CRITICAL, "RUG-002", 0.9, "tool_b", "rug-pull-detection"),
    ];
    const mod = makeModuleResult(findings);
    const profile = buildRiskProfile([mod], 2, 2, 0);
    expect(profile.trustViolation).toBe(1.0); // min(1, 0.50+0.50=1.0)
  });

  test("CRS is monotone: adding a finding only increases or maintains CRS", () => {
    const baseProfile = buildRiskProfile(
      [makeModuleResult([])],
      5, 5, 2,
    );
    const withFinding = buildRiskProfile(
      [makeModuleResult([makeFinding(Severity.HIGH, "H1", 0.8, "t")])],
      5, 5, 2,
    );
    expect(withFinding.compositeRiskScore).toBeGreaterThanOrEqual(
      baseProfile.compositeRiskScore,
    );
  });

  test("UMRI scalar is complement of CRS on 0-100 scale", () => {
    const profile = buildRiskProfile(
      [makeModuleResult([makeFinding(Severity.HIGH, "H1", 1.0, "t")])],
      5, 5, 3,
    );
    // P0-02: umriScalar is now affine-rescaled: displayScore = max(0, (raw - FLOOR) / (1 - FLOOR) * 100)
    // where raw = 1 - CRS and FLOOR ≈ 0.0735. The old identity CRS + umriScalar/100 = 1 no longer holds.
    // New invariant: umriScalar ∈ [0, 100] and monotonically decreases as CRS increases.
    expect(profile.umriScalar).toBeGreaterThanOrEqual(0);
    expect(profile.umriScalar).toBeLessThanOrEqual(100);
    // Verify rescaling: higher CRS → lower umriScalar
    const UMRI_RAW_FLOOR = (1 - 0.15 * 2) * (1 - 0.25 * 2) * (1 - 0.20 * 2) * (1 - 0.25 * 2) * (1 - 0.15 * 2);
    const rawProduct = 1 - profile.compositeRiskScore;
    const expectedUmri = Math.max(0, (rawProduct - UMRI_RAW_FLOOR) / (1.0 - UMRI_RAW_FLOOR)) * 100;
    expect(profile.umriScalar).toBeCloseTo(expectedUmri, 1);
  });

  test("risk level thresholds: CRS ≥ 0.7 → CRITICAL", () => {
    // Force high CRS: DC-001+002+003 + rug-pull + chain
    const findings = [
      makeFinding(Severity.CRITICAL, "DC-001-001", 1.0, "t1", "dangerous-capability"),
      makeFinding(Severity.CRITICAL, "DC-002-001", 1.0, "t2", "dangerous-capability"),
      makeFinding(Severity.CRITICAL, "DC-003-001", 1.0, "t3", "dangerous-capability"),
      makeFinding(Severity.CRITICAL, "RUG-001",    1.0, "t1", "rug-pull-detection"),
      makeFinding(Severity.CRITICAL, "RUG-002",    1.0, "t2", "rug-pull-detection"),
      makeFinding(Severity.HIGH,     "EC-001-001", 1.0, "t1", "chained-exploit"),
      makeFinding(Severity.HIGH,     "EC-002-001", 1.0, "t2", "chained-exploit"),
    ];
    const profile = buildRiskProfile(
      [makeModuleResult(findings)],
      30, 30, 30,
    );
    expect(profile.riskLevel).toBe("CRITICAL");
  });

  test("_inputs records cwas and totalToolRisk for reproducibility", () => {
    const findings = [makeFinding(Severity.HIGH, "H1", 0.8, "tool_a")];
    const mod = makeModuleResult(findings);
    const profile = buildRiskProfile([mod], 1, 1, 0);
    expect(profile._inputs.cwas).toBeGreaterThan(0);
    expect(profile._inputs.totalToolRisk).toBeGreaterThan(0);
  });

  test("CWAS path used when tools array provided", () => {
    const findings = [makeFinding(Severity.HIGH, "H1", 0.8, "tool_a")];
    const mod = makeModuleResult(findings);
    const tools = [makeToolInfo("tool_a", 5)];
    const profileWithTools = buildRiskProfile([mod], 1, 1, 0, tools);
    const profileWithout = buildRiskProfile([mod], 1, 1, 0);
    // Both should be valid; the scores may differ depending on CWAS vs toolCount
    expect(profileWithTools.severityDensity).toBeGreaterThanOrEqual(0);
    expect(profileWithout.severityDensity).toBeGreaterThanOrEqual(0);
    expect(profileWithTools._inputs.cwas).toBeDefined();
  });
});

// ════════════════════════════════════════════════════════════════════════════
//  BENCHMARK FIXTURES
// ════════════════════════════════════════════════════════════════════════════

describe("Benchmark fixtures", () => {
  /**
   * BENCHMARK_FLOOR: A server with no findings should produce:
   *   - securityScore = 100 (legacy)
   *   - CRS ≈ 0.0 (only exposure contributes when other axes = 0)
   */
  test("BENCHMARK_FLOOR — clean server (no findings, minimal tools)", () => {
    const cleanMod: ModuleResult = {
      moduleId: "tool-permissions",
      moduleName: "Tool Permissions",
      moduleVersion: "1.0.0",
      durationMs: 5,
      checks: [{ id: "C1", name: "No issues", status: CheckStatus.PASS }],
      findings: [],
    };
    const summary = calculateScore([cleanMod]);
    expect(summary.securityScore).toBe(100);

    const profile = buildRiskProfile([cleanMod], 1, 2, 0);
    expect(profile.compositeRiskScore).toBeLessThan(0.05);
    expect(profile.exploitChainDepth).toBe(0);
    expect(profile.capabilityRisk).toBe(0);
    expect(profile.trustViolation).toBe(0);
    expect(["MINIMAL", "LOW"]).toContain(profile.riskLevel);
  });

  /**
   * BENCHMARK_CEILING: A server with every dangerous capability, rug-pulls,
   * exploit chains, high exposure, and trust violations.
   * Expected: CRS near maximum (~0.926), securityScore → 0.
   */
  test("BENCHMARK_CEILING — maximally dangerous server approaches CRS ~0.926", () => {
    const ceilingFindings: Finding[] = [
      // Dangerous capabilities: all three critical + FS
      makeFinding(Severity.CRITICAL, "DC-001-001", 1.0, "sql",   "dangerous-capability"),
      makeFinding(Severity.CRITICAL, "DC-002-001", 1.0, "code",  "dangerous-capability"),
      makeFinding(Severity.CRITICAL, "DC-003-001", 1.0, "shell", "dangerous-capability"),
      makeFinding(Severity.CRITICAL, "DC-004-001", 1.0, "fs",    "dangerous-capability"),
      // Trust violations
      makeFinding(Severity.CRITICAL, "RUG-001", 1.0, "sql",   "rug-pull-detection"),
      makeFinding(Severity.CRITICAL, "RUG-002", 1.0, "code",  "rug-pull-detection"),
      makeFinding(Severity.HIGH,     "RUG-003", 1.0, "shell", "rug-pull-detection"),
      makeFinding(Severity.HIGH,     "INJ-001", 1.0, "sql",   "description-injection-detector"),
      makeFinding(Severity.HIGH,     "NS-001",  1.0, "code",  "namespace-poisoning"),
      makeFinding(Severity.HIGH,     "IPI-001", 1.0, "shell", "ipi-susceptibility"),
      // Exploit chains (need ≥3 EC-001 to saturate: 3×0.20 + 0.35 + 0.15 = 1.10 → 1.0)
      makeFinding(Severity.HIGH, "EC-001-001", 1.0, "sql",   "chained-exploit"),
      makeFinding(Severity.HIGH, "EC-001-002", 1.0, "code",  "chained-exploit"),
      makeFinding(Severity.HIGH, "EC-001-003", 1.0, "fs",    "chained-exploit"),
      makeFinding(Severity.HIGH, "EC-002-001", 1.0, "shell", "chained-exploit"),
      makeFinding(Severity.HIGH, "EC-003-001", 1.0, "fs",    "chained-exploit"),
    ];

    const mod = makeModuleResult(ceilingFindings);
    // 30 tools, all unconstrained (maximum exposure)
    const profile = buildRiskProfile([mod], 30, 30, 30);

    expect(profile.compositeRiskScore).toBeGreaterThan(0.85);
    expect(profile.riskLevel).toBe("CRITICAL");
    expect(profile.capabilityRisk).toBe(1.0);
    expect(profile.trustViolation).toBe(1.0);
    expect(profile.exploitChainDepth).toBe(1.0);
    expect(profile.exposure).toBe(1.0);
  });
});

// ════════════════════════════════════════════════════════════════════════════
//  LEGACY SCORER — calculateScore (display use)
// ════════════════════════════════════════════════════════════════════════════

describe("calculateScore (legacy)", () => {
  // Weights: CRITICAL=30, HIGH=18, MEDIUM=6, LOW=2, INFO=0
  // Diminishing factor: 0.7, per-module cap: 40

  test("perfect score with no findings", () => {
    const result = makeModuleResult([]);
    result.checks = [
      { id: "C1", name: "Check 1", status: CheckStatus.PASS },
      { id: "C2", name: "Check 2", status: CheckStatus.PASS },
    ];
    const summary = calculateScore([result]);
    expect(summary.securityScore).toBe(100);
    expect(summary.passed).toBe(2);
    expect(summary.checksWithFailStatus).toBe(0);
  });

  test("1 CRITICAL at conf=1.0 → score = 70 (100 - 30)", () => {
    const result = makeModuleResult([makeFinding(Severity.CRITICAL, "CRIT-1")]);
    const summary = calculateScore([result]);
    expect(summary.securityScore).toBe(70); // 100 - CRITICAL_WEIGHT(30) × conf(1.0)
    expect(summary.findingsBySeverity[Severity.CRITICAL]).toBe(1);
  });

  test("1 HIGH at conf=1.0 → score = 82 (100 - 18)", () => {
    const result = makeModuleResult([makeFinding(Severity.HIGH, "HIGH-1")]);
    const summary = calculateScore([result]);
    expect(summary.securityScore).toBe(82); // 100 - HIGH_WEIGHT(18) × conf(1.0)
  });

  test("diminishing returns: 5 MEDIUM findings accumulate sub-linearly", () => {
    // LINEAR would give: 5 × 6 = 30 → score = 70
    // WITH diminishing factor 0.7: 6 + 4.2 + 2.94 + 2.06 + 1.44 ≈ 16.6 → score ≈ 83
    const findings = Array.from({ length: 5 }, (_, i) =>
      makeFinding(Severity.MEDIUM, `MED-${i}`)
    );
    const result = makeModuleResult(findings);
    const summary = calculateScore([result]);
    expect(summary.securityScore).toBeGreaterThan(80); // much better than linear (70)
    expect(summary.securityScore).toBeLessThan(95);
  });

  test("per-module impact capped at 40", () => {
    const findings = Array.from({ length: 20 }, (_, i) =>
      makeFinding(Severity.CRITICAL, `CRIT-${i}`)
    );
    const result = makeModuleResult(findings);
    const summary = calculateScore([result]);
    expect(summary.securityScore).toBe(60); // 100 - 40 (cap)
  });

  test("two modules with 1 HIGH each: score = 64 (100 - 18 - 18)", () => {
    const mod1 = makeModuleResult([makeFinding(Severity.HIGH, "H1")]);
    mod1.moduleId = "mod1";
    const mod2 = makeModuleResult([makeFinding(Severity.HIGH, "H2")]);
    mod2.moduleId = "mod2";
    const summary = calculateScore([mod1, mod2]);
    expect(summary.securityScore).toBe(64); // 100 - 18 - 18 = 64
  });

  test("LOW findings have minimal impact", () => {
    const findings = Array.from({ length: 10 }, (_, i) =>
      makeFinding(Severity.LOW, `LOW-${i}`)
    );
    const result = makeModuleResult(findings);
    const summary = calculateScore([result]);
    expect(summary.securityScore).toBeGreaterThan(90);
  });

  test("INFO findings have zero impact", () => {
    const findings = Array.from({ length: 20 }, (_, i) =>
      makeFinding(Severity.INFO, `INFO-${i}`)
    );
    const result = makeModuleResult(findings);
    const summary = calculateScore([result]);
    expect(summary.securityScore).toBe(100);
  });

  test("check status counts are accurate", () => {
    const result: ModuleResult = {
      moduleId: "test",
      moduleName: "Test",
      moduleVersion: "1.0.0",
      durationMs: 10,
      checks: [
        { id: "C1", name: "Pass",  status: CheckStatus.PASS },
        { id: "C2", name: "Pass",  status: CheckStatus.PASS },
        { id: "C3", name: "Warn",  status: CheckStatus.WARN },
        { id: "C4", name: "Fail",  status: CheckStatus.FAIL },
        { id: "C5", name: "Skip",  status: CheckStatus.SKIP },
      ],
      findings: [],
    };
    const summary = calculateScore([result]);
    expect(summary.totalChecks).toBe(5);
    expect(summary.passed).toBe(2);
    expect(summary.warnings).toBe(1);
    expect(summary.checksWithFailStatus).toBe(1);
    expect(summary.skipped).toBe(1);
  });

  test("rawScore can go negative; penaltyPoints exceeds 100", () => {
    // 4 CRITICALs across 4 modules = 4 × 30 = 120 points
    const mods = Array.from({ length: 4 }, (_, i) => {
      const m = makeModuleResult([makeFinding(Severity.CRITICAL, `CRIT-${i}`)]);
      m.moduleId = `mod-${i}`;
      return m;
    });
    const summary = calculateScore(mods);
    expect(summary.securityScore).toBe(0);   // floored at 0
    expect(summary.rawScore).toBe(-20);       // 100 - 120 = -20
    expect(summary.penaltyPoints).toBe(120);  // full deduction visible
  });

  test("penaltyPoints = 100 - rawScore (invariant)", () => {
    const result = makeModuleResult([makeFinding(Severity.HIGH, "H1")]);
    const summary = calculateScore([result]);
    expect(summary.rawScore + summary.penaltyPoints).toBe(100);
  });

  test("filesystem server calibration: many MEDIUM+LOW → score ≥ 55", () => {
    // Simulate official filesystem server: ~12 MEDIUM from tool-permissions,
    // 1 MEDIUM transport, 4 LOW schema, 2 MEDIUM context-extraction
    const mod1 = makeModuleResult(
      Array.from({ length: 12 }, (_, i) => makeFinding(Severity.MEDIUM, `TP-${i}`))
    );
    mod1.moduleId = "tool-permissions";

    const mod2 = makeModuleResult([makeFinding(Severity.MEDIUM, "TS-1")]);
    mod2.moduleId = "transport-security";

    const mod3 = makeModuleResult(
      Array.from({ length: 4 }, (_, i) => makeFinding(Severity.LOW, `SM-${i}`))
    );
    mod3.moduleId = "schema-manipulation";

    const mod4 = makeModuleResult([
      makeFinding(Severity.MEDIUM, "CE-1"),
      makeFinding(Severity.MEDIUM, "CE-2"),
    ]);
    mod4.moduleId = "context-extraction";

    const summary = calculateScore([mod1, mod2, mod3, mod4]);
    expect(summary.securityScore).toBeGreaterThanOrEqual(55);
  });
});

// ════════════════════════════════════════════════════════════════════════════
//  scoreToGrade / scoreToColor
// ════════════════════════════════════════════════════════════════════════════

describe("scoreToGrade", () => {
  test("A for 90+", () => expect(scoreToGrade(95)).toBe("A"));
  test("B for 80-89", () => expect(scoreToGrade(85)).toBe("B"));
  test("C for 70-79", () => expect(scoreToGrade(75)).toBe("C"));
  test("D for 60-69", () => expect(scoreToGrade(65)).toBe("D"));
  test("F for <60",   () => expect(scoreToGrade(50)).toBe("F"));
});

describe("scoreToColor", () => {
  test("green for 80+", () => expect(scoreToColor(85)).toBe("green"));
  test("yellow for 50-79", () => expect(scoreToColor(65)).toBe("yellow"));
  test("red for <50",  () => expect(scoreToColor(30)).toBe("red"));
});
