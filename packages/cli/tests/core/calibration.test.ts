import { describe, test, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ModuleRunner } from "../../src/core/module-runner.js";
import { calculateScore, buildRiskProfile } from "../../src/core/scorer.js";
import { assignConfidence } from "../../src/core/confidence.js";
import { deduplicateFindings } from "../../src/core/deduplicator.js";
import type { ServerCapabilities, ModuleResult, AuditModule } from "../../src/types/index.js";

// ── Import ALL passive modules (must match scan.ts getAvailableModules) ─────
import { ToolPermissionsModule } from "../../src/modules/tool-permissions.js";
import { TransportSecurityModule } from "../../src/modules/transport-security.js";
import { SchemaManipulationModule } from "../../src/modules/schema-manipulation.js";
import { ContextExtractionModule } from "../../src/modules/context-extraction.js";
import { SecretLeakDetectionModule } from "../../src/modules/secret-leak-detection.js";
import { ResourcePromptAuditModule } from "../../src/modules/resource-prompt-audit.js";
import { SupplyChainAnalysisModule } from "../../src/modules/supply-chain-analysis.js";
import { RugPullDetectionModule } from "../../src/modules/rug-pull-detection.js";
import { ExfiltrationChainModule } from "../../src/modules/exfiltration-chain.js";
import { NamespacePoisoningModule } from "../../src/modules/namespace-poisoning.js";
import { TokenExhaustionModule } from "../../src/modules/token-exhaustion.js";
import { AgenticLoopTrapModule } from "../../src/modules/agentic-loop-trap.js";
import { OutputInjectionModule } from "../../src/modules/output-injection.js";
import { ToolCapabilityGraphModule } from "../../src/modules/capability-graph.js";
import { DangerousCapabilityModule } from "../../src/modules/dangerous-capability.js";
import { DescriptionInjectionDetectorModule } from "../../src/modules/description-injection-detector.js";
import { IpiSusceptibilityModule } from "../../src/modules/ipi-susceptibility.js";
import { HandshakeFuzzerModule } from "../../src/modules/handshake-fuzzer.js";
import { McpAppsAuditModule } from "../../src/modules/mcp-apps-audit.js";
import { DiscoveryScannerModule } from "../../src/modules/discovery-scanner.js";
import { EuAiActModule } from "../../src/modules/eu-ai-act.js";
import { AgentOutputTrustModule } from "../../src/modules/agent-output-trust.js";

// ════════════════════════════════════════════════════════════════════════════
//  ANCHOR FIXTURE LOADER
// ════════════════════════════════════════════════════════════════════════════

interface AnchorFixture {
  _meta: {
    anchor: string;
    version: string;
    description: string;
  };
  capabilities: ServerCapabilities;
  expected: Record<string, unknown>;
}

function loadAnchor(name: string): AnchorFixture {
  const filePath = join(import.meta.dir, "../fixtures/anchors", `${name}.json`);
  return JSON.parse(readFileSync(filePath, "utf-8"));
}

/**
 * Get all passive modules — mirrors scan.ts getAvailableModules() passive list.
 * Active modules are excluded because anchor fixtures are static capability
 * bundles (no live server to probe).
 */
function getPassiveModules(): AuditModule[] {
  return [
    new ToolPermissionsModule(),
    new TransportSecurityModule(),
    new SchemaManipulationModule(),
    new ContextExtractionModule(),
    new SecretLeakDetectionModule(),
    new ResourcePromptAuditModule(),
    new SupplyChainAnalysisModule(),
    new RugPullDetectionModule(),
    new ExfiltrationChainModule(),
    new NamespacePoisoningModule(),
    new TokenExhaustionModule(),
    new AgenticLoopTrapModule(),
    new OutputInjectionModule(),
    new ToolCapabilityGraphModule(),
    new DangerousCapabilityModule(),
    new DescriptionInjectionDetectorModule(),
    new IpiSusceptibilityModule(),
    new HandshakeFuzzerModule(),
    new McpAppsAuditModule(),
    new DiscoveryScannerModule(),
    new EuAiActModule(),
    new AgentOutputTrustModule(),              // H-4: was missing — must match scan.ts
  ];
}

/**
 * Run the full passive pipeline against a fixture's capabilities.
 * Returns moduleResults, deduplicated findings, score summary, and risk profile.
 */
async function runPipeline(capabilities: ServerCapabilities) {
  const modules = getPassiveModules();
  const runner = new ModuleRunner();

  const moduleResults = await runner.run({
    capabilities,
    modules,
    activeMode: false,
    verbose: false,
  });

  // Pipeline: confidence → dedup → score → risk profile
  assignConfidence(moduleResults);

  const allFindings = moduleResults.flatMap((r) => r.findings);
  const dedupResult = deduplicateFindings(allFindings);
  const summary = calculateScore(moduleResults);

  // Compute risk profile inputs
  const tools = capabilities.tools ?? [];
  let totalParams = 0;
  let unconstrainedParams = 0;
  for (const tool of tools) {
    const props = (tool.inputSchema?.properties ?? {}) as Record<string, any>;
    for (const [, schema] of Object.entries(props)) {
      totalParams++;
      if (!schema?.enum && !schema?.pattern && (!schema?.maxLength || schema.maxLength > 500)) {
        unconstrainedParams++;
      }
    }
  }
  const riskProfile = buildRiskProfile(
    moduleResults,
    tools.length,
    totalParams,
    unconstrainedParams,
    tools,
  );

  return { moduleResults, dedupResult, summary, riskProfile, allFindings };
}

// ════════════════════════════════════════════════════════════════════════════
//  ANCHOR: BENCHMARK_FLOOR (score floor = most dangerous = lowest score)
// ════════════════════════════════════════════════════════════════════════════

describe("Calibration Anchor: BENCHMARK_FLOOR (score floor — dangerous server)", () => {
  const fixture = loadAnchor("anchor-floor");

  test("fixture loads with 30 tools", () => {
    expect(fixture.capabilities.tools.length).toBe(30);
    expect(fixture._meta.anchor).toBe("BENCHMARK_FLOOR");
  });

  test("CRS > 0.85 (near-maximum risk)", async () => {
    const { riskProfile } = await runPipeline(fixture.capabilities);
    expect(riskProfile.compositeRiskScore).toBeGreaterThan(fixture.expected.crsMin as number);
  });

  test("risk level is CRITICAL", async () => {
    const { riskProfile } = await runPipeline(fixture.capabilities);
    const allowed = fixture.expected.riskLevel as string[];
    expect(allowed).toContain(riskProfile.riskLevel);
  });

  test("capability risk = 1.0 (all dangerous capabilities present)", async () => {
    const { riskProfile } = await runPipeline(fixture.capabilities);
    expect(riskProfile.capabilityRisk).toBe(fixture.expected.capabilityRisk as number);
  });

  test("trust violation >= 0.5 (rug-pull annotations present)", async () => {
    const { riskProfile } = await runPipeline(fixture.capabilities);
    expect(riskProfile.trustViolation).toBeGreaterThanOrEqual(
      fixture.expected.trustViolationMin as number,
    );
  });

  test("exploit chain depth >= 0.2", async () => {
    const { riskProfile } = await runPipeline(fixture.capabilities);
    expect(riskProfile.exploitChainDepth).toBeGreaterThanOrEqual(
      fixture.expected.exploitChainDepthMin as number,
    );
  });

  test("produces >= 15 findings", async () => {
    const { allFindings } = await runPipeline(fixture.capabilities);
    expect(allFindings.length).toBeGreaterThanOrEqual(fixture.expected.minFindingCount as number);
  });

  test("required finding prefixes are present", async () => {
    const { allFindings } = await runPipeline(fixture.capabilities);
    const required = fixture.expected.requiredFindingPrefixes as string[];
    for (const prefix of required) {
      const found = allFindings.some((f) => f.id.startsWith(prefix));
      if (!found) {
        throw new Error(
          `FLOOR fixture missing required finding prefix "${prefix}". ` +
          `Found: ${[...new Set(allFindings.map((f) => f.id.split("-").slice(0, 2).join("-")))].join(", ")}`,
        );
      }
    }
  });
});

// ════════════════════════════════════════════════════════════════════════════
//  ANCHOR: BENCHMARK_CEILING (score ceiling = cleanest = highest score)
// ════════════════════════════════════════════════════════════════════════════

describe("Calibration Anchor: BENCHMARK_CEILING (score ceiling — clean server)", () => {
  const fixture = loadAnchor("anchor-ceiling");

  test("fixture loads and has 3 clean tools", () => {
    expect(fixture.capabilities.tools.length).toBe(3);
    expect(fixture._meta.anchor).toBe("BENCHMARK_CEILING");
  });

  test("pipeline produces score = 100", async () => {
    const { summary } = await runPipeline(fixture.capabilities);
    expect(summary.securityScore).toBe(fixture.expected.securityScore as number);
  });

  test("CRS < 0.05 (near-zero risk)", async () => {
    const { riskProfile } = await runPipeline(fixture.capabilities);
    expect(riskProfile.compositeRiskScore).toBeLessThan(fixture.expected.crsMax as number);
  });

  test("risk level is MINIMAL", async () => {
    const { riskProfile } = await runPipeline(fixture.capabilities);
    const allowed = fixture.expected.riskLevel as string[];
    expect(allowed).toContain(riskProfile.riskLevel);
  });

  test("zero capability risk, trust violation, and exploit chain depth", async () => {
    const { riskProfile } = await runPipeline(fixture.capabilities);
    expect(riskProfile.capabilityRisk).toBe(0);
    expect(riskProfile.trustViolation).toBe(0);
    expect(riskProfile.exploitChainDepth).toBe(0);
  });

  test("zero findings (no false positives)", async () => {
    const { allFindings } = await runPipeline(fixture.capabilities);
    // Filter out INFO-level EU AI Act findings which are advisory, not security issues
    const securityFindings = allFindings.filter(
      (f) => f.severity !== "INFO" && !f.id.startsWith("EUAI-"),
    );
    if (securityFindings.length > 0) {
      const ids = securityFindings.map((f) => `${f.id} (${f.severity})`);
      throw new Error(
        `CEILING fixture produced ${securityFindings.length} unexpected security finding(s): ${ids.join(", ")}. ` +
        "This indicates false positives in the detection pipeline.",
      );
    }
  });

  test("no forbidden finding prefixes appear", async () => {
    const { allFindings } = await runPipeline(fixture.capabilities);
    const forbidden = fixture.expected.forbiddenFindingPrefixes as string[];
    for (const f of allFindings) {
      for (const prefix of forbidden) {
        expect(f.id.startsWith(prefix)).toBe(false);
      }
    }
  });

  test("CRS monotonicity: adding a finding to ceiling only increases CRS", async () => {
    const { riskProfile: ceilingProfile } = await runPipeline(fixture.capabilities);
    // Manually add a tool that will trigger DC-001
    const augmented = {
      ...fixture.capabilities,
      tools: [
        ...fixture.capabilities.tools,
        {
          name: "execute_sql",
          description: "Execute arbitrary SQL queries",
          inputSchema: { type: "object", properties: { query: { type: "string" } } },
        },
      ],
    };
    const { riskProfile: augProfile } = await runPipeline(augmented);
    expect(augProfile.compositeRiskScore).toBeGreaterThan(ceilingProfile.compositeRiskScore);
  });
});

// ════════════════════════════════════════════════════════════════════════════
//  ANCHOR: BENCHMARK_MIDPOINT
// ════════════════════════════════════════════════════════════════════════════

describe("Calibration Anchor: BENCHMARK_MIDPOINT", () => {
  const fixture = loadAnchor("anchor-midpoint");

  test("fixture loads with 8 tools", () => {
    expect(fixture.capabilities.tools.length).toBe(8);
    expect(fixture._meta.anchor).toBe("BENCHMARK_MIDPOINT");
  });

  test("CRS within expected range [0.25, 0.60]", async () => {
    const { riskProfile } = await runPipeline(fixture.capabilities);
    const [lo, hi] = fixture.expected.crsRange as [number, number];
    expect(riskProfile.compositeRiskScore).toBeGreaterThanOrEqual(lo);
    expect(riskProfile.compositeRiskScore).toBeLessThanOrEqual(hi);
  });

  test("securityScore within expected range [40, 75]", async () => {
    const { summary } = await runPipeline(fixture.capabilities);
    const [lo, hi] = fixture.expected.securityScoreRange as [number, number];
    expect(summary.securityScore).toBeGreaterThanOrEqual(lo);
    expect(summary.securityScore).toBeLessThanOrEqual(hi);
  });

  test("risk level is MEDIUM or HIGH", async () => {
    const { riskProfile } = await runPipeline(fixture.capabilities);
    const allowed = fixture.expected.riskLevel as string[];
    expect(allowed).toContain(riskProfile.riskLevel);
  });

  test("has at least moderate capability risk", async () => {
    const { riskProfile } = await runPipeline(fixture.capabilities);
    expect(riskProfile.capabilityRisk).toBeGreaterThanOrEqual(
      fixture.expected.capabilityRiskMin as number,
    );
  });

  test("finding count within expected bounds", async () => {
    const { allFindings } = await runPipeline(fixture.capabilities);
    expect(allFindings.length).toBeGreaterThanOrEqual(fixture.expected.minFindingCount as number);
    expect(allFindings.length).toBeLessThanOrEqual(fixture.expected.maxFindingCount as number);
  });

  test("required finding prefixes are present", async () => {
    const { allFindings } = await runPipeline(fixture.capabilities);
    const required = fixture.expected.requiredFindingPrefixes as string[];
    for (const prefix of required) {
      const found = allFindings.some((f) => f.id.startsWith(prefix));
      if (!found) {
        throw new Error(
          `MIDPOINT fixture missing required finding prefix "${prefix}". ` +
          `Found: ${[...new Set(allFindings.map((f) => f.id.split("-").slice(0, 2).join("-")))].join(", ")}`,
        );
      }
    }
  });
});

// ════════════════════════════════════════════════════════════════════════════
//  CROSS-ANCHOR INVARIANTS
// ════════════════════════════════════════════════════════════════════════════

describe("Cross-Anchor Invariants", () => {
  test("CRS ordering: ceiling < midpoint < floor", async () => {
    const ceiling = await runPipeline(loadAnchor("anchor-ceiling").capabilities);
    const mid = await runPipeline(loadAnchor("anchor-midpoint").capabilities);
    const floor = await runPipeline(loadAnchor("anchor-floor").capabilities);

    // Floor = most dangerous = highest CRS; ceiling = safest = lowest CRS
    expect(ceiling.riskProfile.compositeRiskScore).toBeLessThan(
      mid.riskProfile.compositeRiskScore,
    );
    expect(mid.riskProfile.compositeRiskScore).toBeLessThan(
      floor.riskProfile.compositeRiskScore,
    );
  });

  test("securityScore ordering: floor < midpoint < ceiling", async () => {
    const floor = await runPipeline(loadAnchor("anchor-floor").capabilities);
    const mid = await runPipeline(loadAnchor("anchor-midpoint").capabilities);
    const ceiling = await runPipeline(loadAnchor("anchor-ceiling").capabilities);

    // Floor = lowest score (dangerous); ceiling = highest score (clean).
    // Floor and midpoint may both hit 0 (penalty-deduction model bottoms out).
    // Strict ordering is enforced via CRS above. Here we assert the weaker
    // constraint: floor ≤ mid < ceiling.
    expect(floor.summary.securityScore).toBeLessThanOrEqual(mid.summary.securityScore);
    expect(mid.summary.securityScore).toBeLessThan(ceiling.summary.securityScore);
  });

  test("umriScalar is affine-rescaled complement of CRS for all anchors", async () => {
    // P0-02: After affine rescaling, the old identity CRS + umriScalar/100 = 1 no longer holds.
    // New invariant: umriScalar = max(0, (rawProduct - FLOOR) / (1 - FLOOR) * 100)
    const UMRI_RAW_FLOOR = (1 - 0.15 * 2) * (1 - 0.25 * 2) * (1 - 0.20 * 2) * (1 - 0.25 * 2) * (1 - 0.15 * 2);
    for (const name of ["anchor-floor", "anchor-midpoint", "anchor-ceiling"]) {
      const { riskProfile } = await runPipeline(loadAnchor(name).capabilities);
      const rawProduct = 1 - riskProfile.compositeRiskScore;
      const expectedUmri = Math.max(0, (rawProduct - UMRI_RAW_FLOOR) / (1.0 - UMRI_RAW_FLOOR)) * 100;
      expect(riskProfile.umriScalar).toBeCloseTo(expectedUmri, 0);
      expect(riskProfile.umriScalar).toBeGreaterThanOrEqual(0);
      expect(riskProfile.umriScalar).toBeLessThanOrEqual(100);
    }
  });

  test("pipeline is deterministic: two runs produce identical results", async () => {
    const caps = loadAnchor("anchor-midpoint").capabilities;
    const run1 = await runPipeline(caps);
    const run2 = await runPipeline(caps);

    expect(run1.riskProfile.compositeRiskScore).toBe(run2.riskProfile.compositeRiskScore);
    expect(run1.summary.securityScore).toBe(run2.summary.securityScore);
    expect(run1.allFindings.length).toBe(run2.allFindings.length);

    // Check finding IDs match exactly
    const ids1 = run1.allFindings.map((f) => f.id).sort();
    const ids2 = run2.allFindings.map((f) => f.id).sort();
    expect(ids1).toEqual(ids2);
  });
});

// ════════════════════════════════════════════════════════════════════════════
//  ADVERSARIAL VALIDITY FIXTURES
//  These test the scanner's resistance to scoring manipulation:
//  - Stealth: insecure server disguised as clean → must NOT get perfect score
//  - False alarm: safe server with scary names → must NOT get punished unfairly
// ════════════════════════════════════════════════════════════════════════════

describe("Adversarial: Perfect-Score Bypass (stealth malicious)", () => {
  const fixture = loadAnchor("adversarial-stealth");

  test("fixture loads with 3 stealth-malicious tools", () => {
    expect(fixture.capabilities.tools.length).toBe(3);
    expect(fixture._meta.anchor).toBe("ADVERSARIAL_STEALTH");
  });

  test("does NOT score 100 (perfect-score bypass would be a scanner bug)", async () => {
    const { summary } = await runPipeline(fixture.capabilities);
    expect(summary.securityScore).not.toBe(fixture.expected.mustNotScore as number);
  });

  test("detects injection in descriptions", async () => {
    const { allFindings } = await runPipeline(fixture.capabilities);
    const required = fixture.expected.requiredFindingPrefixes as string[];
    for (const prefix of required) {
      const found = allFindings.some((f) => f.id.startsWith(prefix));
      if (!found) {
        throw new Error(
          `STEALTH fixture: scanner missed required finding prefix "${prefix}". ` +
          `The injections in tool descriptions were not detected. ` +
          `Found: ${[...new Set(allFindings.map((f) => f.id.split("-").slice(0, 2).join("-")))].join(", ")}`,
        );
      }
    }
  });

  test("produces at least 2 findings", async () => {
    const { allFindings } = await runPipeline(fixture.capabilities);
    expect(allFindings.length).toBeGreaterThanOrEqual(fixture.expected.minFindingCount as number);
  });
});

describe("Adversarial: False-Alarm Bias (safe server with scary names)", () => {
  const fixture = loadAnchor("adversarial-false-alarm");

  test("fixture loads with 4 safe tools", () => {
    expect(fixture.capabilities.tools.length).toBe(4);
    expect(fixture._meta.anchor).toBe("ADVERSARIAL_FALSE_ALARM");
  });

  test("scores >= 60 (not punished for scary tool names)", async () => {
    const { summary } = await runPipeline(fixture.capabilities);
    expect(summary.securityScore).toBeGreaterThanOrEqual(
      fixture.expected.securityScoreMin as number,
    );
  });

  test("CRS stays below 0.55", async () => {
    const { riskProfile } = await runPipeline(fixture.capabilities);
    expect(riskProfile.compositeRiskScore).toBeLessThanOrEqual(
      fixture.expected.crsMax as number,
    );
  });

  test("risk level is not CRITICAL or HIGH", async () => {
    const { riskProfile } = await runPipeline(fixture.capabilities);
    const allowed = fixture.expected.riskLevelMax as string[];
    expect(allowed).toContain(riskProfile.riskLevel);
  });

  test("does not produce IPI or SSRF false positives", async () => {
    const { allFindings } = await runPipeline(fixture.capabilities);
    const forbidden = fixture.expected.forbiddenFindingPrefixes as string[];
    for (const f of allFindings) {
      for (const prefix of forbidden) {
        if (f.id.startsWith(prefix)) {
          throw new Error(
            `FALSE-ALARM fixture: scanner falsely produced "${f.id}" finding. ` +
            `This safe server should not trigger ${prefix} detections.`,
          );
        }
      }
    }
  });

  test("finding count stays within bounds", async () => {
    const { allFindings } = await runPipeline(fixture.capabilities);
    expect(allFindings.length).toBeLessThanOrEqual(fixture.expected.maxFindingCount as number);
  });
});
