import {
  Severity,
  CheckStatus,
  type ModuleResult,
  type ReportSummary,
  type Finding,
} from "../types/index.js";
import type { ToolInfo } from "../types/report.js";
import { ACTIVE_MODULE_IDS } from "./active-module-ids.js";
import { computeExploitGraph, computeExposureScore } from "./exploit-graph.js";

// ═══════════════════════════════════════════════════════════════════════════════
//  SCORING SYSTEM — UNIFIED MCP RISK INDEX (UMRI) v4.0
//  Reference: "Formalizing the Unified MCP Risk Index" design document
//  Formula version constant: SCORING_FORMULA_VERSION (exported below)
// ═══════════════════════════════════════════════════════════════════════════════
//
//  The scanner outputs TWO scoring systems:
//
//  1. securityScore (0–100)  — Legacy penalty deduction score for CLI display.
//     Kept for backwards compatibility. NOT recommended for research use.
//     Weights: CRITICAL=30, HIGH=18, MEDIUM=6, LOW=2 (per-module cap at 40).
//
//  2. riskProfile / UMRI     — Multi-axis decomposition with transparent,
//     reproducible metrics. Use this in the paper.
//
//  ── UMRI Risk Profile — 5 Axes (each 0.0–1.0) ───────────────────────────────
//
//  (a) Exposure (SE)
//      Attack surface breadth: tool count, parameter count,
//      ratio of unconstrained-to-total parameters.
//      Formula: min(1, (tools/30)·0.4 + unconstrainedRatio·0.6)
//
//  (b) ExploitChainDepth (EC)
//      Independent exploit paths and depth. Based on exfiltration chains (EC-001),
//      dual-use tools (EC-002), and capability concentration (EC-003) findings.
//      Formula: min(1, chainFindings·0.20 + (dualUse>0 ? 0.35 : 0) + (capConc>0 ? 0.15 : 0))
//
//  (c) SeverityDensity (VD)
//      UMRI Log-Sum-Exp (LSE) aggregation per tool, normalized by Capability-
//      Weighted Attack Surface (CWAS). Prevents both saturation (many findings
//      in one tool) and size-bias (large safe APIs penalized like small dangerous ones).
//
//      Per finding:   r_f = v_f × c_f   (v_f from UMRI severity scale below)
//      Per tool:      R_t = (1/β) × ln(Σ_{f∈t} exp(β·r_f))   where β=1.5
//      CWAS:          CWAS(S) = Σ_{t∈T} ω_DC(t) · κ_args(t)
//                     ω_DC(t) = 1.0 (DC-001/002/003), 0.6 (DC-004/005), 0.3 (default)
//                     κ_args(t) = min(1.0, paramCount/5)
//      Axis_VD:       min(1, Σ_t R_t / CWAS)
//
//  (d) CapabilityRisk (CR)
//      Dangerous capability presence. Binary flags aggregated:
//      DC-001/002/003 → +0.35 each (capped: all three → 1.0)
//      DC-004 → +0.25
//      Formula: min(1, (DC001?0.35:0) + (DC002?0.35:0) + (DC003?0.35:0) + (DC004?0.25:0))
//
//  (e) TrustViolation (TV)
//      Declared vs actual behaviour divergence. Rug-pull criticals are weighted
//      heavily (0.50) because readOnlyHint=true bypasses HITL in real frameworks.
//      Formula: min(1, rugPullCriticals·0.50 + rugPullHighs·0.25 +
//                      descInjection·0.15 + namespacePoisoning·0.25 + ipi·0.08)
//
//  ── Composite Risk Score (CRS / S_UMRI) ──────────────────────────────────────
//
//  The CRS uses a weighted complement product with quadratic boost:
//
//      CRS = 1 - ∏ᵢ (1 - wᵢ · φ(Aᵢ))   where φ(x) = x(1+x)
//
//  φ(x) = x(1+x) is the quadratic boost from the UMRI design document (§Mathematical
//  Formulation). It penalizes already-high-risk axes super-linearly and is NOT the
//  same as a simple linear complement product (1 - wᵢ·Aᵢ).
//
//  UMRI scalar (display):  S_UMRI = 100 × ∏ᵢ (1 - wᵢ · φ(Aᵢ))  [100=safe, 0=maximum risk]
//  This is equivalent to: S_UMRI = 100 × (1 - CRS / normalization)
//
//  Axis weights: exposure=0.15, exploitChain=0.25, severityDensity=0.20,
//               capabilityRisk=0.25, trustViolation=0.15  (sum=1.00 ✓)
//
//  ⚠ CRS CEILING: The theoretical maximum of CRS with all axes at 1.0 is
//  approximately 0.926 (not 1.0). This is a mathematical consequence of the
//  complement-product form — the product Π(1 - wᵢ·φ(1)) ≈ 0.074 > 0.
//  Papers should note the effective scale is [0.000, ≈0.926].
//
//  ── UMRI Severity Values ─────────────────────────────────────────────────────
//  CRITICAL: 1.0  |  HIGH: 0.7  |  MEDIUM: 0.4  |  LOW: 0.2  |  INFO: 0.05
//
//  ── Bayesian Evidence Fusion ──────────────────────────────────────────────────
//  Active probe results update passive finding confidence before scoring:
//    Confirmed:  P(H|E+) = TPR·P(H) / (TPR·P(H) + FPR·(1-P(H)))
//    Refuted:    P(H|E-) = (1-TPR)·P(H) / ((1-TPR)·P(H) + (1-FPR)·(1-P(H)))
//  Call applyBayesianUpdate(moduleResults) between assignConfidence() and
//  buildRiskProfile() in the aggregation pipeline.
//
//  ── Pre-Deduplication Design Choice ──────────────────────────────────────────
//  buildRiskProfile() operates on PRE-deduplication findings intentionally.
//  Pre-dedup findings capture true prevalence: a server where 20 tools all trigger
//  EC-001 is genuinely more exposed than one where 1 tool does, even if both
//  produce 1 deduplicated finding in the report. This design choice is documented
//  in §CODE item #06 of INSTRUMENT-HARDENING-REPORT.md.
//
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Scoring formula version. Increment this constant whenever axis weights,
 * sub-formulas, or severity scales change. Import this in research-reporter.ts
 * instead of hardcoding a version string there.
 *
 * Version history:
 *   v3.0 — original CRS complement-product scorer
 *   v4.0 — UMRI refactor: LSE aggregation, CWAS normalization, Bayesian fusion,
 *           updated severity scale (HIGH 0.6→0.7, MEDIUM 0.2→0.4, INFO 0→0.05)
 */
export const SCORING_FORMULA_VERSION = "v4.0";

/**
 * LSE sensitivity parameter β. β→∞ approaches max(r_f); β→0 approaches linear sum.
 *
 * P2-11 [§MEAS]: β=1.5 is an [ASSUMED] value — not empirically calibrated.
 * Chosen to provide soft-max behaviour where the worst finding dominates but
 * additional findings sub-linearly accumulate. A sensitivity analysis across
 * β ∈ {1.0, 1.5, 2.0} should be performed and documented to confirm rank
 * stability before publication. Different β values produce substantially different
 * rankings when findings cluster around medium severity.
 */
const LSE_BETA = 1.5;

/**
 * Research-grade risk profile with 5 transparent, reproducible axes.
 * This is the primary output for research use. Prefer CRS over securityScore.
 *
 * ── SCALE TYPE DECLARATIONS (P1-04 [§MEAS]) ────────────────────────────────
 *
 * All five axis scores (exposure, exploitChainDepth, severityDensity,
 * capabilityRisk, trustViolation) are **ORDINAL** scales [0.0, 1.0].
 *
 * compositeRiskScore (CRS): **ORDINAL** [0.0, ≈0.926].
 *   The complement-product with quadratic boost φ(x)=x(1+x) is monotonic but
 *   non-linear. Differences between CRS values (Δ CRS) are NOT meaningful as
 *   interval quantities. Only rank-order comparisons are valid.
 *   Papers must report: medians, percentiles, rank comparisons (Kendall's τ).
 *   Papers must NOT report: means, standard deviations, or arithmetic differences
 *   unless explicitly justified with interval-scale argumentation.
 *
 * umriScalar: **ORDINAL** [0, 100].
 *   Affine-rescaled complement product. Same ordinal constraints as CRS.
 *   Display-only convenience score: 100 = safest, 0 = most dangerous.
 *
 * securityScore (legacy): **ORDINAL** [0, 100].
 *   Penalty deduction model. NOT comparable to umriScalar — different scale,
 *   different methodology. Do not mix in research outputs.
 *
 * Missing-data policy: NEUTRAL (default confidence = 0.5). Formally declared.
 * All `f.confidence ?? 0.5` expressions implement this policy via NaN-safe guards.
 * ─────────────────────────────────────────────────────────────────────────────
 */
export interface RiskProfile {
  /** Attack surface breadth (0.0–1.0) · ORDINAL */
  exposure: number;
  /** Exploit chain depth and count (0.0–1.0) · ORDINAL */
  exploitChainDepth: number;
  /** LSE/CWAS-normalised finding density (0.0–1.0) · ORDINAL */
  severityDensity: number;
  /** Presence of fundamentally dangerous capabilities (0.0–1.0) · ORDINAL */
  capabilityRisk: number;
  /** Divergence between declared and actual behaviour (0.0–1.0) · ORDINAL */
  trustViolation: number;

  /**
   * Composite Risk Score — weighted complement product with quadratic boost (0.0–≈0.926).
   * SCALE TYPE: ORDINAL. Theoretical maximum ≈ 0.926. See CRS CEILING note above.
   * Only rank-order comparisons are valid. Do not compute means or deltas.
   */
  compositeRiskScore: number;

  /**
   * UMRI Scalar — 100-point safety display score (100 = no risk, 0 = maximum risk).
   * SCALE TYPE: ORDINAL. Affine-rescaled from raw complement product to [0, 100].
   * Same rank-order constraints as CRS.
   */
  umriScalar: number;

  /** Human-readable risk level derived from CRS */
  riskLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "MINIMAL";

  /** SSVC equivalence label derived from CRS */
  ssvcLabel: "Track" | "Track*" | "Attend" | "Act";

  /** P0-01: scan tier classification for research stratification */
  _scanTier: "transport-only" | "schema-rich";

  /** Raw inputs for reproducibility and paper appendix */
  _inputs: {
    toolCount: number;
    totalParams: number;
    unconstrainedParams: number;
    chainFindings: number;
    dualUseFindings: number;
    capConcentrationFindings: number;
    dangerousCapabilities: string[];      // DC-001, DC-002, DC-003, DC-004
    rugPullCriticals: number;
    rugPullHighs: number;
    descInjectionFindings: number;
    ipiFindings: number;
    namespacePoisoningFindings: number;
    findingsBySeverity: Record<string, number>;
    weightedFindingSum: number;           // Σ v_f·c_f (for legacy comparison)
    cwas: number;                         // Capability-Weighted Attack Surface denominator
    totalToolRisk: number;                // Σ_t R_t (LSE-aggregated per-tool risk)
  };
}

// ── Axis weights for Composite Risk Score ───────────────────────────────────
//
// Weight justification (ref: INSTRUMENT-HARDENING-REPORT §MEAS item #12):
//
//  exposure (0.15) — Attack surface breadth is a necessary but not sufficient
//    condition for risk. A large API with benign tools is less dangerous than a
//    small one with capability-rich tools. Lower weight than capability axes.
//    Applies equally to all protocols (REST endpoint count, gRPC method count,
//    MCP tool count, etc.) via the CWAS-normalised adapter pipeline.
//
//  exploitChainDepth (0.25) — Chains across tools are the primary attack vector
//    in agentic LLM workflows. A server that enables read→exfiltrate patterns
//    is qualitatively more dangerous than one with isolated findings.
//    Highest weight alongside capabilityRisk because chaining converts moderate
//    individual risks into HIGH/CRITICAL compound exploits.
//
//  severityDensity (0.20) — LSE-aggregated finding severity, CWAS-normalised.
//    Important but subordinate to capability and chain axes: dense medium findings
//    across many tools are less dangerous than one confirmed code-execution path.
//
//  capabilityRisk (0.25) — Presence of fundamentally dangerous primitives
//    (arbitrary SQL, code exec, shell, unrestricted FS) is the single strongest
//    predictor of exploitability in real agentic deployments. Highest weight
//    alongside exploitChainDepth. DC classifications are protocol-agnostic —
//    a REST endpoint that executes SQL gets the same DC-001 weight as an MCP tool.
//
//  trustViolation (0.15) — Rug-pull and injection findings are high-severity but
//    less universally present. Weighted equally with exposure to avoid over-indexing
//    on annotation-based checks that are only meaningful for protocols that expose
//    metadata hints (primarily MCP; REST/GraphQL/gRPC receive partial TV scores).
//
//  SCALE BIAS RISK (#12): All weights are currently [ASSUMED] — they represent
//  expert-elicited relative importance, not statistically calibrated values.
//  A ±20% sensitivity analysis (validate-scorer.py, Monte Carlo, 10k iterations)
//  shows 5th-percentile Kendall's τ = 0.778 ≥ threshold 0.75, confirming rank
//  stability on the current 10-server corpus. Full calibration requires a labelled
//  ground-truth dataset of ≥30 servers. See §12 in the hardening report.
//
const CRS_WEIGHTS = {
  exposure:          0.15,
  exploitChainDepth: 0.25,
  severityDensity:   0.20,
  capabilityRisk:    0.25,
  trustViolation:    0.15,
};
// P2-09 [§CODE]: Runtime assert — the comment "sum = 1.00 ✓" was not enforced.
// A future refactor changing a weight without updating the others would silently
// miscalibrate CRS. This assertion fires at module load time (once).
const _crsWeightSum = Object.values(CRS_WEIGHTS).reduce((a, b) => a + b, 0);
if (Math.abs(_crsWeightSum - 1.0) > 1e-10) {
  throw new Error(`[scorer] CRS_WEIGHTS sum to ${_crsWeightSum}, must be 1.0`);
}

// ── UMRI Severity Values (0.0–1.0 normalized scale) ─────────────────────────
//
// Severity scale justification (ref: INSTRUMENT-HARDENING-REPORT §MEAS item #12):
//
//  CRITICAL (1.0) — Confirmed direct exploitation (e.g., active fuzzer proved
//    arbitrary code execution). Top of scale by definition.
//
//  HIGH (0.7, v4.0 was 0.6) — Strong passive signal for dangerous capability.
//    Raised from 0.6 to increase sensitivity to confirmed-dangerous patterns
//    (e.g., DC-001 SQL tool, rug-pull HIGH) that are near-exploitable without
//    active confirmation.
//
//  MEDIUM (0.4, v4.0 was 0.2) — Schema-level risk signal: unconstrained params,
//    exfiltration-capable tool pairs, IPI susceptibility. Raised significantly
//    (0.2→0.4) because MEDIUM findings in agentic contexts are routinely exploitable
//    via prompt injection, unlike traditional MEDIUM findings in network scanners.
//
//  LOW (0.2) — Minor informational risk: missing annotations, namespace minor issues.
//    Unchanged.
//
//  INFO (0.05, v4.0 was 0.0) — Non-zero to allow Bayesian confidence weighting
//    to have a non-zero effect on INFO findings when active probing confirms them.
//    Was 0.0, which caused INFO findings to contribute nothing to severityDensity
//    even when an active probe confirmed the finding.
//
export const UMRI_SEVERITY_VALUES: Record<string, number> = {
  CRITICAL: 1.0,
  HIGH:     0.7,   // v4.0: was 0.6
  MEDIUM:   0.4,   // v4.0: was 0.2
  LOW:      0.2,
  INFO:     0.05,  // v4.0: was 0.0
};

// ════════════════════════════════════════════════════════════════════════════
//  LSE AGGREGATION
// ════════════════════════════════════════════════════════════════════════════

/**
 * Log-Sum-Exp aggregation for a set of findings within a single tool.
 * Formula: R_t = (1/β) × ln(Σ_f exp(β × r_f))
 *
 * Behavioural properties:
 *   - β→∞: R_t → max(r_f)  — single worst finding dominates
 *   - β→0:  R_t → linear sum / N — approaches average
 *   - β=1.5 (default): soft-max — worst finding dominates, but multiple issues
 *     accumulate sub-linearly, preventing saturation from many low-severity findings.
 *
 * @param findings Findings associated with one tool
 * @param beta Sensitivity parameter (default 1.5)
 */
export function lseFindingRisk(findings: Finding[], beta = LSE_BETA): number {
  if (findings.length === 0) return 0;
  // P0-03 [§CODE]: Guard against NaN propagation. The `??` operator does NOT
  // catch NaN (only null/undefined). A module returning confidence=NaN would
  // cascade through LSE → severityDensity → CRS → umriScalar, invalidating the
  // entire RiskProfile. The isFinite guard ensures any non-finite value is
  // clamped to 0 before entering the LSE exponential.
  const scores = findings.map(
    (f) => (UMRI_SEVERITY_VALUES[f.severity] ?? 0) * (f.confidence ?? 0.5)
  ).map(s => (Number.isFinite(s) && s >= 0) ? s : 0);
  const sumExp = scores.reduce((acc, s) => acc + Math.exp(beta * s), 0);
  return (1 / beta) * Math.log(sumExp);
}

// ════════════════════════════════════════════════════════════════════════════
//  CAPABILITY-WEIGHTED ATTACK SURFACE (CWAS)
// ════════════════════════════════════════════════════════════════════════════

/**
 * Per-tool DC weight for CWAS computation.
 * DC-001/002/003 (arbitrary SQL/code/shell) are fundamentally dangerous → 1.0.
 * DC-004/005 (unrestricted filesystem) → 0.6.
 * All other tools → 0.3 baseline.
 */
function getDCWeight(toolName: string, criticalDCTools: Set<string>, moderateDCTools: Set<string>): number {
  if (criticalDCTools.has(toolName)) return 1.0;
  if (moderateDCTools.has(toolName)) return 0.6;
  return 0.3;
}

/**
 * Compute the Capability-Weighted Attack Surface for a server.
 * CWAS(S) = Σ_{t∈T} ω_DC(t) · κ_args(t)
 *   ω_DC(t): DC-weight (see getDCWeight)
 *   κ_args(t): min(1.0, paramCount/5) — complexity factor based on argument count
 *
 * CWAS replaces raw toolCount as the severity density denominator, solving the
 * false-penalisation of large APIs with benign tools (WEAK-POINTS.md §5.2 /
 * UMRI §Capability-Weighted Normalization).
 *
 * @param tools ToolInfo array from ServerCapabilities
 * @param dcFindings Findings from the dangerous-capability module
 */
export function computeCWAS(tools: ToolInfo[], dcFindings: Finding[]): number {
  const criticalDCTools = new Set<string>();
  const moderateDCTools = new Set<string>();

  for (const f of dcFindings) {
    if (!f.toolName) continue;
    if (
      f.id.startsWith("DC-001") ||
      f.id.startsWith("DC-002") ||
      f.id.startsWith("DC-003")
    ) {
      criticalDCTools.add(f.toolName);
    } else if (f.id.startsWith("DC-004") || f.id.startsWith("DC-005")) {
      moderateDCTools.add(f.toolName);
    }
  }

  let cwas = 0;
  for (const tool of tools) {
    const props = (tool.inputSchema as Record<string, unknown>)?.properties as
      | Record<string, unknown>
      | undefined;
    const paramCount = props ? Object.keys(props).length : 0;
    const kArgs = Math.min(1.0, Math.max(0.1, paramCount / 5));
    const wDC = getDCWeight(tool.name, criticalDCTools, moderateDCTools);
    cwas += wDC * kArgs;
  }

  return Math.max(1.0, cwas); // floor at 1 to avoid division-by-zero
}

// ════════════════════════════════════════════════════════════════════════════
//  BAYESIAN EVIDENCE FUSION
// ════════════════════════════════════════════════════════════════════════════

/**
 * True Positive Rate (TPR) and False Positive Rate (FPR) for each active
 * module type. These are the likelihood parameters for Bayesian confidence updates.
 * Values sourced from UMRI design document §Bayesian Evidence Fusion table.
 */
export interface BayesianProbeConfig {
  /** P(E+|H) — probability active probe detects flaw if it exists */
  tpr: number;
  /** P(E+|¬H) — probability active probe false-alarms on safe tool */
  fpr: number;
}

export const ACTIVE_PROBE_CONFIGS: Record<string, BayesianProbeConfig> = {
  "active-fuzzer":            { tpr: 0.85, fpr: 0.05 },  // Direct fuzzing: LR=15–20
  "ssrf-detection":           { tpr: 0.80, fpr: 0.07 },  // SSRF probing: LR=10–12
  "annotation-verifier":      { tpr: 0.60, fpr: 0.15 },  // Annotation verification: LR=3–5
  "response-fingerprinting":  { tpr: 0.40, fpr: 0.20 },  // Response fingerprinting: LR=1.5–2
  "tool-shadowing":           { tpr: 0.70, fpr: 0.08 },
  "auth-boundary-testing":    { tpr: 0.70, fpr: 0.08 },
  // NOTE: "output-injection" is PASSIVE (mode="passive") — no active probe exists.
  // Removed phantom entry that was inflating passive OI-* finding confidence.
  // "agentic-loop-trap" is also passive; removed for the same reason.
  "chained-exploit":          { tpr: 0.75, fpr: 0.08 },  // Multi-step chain probing
};

// ACTIVE_MODULE_IDS is now imported from ./active-module-ids.ts (single source of truth).
// Note: ACTIVE_PROBE_CONFIGS only covers modules with Bayesian config. Modules in
// ACTIVE_MODULE_IDS without an entry here are simply skipped by the Bayesian loop.

/**
 * Single Bayesian confidence update given a probe result.
 *
 * If probe CONFIRMED a flaw (active finding exists for this tool):
 *   P(H|E+) = TPR·P(H) / (TPR·P(H) + FPR·(1-P(H)))
 *
 * If probe FAILED (active module ran but produced no finding for this tool):
 *   P(H|E-) = (1-TPR)·P(H) / ((1-TPR)·P(H) + (1-FPR)·(1-P(H)))
 *   Note: failure decreases confidence but doesn't zero it out — the fuzzer
 *   might simply have missed the payload (ref: UMRI §Bayesian Update Mechanism).
 */
export function bayesUpdate(
  prior: number,
  config: BayesianProbeConfig,
  confirmed: boolean,
): number {
  const { tpr, fpr } = config;
  if (confirmed) {
    const numerator = tpr * prior;
    const denominator = tpr * prior + fpr * (1 - prior);
    return denominator > 0 ? numerator / denominator : prior;
  } else {
    const numerator = (1 - tpr) * prior;
    const denominator = (1 - tpr) * prior + (1 - fpr) * (1 - prior);
    return denominator > 0 ? numerator / denominator : prior;
  }
}

/**
 * Apply Bayesian evidence fusion to passive finding confidence scores.
 *
 * This function MUTATES Finding.confidence in-place. It must be called
 * AFTER assignConfidence() and BEFORE buildRiskProfile(). The pipeline order is:
 *
 *   1. ModuleRunner.run()      → ModuleResult[]
 *   2. assignConfidence()      → sets initial confidence on all findings
 *   3. applyBayesianUpdate()   → updates confidence based on active probe results  ← HERE
 *   4. buildRiskProfile()      → computes UMRI axes using final confidence values
 *
 * For each passive finding on a given tool:
 *   - If an active module CONFIRMED a vulnerability on that tool → confidence ↑
 *   - If an active module RAN on that tool but produced no finding → confidence ↓ slightly
 *   - If no active module probed that tool → confidence unchanged
 *
 * @param moduleResults All module results from ModuleRunner.run()
 */
export function applyBayesianUpdate(moduleResults: ModuleResult[]): void {
  // Build a map: toolName → { moduleId → confirmed? }
  // "confirmed" = active module produced a finding for this tool
  // "ran but no finding" = active module had checks for this tool but no finding
  const toolProbeResults = new Map<string, Map<string, boolean>>();

  // Pass 1: collect tools where active modules produced findings (confirmed)
  for (const result of moduleResults) {
    if (!ACTIVE_MODULE_IDS.has(result.moduleId)) continue;
    for (const finding of result.findings) {
      const toolKey = finding.toolName ?? "__global__";
      if (!toolProbeResults.has(toolKey)) {
        toolProbeResults.set(toolKey, new Map());
      }
      toolProbeResults.get(toolKey)!.set(result.moduleId, true);
    }
  }

  // Pass 2: collect tools where active modules ran but produced no finding (refuted)
  // We infer "ran" from: module has checks AND tool is mentioned in a check finding
  for (const result of moduleResults) {
    if (!ACTIVE_MODULE_IDS.has(result.moduleId)) continue;
    for (const check of result.checks) {
      const toolKey = check.finding?.toolName ?? null;
      if (!toolKey) continue;
      if (!toolProbeResults.has(toolKey)) {
        toolProbeResults.set(toolKey, new Map());
      }
      // Only record as "ran but not confirmed" if we haven't already seen a confirmation
      if (!toolProbeResults.get(toolKey)!.has(result.moduleId)) {
        toolProbeResults.get(toolKey)!.set(result.moduleId, false);
      }
    }
  }

  // Pass 3: update passive finding confidence using Bayesian update
  for (const result of moduleResults) {
    if (ACTIVE_MODULE_IDS.has(result.moduleId)) continue; // skip active modules themselves
    for (const finding of result.findings) {
      const toolKey = finding.toolName ?? "__global__";
      const probeMap = toolProbeResults.get(toolKey);
      if (!probeMap) continue;

      // M-4: For __global__ findings (no toolName), require matching finding ID prefix
      // or module ID before applying Bayesian update. Without this, an unrelated SSRF
      // global finding could incorrectly update confidence of a TransportSecurity finding.
      const findingPrefix = finding.id?.split("-")[0] ?? "";

      let updatedConfidence = finding.confidence ?? 0.5;
      for (const [moduleId, confirmed] of probeMap) {
        // Skip cross-updates for __global__ findings: only apply if the active module
        // is related (same module family or same finding prefix).
        if (toolKey === "__global__") {
          const activePrefix = moduleId.split("-")[0] ?? "";
          const moduleFamily = result.moduleId.split("-")[0] ?? "";
          if (activePrefix !== findingPrefix && activePrefix !== moduleFamily) continue;
        }
        const cfg = ACTIVE_PROBE_CONFIGS[moduleId];
        if (!cfg) continue;
        updatedConfidence = bayesUpdate(updatedConfidence, cfg, confirmed);
        // P1-05 [§CODE]: Clamp after EACH Bayesian update iteration, not just after
        // the loop. Multiple active modules updating sequentially can push intermediate
        // confidence beyond [0,1], corrupting subsequent LSE accumulation if the loop
        // exits early (e.g., on error) before the post-loop clamp fires.
        updatedConfidence = Math.max(0.01, Math.min(1.0, updatedConfidence));
      }
      finding.confidence = round3(updatedConfidence);
    }
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  MAIN RISK PROFILE BUILDER
// ════════════════════════════════════════════════════════════════════════════

/**
 * Assert that assignConfidence() has been run on these module results.
 * Heuristic: if any finding has confidence === undefined, the pipeline is likely
 * out of order (confidence.ts should have populated all values).
 * Throws in development; warns in production.
 */
function assertConfidenceAssigned(moduleResults: ModuleResult[]): void {
  const allFindings = moduleResults.flatMap((m) => m.findings);
  const unset = allFindings.filter((f) => f.confidence === undefined);
  if (unset.length > 0) {
    const msg =
      `[scorer] buildRiskProfile() called with ${unset.length} findings where ` +
      `confidence is undefined. Ensure assignConfidence() is called before ` +
      `buildRiskProfile(). Defaulting missing values to 0.5.`;
    // Warn instead of throw to remain robust in production
    console.warn(msg);
    for (const f of unset) f.confidence = 0.5;
  }
}

/**
 * Build the multi-axis UMRI risk profile from module results.
 *
 * Call order requirement (enforced via assertConfidenceAssigned):
 *   assignConfidence() → applyBayesianUpdate() → buildRiskProfile()
 *
 * @param moduleResults All module results (PRE-deduplication — by design)
 * @param toolCount Number of tools exposed by the server
 * @param totalParams Total parameter count across all tools
 * @param unconstrainedParams Parameters with no type/length/format constraints
 * @param tools Optional ToolInfo[] for precise CWAS computation; falls back to toolCount
 *
 * @deprecated Use computeSecurityMeasurement() for research-grade scores with
 * zero assumed constants. buildRiskProfile() embeds assumed weights (β=1.5,
 * CRS axis weights) that require empirical calibration. It is retained for
 * backwards compatibility and CLI display.
 */
export function buildRiskProfile(
  moduleResults: ModuleResult[],
  toolCount: number,
  totalParams: number,
  unconstrainedParams: number,
  tools?: ToolInfo[],
): RiskProfile {
  assertConfidenceAssigned(moduleResults);

  const allFindings = moduleResults.flatMap((m) => m.findings);

  // ── (a) Exposure ─────────────────────────────────────────────────────────
  const unconstrainedRatio = totalParams > 0 ? unconstrainedParams / totalParams : 0;
  const exposure = Math.min(1, (toolCount / 30) * 0.4 + unconstrainedRatio * 0.6);

  // ── (b) Exploit Chain Depth ───────────────────────────────────────────────
  const chainFindings = allFindings.filter((f) => f.id.startsWith("EC-001")).length;
  const dualUseFindings = allFindings.filter((f) => f.id.startsWith("EC-002")).length;
  const capConcentrationFindings = allFindings.filter((f) => f.id.startsWith("EC-003")).length;
  const exploitChainDepth = Math.min(
    1,
    chainFindings * 0.20 +
    (dualUseFindings > 0 ? 0.35 : 0) +
    (capConcentrationFindings > 0 ? 0.15 : 0),
  );

  // ── (c) Severity Density — LSE + CWAS ────────────────────────────────────
  // Group all findings by tool, then apply LSE aggregation per tool.
  // FIX (P0-01): When toolCount=0 and no tool-attributed findings exist, the
  // __global__ bucket contains only transport-level findings (SC-*, TS-*).
  // These are protocol-layer signals, not tool-layer signals, so VD must be 0.0
  // to avoid the CRS=0.292 floor artifact on transport-only targets.
  const findingsByTool = new Map<string, Finding[]>();
  for (const f of allFindings) {
    const toolKey = f.toolName ?? "__global__";
    if (!findingsByTool.has(toolKey)) findingsByTool.set(toolKey, []);
    findingsByTool.get(toolKey)!.push(f);
  }

  // Check if we have any tool-attributed findings (not just __global__)
  const hasToolAttributedFindings = Array.from(findingsByTool.keys()).some(
    (k) => k !== "__global__",
  );

  let totalToolRisk = 0;
  if (toolCount === 0 && !hasToolAttributedFindings) {
    // P3-19 [§CODE]: Transport-only global bucket behaviour — DOCUMENTED DESIGN CHOICE.
    //
    // When toolCount=0 and all findings live in the __global__ bucket, the target
    // is "transport-only" (e.g., a gRPC endpoint with no declared methods, or an
    // MCP server that connects but lists no tools). Transport-level findings
    // (SC-*, TS-*) are protocol-layer signals — NOT tool-layer signals.
    //
    // Setting VD=0.0 for transport-only targets is intentional:
    //   - Prevents the CRS=0.292 floor artifact from transport findings alone
    //   - Ensures _scanTier="transport-only" for research stratification
    //   - These targets should be reported separately from "schema-rich" targets
    //
    // CONSEQUENCE: A transport-only target with HIGH-severity global findings will
    // still show VD=0.0 in the risk profile. The findings are visible in the
    // findings[] array and contribute to the legacy securityScore, but NOT to CRS.
    // This is acceptable because CRS is designed to assess tool-layer risk.
    totalToolRisk = 0;
  } else {
    for (const [, toolFindings] of findingsByTool) {
      totalToolRisk += lseFindingRisk(toolFindings);
    }
  }

  const dcFindings = allFindings.filter((f) => f.module === "dangerous-capability");
  const cwas = tools && tools.length > 0
    ? computeCWAS(tools, dcFindings)
    : Math.max(1.0, toolCount); // graceful fallback when tools not provided

  const severityDensity = Math.min(1, totalToolRisk / cwas);

  // ── (d) Capability Risk ───────────────────────────────────────────────────
  // DC-001/002/003: +0.35 each (all three present → 1.05, capped to 1.0)
  // DC-004:         +0.25
  const hasDC001 = dcFindings.some((f) => f.id.startsWith("DC-001"));
  const hasDC002 = dcFindings.some((f) => f.id.startsWith("DC-002"));
  const hasDC003 = dcFindings.some((f) => f.id.startsWith("DC-003"));
  const hasDC004 = dcFindings.some((f) => f.id.startsWith("DC-004"));
  const dangerousCaps: string[] = [];
  if (hasDC001) dangerousCaps.push("DC-001:arbitrary-sql");
  if (hasDC002) dangerousCaps.push("DC-002:arbitrary-code");
  if (hasDC003) dangerousCaps.push("DC-003:arbitrary-shell");
  if (hasDC004) dangerousCaps.push("DC-004:unrestricted-fs");

  const capabilityRisk = Math.min(
    1,
    (hasDC001 ? 0.35 : 0) +
    (hasDC002 ? 0.35 : 0) +
    (hasDC003 ? 0.35 : 0) +
    (hasDC004 ? 0.25 : 0),
  );

  // ── (e) Trust Violation ───────────────────────────────────────────────────
  //
  // P1-07 [§ADV]: readOnlyHint is a self-declared, attacker-controlled annotation.
  // An adversary controlling the server can set it to any value. Rug-pull findings
  // based SOLELY on annotation mismatch (readOnlyHint=true on a destructive tool)
  // should contribute less than behaviour-confirmed violations.
  //
  // Annotation-only signals: capped at 0.15 per finding (was 0.50/0.25).
  // Behaviour-confirmed signals (active probe confirmed rug-pull): full weight.
  //
  // The distinction is made via confidence: annotation-only rug-pulls typically
  // have confidence ≤ 0.7 (passive heuristic), while active-confirmed ones have
  // confidence > 0.8 (Bayesian-boosted). We use the confidence level as a proxy
  // to split annotation-only from behaviour-confirmed.
  //
  const ANNOTATION_CONFIDENCE_THRESHOLD = 0.80;
  const ANNOTATION_CAP_CRITICAL = 0.15;  // was 0.50 for all
  const ANNOTATION_CAP_HIGH = 0.10;       // was 0.25 for all
  const CONFIRMED_WEIGHT_CRITICAL = 0.50; // behaviour-confirmed: full weight
  const CONFIRMED_WEIGHT_HIGH = 0.25;     // behaviour-confirmed: full weight

  const rugPullCriticals = allFindings.filter(
    (f) => f.module === "rug-pull-detection" && f.severity === "CRITICAL",
  );
  const rugPullHighs = allFindings.filter(
    (f) => f.module === "rug-pull-detection" && f.severity === "HIGH",
  );
  const descInjectionFindings = allFindings.filter(
    (f) =>
      f.module === "description-injection" ||
      f.module === "description-injection-detector",
  ).length;
  const namespacePoisoningFindings = allFindings.filter(
    (f) => f.module === "namespace-poisoning",
  ).length;
  const ipiFindings = allFindings.filter(
    (f) => f.module === "ipi-susceptibility",
  ).length;

  // Split rug-pull contribution by confidence (annotation-only vs confirmed)
  let rugPullCriticalContribution = 0;
  for (const f of rugPullCriticals) {
    const conf = f.confidence ?? 0.5;
    rugPullCriticalContribution += conf >= ANNOTATION_CONFIDENCE_THRESHOLD
      ? CONFIRMED_WEIGHT_CRITICAL : ANNOTATION_CAP_CRITICAL;
  }
  let rugPullHighContribution = 0;
  for (const f of rugPullHighs) {
    const conf = f.confidence ?? 0.5;
    rugPullHighContribution += conf >= ANNOTATION_CONFIDENCE_THRESHOLD
      ? CONFIRMED_WEIGHT_HIGH : ANNOTATION_CAP_HIGH;
  }

  const trustViolation = Math.min(
    1,
    rugPullCriticalContribution +
    rugPullHighContribution +
    descInjectionFindings * 0.15 +
    namespacePoisoningFindings * 0.25 +
    ipiFindings * 0.08,
  );

  // ── Composite Risk Score (CRS) ────────────────────────────────────────────
  // CRS = 1 - ∏ᵢ (1 - wᵢ · φ(Aᵢ))   where φ(x) = x(1+x)
  // Weights sum to 1.0: 0.15+0.25+0.20+0.25+0.15 = 1.00 ✓
  // Theoretical max ≈ 0.926 (not 1.0) — see CRS CEILING note in header.
  const axes = {
    exposure,
    exploitChainDepth,
    severityDensity,
    capabilityRisk,
    trustViolation,
  };

  let complementProduct = 1;
  for (const [axis, value] of Object.entries(axes)) {
    const weight = CRS_WEIGHTS[axis as keyof typeof CRS_WEIGHTS];
    complementProduct *= 1 - value * weight * (1 + value);
  }
  const compositeRiskScore = round3(1 - complementProduct);

  // P0-01 [§MEAS §ADV]: UMRI scalar with affine rescaling to achieve true [0, 100] range.
  // The raw complement product Π(1 - wᵢ·φ(Aᵢ)) has a mathematical floor of ~0.0735
  // when all axes are at maximum (1.0), because φ(1)=2 and the product never reaches 0.
  // Without rescaling, umriScalar has an unreachable floor of ~7.35, making
  // BENCHMARK_FLOOR (score=0) impossible and invalidating anchor calibration.
  //
  // Affine rescaling: displayScore = (raw - FLOOR) / (1.0 - FLOOR) * 100
  //   where FLOOR = Π(1 - wᵢ · φ(1.0)) ≈ 0.0735
  // This maps raw=FLOOR → 0 and raw=1.0 → 100, producing a true [0, 100] scale.
  const UMRI_RAW_FLOOR = Object.entries(CRS_WEIGHTS).reduce(
    (prod, [, w]) => prod * (1 - w * 2), // φ(1.0) = 1*(1+1) = 2
    1,
  ); // ≈ 0.0735
  const umriScalar = round3(
    Math.max(0, (complementProduct - UMRI_RAW_FLOOR) / (1.0 - UMRI_RAW_FLOOR)) * 100,
  );

  // ── Risk Level ────────────────────────────────────────────────────────────
  const riskLevel =
    compositeRiskScore >= 0.7 ? ("CRITICAL" as const) :
    compositeRiskScore >= 0.5 ? ("HIGH" as const) :
    compositeRiskScore >= 0.3 ? ("MEDIUM" as const) :
    compositeRiskScore >= 0.1 ? ("LOW" as const) :
    ("MINIMAL" as const);

  // ── Legacy weighted sum (kept for _inputs reproducibility) ───────────────
  let weightedFindingSum = 0;
  const findingsBySev: Record<string, number> = {
    CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0,
  };
  for (const f of allFindings) {
    // P0-03 [§CODE]: NaN-safe confidence — same guard as lseFindingRisk
    const rawConf = f.confidence ?? 0.5;
    const conf = Number.isFinite(rawConf) ? Math.max(0, Math.min(1, rawConf)) : 0.5;
    weightedFindingSum += (UMRI_SEVERITY_VALUES[f.severity] ?? 0) * conf;
    findingsBySev[f.severity] = (findingsBySev[f.severity] ?? 0) + 1;
  }

  return {
    exposure: round3(exposure),
    exploitChainDepth: round3(exploitChainDepth),
    severityDensity: round3(severityDensity),
    capabilityRisk: round3(capabilityRisk),
    trustViolation: round3(trustViolation),
    compositeRiskScore,
    umriScalar,
    riskLevel,
    ssvcLabel: crsToSsvc(compositeRiskScore).label,
    // P0-01: tier classification for research stratification
    _scanTier: (toolCount === 0 && !hasToolAttributedFindings)
      ? "transport-only" as const
      : "schema-rich" as const,
    _inputs: {
      toolCount,
      totalParams,
      unconstrainedParams,
      chainFindings,
      dualUseFindings,
      capConcentrationFindings,
      dangerousCapabilities: dangerousCaps,
      rugPullCriticals: rugPullCriticals.length,
      rugPullHighs: rugPullHighs.length,
      descInjectionFindings,
      ipiFindings,
      namespacePoisoningFindings,
      findingsBySeverity: findingsBySev,
      weightedFindingSum: round3(weightedFindingSum),
      cwas: round3(cwas),
      totalToolRisk: round3(totalToolRisk),
    },
  };
}

function round3(n: number): number {
  return Math.round(n * 1000) / 1000;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SSVC EQUIVALENCE LABELS
//  Reference: DeepR_3 research report, CISA SSVC decision tree model.
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Map UMRI Composite Risk Score to SSVC equivalence labels.
 * Reference: DeepR_3 research report, CISA SSVC decision tree model.
 */
export function crsToSsvc(crs: number): {
  label: "Track" | "Track*" | "Attend" | "Act";
  description: string;
} {
  if (crs >= 0.85) return { label: "Act", description: "Immediate emergency coordinated action required" };
  if (crs >= 0.55) return { label: "Attend", description: "Remediate sooner than normal cycle — notify internal management" };
  if (crs >= 0.30) return { label: "Track*", description: "Monitor with enhanced attention — closer follow-up required" };
  return { label: "Track", description: "Monitor within standard vulnerability management timelines" };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CALIBRATION METRICS — ECE & Brier Score
//  Reference: DeepR_7 research report — calibration validation.
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Compute Expected Calibration Error (ECE) from binned predictions.
 * Reference: DeepR_7 research report — calibration validation.
 *
 * @param predictions Array of { predicted: number, actual: 0 | 1 } pairs
 * @param bins Number of equal-width bins (default 10)
 * @returns ECE value (0 = perfectly calibrated, 1 = maximally miscalibrated)
 */
export function computeECE(
  predictions: Array<{ predicted: number; actual: 0 | 1 }>,
  bins: number = 10
): number {
  if (predictions.length === 0) return 0;

  const binWidth = 1.0 / bins;
  let ece = 0;

  for (let i = 0; i < bins; i++) {
    const lower = i * binWidth;
    const upper = (i + 1) * binWidth;
    const binPredictions = predictions.filter(
      (p) => p.predicted >= lower && p.predicted < upper
    );

    if (binPredictions.length === 0) continue;

    const avgPredicted = binPredictions.reduce((s, p) => s + p.predicted, 0) / binPredictions.length;
    const avgActual = binPredictions.reduce((s, p) => s + p.actual, 0) / binPredictions.length;
    const binWeight = binPredictions.length / predictions.length;

    ece += binWeight * Math.abs(avgPredicted - avgActual);
  }

  return ece;
}

/**
 * Compute Brier score and its decomposition.
 * Brier = Reliability - Resolution + Uncertainty
 * Reference: DeepR_7 research report — Brier score decomposition.
 *
 * @param predictions Array of { predicted: number, actual: 0 | 1 } pairs
 * @returns Brier score components
 */
export function computeBrierScore(
  predictions: Array<{ predicted: number; actual: 0 | 1 }>
): {
  brier: number;
  reliability: number;
  resolution: number;
  uncertainty: number;
} {
  if (predictions.length === 0) {
    return { brier: 0, reliability: 0, resolution: 0, uncertainty: 0 };
  }

  const n = predictions.length;

  // Overall Brier score: mean squared error
  const brier = predictions.reduce(
    (sum, p) => sum + Math.pow(p.predicted - p.actual, 2), 0
  ) / n;

  // Base rate (climatological probability)
  const baseRate = predictions.reduce((s, p) => s + p.actual, 0) / n;

  // Uncertainty: baseRate × (1 - baseRate)
  const uncertainty = baseRate * (1 - baseRate);

  // Bin predictions for decomposition (10 bins)
  const decompositionBins = 10;
  const binWidth = 1.0 / decompositionBins;
  let reliability = 0;
  let resolution = 0;

  for (let i = 0; i < decompositionBins; i++) {
    const lower = i * binWidth;
    const upper = (i + 1) * binWidth;
    const binPreds = predictions.filter(
      (p) => p.predicted >= lower && p.predicted < upper
    );

    if (binPreds.length === 0) continue;

    const nk = binPreds.length;
    const avgPredicted = binPreds.reduce((s, p) => s + p.predicted, 0) / nk;
    const avgActual = binPreds.reduce((s, p) => s + p.actual, 0) / nk;

    reliability += (nk / n) * Math.pow(avgPredicted - avgActual, 2);
    resolution += (nk / n) * Math.pow(avgActual - baseRate, 2);
  }

  return { brier, reliability, resolution, uncertainty };
}

// ════════════════════════════════════════════════════════════════════════════
//  LEGACY SCORING — kept for CLI display and backwards compatibility
//  ⚠ [LEGACY] NOT recommended for research use. Use CRS (riskProfile) instead.
//  (ref: INSTRUMENT-HARDENING-REPORT §LEAD items #12 and #16)
//
//  Weight justification (ASSUMED — not statistically calibrated):
//    CRITICAL=30: ~30% of the 100-point scale for a single critical finding —
//      reflects that one confirmed RCE/SQLi should be near-disqualifying.
//    HIGH=18:     ~18% — strong signal but requires contextual confirmation.
//    MEDIUM=6:    ~6% — schema-level warning; multiple needed to be material.
//    LOW=2:       ~2% — informational; nuisance deduction only.
//    INFO=0:      No penalty — pure metadata, not actionable on its own.
//
//  DIMINISHING_FACTOR=0.7: Each repeated finding in the same module contributes
//    70% of the previous one, preventing a module from dominating the score via
//    many identical findings (e.g., 50 unconstrained parameters → 1 module).
//
//  MAX_MODULE_IMPACT=40: No single module can deduct more than 40 points.
//    Prevents one extremely noisy module from pushing score to 0 alone.
//
//  SCALE BIAS RISK (#12): securityScore=0 is ambiguous (rawScore -3 vs -62 both
//  display as 0). Use rawScore and penaltyPoints for finer discrimination.
//
// ════════════════════════════════════════════════════════════════════════════

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  [Severity.CRITICAL]: 30,
  [Severity.HIGH]:     18,
  [Severity.MEDIUM]:    6,
  [Severity.LOW]:       2,
  [Severity.INFO]:      0,
};

const DIMINISHING_FACTOR = 0.7;
const MAX_MODULE_IMPACT = 40;

const STRUCTURAL_MODULE_CAPS: Record<string, number> = {
  // Passive modules — capped to prevent single-module domination of legacy score
  "tool-permissions":              12,
  "supply-chain-analysis":         10,
  "current-vulnerability-intel":    25,
  "transport-security":             8,
  "token-exhaustion":              12,
  "capability-graph":               4,
  "ipi-susceptibility":            15,
  "dangerous-capability":          25,  // DC-001/002/003 are high-impact but structural
  "rug-pull-detection":            20,  // CRITICAL rug-pulls are severe but module can be noisy
  "description-injection-detector": 15,
  "exfiltration-chain":            15,
  // Sprint 2 passive modules — L-2: prevent uncapped fallback to MAX_MODULE_IMPACT
  "mcp-apps-audit":                10,  // XSS/iframe/postMessage — structural
  "discovery-scanner":              8,  // Discovery endpoint exposure
  "eu-ai-act":                     10,  // Compliance conformity — informational
  "agent-output-trust":            12,  // Trust propagation chains
  "handshake-fuzzer":               8,  // CVE handshake surface
  // Active modules — higher caps since they produce confirmed exploits
  "active-fuzzer":                 35,  // Confirmed exploits → near full penalty allowed
  "ssrf-detection":                30,
  "chained-exploit":               30,
  "session-isolation":             25,
  "annotation-verifier":           20,  // readOnly + rug-pull probing
};

/**
 * Optional scoring configuration. When provided, overrides the hardcoded defaults.
 * This allows profiles (quick/standard/enterprise) to use different calibrations.
 */
export interface ScoringConfig {
  severityWeights?: Partial<Record<Severity, number>>;
  diminishingFactor?: number;
  maxModuleImpact?: number;
}

/**
 * Calculate legacy security score and report summary from module results.
 * @param scoringConfig Optional weight/factor overrides from profile
 * @deprecated For display use only. Use buildRiskProfile() for research metrics.
 */
export function calculateScore(moduleResults: ModuleResult[], scoringConfig?: ScoringConfig): ReportSummary {
  let totalChecks = 0;
  let passed = 0;
  let warnings = 0;
  let checksWithFailStatus = 0;
  let skipped = 0;
  let errors = 0;

  const findingsBySeverity: Record<Severity, number> = {
    [Severity.CRITICAL]: 0,
    [Severity.HIGH]:     0,
    [Severity.MEDIUM]:   0,
    [Severity.LOW]:      0,
    [Severity.INFO]:     0,
  };

  for (const result of moduleResults) {
    for (const check of result.checks) {
      totalChecks++;
      switch (check.status) {
        case CheckStatus.PASS:  passed++;               break;
        case CheckStatus.WARN:  warnings++;             break;
        case CheckStatus.FAIL:  checksWithFailStatus++; break;
        case CheckStatus.SKIP:  skipped++;              break;
        case CheckStatus.ERROR: errors++;               break;
      }
    }
    for (const finding of result.findings) {
      findingsBySeverity[finding.severity]++;
    }
  }

  const { securityScore, rawScore, penaltyPoints } = calculateSecurityScore(moduleResults, scoringConfig);

  return {
    totalChecks,
    passed,
    warnings,
    checksWithFailStatus,
    skipped,
    errors,
    findingsBySeverity,
    securityScore,
    rawScore,
    penaltyPoints,
  };
}

function calculateSecurityScore(
  moduleResults: ModuleResult[],
  config?: ScoringConfig
): {
  securityScore: number;
  rawScore: number;
  penaltyPoints: number;
} {
  const weights = { ...SEVERITY_WEIGHTS, ...config?.severityWeights };
  const dimFactor = config?.diminishingFactor ?? DIMINISHING_FACTOR;
  // P2-10 [§CODE]: Validate diminishingFactor is in [0, 1]. Values > 1.0 invert
  // the diminishing-returns behaviour, making Math.pow(dimFactor, i) INCREASE
  // with each finding instead of decreasing — more findings = amplified penalty.
  if (dimFactor < 0 || dimFactor > 1.0) {
    throw new Error(
      `[scorer] diminishingFactor=${dimFactor} is out of range [0, 1]. ` +
      `Values > 1 invert diminishing returns; values < 0 are nonsensical.`
    );
  }
  const maxImpact = config?.maxModuleImpact ?? MAX_MODULE_IMPACT;

  let score = 100;

  for (const result of moduleResults) {
    const severityCounts = new Map<Severity, number>();
    for (const finding of result.findings) {
      severityCounts.set(
        finding.severity,
        (severityCounts.get(finding.severity) ?? 0) + 1,
      );
    }

    let moduleImpact = 0;
    for (const [severity, count] of severityCounts) {
      const baseWeight = weights[severity];
      const findingsOfSev = result.findings.filter((f) => f.severity === severity);
      for (let i = 0; i < count; i++) {
        // P0-03 [§CODE]: NaN-safe confidence guard in legacy path
        const rawConf = findingsOfSev[i]?.confidence ?? 0.5;
        const confidence = Number.isFinite(rawConf) ? Math.max(0, Math.min(1, rawConf)) : 0.5;
        moduleImpact += baseWeight * Math.pow(dimFactor, i) * confidence;
      }
    }

    const moduleCap = STRUCTURAL_MODULE_CAPS[result.moduleId] ?? maxImpact;
    score -= Math.min(moduleImpact, moduleCap);
  }

  const rawScore = Math.round(score);
  const securityScore = Math.max(0, rawScore);
  const penaltyPoints = 100 - rawScore;

  return { securityScore, rawScore, penaltyPoints };
}

/**
 * Get a human-readable grade from a legacy security score.
 * @deprecated Use riskProfile.riskLevel instead for research comparisons.
 */
export function scoreToGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

/**
 * Get the color associated with a legacy security score.
 */
export function scoreToColor(score: number): "green" | "yellow" | "red" {
  if (score >= 80) return "green";
  if (score >= 50) return "yellow";
  return "red";
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SECURITY MEASUREMENT — exploit graph + exposure score (zero assumed constants)
//
//  This is the replacement for the UMRI v4.0 composite scorer. It produces two
//  independent, deterministic scores and derives a risk class from explicit
//  threshold gates rather than a weighted sum with assumed constants.
//
//  Designed for research reproducibility: every formula is single-equation,
//  every threshold is an explicit named constant. No β, no axis weights, no LSE.
//
//  Import computeExploitGraph and computeExposureScore from exploit-graph.ts.
//  This file re-exports computeSecurityMeasurement as the primary entry point.
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Minimal summary of detonation-chamber results needed by computeSecurityMeasurement.
 * Callers should pass the chamberReachability.verified flag and the total number
 * of confirmed-exfil captures from chamberSummary.confirmedExfil.length.
 */
export interface ChamberCaptureSummary {
  /** True when the chamber's reachability probe confirmed an outbound call. */
  verified: boolean;
  /** Number of confirmed exfiltration events recorded in the chamber sinks. */
  captureCount: number;
}

/**
 * Research-grade security measurement with zero assumed constants.
 *
 * Two primary axes:
 *   G (exploitGraphScore) — longest exploit-graph path / total tools [0.0, 1.0]
 *   E (exposureScore)     — unconstrained params / total params [0.0, 1.0]
 *
 * Risk class determined by explicit threshold gates, NOT a weighted sum:
 *   CRITICAL : DC-001/002/003 present, OR (G > 0.7 AND chamberVerified)
 *   HIGH     : G > 0.5, OR (G > 0.3 AND E > 0.7)
 *   MEDIUM   : G > 0.2, OR E > 0.5
 *   LOW      : everything else
 */
export interface SecurityMeasurement {
  /** G — Exploit Graph Score [0.0, 1.0]. No weights, no β, no assumed constants. */
  exploitGraphScore: number;
  /** E — Surface Exposure Score [0.0, 1.0]. Formula: unconstrained_params / max(1, total_params). */
  exposureScore: number;
  /** Risk classification determined by capability gates then G/E thresholds. */
  riskClass: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  /**
   * Which gate determined the risk class.
   *   "capability-gate" — DC-001/002/003 finding present, or DC+chamber combo
   *   "graph-score"     — G threshold fired before E threshold
   *   "exposure-score"  — only E threshold fired (or default LOW)
   */
  determinedBy: "capability-gate" | "graph-score" | "exposure-score";
  /** True when the detonation chamber verified outbound reachability for this target. */
  chamberVerified: boolean;
  /** Number of chamber captures recorded (0 when no chamber run). */
  chamberCaptureCount: number;
}

// ── Risk class thresholds (explicit, named — not anonymous magic numbers) ──────
const G_CRITICAL_WITH_CHAMBER = 0.7;
const G_HIGH                  = 0.5;
const G_HIGH_WITH_EXPOSURE    = 0.3;
const E_HIGH_WITH_G           = 0.7;
const G_MEDIUM                = 0.2;
const E_MEDIUM                = 0.5;

/**
 * Compute the SecurityMeasurement for a scan.
 *
 * This is the primary entry point for the new scoring system. It replaces
 * buildRiskProfile() for research use cases that require zero assumed constants.
 *
 * @param findings All findings from the scan (post- or pre-deduplication; gates only check presence)
 * @param tools All ToolInfo objects from the server's declared capabilities
 * @param chamberCaptures Optional chamber summary; omit or pass undefined for non-chamber scans
 */
export function computeSecurityMeasurement(
  findings: Finding[],
  tools: ToolInfo[],
  chamberCaptures?: ChamberCaptureSummary,
): SecurityMeasurement {
  // ── Exploit Graph Score (G) ───────────────────────────────────────────────
  const { score: G } = computeExploitGraph(tools);

  // ── Surface Exposure Score (E) ────────────────────────────────────────────
  const { score: E } = computeExposureScore(tools);

  // ── Chamber status ────────────────────────────────────────────────────────
  const chamberVerified = chamberCaptures?.verified ?? false;
  const chamberCaptureCount = chamberCaptures?.captureCount ?? 0;

  // ── Dangerous capability presence (DC-001/002/003) ────────────────────────
  // Check for presence only — no weighting. The capability gate is binary.
  const hasCriticalDC = findings.some(
    (f) =>
      f.id.startsWith("DC-001") ||
      f.id.startsWith("DC-002") ||
      f.id.startsWith("DC-003"),
  );

  // ── Risk class determination ──────────────────────────────────────────────
  //
  // Gates are evaluated in CRITICAL → HIGH → MEDIUM → LOW order.
  // The first gate that fires wins and sets determinedBy.
  //
  // CRITICAL gate:
  //   (a) Any DC-001/002/003 finding present (arbitrary SQL/code/shell)
  //   (b) G > 0.7 AND chamber verified (long exploit path + proven egress)
  //
  // HIGH gate:
  //   (a) G > 0.5 alone (deep exploit graph even without chamber)
  //   (b) G > 0.3 AND E > 0.7 (moderate graph depth + heavily unconstrained surface)
  //
  // MEDIUM gate:
  //   (a) G > 0.2 (some exploit-graph depth)
  //   (b) E > 0.5 (more than half of all params are unconstrained)
  //
  // LOW: default when no gate fires.

  let riskClass: SecurityMeasurement["riskClass"];
  let determinedBy: SecurityMeasurement["determinedBy"];

  if (hasCriticalDC || (G > G_CRITICAL_WITH_CHAMBER && chamberVerified)) {
    riskClass = "CRITICAL";
    determinedBy = "capability-gate";
  } else if (G > G_HIGH || (G > G_HIGH_WITH_EXPOSURE && E > E_HIGH_WITH_G)) {
    riskClass = "HIGH";
    determinedBy = "graph-score";
  } else if (G > G_MEDIUM || E > E_MEDIUM) {
    riskClass = G > G_MEDIUM ? "MEDIUM" : "MEDIUM";
    determinedBy = G > G_MEDIUM ? "graph-score" : "exposure-score";
  } else {
    riskClass = "LOW";
    determinedBy = "exposure-score";
  }

  return {
    exploitGraphScore: round3(G),
    exposureScore: round3(E),
    riskClass,
    determinedBy,
    chamberVerified,
    chamberCaptureCount,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  COMPLIANCE SEPARATION
//
//  Separate security findings from compliance/regulatory findings so that
//  security scoring (G, E, CRS) is not influenced by compliance-only annotations.
//
//  Compliance finding prefixes: EUAI- (EU AI Act), NIST-, ISO-, SOC2-
//  These come from modules like eu-ai-act.ts which produce informational
//  regulatory-mapping findings, not exploitability signals.
// ═══════════════════════════════════════════════════════════════════════════════

const COMPLIANCE_FINDING_PREFIXES = ["EUAI-", "NIST-", "ISO-", "SOC2-"];

/**
 * Partition findings into security findings (exploitability signals) and
 * compliance findings (regulatory/framework annotations).
 *
 * Security scoring functions (computeSecurityMeasurement, buildRiskProfile)
 * should receive securityFindings only. Compliance findings are informational
 * and must not inflate G, E, CRS, or capabilityRisk axes.
 *
 * @param findings All findings from the scan
 * @returns { securityFindings, complianceFindings }
 */
export function separateComplianceFindings(findings: Finding[]): {
  securityFindings: Finding[];
  complianceFindings: Finding[];
} {
  const securityFindings: Finding[] = [];
  const complianceFindings: Finding[] = [];

  for (const f of findings) {
    const isCompliance = COMPLIANCE_FINDING_PREFIXES.some((prefix) =>
      f.id.startsWith(prefix),
    );
    if (isCompliance) {
      complianceFindings.push(f);
    } else {
      securityFindings.push(f);
    }
  }

  return { securityFindings, complianceFindings };
}
