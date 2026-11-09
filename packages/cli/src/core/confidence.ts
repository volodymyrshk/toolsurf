import type { Finding } from "../types/finding.js";
import type { ModuleResult } from "../types/report.js";
import { ACTIVE_MODULE_IDS } from "./active-module-ids.js";

/**
 * Confidence score assignment for findings.
 *
 * Rather than modifying every module, confidence is assigned post-hoc
 * based on the module type (active vs passive) and finding characteristics.
 *
 * Scale:
 *   0.9–1.0  Active module confirmed exploit (tool accepted malicious input)
 *   0.7–0.8  Active module detected suspicious behavior (timing, state)
 *   0.5–0.6  Passive schema analysis with strong pattern match
 *   0.3–0.4  Passive analysis with weak/heuristic match
 *   0.1–0.2  Reconciled down — passive flagged but active showed server rejects
 */

/** Active module findings that represent confirmed exploits (high confidence) */
const HIGH_CONFIDENCE_ACTIVE_PREFIXES = [
  "AF-001", // Command injection confirmed
  "AF-002", // Path traversal confirmed
  "AF-003", // SQL injection confirmed
  "AF-004", // XSS reflection confirmed
  "AF-005", // Prompt injection confirmed
  "AF-007", // Unicode bypass confirmed
  "SSRF-",  // SSRF confirmed
  "AB-001", // Cross-tool data leakage
  "AB-002", // Privilege escalation
];

/** Active module findings that represent behavioral anomalies (medium-high confidence) */
const MEDIUM_CONFIDENCE_ACTIVE_PREFIXES = [
  "AF-006", // Oversized input accepted (suspicious but not exploit)
  "AF-009", // Mutation fuzzing bypass
  "TS-001", // Schema honesty failure
  "RF-001", // Non-deterministic response
  "RF-002", // Timing variance
  "RF-003", // Stateful behavior
];

/** Passive findings with very high structural evidence — near-certain */
const VERY_STRONG_PASSIVE_PREFIXES = [
  "DC-001", // Arbitrary SQL execution — structural proof
  "DC-002", // Arbitrary code execution — structural proof
  "DC-003", // Arbitrary shell command — structural proof
  "EC-002", // Dual-use tool — structural proof (single tool = source + sink)
  "RD-001", // Rug pull: annotation-schema mismatch — structural proof
  "RD-004", // Hidden undisclosed capabilities — structural proof
  "SL-",    // Secret leak — direct evidence
  "NP-002", // Homoglyph attack — deterministic detection
];

/** Passive findings with strong structural evidence */
const STRONG_PASSIVE_PREFIXES = [
  "CE-002", // Context access (get-env etc.) — structural proof
  "CE-003", // Exfiltration chain — structural proof
  "SM-001", // Prompt injection in descriptions — direct pattern
  "SM-002", // Injection in param descriptions
  "TP-003", // Dangerous tool names — direct match
  "EC-001", // Cross-tool exfiltration chain — graph analysis
  "EC-003", // Capability concentration — graph analysis
  "DC-004", // Unrestricted file access — structural pattern
  "DC-005", // Path traversal susceptibility — schema analysis
  "LT-001", // Self-referential loop instructions — pattern match
  "DI-010", // Token smuggling: encoded/obfuscated payloads
  "DI-MAIN-1", // Tool description injection (direct pattern match)
  "DI-MAIN-2", // Parameter description injection
  "IPI-001", // Web content IPI vector — high certainty
  "IPI-005", // Compound IPI exposure — graph-based analysis
];

/**
 * Assign confidence scores to all findings in module results.
 * Mutates the findings in place.
 */
export function assignConfidence(moduleResults: ModuleResult[]): void {
  for (const result of moduleResults) {
    const isActive = ACTIVE_MODULE_IDS.has(result.moduleId);

    for (const finding of result.findings) {
      if (finding.confidence !== undefined) continue; // already set

      if (isActive) {
        finding.confidence = getActiveConfidence(finding.id);
      } else {
        finding.confidence = getPassiveConfidence(finding.id);
      }
    }

    // Also update check-level findings
    for (const check of result.checks) {
      if (check.finding && check.finding.confidence === undefined) {
        if (isActive) {
          check.finding.confidence = getActiveConfidence(check.finding.id);
        } else {
          check.finding.confidence = getPassiveConfidence(check.finding.id);
        }
      }
    }
  }
}

function getActiveConfidence(findingId: string): number {
  for (const prefix of HIGH_CONFIDENCE_ACTIVE_PREFIXES) {
    if (findingId.startsWith(prefix)) return 0.95;
  }
  for (const prefix of MEDIUM_CONFIDENCE_ACTIVE_PREFIXES) {
    if (findingId.startsWith(prefix)) return 0.75;
  }
  // Default for other active findings
  return 0.85;
}

function getPassiveConfidence(findingId: string): number {
  for (const prefix of VERY_STRONG_PASSIVE_PREFIXES) {
    if (findingId.startsWith(prefix)) return 0.85;
  }
  for (const prefix of STRONG_PASSIVE_PREFIXES) {
    if (findingId.startsWith(prefix)) return 0.7;
  }
  // Default for passive findings — schema heuristic
  return 0.5;
}

/**
 * Filter findings by minimum confidence threshold.
 */
export function filterByConfidence(findings: Finding[], minConfidence: number): Finding[] {
  return findings.filter((f) => (f.confidence ?? 0.5) >= minConfidence);
}
