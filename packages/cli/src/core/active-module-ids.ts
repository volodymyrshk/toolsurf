/**
 * Active module ID set — derived from module metadata at runtime.
 *
 * At scan time, `buildActiveModuleIds()` populates this set from the
 * actual module instances, ensuring it's always in sync with each
 * module's `mode` field (fixing the class of bugs from C-1).
 *
 * The static fallback list ensures tests and utilities that import
 * ACTIVE_MODULE_IDS without running a full scan still get correct values.
 */

import type { AuditModule } from "../types/index.js";

/**
 * All module IDs that perform active testing (make actual tool calls).
 * Used by confidence.ts, scorer.ts Bayesian fusion, and scan.ts reconciliation.
 *
 * Initialized with known active modules as fallback; overridden at runtime
 * by `buildActiveModuleIds()` which reads from actual module metadata.
 */
export let ACTIVE_MODULE_IDS: Set<string> = new Set([
  "active-fuzzer",
  "ssrf-detection",
  "tool-shadowing",
  "response-fingerprinting",
  "auth-boundary-testing",
  "annotation-verifier",
  "chained-exploit",
  "session-isolation",
]);

/**
 * Build the active module ID set from actual module instances.
 * Called during scan initialization — replaces the static fallback
 * with values derived from each module's `mode` field.
 */
export function buildActiveModuleIds(modules: AuditModule[]): void {
  ACTIVE_MODULE_IDS = new Set(
    modules
      .filter(m => m.mode === "active")
      .map(m => m.id)
  );
}
