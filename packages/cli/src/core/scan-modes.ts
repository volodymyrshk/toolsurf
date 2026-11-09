/**
 * Scan Mode Enforcement for toolsurf.
 *
 * Implements ZAP-inspired scan mode system:
 * - passive-only: Schema analysis only, zero tool calls
 * - safe-active: Low-risk active modules (schema validation, benign probes)
 * - full-active: All modules including destructive fuzzers (sandbox required)
 *
 * This module provides the enforcement layer that prevents accidental
 * destructive scans against production targets.
 */

import type { AuditModule } from "../types/module.js";
import {
  type ScanMode,
  type TargetProfile,
  type ModuleRiskLevel,
  resolveEffectiveScanMode,
  isModuleAllowed,
  getModuleRiskLevel,
} from "./target-profile.js";

/**
 * Result of scan mode enforcement — tells the caller what was filtered.
 */
export interface ScanModeEnforcementResult {
  /** The scan mode that was requested */
  requestedMode: ScanMode;
  /** The effective mode after profile/environment clamping */
  effectiveMode: ScanMode;
  /** Whether the mode was downgraded from what was requested */
  wasDowngraded: boolean;
  /** Modules that were allowed through */
  allowedModules: AuditModule[];
  /** Modules that were filtered out (with reasons) */
  filteredModules: Array<{
    module: AuditModule;
    reason: string;
    riskLevel: ModuleRiskLevel;
  }>;
}

/**
 * Enforce scan mode on a set of modules.
 * Returns the filtered module list and details about what was removed.
 */
export function enforceScanMode(
  modules: AuditModule[],
  requestedMode: ScanMode,
  profile?: TargetProfile
): ScanModeEnforcementResult {
  const effectiveMode = resolveEffectiveScanMode(requestedMode, profile);
  const wasDowngraded = effectiveMode !== requestedMode;

  const allowedModules: AuditModule[] = [];
  const filteredModules: ScanModeEnforcementResult["filteredModules"] = [];

  for (const mod of modules) {
    // Passive modules always pass
    if (mod.mode === "passive") {
      allowedModules.push(mod);
      continue;
    }

    // Check if active module's risk level fits the effective mode
    if (isModuleAllowed(mod.id, effectiveMode)) {
      allowedModules.push(mod);
    } else {
      const riskLevel = getModuleRiskLevel(mod.id);
      filteredModules.push({
        module: mod,
        riskLevel,
        reason: `Module risk "${riskLevel}" exceeds "${effectiveMode}" mode limit`,
      });
    }
  }

  return {
    requestedMode,
    effectiveMode,
    wasDowngraded,
    allowedModules,
    filteredModules,
  };
}

/**
 * Convert legacy --active flag to ScanMode.
 * Maintains backward compatibility with existing CLI.
 */
export function legacyActiveToScanMode(active: boolean): ScanMode {
  return active ? "full-active" : "passive-only";
}

/**
 * Parse a scan mode string from CLI input.
 */
export function parseScanMode(input: string): ScanMode {
  const normalized = input.toLowerCase().trim();
  switch (normalized) {
    case "passive":
    case "passive-only":
      return "passive-only";
    case "safe":
    case "safe-active":
      return "safe-active";
    case "full":
    case "full-active":
      return "full-active";
    default:
      throw new Error(
        `Unknown scan mode: "${input}". Valid modes: passive-only, safe-active, full-active`
      );
  }
}

/**
 * Get a human-readable description of a scan mode.
 */
export function describeScanMode(mode: ScanMode): string {
  switch (mode) {
    case "passive-only":
      return "Passive only — schema analysis, no tool calls";
    case "safe-active":
      return "Safe active — low-risk probes (schema validation, benign calls)";
    case "full-active":
      return "Full active — all modules including destructive fuzzers (sandbox recommended)";
  }
}

/**
 * Format enforcement result as a human-readable string for CLI output.
 */
export function formatEnforcementResult(result: ScanModeEnforcementResult): string {
  const lines: string[] = [];

  if (result.wasDowngraded) {
    lines.push(
      `Scan mode downgraded: ${result.requestedMode} → ${result.effectiveMode} (target profile restriction)`
    );
  }

  lines.push(`Effective scan mode: ${describeScanMode(result.effectiveMode)}`);
  lines.push(`Modules allowed: ${result.allowedModules.length}`);

  if (result.filteredModules.length > 0) {
    lines.push(`Modules filtered: ${result.filteredModules.length}`);
    for (const { module, reason } of result.filteredModules) {
      lines.push(`  - ${module.id}: ${reason}`);
    }
  }

  return lines.join("\n");
}
