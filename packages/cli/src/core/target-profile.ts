/**
 * Target Profile System for toolsurf.
 *
 * Classifies scan targets by environment type, allowed scan modes,
 * isolation requirements, and credential strategies. This ensures
 * destructive active modules never run against production targets.
 */

// Environment types — determines what isolation and modes are allowed
export type EnvironmentType = "prod-external" | "test-sandbox" | "local-lab";

// Scan modes — inspired by OWASP ZAP's Safe/Protected/Attack modes
export type ScanMode = "passive-only" | "safe-active" | "full-active";

// Isolation strategies
export type IsolationType = "none" | "docker" | "gvisor" | "firecracker";

// Credential strategies
export type CredentialStrategy =
  | "none"           // No credentials needed
  | "stub"           // Fake credentials + mock backend
  | "sandbox-keys"   // Official vendor sandbox (e.g., Stripe sk_test_*)
  | "scoped-token"   // Real but heavily restricted token (e.g., GitHub fine-grained PAT)
  | "full-access";   // Full credentials (only for local-lab)

// Module risk levels
export type ModuleRiskLevel = "low" | "medium" | "high" | "critical";
export type TargetProfilePreset = "ide" | "ci" | "production";

/**
 * Target profile — describes a scan target's environment and constraints.
 */
export interface TargetProfile {
  /** Human-readable name */
  name: string;
  /** Environment classification */
  environment: EnvironmentType;
  /** Maximum allowed scan mode for this target */
  maxScanMode: ScanMode;
  /** Required isolation level */
  isolation: IsolationType;
  /** Credential strategy */
  credentials: CredentialStrategy;
  /** Whether a mock/shadow backend is available */
  mockBackend?: string;  // e.g., "shadow-mcp", "prism", "gripmock"
  /** Filesystem strategy for isolated execution */
  filesystem?: "host" | "overlayfs" | "tmpfs";
  /** Network egress policy */
  egress?: "unrestricted" | "allowlist-only" | "blocked";
  /** Protocol-specific overrides */
  protocolOverrides?: Record<string, unknown>;
}

/**
 * Module risk classification — maps each module to its operational risk.
 * Used by scan mode enforcement to determine which modules can run.
 */
export const MODULE_RISK_LEVELS: Record<string, ModuleRiskLevel> = {
  // ── Passive modules — all low risk (no tool calls) ──
  "tool-permissions": "low",
  "transport-security": "low",
  "schema-manipulation": "low",
  "context-extraction": "low",
  "secret-leak-detection": "low",
  "resource-prompt-audit": "low",
  "supply-chain-analysis": "low",
  "current-vulnerability-intel": "low",
  "rug-pull-detection": "low",
  "exfiltration-chain": "low",
  "namespace-poisoning": "low",
  "token-exhaustion": "low",
  "agentic-loop-trap": "low",
  "capability-graph": "low",
  "dangerous-capability": "low",
  "description-injection-detector": "low",
  "ipi-susceptibility": "low",
  "handshake-fuzzer": "low",              // passive schema-only CVE check
  "mcp-apps-audit": "low",               // passive XSS/iframe/postMessage analysis
  "discovery-scanner": "low",            // passive discovery endpoint security check
  "eu-ai-act": "low",                    // passive compliance check
  "agent-output-trust": "low",           // passive multi-agent output trust analysis
  "semantic-injection-detector": "low",  // passive semantic description analysis
  // ── Active modules — risk varies ──
  "tool-shadowing": "low",           // Sends invalid inputs → expects 400 errors
  "response-fingerprinting": "low",  // Repeated benign calls only
  "annotation-verifier": "medium",   // Read-only checks are safe; write probes need sandbox
  "auth-boundary-testing": "medium", // Probes scope boundaries; safe with scoped tokens
  "output-injection": "medium",      // Benign tool calls; analyzes returned instructions
  "output-injection-detector": "medium", // Benign calls; detects hidden output directives
  "timing-anomaly": "medium",      // Repeated benign/suspicious timing probes
  "rug-pull-active": "medium",       // Behavioral drift checks; mild on prod
  "agentic-loop-trap-active": "medium", // Can induce loops; needs depth limits
  "active-fuzzer": "high",           // Sends cmd/sql/path/xss payloads
  "context-aware-fuzzer": "high",    // Sends domain-specific cmd/sql/path/network payloads
  "token-exhaustion-active": "high", // Response inflation / DoS risk
  "session-isolation": "high",       // Cross-session data leakage probes — NOT safe on prod
  "session-state-leakage": "high",   // Writes canary state and checks cross-turn/tool leakage
  "state-oracle": "high",            // Writes canary files into chamber workdir; sandbox-only
  "ssrf-detection": "critical",      // Probes internal network / cloud metadata
  "chained-exploit": "critical",     // Read→write exploit chains
  "adversarial-agent": "critical",   // Drives second-order tool calls from hostile chamber content
  "chamber-evidence": "low",         // Reads local chamber capture files after active probes
};

/**
 * Maximum module risk level allowed per scan mode.
 */
const SCAN_MODE_MAX_RISK: Record<ScanMode, ModuleRiskLevel> = {
  "passive-only": "low",
  "safe-active": "medium",
  "full-active": "critical",
};

/**
 * Maximum scan mode allowed per environment type.
 */
const ENVIRONMENT_MAX_MODE: Record<EnvironmentType, ScanMode> = {
  "prod-external": "safe-active",  // Never full-active on prod
  "test-sandbox": "full-active",
  "local-lab": "full-active",
};

/**
 * Risk level ordering for comparison.
 */
const RISK_ORDER: Record<ModuleRiskLevel, number> = {
  "low": 0,
  "medium": 1,
  "high": 2,
  "critical": 3,
};

/**
 * Check if a module is allowed to run under a given scan mode.
 */
export function isModuleAllowed(moduleId: string, scanMode: ScanMode): boolean {
  const moduleRisk = getModuleRiskLevel(moduleId);
  const maxAllowedRisk = SCAN_MODE_MAX_RISK[scanMode];
  return RISK_ORDER[moduleRisk] <= RISK_ORDER[maxAllowedRisk];
}

/**
 * Filter a list of modules to only those allowed by the scan mode.
 */
export function filterModulesByScanMode(
  modules: Array<{ id: string; mode: string }>,
  scanMode: ScanMode
): Array<{ id: string; mode: string }> {
  return modules.filter((mod) => {
    // Passive modules always run
    if (mod.mode === "passive") return true;
    // Active modules filtered by risk level
    return isModuleAllowed(mod.id, scanMode);
  });
}

/**
 * Resolve the effective scan mode from target profile + CLI flag.
 * Takes the minimum of: environment max, profile max, and CLI-requested mode.
 */
export function resolveEffectiveScanMode(
  requested: ScanMode,
  profile?: TargetProfile
): ScanMode {
  if (!profile) return requested;

  const envMax = ENVIRONMENT_MAX_MODE[profile.environment];
  const profileMax = profile.maxScanMode;

  const modes: ScanMode[] = ["passive-only", "safe-active", "full-active"];
  const requestedIdx = modes.indexOf(requested);
  const envIdx = modes.indexOf(envMax);
  const profileIdx = modes.indexOf(profileMax);

  const effectiveIdx = Math.min(requestedIdx, envIdx, profileIdx);
  return modes[effectiveIdx];
}

/**
 * Get the risk level for a module.
 */
export function getModuleRiskLevel(moduleId: string): ModuleRiskLevel {
  return MODULE_RISK_LEVELS[moduleId] ?? "high";
}

/**
 * Create a default target profile for a given environment.
 */
export function createDefaultProfile(
  name: string,
  environment: EnvironmentType
): TargetProfile {
  switch (environment) {
    case "prod-external":
      return {
        name,
        environment,
        maxScanMode: "safe-active",
        isolation: "none",
        credentials: "scoped-token",
        egress: "unrestricted",
      };
    case "test-sandbox":
      return {
        name,
        environment,
        maxScanMode: "full-active",
        isolation: "docker",
        credentials: "sandbox-keys",
        egress: "allowlist-only",
      };
    case "local-lab":
      return {
        name,
        environment,
        maxScanMode: "full-active",
        isolation: "gvisor",
        credentials: "stub",
        filesystem: "overlayfs",
        egress: "blocked",
      };
  }
}

/**
 * Parse a CLI-facing target profile preset.
 *
 * Presets map human-friendly execution contexts onto the internal
 * environment model:
 *   - ide         -> local-lab
 *   - ci          -> test-sandbox
 *   - production  -> prod-external
 */
export function parseTargetProfilePreset(input: string): TargetProfilePreset {
  const normalized = input.toLowerCase().trim();
  switch (normalized) {
    case "ide":
    case "local":
    case "local-lab":
    case "dev":
      return "ide";
    case "ci":
    case "test":
    case "sandbox":
    case "test-sandbox":
      return "ci";
    case "production":
    case "prod":
    case "prod-external":
      return "production";
    default:
      throw new Error(
        `Unknown target profile: "${input}". Valid profiles: ide, ci, production`
      );
  }
}

/**
 * Materialize a preset into a concrete target profile.
 */
export function presetToTargetProfile(preset: TargetProfilePreset): TargetProfile {
  switch (preset) {
    case "ide":
      return createDefaultProfile("ide", "local-lab");
    case "ci":
      return createDefaultProfile("ci", "test-sandbox");
    case "production":
      return createDefaultProfile("production", "prod-external");
  }
}

/**
 * Validate a target profile for consistency.
 */
export function validateProfile(profile: TargetProfile): string[] {
  const errors: string[] = [];

  // Full-active on prod is never allowed
  if (profile.environment === "prod-external" && profile.maxScanMode === "full-active") {
    errors.push("Cannot use full-active scan mode on prod-external targets");
  }

  // gVisor/firecracker only makes sense for local-lab
  if (profile.isolation === "gvisor" || profile.isolation === "firecracker") {
    if (profile.environment === "prod-external") {
      errors.push(`Isolation "${profile.isolation}" is not applicable to prod-external targets`);
    }
  }

  // Full credentials on prod with active scanning is risky
  if (profile.credentials === "full-access" && profile.maxScanMode !== "passive-only") {
    if (profile.environment === "prod-external") {
      errors.push("Full-access credentials on prod-external with active scanning is prohibited");
    }
  }

  // Blocked egress requires local-lab or test-sandbox
  if (profile.egress === "blocked" && profile.environment === "prod-external") {
    errors.push("Cannot block egress on prod-external targets (they need network access)");
  }

  return errors;
}
