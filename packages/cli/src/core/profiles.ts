/**
 * Scan Profiles — named presets that bundle common flag combinations.
 *
 * Simplifies the CLI from 18 flags to a single --profile choice.
 * Profile defaults can be overridden by config file and CLI flags.
 */

export type ProfileName = "quick" | "standard" | "enterprise";

/**
 * Configurable severity weights for the legacy security score calculation.
 * Different profiles can use different calibrations to match their use case.
 */
export interface SeverityWeights {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  INFO: number;
}

export interface ProfileDefaults {
  active: boolean;
  tui: boolean;
  autofix: boolean;
  executiveSummary: boolean;
  compliance?: string[];
  minSeverity?: string;
  verbose: boolean;
  /** Severity weights for legacy score. If omitted, uses scorer defaults. */
  severityWeights?: SeverityWeights;
  /** Diminishing factor for repeated findings. If omitted, uses scorer default (0.7). */
  diminishingFactor?: number;
  /** Max impact per module. If omitted, uses scorer default (40). */
  maxModuleImpact?: number;
}

/**
 * Built-in scan profiles.
 *
 * quick      — passive checks only, fast feedback
 * standard   — passive + active probes for thorough testing
 * enterprise — full suite with compliance, TUI, autofix, exec summary
 */
export const PROFILES: Record<ProfileName, ProfileDefaults> = {
  quick: {
    active: false,
    tui: false,
    autofix: false,
    executiveSummary: false,
    verbose: false,
  },
  standard: {
    active: true,
    tui: false,
    autofix: false,
    executiveSummary: false,
    verbose: false,
  },
  enterprise: {
    active: true,
    tui: true,
    autofix: true,
    executiveSummary: true,
    compliance: ["all"],
    minSeverity: "LOW",
    verbose: false,
    // Enterprise weights are slightly more aggressive on critical/high
    // since enterprise environments have lower risk tolerance
    severityWeights: {
      CRITICAL: 35,
      HIGH: 20,
      MEDIUM: 6,
      LOW: 2,
      INFO: 0,
    },
    diminishingFactor: 0.65,
    maxModuleImpact: 45,
  },
};

/**
 * Type guard for profile names.
 */
export function isProfileName(s: string): s is ProfileName {
  return s === "quick" || s === "standard" || s === "enterprise";
}

/**
 * Resolve a profile name to its defaults.
 * Throws if the name is not a valid profile.
 */
export function resolveProfile(profileName: string): ProfileDefaults {
  if (!isProfileName(profileName)) {
    throw new Error(
      `Unknown profile "${profileName}". Available: quick, standard, enterprise`
    );
  }
  return { ...PROFILES[profileName] };
}
