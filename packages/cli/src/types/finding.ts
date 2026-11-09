/**
 * Severity levels for security findings, ordered by impact.
 */
export enum Severity {
  CRITICAL = "CRITICAL",
  HIGH = "HIGH",
  MEDIUM = "MEDIUM",
  LOW = "LOW",
  INFO = "INFO",
}

/**
 * A compliance framework control mapped to a finding.
 */
export interface ComplianceControl {
  /** Framework name (e.g., "NIST SP 800-171", "SOC 2 TSC", "OWASP ASVS") */
  framework: string;
  /** Control identifier (e.g., "3.1.1", "CC6.1", "V5.1") */
  controlId: string;
  /** Human-readable control title */
  controlTitle: string;
  /** Requirement description */
  requirement: string;
}

/**
 * A single security finding discovered during an audit.
 */
export interface Finding {
  /** Unique identifier for this finding (e.g., "TP-001") */
  id: string;
  /** Module that discovered this finding */
  module: string;
  /** Severity level */
  severity: Severity;
  /** Short title describing the finding */
  title: string;
  /** Detailed description of the vulnerability */
  description: string;
  /** Evidence that triggered this finding (tool name, schema excerpt, response data) */
  evidence: Record<string, unknown>;
  /** Remediation guidance */
  remediation: string;
  /** Tool/function/endpoint name involved, if applicable */
  toolName?: string;
  /** CWE ID if mappable */
  cweId?: string;
  /** Compliance controls this finding maps to */
  complianceControls?: ComplianceControl[];
  /**
   * Confidence score (0.0–1.0) indicating how certain we are this is a real issue.
   * - 0.9–1.0: Active module confirmed the vulnerability (exploit succeeded)
   * - 0.6–0.8: Active module detected suspicious behavior
   * - 0.4–0.6: Passive schema analysis pattern match
   * - 0.1–0.3: Reconciled — passive flagged but active probing showed server rejects input
   */
  confidence?: number;
  /** Deduplication group key — findings with the same group are collapsed in reports */
  dedupGroup?: string;
  /** Number of tools/instances affected by this same issue (set on primary finding after dedup) */
  affectedCount?: number;
  /** Tool names affected (set on primary finding after dedup) */
  affectedTools?: string[];
  /** Kill-chain IDs this finding contributes to, when synthesized at report time. */
  killChainIds?: string[];
  /** Structured proof IDs cited by this finding/vendor bundle. */
  proofIds?: string[];
  /** Sensor/proof classes backing this finding (for example outbound-http-callback). */
  proofTypes?: string[];
}

/**
 * Result status for an individual security check within a module.
 */
export enum CheckStatus {
  PASS = "PASS",
  WARN = "WARN",
  FAIL = "FAIL",
  SKIP = "SKIP",
  ERROR = "ERROR",
}

/**
 * A single check result (more granular than a Finding).
 */
export interface CheckResult {
  /** Check identifier */
  id: string;
  /** Human-readable check name */
  name: string;
  /** Result status */
  status: CheckStatus;
  /** Optional message with details */
  message?: string;
  /** Associated finding if status is WARN or FAIL */
  finding?: Finding;
}
