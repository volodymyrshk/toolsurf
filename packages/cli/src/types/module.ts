import type { CheckResult } from "./finding.js";
import type { ServerCapabilities, TransportConfig } from "./report.js";

export interface ChamberProbeConfig {
  runDir?: string;
  networkName?: string;
  fakeHttpUrl: string;
  fakeMetadataUrl: string;
  fakeDnsHost: string;
  captures?: {
    http?: string;
    metadata?: string;
    dns?: string;
    smtp?: string;
    /** Promiscuous netflow log — every packet on the chamber bridge. */
    netflow?: string;
  };
  /** IPs operated by the chamber's own services. Anything else seen in the
   *  netflow log is a tool-attempted connection to a non-fake destination. */
  fakeServiceIps?: string[];
  /**
   * State-oracle workdir, when one was provisioned for this chamber. The
   * host path is what modules diff; the container path is what they pass to
   * the target as a tool argument. Undefined means state-oracle is disabled
   * for this run.
   */
  workdir?: {
    hostPath: string;
    containerPath: string;
  };
}

/**
 * Execution mode for audit modules.
 * - passive: Analyzes schemas/metadata only, no tool calls
 * - active:  Makes tool calls to the server (e.g., SSRF probes)
 */
export type ModuleMode = "passive" | "active";

export type PackageEvidenceSource =
  | "serverInfo"
  | "transport"
  | "package-json"
  | "package-lock"
  | "pnpm-lock"
  | "yarn-lock"
  | "requirements"
  | "pyproject"
  | "uv-lock"
  | "go-mod"
  | "pom-xml";

export interface PackageVersionEvidence {
  name: string;
  version?: string;
  /** exact = lockfile/resolved version; range = manifest constraint; unknown = package identity only. */
  versionKind: "exact" | "range" | "unknown";
  ecosystem?: "npm" | "pip" | "gomod" | "maven" | "unknown";
  source: PackageEvidenceSource;
  path?: string;
  raw?: string;
  devDependency?: boolean;
}

/**
 * Context provided to each audit module during execution.
 */
export interface ModuleContext {
  /** Full server capabilities manifest */
  capabilities: ServerCapabilities;
  /** MCP client for making tool calls (only used by active modules) */
  callTool?: (name: string, args: Record<string, unknown>) => Promise<unknown>;
  /** Whether active scanning is enabled */
  activeMode: boolean;
  /** Verbose logging enabled */
  verbose: boolean;
  /** Timeout per active probe in ms (default: 5000) */
  probeTimeout?: number;
  /** Delay between active probes in ms (default: 100) */
  probeDelay?: number;
  /** Progress callback for granular status updates during active scans */
  onProgress?: (message: string) => void;
  /** Custom payloads loaded from --payloads file */
  customPayloads?: Array<{ value: string; label: string }>;
  /**
   * Package/version evidence from repo manifests and lockfiles. Current
   * vulnerability intelligence uses exact evidence for CVE claims and range
   * evidence only for verification warnings.
   */
  packageEvidence?: PackageVersionEvidence[];
  /** Max tools to fuzz per strategy in active-fuzzer (default: 10). Controls how many
   *  tools with matching parameters get tested for oversized input, mutations, etc. */
  maxFuzzTargets?: number;
  /**
   * Maximum output tokens the deployed LLM can emit for a single response.
   * Passive token-exhaustion checks use this to cap theoretical tool-call
   * argument size; direct client/API pass-through remains a separate risk.
   */
  llmOutputTokenLimit?: number;
  /**
   * Abort signal fired when the per-module timeout expires.
   * Active modules MUST check this between probe iterations and return early
   * when aborted — this prevents in-flight fetch calls from keeping the
   * Node.js event loop alive after the module-runner has moved on.
   */
  signal?: AbortSignal;

  /**
   * Tool names that PEAV (Passive Evidence of Active Vulnerability) already
   * identified as having vulnerability evidence from a cheap pre-flight probe.
   * Active modules SHOULD treat these tools as high-interest candidates, not as
   * proof that deeper fuzzing can be skipped.
   */
  peavEvidenceTools?: Set<string>;
  /** @deprecated Use peavEvidenceTools. Kept for older in-tree modules/tests. */
  peavSkipTools?: Set<string>;

  /**
   * Transport configuration used to reach the server. Modules that emit
   * transport-specific findings (e.g. SSE/HTTP-only checks in
   * discovery-scanner DS-004) MUST gate on this — a stdio target is not
   * vulnerable to deprecated HTTP transports.
   */
  transport?: TransportConfig;

  /**
   * Optional detonation chamber endpoints for active modules. When present,
   * active probes should prefer these endpoints because the chamber captures
   * HTTP/SMTP/DNS/metadata attempts as reproducible exploit evidence.
   */
  chamber?: ChamberProbeConfig;
}

/**
 * Abstract interface for all audit modules.
 * Each module implements a specific category of security checks.
 */
export interface AuditModule {
  /** Unique module identifier (e.g., "tool-permissions") */
  id: string;
  /** Human-readable module name */
  name: string;
  /** Short description of what this module checks */
  description: string;
  /** Module version */
  version: string;
  /** Execution mode */
  mode: ModuleMode;

  /**
   * Execute the audit module and return results.
   * @param context - Server capabilities and execution context
   * @returns Array of check results with associated findings
   */
  run(context: ModuleContext): Promise<CheckResult[]>;
}
