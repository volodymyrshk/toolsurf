export {
  Severity,
  CheckStatus,
  type ComplianceControl,
  type Finding,
  type CheckResult,
} from "./finding.js";

export {
  type ModuleMode,
  type ChamberProbeConfig,
  type PackageEvidenceSource,
  type PackageVersionEvidence,
  type ModuleContext,
  type AuditModule,
} from "./module.js";

export {
  type ToolInfo,
  type ResourceInfo,
  type PromptInfo,
  type ServerCapabilities,
  type ReportSummary,
  type ModuleResult,
  type TransportConfig,
  type ScanReport,
} from "./report.js";

export { type ProtocolType } from "../adapters/types.js";

// P3-19 [§ARCH]: Re-export types that were internal-only but needed by consumers
export { type PeavReport } from "../core/peav.js";
export { type ScoringConfig } from "../core/scorer.js";
export { type TargetProfile, type ScanMode } from "../core/target-profile.js";
export {
  type KillChain,
  type KillChainImpact,
  type KillChainProofArtifact,
  type KillChainProofArtifactKind,
  type KillChainProofType,
  type KillChainStage,
  type KillChainStageKind,
  type KillChainStatus,
  type KillChainSummary,
} from "../core/kill-chain.js";

export {
  type ChamberProofBundle,
  type ChamberProofBundleSummary,
  type ChamberProofLineRange,
  type ChamberProofRecord,
} from "../core/chamber-proofs.js";
