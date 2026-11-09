import type { AuditModule } from "../types/index.js";
import { ToolPermissionsModule } from "../modules/tool-permissions.js";
import { TransportSecurityModule } from "../modules/transport-security.js";
import { SchemaManipulationModule } from "../modules/schema-manipulation.js";
import { ContextExtractionModule } from "../modules/context-extraction.js";
import { SecretLeakDetectionModule } from "../modules/secret-leak-detection.js";
import { ResourcePromptAuditModule } from "../modules/resource-prompt-audit.js";
import { SupplyChainAnalysisModule } from "../modules/supply-chain-analysis.js";
import { CurrentVulnerabilityIntelModule } from "../modules/current-vulnerability-intel.js";
import { RugPullDetectionModule } from "../modules/rug-pull-detection.js";
import { ExfiltrationChainModule } from "../modules/exfiltration-chain.js";
import { NamespacePoisoningModule } from "../modules/namespace-poisoning.js";
import { TokenExhaustionModule } from "../modules/token-exhaustion.js";
import { AgenticLoopTrapModule } from "../modules/agentic-loop-trap.js";
import { OutputInjectionModule } from "../modules/output-injection.js";
import { ToolCapabilityGraphModule } from "../modules/capability-graph.js";
import { DangerousCapabilityModule } from "../modules/dangerous-capability.js";
import { DescriptionInjectionDetectorModule } from "../modules/description-injection-detector.js";
import { SemanticInjectionDetectorModule } from "../modules/semantic-injection-detector.js";
import { IpiSusceptibilityModule } from "../modules/ipi-susceptibility.js";
import { HandshakeFuzzerModule } from "../modules/handshake-fuzzer.js";
import { McpAppsAuditModule } from "../modules/mcp-apps-audit.js";
import { DiscoveryScannerModule } from "../modules/discovery-scanner.js";
import { EuAiActModule } from "../modules/eu-ai-act.js";
import { AgentOutputTrustModule } from "../modules/agent-output-trust.js";
import { ContextAwareFuzzerModule } from "../modules/context-aware-fuzzer.js";
import { OutputInjectionDetectorModule } from "../modules/output-injection-detector.js";
import { TimingAnomalyDetectorModule } from "../modules/timing-anomaly-detector.js";
import { SessionStateLeakageModule } from "../modules/session-state-leakage.js";
import { SsrfDetectionModule } from "../modules/ssrf-detection.js";
import { ActiveFuzzerModule } from "../modules/active-fuzzer.js";
import { ToolShadowingModule } from "../modules/tool-shadowing.js";
import { ResponseFingerprintingModule } from "../modules/response-fingerprinting.js";
import { AuthBoundaryTestingModule } from "../modules/auth-boundary-testing.js";
import { ChainedExploitModule } from "../modules/chained-exploit.js";
import { AnnotationVerifierModule } from "../modules/annotation-verifier.js";
import { SessionIsolationModule } from "../modules/session-isolation.js";
import { ChamberEvidenceModule } from "../modules/chamber-evidence.js";
import { StateOracleModule } from "../modules/state-oracle.js";
import { AdversarialAgentModule } from "../modules/adversarial-agent.js";

export const MODULE_CATALOG_VERSION = "2026.05-agent-juice-shop";

/**
 * Single source of truth for built-in scanner modules.
 * Keep benchmark, scan execution, list-modules, and hardening checks in sync.
 */
export function createAllModules(): AuditModule[] {
  return [
    new ToolPermissionsModule(),
    new TransportSecurityModule(),
    new SchemaManipulationModule(),
    new ContextExtractionModule(),
    new SecretLeakDetectionModule(),
    new ResourcePromptAuditModule(),
    new SupplyChainAnalysisModule(),
    new CurrentVulnerabilityIntelModule(),
    new RugPullDetectionModule(),
    new ExfiltrationChainModule(),
    new NamespacePoisoningModule(),
    new TokenExhaustionModule(),
    new AgenticLoopTrapModule(),
    new OutputInjectionModule(),
    new ToolCapabilityGraphModule(),
    new DangerousCapabilityModule(),
    new DescriptionInjectionDetectorModule(),
    new SemanticInjectionDetectorModule(),
    new IpiSusceptibilityModule(),
    new HandshakeFuzzerModule(),
    new McpAppsAuditModule(),
    new DiscoveryScannerModule(),
    new EuAiActModule(),
    new AgentOutputTrustModule(),
    new ContextAwareFuzzerModule(),
    new OutputInjectionDetectorModule(),
    new TimingAnomalyDetectorModule(),
    new SessionStateLeakageModule(),
    new SsrfDetectionModule(),
    new ActiveFuzzerModule(),
    new ToolShadowingModule(),
    new ResponseFingerprintingModule(),
    new AuthBoundaryTestingModule(),
    new ChainedExploitModule(),
    new AnnotationVerifierModule(),
    new SessionIsolationModule(),
    // StateOracleModule must run AFTER all write-class modules so its
    // baseline-vs-after diff is bounded to its own probes. It produces a
    // CHAMBER-FS-001 finding when canary-laced files land on disk.
    new StateOracleModule(),
    // AdversarialAgentModule drives the deterministic IPI harness: fetch
    // poisoned chamber → parse __IPI_DIRECTIVE__ → call directed tool →
    // verify chamber-side second-order capture. Runs AFTER state-oracle
    // because both write to the chamber and we want a clean before/after
    // delineation between filesystem proof and cognitive-IPI proof.
    new AdversarialAgentModule(),
    // ChamberEvidenceModule runs LAST. Active modules execute sequentially
    // (see module-runner.ts). By placing it at the end of the active list,
    // every other probe has already had its chance to land captures by the
    // time this synthesizer reads the chamber files.
    new ChamberEvidenceModule(),
  ];
}

export function createPassiveModules(): AuditModule[] {
  return createAllModules().filter((module) => module.mode === "passive");
}

export function createActiveModules(): AuditModule[] {
  return createAllModules().filter((module) => module.mode === "active");
}
