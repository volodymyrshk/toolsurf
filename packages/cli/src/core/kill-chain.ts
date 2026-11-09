import { existsSync, statSync } from "node:fs";
import type { ProtocolType } from "../adapters/types.js";
import type { ChamberReachabilityResult } from "./chamber-runtime.js";
import { Severity, type Finding } from "../types/finding.js";
import type { ScanReport, ServerCapabilities } from "../types/report.js";

export type KillChainStatus = "complete" | "partial" | "blocked";

export type KillChainStageKind =
  | "entrypoint"
  | "attacker-control"
  | "capability"
  | "chamber-sensor"
  | "proof"
  | "impact";

export type KillChainImpact =
  | "ssrf"
  | "ipi-relay"
  | "exfiltration"
  | "state-corruption"
  | "unknown";

export type KillChainProofType =
  | "outbound-http-callback"
  | "cloud-metadata-callback"
  | "dns-resolution-callback"
  | "smtp-callback"
  | "non-fake-netflow"
  | "agent-triggered-callback"
  | "state-delta"
  | "static-chain";

export type KillChainProofArtifactKind =
  | "http-capture"
  | "metadata-capture"
  | "dns-capture"
  | "smtp-capture"
  | "netflow-capture"
  | "state-diff"
  | "filesystem-diff"
  | "replay-transcript";

export interface KillChainProofArtifact {
  proofId: string;
  proofType: KillChainProofType;
  kind: KillChainProofArtifactKind;
  path: string;
  findingIds: string[];
  downloadable: true;
  canary?: string;
}

export interface KillChainStage {
  kind: KillChainStageKind;
  status: KillChainStatus;
  label: string;
  findingIds?: string[];
  evidence?: Record<string, unknown>;
}

/**
 * Explains why a chain was demoted to "partial" when it would otherwise have
 * been "complete". Only set when the demotion reason is actionable.
 *
 * - "hollow-capture": one or more captureFile paths referenced by findings
 *   exist in the finding evidence but are either missing on disk or are empty
 *   (0 bytes). The chain cannot be treated as complete without a non-empty
 *   artifact file.
 */
export type KillChainDeterminedBy = "hollow-capture";

export interface KillChain {
  id: string;
  title: string;
  status: KillChainStatus;
  /**
   * Set only when `status` is "partial" and the demotion was caused by a
   * specific, diagnosable artifact problem rather than simply an absent proof.
   * Research reporters should surface this prominently so hollow captures are
   * never silently counted as evidence.
   */
  determinedBy?: KillChainDeterminedBy;
  impact: KillChainImpact;
  severity: Severity;
  /**
   * Only set for partial chains. Completed chains are deterministic and must
   * be backed by proofArtifacts; they do not carry heuristic confidence.
   */
  confidence?: number;
  protocol?: ProtocolType;
  toolNames: string[];
  findingIds: string[];
  proofTypes: KillChainProofType[];
  proofArtifacts: KillChainProofArtifact[];
  stages: KillChainStage[];
  summary: string;
  whatWorked: string[];
  whatDidNotWork: string[];
}

export interface KillChainSummary {
  chains: KillChain[];
  total: number;
  completed: number;
  partial: number;
  blocked: number;
  highestSeverity: Severity | "NONE";
  proofTypes: KillChainProofType[];
}

export interface BuildKillChainsInput {
  reportId: string;
  protocol?: ProtocolType;
  capabilities: ServerCapabilities;
  findings: Finding[];
  chamberReachability?: ChamberReachabilityResult;
  chamberSummary?: ScanReport["chamberSummary"];
}

type ChamberSummary = NonNullable<ScanReport["chamberSummary"]>;

const SEVERITY_RANK: Record<Severity, number> = {
  [Severity.INFO]: 1,
  [Severity.LOW]: 2,
  [Severity.MEDIUM]: 3,
  [Severity.HIGH]: 4,
  [Severity.CRITICAL]: 5,
};

const STATUS_RANK: Record<KillChainStatus, number> = {
  complete: 3,
  partial: 2,
  blocked: 1,
};

const CHAMBER_NETWORK_PREFIXES = [
  "CHAMBER-HTTP",
  "CHAMBER-METADATA",
  "CHAMBER-DNS",
  "CHAMBER-SMTP",
  "CHAMBER-NETFLOW",
  "AF-CHAMBER",
];

/**
 * Build deterministic kill chains from existing findings and chamber evidence.
 *
 * This is intentionally side-effect free: it does not run probes, read capture
 * files, or mutate findings. Active modules remain responsible for producing
 * evidence; this layer turns that evidence into an attack-path narrative.
 */
export function buildKillChains(input: BuildKillChainsInput): KillChainSummary {
  const chains: KillChain[] = [];
  const findings = input.findings ?? [];
  const chamberNetworkFindings = findings.filter(isChamberNetworkFinding);
  const ipiFindings = findings.filter(
    (f) => f.id === "CHAMBER-IPI-RELAY-001" || isSecondOrderIpiFinding(f),
  );
  const exfilFindings = findings.filter(isExfilFinding);
  const stateFindings = findings.filter(isStateFinding);
  const chamberStateFindings = findings.filter(isChamberStateFinding);

  if (chamberNetworkFindings.length > 0) {
    chains.push(buildOutboundChain(input, chamberNetworkFindings));
  }

  if (ipiFindings.length > 0) {
    chains.push(buildIpiChain(input, ipiFindings));
  }

  if (
    exfilFindings.length > 0 ||
    hasConfirmedExfil(input.chamberSummary) ||
    chamberNetworkFindings.some(isChamberEgressFinding)
  ) {
    chains.push(buildExfilChain(input, exfilFindings, chamberNetworkFindings));
  }

  if (stateFindings.length > 0 || chamberStateFindings.length > 0) {
    chains.push(buildStateChain(input, stateFindings, chamberStateFindings));
  }

  if (shouldBuildBlockedChamberChain(input, chamberNetworkFindings)) {
    chains.push(buildBlockedChamberChain(input));
  }

  const sorted = chains.sort(compareChains);
  const proofTypes = unique(sorted.flatMap((chain) => chain.proofTypes));

  return {
    chains: sorted,
    total: sorted.length,
    completed: sorted.filter((chain) => chain.status === "complete").length,
    partial: sorted.filter((chain) => chain.status === "partial").length,
    blocked: sorted.filter((chain) => chain.status === "blocked").length,
    highestSeverity: highestSeverity(sorted.map((chain) => chain.severity)) ?? "NONE",
    proofTypes,
  };
}

function buildOutboundChain(
  input: BuildKillChainsInput,
  findings: Finding[],
): KillChain {
  const { artifacts: proofArtifacts, hadHollowCapture } = buildProofArtifacts("KC-SSRF-001", findings, input.chamberSummary);
  const status: KillChainStatus = proofArtifacts.length > 0 ? "complete" : "partial";
  const determinedBy: KillChainDeterminedBy | undefined = status === "partial" && hadHollowCapture ? "hollow-capture" : undefined;
  const proofTypes = status === "complete"
    ? unique(proofArtifacts.map((artifact) => artifact.proofType))
    : ["static-chain" as KillChainProofType];
  const toolNames = collectToolNames(findings, input.chamberSummary);
  const findingIds = findings.map((f) => f.id);
  const sensors = proofTypes.map(formatProofType);
  const hasCanary = findings.some(hasCanaryEvidence) || hasConfirmedExfil(input.chamberSummary);
  const severity = highestSeverity(findings.map((f) => f.severity)) ?? Severity.HIGH;

  // Per-variant progression: read every (variant, sink, canary, tool, param)
  // tuple off the AF-CHAMBER-* findings and render one chamber-sensor stage
  // per tuple, ordered Seed → Escalation. This turns the chain output from
  // a single "captured by X, Y" line into the linear progression that
  // matches what the probe-escalator actually fired.
  const variantStages = buildVariantProgressionStages(findings);
  const sensorStages: KillChainStage[] =
    variantStages.length > 0
      ? variantStages
      : [
          {
            kind: "chamber-sensor",
            status,
            label: `Captured by ${sensors.join(", ")}.`,
            findingIds,
          },
        ];

  return {
    id: "KC-SSRF-001",
    title: status === "complete"
      ? "Attacker-controlled outbound request reached chamber sensors"
      : "Outbound request signal needs a downloadable proof artifact",
    status,
    ...(determinedBy ? { determinedBy } : {}),
    impact: "ssrf",
    severity,
    ...(status === "partial" ? { confidence: maxConfidence(findings, hasCanary ? 0.8 : 0.65) } : {}),
    protocol: input.protocol,
    toolNames,
    findingIds,
    proofTypes,
    proofArtifacts,
    stages: [
      makeEntryStage(input, toolNames, status, findingIds),
      {
        kind: "attacker-control",
        status: status === "complete" && hasCanary ? "complete" : "partial",
        label: hasCanary
          ? "Scanner canary or active probe data appeared in chamber evidence."
          : "Target reached the chamber, but direct canary correlation was not available.",
        findingIds,
      },
      {
        kind: "capability",
        status: "complete",
        label: "Target runtime issued outbound network traffic.",
        findingIds,
      },
      ...sensorStages,
      {
        kind: "proof",
        status,
        label: status === "complete"
          ? "Captured chamber evidence is attached as downloadable proof artifacts."
          : "A chamber signal exists, but no downloadable proof artifact was linked.",
        findingIds,
        evidence: collectCaptureEvidence(findings, proofArtifacts),
      },
      {
        kind: "impact",
        status,
        label: status === "complete"
          ? "Attacker input can steer the target toward sandbox-controlled infrastructure."
          : "The scanner cannot claim a completed outbound chain without an artifact.",
        findingIds,
      },
    ],
    summary: status === "complete"
      ? "The target produced observable chamber callbacks during active probing, and the chain references downloadable proof artifacts."
      : "The target produced chamber-related signal, but the chain is partial because no proof artifact was linked.",
    whatWorked: status === "complete"
      ? [
          "The chamber received network traffic from the target.",
          "The chain includes downloadable proof artifacts.",
        ]
      : ["The scanner observed chamber-related outbound behavior."],
    whatDidNotWork: [
      ...(hasCanary
        ? []
        : ["The scanner could not correlate every callback to a specific planted canary."]),
      ...(status === "complete"
        ? []
        : ["No downloadable proof artifact was attached to the chain."]),
    ],
  };
}

function buildIpiChain(input: BuildKillChainsInput, findings: Finding[]): KillChain {
  const finding = findings[0];
  const secondOrderFindings = findings.filter(isSecondOrderIpiFinding);
  const { artifacts: proofArtifacts, hadHollowCapture } = buildProofArtifacts("KC-IPI-001", secondOrderFindings, input.chamberSummary);
  const status: KillChainStatus = proofArtifacts.length > 0 ? "complete" : "partial";
  const determinedBy: KillChainDeterminedBy | undefined = status === "partial" && hadHollowCapture ? "hollow-capture" : undefined;
  const toolNames = collectToolNames(findings, input.chamberSummary);
  const findingIds = findings.map((f) => f.id);
  const severity = highestSeverity(findings.map((f) => f.severity)) ?? Severity.HIGH;

  return {
    id: "KC-IPI-001",
    title: status === "complete"
      ? "Hostile chamber content triggered a sensor-observed action"
      : "Hostile chamber content was relayed into scanner-visible output",
    status,
    ...(determinedBy ? { determinedBy } : {}),
    impact: "ipi-relay",
    severity,
    ...(status === "partial" ? { confidence: maxConfidence(findings, 0.75) } : {}),
    protocol: input.protocol,
    toolNames,
    findingIds,
    proofTypes: status === "complete"
      ? unique(proofArtifacts.map((artifact) => artifact.proofType))
      : ["static-chain"],
    proofArtifacts,
    stages: [
      makeEntryStage(input, toolNames, toolNames.length > 0 ? "complete" : "partial", findingIds),
      {
        kind: "attacker-control",
        status: "complete",
        label: "Scanner supplied a chamber URL that returned hostile content.",
        findingIds,
      },
      {
        kind: "capability",
        status: "complete",
        label: "Target fetched attacker-controlled HTTP content.",
        findingIds,
      },
      {
        kind: "chamber-sensor",
        status,
        label: status === "complete"
          ? "A second-order attacker-controlled action reached a chamber sensor."
          : "fake-http emitted a poison token, but no second-order chamber callback was observed.",
        findingIds,
      },
      {
        kind: "proof",
        status,
        label: status === "complete"
          ? "The injected content caused an artifact-backed sensor callback."
          : "The poison token was observed in scanner-visible tool output only; this is not sensor-bound proof.",
        findingIds,
        evidence: {
          hits: finding?.evidence?.hits,
          ...collectCaptureEvidence(secondOrderFindings, proofArtifacts),
        },
      },
      {
        kind: "impact",
        status,
        label: status === "complete"
          ? "Attacker-controlled upstream content caused the agent/tool runtime to perform an observable action."
          : "Attacker-controlled upstream content can enter tool output, but downstream execution was not proven.",
        findingIds,
      },
    ],
    summary: status === "complete"
      ? "The chamber-hosted poison content caused a later chamber-observed action, completing a sensor-bound IPI chain."
      : "The tool relayed the chamber poison marker into scanner-visible output. That is useful active evidence, but the IPI kill chain remains partial until the injected content causes a chamber-observed action.",
    whatWorked: [
      "The target fetched a chamber-controlled URL.",
      "The poisoned response crossed back into scanner-visible tool output.",
    ],
    whatDidNotWork: status === "complete"
      ? []
      : ["No second-order chamber sensor callback was caused by the poisoned content."],
  };
}

function buildExfilChain(
  input: BuildKillChainsInput,
  exfilFindings: Finding[],
  chamberNetworkFindings: Finding[],
): KillChain {
  const completedFindings = [
    ...exfilFindings,
    ...chamberNetworkFindings.filter(isChamberEgressFinding),
  ];
  const chainFindings = uniqueFindings(completedFindings.length > 0 ? completedFindings : exfilFindings);
  const { artifacts: proofArtifacts, hadHollowCapture } = buildProofArtifacts("KC-EXFIL-001", chainFindings, input.chamberSummary);
  const hasProof = proofArtifacts.length > 0;
  const findingIds = chainFindings.map((f) => f.id);
  const proofTypes = hasProof
    ? unique(proofArtifacts.map((artifact) => artifact.proofType))
    : ["static-chain" as KillChainProofType];
  const status: KillChainStatus = hasProof ? "complete" : "partial";
  const determinedBy: KillChainDeterminedBy | undefined = status === "partial" && hadHollowCapture ? "hollow-capture" : undefined;
  const toolNames = collectToolNames(chainFindings, input.chamberSummary);
  const severity = highestSeverity(chainFindings.map((f) => f.severity)) ?? Severity.MEDIUM;

  return {
    id: "KC-EXFIL-001",
    title: hasProof
      ? "Cross-boundary exfiltration path has chamber evidence"
      : "Potential cross-tool exfiltration path needs chamber proof",
    status,
    ...(determinedBy ? { determinedBy } : {}),
    impact: "exfiltration",
    severity,
    ...(status === "partial" ? { confidence: maxConfidence(chainFindings, 0.65) } : {}),
    protocol: input.protocol,
    toolNames,
    findingIds,
    proofTypes,
    proofArtifacts,
    stages: [
      makeEntryStage(input, toolNames, toolNames.length > 0 ? "complete" : "partial", findingIds),
      {
        kind: "attacker-control",
        status: hasProof ? "complete" : "partial",
        label: hasProof
          ? "Scanner-controlled payloads reached an egress sensor."
          : "Static analysis found source/sink composition but no egress proof yet.",
        findingIds,
      },
      {
        kind: "capability",
        status: "complete",
        label: "Target exposes a data source, egress sink, or both.",
        findingIds,
      },
      {
        kind: "chamber-sensor",
        status: hasProof ? "complete" : "partial",
        label: hasProof
          ? "Chamber captured the egress path."
          : "No chamber callback has been linked to this chain yet.",
        findingIds,
      },
      {
        kind: "proof",
        status: hasProof ? "complete" : "partial",
        label: hasProof
          ? "Capture-backed evidence exists for at least one egress hop."
          : "Only static or module-level evidence is available.",
        findingIds,
        evidence: collectCaptureEvidence(chainFindings, proofArtifacts),
      },
      {
        kind: "impact",
        status,
        label: hasProof
          ? "Data can leave the target boundary through an attacker-observable channel."
          : "The exposed capabilities could form an exfiltration path if the runtime permits composition.",
        findingIds,
      },
    ],
    summary: hasProof
      ? "The scanner found an egress path and the chamber recorded matching evidence, completing an exfiltration kill chain."
      : "The scanner found source/sink composition but lacks chamber evidence, so the exfiltration chain remains partial.",
    whatWorked: hasProof
      ? ["Chamber evidence confirms at least one outbound egress hop."]
      : ["Static modules identified a plausible source/sink composition."],
    whatDidNotWork: hasProof
      ? []
      : ["No chamber sensor observed the full exfiltration path during this scan."],
  };
}

function buildStateChain(
  input: BuildKillChainsInput,
  stateFindings: Finding[],
  chamberStateFindings: Finding[],
): KillChain {
  const chainFindings = uniqueFindings([...chamberStateFindings, ...stateFindings]);
  const { artifacts: proofArtifacts, hadHollowCapture } = buildProofArtifacts("KC-STATE-001", chamberStateFindings, input.chamberSummary);
  const hasProof = proofArtifacts.length > 0;
  const findingIds = chainFindings.map((f) => f.id);
  const toolNames = collectToolNames(chainFindings, input.chamberSummary);
  const status: KillChainStatus = hasProof ? "complete" : "partial";
  const determinedBy: KillChainDeterminedBy | undefined = status === "partial" && hadHollowCapture ? "hollow-capture" : undefined;

  return {
    id: "KC-STATE-001",
    title: hasProof
      ? "State mutation chain has oracle proof"
      : "State mutation or annotation-mismatch chain needs oracle proof",
    status,
    ...(determinedBy ? { determinedBy } : {}),
    impact: "state-corruption",
    severity: highestSeverity(chainFindings.map((f) => f.severity)) ?? Severity.MEDIUM,
    ...(status === "partial" ? { confidence: maxConfidence(chainFindings, 0.65) } : {}),
    protocol: input.protocol,
    toolNames,
    findingIds,
    proofTypes: hasProof ? ["state-delta"] : ["static-chain"],
    proofArtifacts,
    stages: [
      makeEntryStage(input, toolNames, toolNames.length > 0 ? "complete" : "partial", findingIds),
      {
        kind: "attacker-control",
        status: "partial",
        label: "Scanner identified stateful or annotation-sensitive behavior.",
        findingIds,
      },
      {
        kind: "capability",
        status: "complete",
        label: "Target exposes a stateful capability or safety-annotation mismatch.",
        findingIds,
      },
      {
        kind: "chamber-sensor",
        status,
        label: hasProof
          ? "State/fs oracle produced a delta."
          : "State/fs oracle proof is not available in this scan.",
        findingIds,
      },
      {
        kind: "proof",
        status,
        label: hasProof
          ? "State delta proof is attached to the referenced finding."
          : "Only module evidence is available; run with state/fs oracles to complete the chain.",
        findingIds,
        evidence: collectCaptureEvidence(chamberStateFindings, proofArtifacts),
      },
      {
        kind: "impact",
        status,
        label: hasProof
          ? "Attacker-controlled input caused observable state mutation."
          : "The target may mutate or leak state, but this scan did not prove the mutation boundary.",
        findingIds,
      },
    ],
    summary: hasProof
      ? "A state or filesystem oracle observed mutation, completing a state-corruption kill chain."
      : "The scanner found stateful risk, but the current chamber run did not include oracle proof, so the chain remains partial.",
    whatWorked: ["Modules identified stateful behavior worth validating."],
    whatDidNotWork: hasProof ? [] : ["No state/fs oracle delta was attached to this report."],
  };
}

function buildBlockedChamberChain(input: BuildKillChainsInput): KillChain {
  const reach = input.chamberReachability!;
  return {
    id: "KC-CHAMBER-BLOCKED-001",
    title: "Chamber evidence path was not verified",
    status: "blocked",
    impact: "unknown",
    severity: Severity.INFO,
    protocol: input.protocol,
    toolNames: [],
    findingIds: [],
    proofTypes: [],
    proofArtifacts: [],
    stages: [
      makeEntryStage(input, [], "partial", []),
      {
        kind: "attacker-control",
        status: "partial",
        label: "The scanner could not identify or complete a reachability probe.",
      },
      {
        kind: "capability",
        status: "partial",
        label: "Target behavior may still be probeable, but chamber placement was not proven.",
      },
      {
        kind: "chamber-sensor",
        status: "blocked",
        label: `Reachability status: ${reach.status}.`,
        evidence: {
          reason: reach.reason,
          method: reach.method,
          captureFile: reach.captureFile,
        },
      },
      {
        kind: "proof",
        status: "blocked",
        label: "No chamber-backed proof can be claimed until target-to-chamber reachability is verified.",
      },
      {
        kind: "impact",
        status: "blocked",
        label: "Absence of chamber captures should not be interpreted as absence of exploitability.",
      },
    ],
    summary:
      "The scan used a chamber, but the target did not prove it could reach chamber sensors. Treat chamber-backed negative results as blocked, not clean.",
    whatWorked: [],
    whatDidNotWork: [reach.reason],
  };
}

function makeEntryStage(
  input: BuildKillChainsInput,
  toolNames: string[],
  status: KillChainStatus,
  findingIds: string[],
): KillChainStage {
  const surface =
    toolNames.length > 0
      ? `${toolNames.slice(0, 5).join(", ")}${toolNames.length > 5 ? "..." : ""}`
      : `${input.capabilities.tools.length} discovered tool(s)`;
  return {
    kind: "entrypoint",
    status,
    label: `Entrypoint surface: ${surface}.`,
    findingIds,
    evidence: {
      protocol: input.protocol ?? input.capabilities.protocol ?? "unknown",
      toolCount: input.capabilities.tools.length,
    },
  };
}

function shouldBuildBlockedChamberChain(
  input: BuildKillChainsInput,
  chamberNetworkFindings: Finding[],
): boolean {
  const reach = input.chamberReachability;
  if (!reach) return false;
  if (reach.verified) return false;
  return chamberNetworkFindings.length === 0;
}

function isChamberNetworkFinding(finding: Finding): boolean {
  return CHAMBER_NETWORK_PREFIXES.some((prefix) => finding.id.startsWith(prefix));
}

function isChamberStateFinding(finding: Finding): boolean {
  return finding.id.startsWith("CHAMBER-STATE") || finding.id.startsWith("CHAMBER-FS");
}

function isExfilFinding(finding: Finding): boolean {
  return (
    finding.id.startsWith("EC-") ||
    finding.id.startsWith("CE-") ||
    finding.id.startsWith("CTX-") ||
    finding.id.startsWith("SL-")
  );
}

function isStateFinding(finding: Finding): boolean {
  return (
    finding.id.startsWith("AV-") ||
    finding.id.startsWith("RD-") ||
    finding.id.startsWith("SI-") ||
    finding.id.startsWith("SSL-")
  );
}

function isChamberBacked(finding: Finding): boolean {
  const verifiedBy = String(finding.evidence?.verifiedBy ?? "");
  return (
    finding.id.startsWith("CHAMBER-") ||
    finding.id.startsWith("AF-CHAMBER") ||
    verifiedBy.includes("chamber")
  );
}

function isChamberEgressFinding(finding: Finding): boolean {
  return finding.id.startsWith("AF-CHAMBER") || finding.id === "CHAMBER-SMTP-001";
}

function isSecondOrderIpiFinding(finding: Finding): boolean {
  const verifiedBy = String(finding.evidence?.verifiedBy ?? "");
  return (
    finding.id.startsWith("CHAMBER-IPI-ACTION") ||
    finding.id.startsWith("AF-CHAMBER-IPI-ACTION") ||
    verifiedBy === "chamber-ipi-action"
  );
}

/**
 * Per-variant progression renderer (Item 3 follow-up).
 *
 * Reads every (variant, sink, canary, tool, paramName) tuple off the
 * AF-CHAMBER-* findings and emits an ordered list of chamber-sensor stages.
 * Order is: seed (variant === "plain" or "shell-curl-multi") first, then
 * escalation steps in the order they appear in the source captures.
 *
 * Returns [] when no per-variant captures are available — caller falls back
 * to the legacy single-stage rendering.
 */
function buildVariantProgressionStages(findings: Finding[]): KillChainStage[] {
  interface VariantCapture {
    variant: string;
    sink: string;
    canary?: string;
    payload?: string;
    tool?: string;
    paramName?: string;
    findingId: string;
  }
  const SEED_VARIANTS = new Set(["plain", "shell-curl-multi", "shell-backtick"]);

  const captures: VariantCapture[] = [];
  for (const finding of findings) {
    // active-fuzzer's AF-CHAMBER-* findings carry per-variant captures here.
    const evCaptures = finding.evidence?.captures as Array<Record<string, unknown>> | undefined;
    if (!Array.isArray(evCaptures)) continue;
    for (const capture of evCaptures) {
      const variant = String(capture.payloadVariant ?? capture.variant ?? "");
      const sink = String(capture.sink ?? "");
      if (!variant || !sink) continue;
      captures.push({
        variant,
        sink,
        canary: typeof capture.canary === "string" ? capture.canary : undefined,
        payload: typeof capture.payload === "string" ? capture.payload : undefined,
        tool: typeof capture.tool === "string" ? capture.tool : undefined,
        paramName: typeof capture.paramName === "string" ? capture.paramName : undefined,
        findingId: finding.id,
      });
    }
  }

  if (captures.length === 0) return [];

  // Stable ordering: seed first, then escalations preserving source order.
  const seeds: VariantCapture[] = [];
  const escalations: VariantCapture[] = [];
  for (const c of captures) {
    if (SEED_VARIANTS.has(c.variant)) seeds.push(c);
    else escalations.push(c);
  }

  // Dedup within each group by (variant, sink, canary) so multi-finding
  // overlap (e.g., AF-CHAMBER-HTTP and AF-CHAMBER-DNS both reference the
  // same canary) collapses to a single stage.
  const dedup = (xs: VariantCapture[]): VariantCapture[] => {
    const seen = new Set<string>();
    const out: VariantCapture[] = [];
    for (const x of xs) {
      const key = `${x.variant}|${x.sink}|${x.canary ?? ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(x);
    }
    return out;
  };

  const ordered = [...dedup(seeds), ...dedup(escalations)];

  return ordered.map((c, index) => {
    const role = SEED_VARIANTS.has(c.variant) ? "Seed" : "Escalation";
    const target = c.tool && c.paramName ? `${c.tool}.${c.paramName}` : (c.tool ?? "");
    const label =
      `${role} [${c.variant}] → ${formatSinkLabel(c.sink)}` +
      (target ? ` on ${target}` : "");
    return {
      kind: "chamber-sensor" as const,
      status: "complete" as const,
      label,
      findingIds: [c.findingId],
      evidence: {
        progressionIndex: index,
        role: role.toLowerCase(),
        variant: c.variant,
        sink: c.sink,
        ...(c.canary ? { canary: c.canary } : {}),
        ...(c.payload ? { payload: c.payload } : {}),
        ...(target ? { target } : {}),
      },
    };
  });
}

function formatSinkLabel(sink: string): string {
  switch (sink) {
    case "http": return "fake-http";
    case "metadata": return "fake-metadata";
    case "dns": return "fake-dns";
    case "smtp": return "fake-smtp";
    case "netflow": return "netflow";
    default: return sink;
  }
}

function hasCanaryEvidence(finding: Finding): boolean {
  const ev = finding.evidence ?? {};
  const canaryTokens = ev.canaryTokens as unknown[] | undefined;
  const captures = ev.captures as unknown[] | undefined;
  const hits = ev.hits as unknown[] | undefined;
  return Boolean(
    (Array.isArray(canaryTokens) && canaryTokens.length > 0) ||
      (Array.isArray(captures) && captures.length > 0) ||
      (Array.isArray(hits) && hits.length > 0),
  );
}

function hasConfirmedExfil(summary: ChamberSummary | undefined): boolean {
  return Boolean(summary?.confirmedExfil && summary.confirmedExfil.length > 0);
}

function proofTypesForFinding(finding: Finding): KillChainProofType[] {
  const ids: KillChainProofType[] = [];
  if (finding.id.includes("METADATA")) ids.push("cloud-metadata-callback");
  if (finding.id.includes("HTTP")) ids.push("outbound-http-callback");
  if (finding.id.includes("DNS")) ids.push("dns-resolution-callback");
  if (finding.id.includes("SMTP")) ids.push("smtp-callback");
  if (finding.id.includes("NETFLOW")) ids.push("non-fake-netflow");
  if (isSecondOrderIpiFinding(finding)) ids.push("agent-triggered-callback");
  if (isChamberStateFinding(finding)) ids.push("state-delta");
  if (ids.length === 0 && isChamberBacked(finding)) ids.push("outbound-http-callback");
  if (ids.length === 0) ids.push("static-chain");
  return unique(ids);
}

function formatProofType(proofType: KillChainProofType): string {
  switch (proofType) {
    case "outbound-http-callback": return "fake-http";
    case "cloud-metadata-callback": return "fake-metadata";
    case "dns-resolution-callback": return "fake-dns";
    case "smtp-callback": return "fake-smtp";
    case "non-fake-netflow": return "netflow";
    case "agent-triggered-callback": return "second-order chamber callback";
    case "state-delta": return "state/fs oracle";
    case "static-chain": return "static analysis";
  }
}

/**
 * Returns true when `path` refers to a file that exists on disk AND has at
 * least 1 byte of content.  An empty file is treated as absent: a capture
 * writer that opens/closes a file without writing anything produces a 0-byte
 * file that is indistinguishable from a missing file for evidentiary purposes.
 */
function captureFileIsSubstantive(path: string): boolean {
  try {
    if (!existsSync(path)) return false;
    const st = statSync(path);
    return st.isFile() && st.size > 0;
  } catch {
    return false;
  }
}

export interface BuildProofArtifactsResult {
  artifacts: KillChainProofArtifact[];
  /**
   * True when at least one captureFile path was referenced by finding evidence
   * but failed the substantive-file check (missing on disk or 0 bytes). This
   * is distinct from simply having no captureFile at all.
   */
  hadHollowCapture: boolean;
}

function buildProofArtifacts(
  chainId: string,
  findings: Finding[],
  chamberSummary: ChamberSummary | undefined,
): BuildProofArtifactsResult {
  const candidates: Array<Omit<KillChainProofArtifact, "proofId" | "downloadable">> = [];
  let hadHollowCapture = false;

  for (const finding of findings) {
    const findingIds = [finding.id];
    const captureFile = finding.evidence?.captureFile;
    if (typeof captureFile === "string" && captureFile.length > 0) {
      if (captureFileIsSubstantive(captureFile)) {
        candidates.push({
          proofType: primaryProofTypeForFinding(finding),
          kind: artifactKindForFinding(finding),
          path: captureFile,
          findingIds,
          canary: firstCanary(finding),
        });
      } else {
        // The finding references a captureFile path but the file is absent or
        // empty on disk.  Flag this so callers can demote the chain to partial
        // with determinedBy="hollow-capture" rather than silently promoting it.
        hadHollowCapture = true;
      }
    }

    const sink = finding.evidence?.sink;
    if (typeof sink === "string") {
      const artifact = artifactForSink(sink, findingIds, chamberSummary, firstCanary(finding));
      if (artifact) candidates.push(artifact);
    }

    const captures = finding.evidence?.captures as Array<Record<string, unknown>> | undefined;
    if (Array.isArray(captures)) {
      for (const capture of captures) {
        const captureSink = capture.sink;
        if (typeof captureSink !== "string") continue;
        const artifact = artifactForSink(
          captureSink,
          findingIds,
          chamberSummary,
          typeof capture.canary === "string" ? capture.canary : firstCanary(finding),
        );
        if (artifact) candidates.push(artifact);
      }
    }

    const stateDiffPath = finding.evidence?.stateDiffFile ?? finding.evidence?.fsDiffFile;
    if (typeof stateDiffPath === "string" && stateDiffPath.length > 0) {
      if (captureFileIsSubstantive(stateDiffPath)) {
        candidates.push({
          proofType: "state-delta",
          kind: finding.id.startsWith("CHAMBER-FS") ? "filesystem-diff" : "state-diff",
          path: stateDiffPath,
          findingIds,
        });
      } else {
        hadHollowCapture = true;
      }
    }
  }

  const deduped = new Map<string, Omit<KillChainProofArtifact, "proofId" | "downloadable">>();
  for (const candidate of candidates) {
    const key = `${candidate.kind}:${candidate.path}:${candidate.findingIds.join(",")}:${candidate.canary ?? ""}`;
    if (!deduped.has(key)) deduped.set(key, candidate);
  }

  const artifacts = Array.from(deduped.values()).map((candidate, index) => ({
    ...candidate,
    proofId: `${chainId}-PROOF-${index + 1}`,
    downloadable: true as const,
  }));

  return { artifacts, hadHollowCapture };
}

function artifactForSink(
  sink: string,
  findingIds: string[],
  chamberSummary: ChamberSummary | undefined,
  canary: string | undefined,
): Omit<KillChainProofArtifact, "proofId" | "downloadable"> | undefined {
  const normalized = sink === "meta" ? "metadata" : sink;
  const path = capturePathForSink(chamberSummary, normalized);
  if (!path) return undefined;
  return {
    proofType: proofTypeForSink(normalized),
    kind: artifactKindForSink(normalized),
    path,
    findingIds,
    canary,
  };
}

function capturePathForSink(
  chamberSummary: ChamberSummary | undefined,
  sink: string,
): string | undefined {
  if (!chamberSummary) return undefined;
  switch (sink) {
    case "http": return chamberSummary.captures.http.capturePath;
    case "metadata": return chamberSummary.captures.metadata.capturePath;
    case "dns": return chamberSummary.captures.dns.capturePath;
    case "smtp": return chamberSummary.captures.smtp.capturePath;
    case "netflow": return chamberSummary.captures.netflow.capturePath;
    default: return undefined;
  }
}

function proofTypeForSink(sink: string): KillChainProofType {
  switch (sink) {
    case "metadata": return "cloud-metadata-callback";
    case "dns": return "dns-resolution-callback";
    case "smtp": return "smtp-callback";
    case "netflow": return "non-fake-netflow";
    default: return "outbound-http-callback";
  }
}

function artifactKindForSink(sink: string): KillChainProofArtifactKind {
  switch (sink) {
    case "metadata": return "metadata-capture";
    case "dns": return "dns-capture";
    case "smtp": return "smtp-capture";
    case "netflow": return "netflow-capture";
    default: return "http-capture";
  }
}

function artifactKindForFinding(finding: Finding): KillChainProofArtifactKind {
  if (finding.id.includes("METADATA")) return "metadata-capture";
  if (finding.id.includes("DNS")) return "dns-capture";
  if (finding.id.includes("SMTP")) return "smtp-capture";
  if (finding.id.includes("NETFLOW")) return "netflow-capture";
  if (finding.id.startsWith("CHAMBER-FS")) return "filesystem-diff";
  if (finding.id.startsWith("CHAMBER-STATE")) return "state-diff";
  return "http-capture";
}

function primaryProofTypeForFinding(finding: Finding): KillChainProofType {
  return proofTypesForFinding(finding).find((proofType) => proofType !== "static-chain") ?? "static-chain";
}

function firstCanary(finding: Finding): string | undefined {
  const canaryTokens = finding.evidence?.canaryTokens as unknown[] | undefined;
  if (Array.isArray(canaryTokens)) {
    const first = canaryTokens.find((value) => typeof value === "string");
    if (typeof first === "string") return first;
  }
  const captures = finding.evidence?.captures as Array<Record<string, unknown>> | undefined;
  if (Array.isArray(captures)) {
    for (const capture of captures) {
      if (typeof capture.canary === "string") return capture.canary;
    }
  }
  return undefined;
}

function collectCaptureEvidence(
  findings: Finding[],
  artifacts: KillChainProofArtifact[],
): Record<string, unknown> {
  const captureFiles = unique(
    findings
      .map((f) => f.evidence?.captureFile)
      .filter((v): v is string => typeof v === "string" && v.length > 0),
  );
  const sinks = unique(
    findings
      .map((f) => f.evidence?.sink)
      .filter((v): v is string => typeof v === "string" && v.length > 0),
  );
  const verifiedBy = unique(
    findings
      .map((f) => f.evidence?.verifiedBy)
      .filter((v): v is string => typeof v === "string" && v.length > 0),
  );
  return {
    ...(artifacts.length > 0
      ? {
          proofIds: artifacts.map((artifact) => artifact.proofId),
          proofArtifactPaths: artifacts.map((artifact) => artifact.path),
        }
      : {}),
    ...(captureFiles.length > 0 ? { captureFiles } : {}),
    ...(sinks.length > 0 ? { sinks } : {}),
    ...(verifiedBy.length > 0 ? { verifiedBy } : {}),
  };
}

function collectToolNames(
  findings: Finding[],
  chamberSummary: ChamberSummary | undefined,
): string[] {
  const names: string[] = [];
  for (const finding of findings) {
    if (finding.toolName) names.push(finding.toolName);
    if (finding.affectedTools) names.push(...finding.affectedTools);

    const captures = finding.evidence?.captures as Array<Record<string, unknown>> | undefined;
    if (Array.isArray(captures)) {
      for (const capture of captures) {
        if (typeof capture.tool === "string") names.push(capture.tool);
      }
    }

    const hits = finding.evidence?.hits as Array<Record<string, unknown>> | undefined;
    if (Array.isArray(hits)) {
      for (const hit of hits) {
        if (typeof hit.tool === "string") names.push(hit.tool);
      }
    }
  }

  for (const hit of chamberSummary?.confirmedExfil ?? []) {
    if (hit.tool) names.push(hit.tool);
  }
  for (const hit of chamberSummary?.ipiRelays ?? []) {
    if (hit.tool) names.push(hit.tool);
  }

  return unique(names).sort();
}

function uniqueFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const finding of findings) {
    if (seen.has(finding.id)) continue;
    seen.add(finding.id);
    out.push(finding);
  }
  return out;
}

function unique<T>(values: T[]): T[] {
  return Array.from(new Set(values));
}

function highestSeverity(values: Severity[]): Severity | undefined {
  return values.reduce<Severity | undefined>((best, current) => {
    if (!best) return current;
    return SEVERITY_RANK[current] > SEVERITY_RANK[best] ? current : best;
  }, undefined);
}

function maxConfidence(findings: Finding[], fallback: number): number {
  const values = findings
    .map((f) => f.confidence)
    .filter((v): v is number => typeof v === "number");
  if (values.length === 0) return fallback;
  return Math.max(fallback, ...values);
}

function compareChains(a: KillChain, b: KillChain): number {
  const statusDelta = STATUS_RANK[b.status] - STATUS_RANK[a.status];
  if (statusDelta !== 0) return statusDelta;
  const severityDelta = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
  if (severityDelta !== 0) return severityDelta;
  const confidenceDelta = (b.confidence ?? 0) - (a.confidence ?? 0);
  if (confidenceDelta !== 0) return confidenceDelta;
  return a.id.localeCompare(b.id);
}
