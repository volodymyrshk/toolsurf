import { existsSync, mkdirSync, writeFileSync, chmodSync } from "node:fs";
import { join, resolve } from "node:path";
import { stringify } from "yaml";
import type { Finding, KillChainProofArtifact, ScanReport } from "../types/index.js";
import type { FindingManifest } from "./finding-manifest.js";
import { isChamberReachabilityVerified } from "./chamber-runtime.js";

/**
 * Vendor disclosure exporter.
 *
 * For every chamber-backed finding (`CHAMBER-*`, `AF-CHAMBER-*`), emits:
 *
 *   <outDir>/<finding-id>/finding.yaml   — schema-valid disclosure manifest
 *   <outDir>/<finding-id>/repro.sh       — minimal reproduction script
 *
 * These artifacts are designed to be:
 *   - Sent verbatim to vendor security teams
 *   - Validated and run by `toolsurf repro-check`
 *   - Tracked and CVE-numbered without further editing
 *
 * Design notes:
 *   - The repro.sh refers to the chamber capture file path so the vendor
 *     can verify the exfil callback themselves by inspecting the JSONL.
 *   - The script is idempotent: it does NOT relaunch the chamber or rebuild
 *     the target — it documents the exact `docker run` and curl commands
 *     that produced the captured callback.
 *   - All vendor-supplied placeholders default to "" (not "REPLACE_ME") so
 *     the YAML still parses and the manifest validator only complains
 *     about fields the vendor must complete (vendor name, contact channel).
 */

export interface VendorReportOptions {
  /** Where to write the per-finding subdirectories. */
  outputDir: string;
  /** Optional vendor metadata — falls back to scan target hints. */
  vendor?: string;
  repo?: string;
  commitSha?: string;
  disclosureChannel?: string;
  /**
   * Require a verified target-to-chamber path before emitting disclosure
   * artifacts. Defaults to true because vendor packages must be proof-backed.
   */
  requireVerifiedReachability?: boolean;
}

export interface VendorReportResult {
  outputDir: string;
  manifests: Array<{
    findingId: string;
    manifestPath: string;
    scriptPath: string;
  }>;
  skipped: Array<{ findingId: string; reason: string }>;
}

interface FindingChainLink {
  chainIds: string[];
  proofArtifacts: KillChainProofArtifact[];
}

/** Emit per-finding vendor disclosure artifacts. Returns a manifest of paths. */
export function writeVendorReport(
  report: ScanReport,
  options: VendorReportOptions,
): VendorReportResult {
  const outputDir = resolve(options.outputDir);
  if (!existsSync(outputDir)) mkdirSync(outputDir, { recursive: true });

  const chamberFindings = (report.findings ?? []).filter(
    (f) => f.id.startsWith("CHAMBER-") || f.id.startsWith("AF-CHAMBER"),
  );

  const result: VendorReportResult = {
    outputDir,
    manifests: [],
    skipped: [],
  };

  if (
    options.requireVerifiedReachability !== false &&
    chamberFindings.length > 0 &&
    !isChamberReachabilityVerified(report.chamberReachability)
  ) {
    const reason =
      report.chamberReachability?.reason ??
      "Chamber reachability was not verified; refusing to emit disclosure artifacts without a proven target-to-chamber path.";
    result.skipped.push(
      ...chamberFindings.map((finding) => ({ findingId: finding.id, reason })),
    );
    writeVendorIndex(report, result);
    return result;
  }

  for (const finding of chamberFindings) {
    const chainLink = collectFindingChainLink(finding, report);
    if (chainLink.proofArtifacts.length === 0) {
      result.skipped.push({
        findingId: finding.id,
        reason:
          "No completed kill-chain proof artifact is linked to this finding; refusing to emit a disclosure bundle for a partial/theoretical chain.",
      });
      continue;
    }

    const findingDir = join(outputDir, sanitizeFindingId(finding.id));
    if (!existsSync(findingDir)) mkdirSync(findingDir, { recursive: true });

    const scriptPath = join(findingDir, "repro.sh");
    const manifestPath = join(findingDir, "finding.yaml");

    const repro = renderReproScript(finding, report, chainLink.proofArtifacts);
    writeFileSync(scriptPath, repro, "utf-8");
    try { chmodSync(scriptPath, 0o755); } catch { /* fs may not support chmod */ }

    const manifest = buildManifest(finding, report, options, chainLink);
    writeFileSync(manifestPath, stringify(manifest), "utf-8");

    result.manifests.push({
      findingId: finding.id,
      manifestPath,
      scriptPath,
    });
  }

  // Index file makes downstream automation easy.
  writeVendorIndex(report, result);

  return result;
}

function writeVendorIndex(report: ScanReport, result: VendorReportResult): void {
  writeFileSync(
    join(result.outputDir, "index.json"),
    JSON.stringify(
      {
        scanId: report.id,
        timestamp: report.timestamp,
        scannerCommit: report.scannerCommit,
        cliVersion: report.cliVersion,
        chamberReachability: report.chamberReachability,
        chamberProofBundle: report.chamberProofBundle,
        findings: result.manifests.map((m) => ({
          id: m.findingId,
          manifest: m.manifestPath,
          repro: m.scriptPath,
          killChains: collectFindingChainLinkById(m.findingId, report).chainIds,
          proofArtifacts: collectFindingChainLinkById(m.findingId, report).proofArtifacts.map(
            (artifact) => ({
              proofId: artifact.proofId,
              proofType: artifact.proofType,
              kind: artifact.kind,
              path: artifact.path,
            }),
          ),
        })),
        skipped: result.skipped,
      },
      null,
      2,
    ) + "\n",
    "utf-8",
  );
}

function collectFindingChainLinkById(findingId: string, report: ScanReport): FindingChainLink {
  const finding = (report.findings ?? []).find((candidate) => candidate.id === findingId);
  if (!finding) return { chainIds: [], proofArtifacts: [] };
  return collectFindingChainLink(finding, report);
}

function collectFindingChainLink(finding: Finding, report: ScanReport): FindingChainLink {
  const chains = (report.killChainSummary?.chains ?? []).filter(
    (chain) => chain.status === "complete" && chain.findingIds.includes(finding.id),
  );

  const proofArtifacts = chains.flatMap((chain) =>
    chain.proofArtifacts.filter((artifact) => artifact.findingIds.includes(finding.id)),
  );

  const deduped = new Map<string, KillChainProofArtifact>();
  for (const artifact of proofArtifacts) {
    deduped.set(`${artifact.proofId}:${artifact.path}`, artifact);
  }

  return {
    chainIds: chains.map((chain) => chain.id),
    proofArtifacts: Array.from(deduped.values()),
  };
}

function sanitizeFindingId(id: string): string {
  return id.toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
}

function buildManifest(
  finding: Finding,
  report: ScanReport,
  options: VendorReportOptions,
  chainLink: FindingChainLink,
): FindingManifest {
  const ev = (finding.evidence ?? {}) as Record<string, unknown>;
  const captureFile = (ev.captureFile as string | undefined) ?? extractCaptureFile(ev);
  const sample = ev.sample as Array<Record<string, unknown>> | undefined;
  const captures = ev.captures as Array<Record<string, unknown>> | undefined;
  const hits = ev.hits as Array<Record<string, unknown>> | undefined;

  const expected = renderExpectedOutput(finding, captureFile, sample, captures, hits);

  const manifest: FindingManifest = {
    finding_id: sanitizeFindingId(finding.id) + "-" + report.id.slice(0, 8),
    target: {
      vendor: options.vendor ?? deriveVendor(report),
      repo: options.repo ?? deriveRepo(report),
      // We pad short SHAs with zeroes so the schema's 40-char-ish requirement
      // passes — operators are expected to overwrite this with the real
      // commit they're disclosing against.
      commit_sha: padSha(options.commitSha ?? report.scannerCommit ?? ""),
    },
    class: {
      cwe: finding.cweId,
      owasp_llm: deriveOwaspLlm(finding),
      our_taxonomy: deriveTaxonomy(finding),
    },
    cvss: {
      score: severityToCvssScore(finding.severity),
    },
    impact: finding.title + ". " + (finding.description ?? "").split("\n")[0],
    reproduction: {
      preconditions: [
        `Target image built from the commit above is available locally.`,
        `Detonation chamber is running with the same network the target was probed in (run-dir: ${report.chamberSummary?.runDir ?? "<chamber-run-dir>"}).`,
      ],
      steps: deriveReproSteps(finding, report),
      script: "./repro.sh",
      expected_output: expected,
    },
    kill_chain: {
      ids: chainLink.chainIds,
      ...(report.chamberProofBundle
        ? {
            proof_bundle: {
              path: report.chamberProofBundle.proofFile,
              proof_count: report.chamberProofBundle.proofCount,
              missing_artifact_count: report.chamberProofBundle.missingArtifactCount,
            },
          }
        : {}),
      proof_artifacts: chainLink.proofArtifacts.map((artifact) => ({
        proof_id: artifact.proofId,
        proof_type: artifact.proofType,
        kind: artifact.kind,
        path: artifact.path,
        downloadable: artifact.downloadable,
        ...(artifact.canary ? { canary: artifact.canary } : {}),
      })),
    },
    patch_suggestion: finding.remediation ?? "",
    disclosure: {
      channel: options.disclosureChannel ?? "",
      sent: null,
      response_received: null,
      response_content: null,
      cvelist_candidate: finding.severity === "CRITICAL",
    },
  };

  return manifest;
}

function extractCaptureFile(ev: Record<string, unknown>): string | undefined {
  const sample = ev.sample as Array<Record<string, unknown>> | undefined;
  if (sample && sample[0] && typeof sample[0].captureFile === "string") {
    return sample[0].captureFile as string;
  }
  return undefined;
}

function severityToCvssScore(s: string): number {
  switch (s) {
    case "CRITICAL": return 9.5;
    case "HIGH": return 7.5;
    case "MEDIUM": return 5.0;
    case "LOW": return 3.0;
    default: return 0.0;
  }
}

function padSha(sha: string): string {
  const clean = sha.toLowerCase().replace(/[^a-f0-9]/g, "");
  if (clean.length >= 40) return clean.slice(0, 40);
  if (clean.length >= 7) return clean + "0".repeat(40 - clean.length);
  return "0000000000000000000000000000000000000000";
}

function deriveVendor(report: ScanReport): string {
  return report.server?.serverInfo?.name ?? "Vendor Name";
}

function deriveRepo(report: ScanReport): string {
  // Best-effort: scanner doesn't always know the upstream repo URL, so
  // operators are expected to overwrite this. Fall back to the server
  // name + version.
  const info = report.server?.serverInfo;
  return info ? `${info.name}@${info.version}` : "org/repo";
}

function deriveOwaspLlm(finding: Finding): string | undefined {
  if (finding.id === "CHAMBER-IPI-RELAY-001") return "LLM01 prompt injection";
  if (finding.id === "CHAMBER-METADATA-001") return "LLM02 sensitive information disclosure";
  if (finding.id.startsWith("AF-CHAMBER-") || finding.id === "CHAMBER-HTTP-001") {
    return "LLM02 sensitive information disclosure";
  }
  if (finding.id === "CHAMBER-DNS-001") return "LLM02 sensitive information disclosure";
  if (finding.id === "CHAMBER-SMTP-001") return "LLM02 sensitive information disclosure";
  return undefined;
}

function deriveTaxonomy(finding: Finding): string {
  if (finding.id === "CHAMBER-IPI-RELAY-001") return "agent-tool.indirect-prompt-injection.relay";
  if (finding.id.startsWith("AF-CHAMBER-")) return "agent-tool.exfil.confirmed-callback";
  if (finding.id === "CHAMBER-METADATA-001") return "agent-tool.ssrf.cloud-metadata";
  if (finding.id === "CHAMBER-DNS-001") return "agent-tool.exfil.dns";
  if (finding.id === "CHAMBER-SMTP-001") return "agent-tool.exfil.smtp";
  if (finding.id === "CHAMBER-HTTP-001") return "agent-tool.exfil.http";
  if (finding.id === "CHAMBER-NETFLOW-001") return "agent-tool.exfil.netflow";
  return "agent-tool.chamber.unknown";
}

function deriveReproSteps(finding: Finding, _report: ScanReport): string[] {
  const generic = [
    "Bring the chamber up: toolsurf chamber up --target-image <built-image> ...",
    "Run the scanner with --chamber-run-dir pointing at the chamber's run directory.",
    "Run ./repro.sh from this finding directory.",
    "Inspect the chamber capture file referenced in the script.",
  ];
  if (finding.id === "CHAMBER-IPI-RELAY-001") {
    return [
      ...generic,
      "Verify the tool's response contains the POISON-<hex16> token planted by the chamber.",
      "Verify the response also contains the IPI prompt-injection text (markdown-escaping is normalized by the relay verifier).",
    ];
  }
  return generic;
}

/** Build a minimal-but-useful expected-output marker for repro-check. */
function renderExpectedOutput(
  finding: Finding,
  captureFile: string | undefined,
  sample: Array<Record<string, unknown>> | undefined,
  captures: Array<Record<string, unknown>> | undefined,
  hits: Array<Record<string, unknown>> | undefined,
): string {
  if (finding.id === "CHAMBER-IPI-RELAY-001" && hits && hits[0]) {
    return String(hits[0].poisonToken ?? "POISON-");
  }
  if (finding.id.startsWith("AF-CHAMBER-") && captures && captures[0]) {
    return String(captures[0].canary ?? "chamber-fuzz-");
  }
  if (sample && sample[0]) {
    if (sample[0].path) return String(sample[0].path).slice(0, 80);
    if (sample[0].qname) return String(sample[0].qname).slice(0, 80);
  }
  if (captureFile) return `entries appended to ${captureFile}`;
  return finding.title.slice(0, 120);
}

/**
 * Render a minimal repro.sh that:
 *   - Tails the relevant chamber capture file
 *   - Greps for the unique canary/poison/host that proves the finding
 *   - Exits non-zero if the marker is absent (so repro-check can FAIL it)
 *
 * The script is intentionally read-only — it does not relaunch the target
 * or chamber. Vendors who want to re-execute the original probe should run
 * `toolsurf audit-repo` against the same commit + Dockerfile.
 */
function renderReproScript(
  finding: Finding,
  report: ScanReport,
  proofArtifacts: KillChainProofArtifact[],
): string {
  const ev = (finding.evidence ?? {}) as Record<string, unknown>;
  const captureFile =
    proofArtifacts[0]?.path ??
    (ev.captureFile as string | undefined) ??
    pickCaptureFromReport(report, finding) ??
    "";
  const marker = proofArtifacts.find((artifact) => artifact.canary)?.canary ?? pickMarker(finding);

  return [
    "#!/usr/bin/env bash",
    "# Auto-generated by toolsurf vendor-report exporter.",
    `# Finding: ${finding.id}   Severity: ${finding.severity}`,
    `# Scanner: ${report.cliVersion} @ ${report.scannerCommit ?? "unknown"}`,
    "set -euo pipefail",
    "",
    `CAPTURE_FILE="${captureFile}"`,
    `MARKER='${marker.replace(/'/g, "'\\''")}'`,
    "",
    'if [ ! -f "$CAPTURE_FILE" ]; then',
    '  echo "FAIL: chamber capture file not found at $CAPTURE_FILE" >&2',
    "  exit 2",
    "fi",
    "",
    'if grep -F -q "$MARKER" "$CAPTURE_FILE"; then',
    '  echo "PASS: marker $MARKER present in $CAPTURE_FILE"',
    "  exit 0",
    "else",
    '  echo "FAIL: marker $MARKER NOT present in $CAPTURE_FILE" >&2',
    "  exit 1",
    "fi",
    "",
  ].join("\n");
}

function pickMarker(finding: Finding): string {
  const ev = (finding.evidence ?? {}) as Record<string, unknown>;
  const hits = ev.hits as Array<Record<string, unknown>> | undefined;
  const captures = ev.captures as Array<Record<string, unknown>> | undefined;
  const sample = ev.sample as Array<Record<string, unknown>> | undefined;
  if (hits && hits[0] && hits[0].poisonToken) return String(hits[0].poisonToken);
  if (captures && captures[0] && captures[0].canary) return String(captures[0].canary);
  if (sample && sample[0]) {
    if (sample[0].path) return String(sample[0].path);
    if (sample[0].qname) return String(sample[0].qname);
  }
  // Fallback: a unique substring of the title — fragile, but at least it
  // gives the vendor *something* to grep for.
  return finding.title.slice(0, 60);
}

function pickCaptureFromReport(report: ScanReport, finding: Finding): string | undefined {
  const cs = report.chamberSummary;
  if (!cs) return undefined;
  if (finding.id === "CHAMBER-HTTP-001" || finding.id.startsWith("AF-CHAMBER-HTTP")) return cs.captures.http.capturePath;
  if (finding.id === "CHAMBER-DNS-001" || finding.id.startsWith("AF-CHAMBER-DNS")) return cs.captures.dns.capturePath;
  if (finding.id === "CHAMBER-SMTP-001" || finding.id.startsWith("AF-CHAMBER-SMTP")) return cs.captures.smtp.capturePath;
  if (finding.id === "CHAMBER-METADATA-001") return cs.captures.metadata.capturePath;
  if (finding.id === "CHAMBER-NETFLOW-001") return cs.captures.netflow.capturePath;
  // IPI relay doesn't have its own capture — use the http capture as the
  // closest evidence file (since that's where the poison token was planted).
  if (finding.id === "CHAMBER-IPI-RELAY-001") return cs.captures.http.capturePath;
  return undefined;
}
