import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type {
  KillChainProofArtifact,
  KillChainProofArtifactKind,
  KillChainProofType,
  KillChainSummary,
} from "./kill-chain.js";

export interface ChamberProofLineRange {
  start: number;
  end: number;
}

export interface ChamberProofRecord {
  version: 1;
  reportId: string;
  chainId: string;
  proofId: string;
  proofType: KillChainProofType;
  artifactKind: KillChainProofArtifactKind;
  artifactPath: string;
  artifactExists: boolean;
  artifactSha256?: string;
  artifactSizeBytes?: number;
  findingIds: string[];
  canary?: string;
  marker?: string;
  captureLineRange?: ChamberProofLineRange;
  matchedLineCount?: number;
  downloadable: boolean;
  writtenAt: string;
}

export interface ChamberProofBundleSummary {
  version: 1;
  proofFile: string;
  proofCount: number;
  missingArtifactCount: number;
  writtenAt: string;
}

export interface ChamberProofBundle extends ChamberProofBundleSummary {
  records: ChamberProofRecord[];
}

export interface BuildChamberProofRecordsOptions {
  reportId: string;
  killChainSummary?: KillChainSummary;
  writtenAt?: string;
}

export interface WriteChamberProofBundleOptions extends BuildChamberProofRecordsOptions {
  outputDir: string;
}

/**
 * Convert completed kill-chain proof artifacts into durable proof records.
 *
 * The kill-chain engine decides whether a chain is complete. This layer makes
 * that decision audit-grade by binding every proof ID to a concrete file path,
 * hash, size, and optional marker line range.
 */
export function buildChamberProofRecords(
  options: BuildChamberProofRecordsOptions,
): ChamberProofRecord[] {
  const writtenAt = options.writtenAt ?? new Date().toISOString();
  const records: ChamberProofRecord[] = [];
  const seen = new Set<string>();

  for (const chain of options.killChainSummary?.chains ?? []) {
    if (chain.status !== "complete") continue;

    for (const artifact of chain.proofArtifacts) {
      const key = `${chain.id}:${artifact.proofId}:${artifact.path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      records.push(buildRecord(options.reportId, chain.id, artifact, writtenAt));
    }
  }

  return records;
}

/**
 * Write `proofs/chamber-proofs.jsonl`. Returns undefined when there are no
 * completed proof artifacts to persist.
 */
export function writeChamberProofBundle(
  options: WriteChamberProofBundleOptions,
): ChamberProofBundle | undefined {
  const records = buildChamberProofRecords(options);
  if (records.length === 0) return undefined;

  mkdirSync(options.outputDir, { recursive: true });
  const proofFile = join(options.outputDir, "chamber-proofs.jsonl");
  writeFileSync(
    proofFile,
    records.map((record) => JSON.stringify(record)).join("\n") + "\n",
    "utf-8",
  );

  return {
    version: 1,
    proofFile,
    proofCount: records.length,
    missingArtifactCount: records.filter((record) => !record.artifactExists).length,
    writtenAt: records[0].writtenAt,
    records,
  };
}

function buildRecord(
  reportId: string,
  chainId: string,
  artifact: KillChainProofArtifact,
  writtenAt: string,
): ChamberProofRecord {
  const fileMeta = inspectArtifactFile(artifact.path, artifact.canary);

  return {
    version: 1,
    reportId,
    chainId,
    proofId: artifact.proofId,
    proofType: artifact.proofType,
    artifactKind: artifact.kind,
    artifactPath: artifact.path,
    artifactExists: fileMeta.exists,
    ...(fileMeta.sha256 ? { artifactSha256: fileMeta.sha256 } : {}),
    ...(fileMeta.sizeBytes !== undefined ? { artifactSizeBytes: fileMeta.sizeBytes } : {}),
    findingIds: artifact.findingIds,
    ...(artifact.canary ? { canary: artifact.canary, marker: artifact.canary } : {}),
    ...(fileMeta.lineRange ? { captureLineRange: fileMeta.lineRange } : {}),
    ...(fileMeta.matchedLineCount !== undefined ? { matchedLineCount: fileMeta.matchedLineCount } : {}),
    downloadable: artifact.downloadable && fileMeta.exists,
    writtenAt,
  };
}

function inspectArtifactFile(
  path: string,
  marker: string | undefined,
): {
  exists: boolean;
  sha256?: string;
  sizeBytes?: number;
  lineRange?: ChamberProofLineRange;
  matchedLineCount?: number;
} {
  if (!existsSync(path)) return { exists: false };

  const bytes = readFileSync(path);
  const st = statSync(path);
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const lineNumbers = marker ? findMarkerLines(path, marker) : [];

  return {
    exists: true,
    sha256,
    sizeBytes: st.size,
    ...(lineNumbers.length > 0
      ? {
          lineRange: {
            start: lineNumbers[0],
            end: lineNumbers[lineNumbers.length - 1],
          },
          matchedLineCount: lineNumbers.length,
        }
      : {}),
  };
}

function findMarkerLines(path: string, marker: string): number[] {
  try {
    const lines = readFileSync(path, "utf-8").split(/\r?\n/);
    const out: number[] = [];
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes(marker)) out.push(i + 1);
    }
    return out;
  } catch {
    return [];
  }
}
