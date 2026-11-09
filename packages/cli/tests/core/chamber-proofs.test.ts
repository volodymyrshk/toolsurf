import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  buildChamberProofRecords,
  writeChamberProofBundle,
} from "../../src/core/chamber-proofs.js";
import { Severity, type KillChainSummary } from "../../src/types/index.js";

const TMP_DIRS: string[] = [];

function freshDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "scanner-chamber-proofs-"));
  TMP_DIRS.push(dir);
  return dir;
}

function summaryWithArtifact(path: string, canary = "chamber-fuzz-0-deadbeef"): KillChainSummary {
  return {
    total: 1,
    completed: 1,
    partial: 0,
    blocked: 0,
    highestSeverity: Severity.CRITICAL,
    proofTypes: ["outbound-http-callback"],
    chains: [
      {
        id: "KC-SSRF-001",
        title: "SSRF via chamber HTTP capture",
        status: "complete",
        impact: "ssrf",
        severity: Severity.CRITICAL,
        protocol: "mcp",
        toolNames: ["fetch"],
        findingIds: ["CHAMBER-HTTP-001"],
        proofTypes: ["outbound-http-callback"],
        proofArtifacts: [
          {
            proofId: "KC-SSRF-001-PROOF-1",
            proofType: "outbound-http-callback",
            kind: "http-capture",
            path,
            findingIds: ["CHAMBER-HTTP-001"],
            downloadable: true,
            canary,
          },
        ],
        stages: [],
        summary: "Target reached fake-http.",
        whatWorked: ["Captured callback."],
        whatDidNotWork: [],
      },
    ],
  };
}

afterEach(() => {
  for (const dir of TMP_DIRS.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("chamber proof bundle", () => {
  test("builds proof records with file hash, size, and marker line range", () => {
    const dir = freshDir();
    const capture = join(dir, "requests.jsonl");
    writeFileSync(
      capture,
      [
        JSON.stringify({ path: "/before" }),
        JSON.stringify({ path: "/collect/chamber-fuzz-0-deadbeef" }),
        JSON.stringify({ body: "again chamber-fuzz-0-deadbeef" }),
      ].join("\n") + "\n",
      "utf-8",
    );

    const records = buildChamberProofRecords({
      reportId: "report-1",
      killChainSummary: summaryWithArtifact(capture),
      writtenAt: "2026-05-06T00:00:00.000Z",
    });

    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      version: 1,
      reportId: "report-1",
      chainId: "KC-SSRF-001",
      proofId: "KC-SSRF-001-PROOF-1",
      artifactPath: capture,
      artifactExists: true,
      artifactKind: "http-capture",
      downloadable: true,
      canary: "chamber-fuzz-0-deadbeef",
      marker: "chamber-fuzz-0-deadbeef",
      captureLineRange: { start: 2, end: 3 },
      matchedLineCount: 2,
    });
    expect(records[0].artifactSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(records[0].artifactSizeBytes).toBeGreaterThan(0);
  });

  test("marks missing artifacts as not downloadable instead of pretending proof is present", () => {
    const records = buildChamberProofRecords({
      reportId: "report-1",
      killChainSummary: summaryWithArtifact("/tmp/does-not-exist/chamber.jsonl"),
    });

    expect(records).toHaveLength(1);
    expect(records[0].artifactExists).toBe(false);
    expect(records[0].downloadable).toBe(false);
    expect(records[0].artifactSha256).toBeUndefined();
  });

  test("does not persist partial chains without proof artifacts", () => {
    const summary: KillChainSummary = {
      total: 1,
      completed: 0,
      partial: 1,
      blocked: 0,
      highestSeverity: Severity.MEDIUM,
      proofTypes: ["static-chain"],
      chains: [
        {
          id: "KC-EXFIL-001",
          title: "Static exfiltration chain",
          status: "partial",
          impact: "exfiltration",
          severity: Severity.MEDIUM,
          confidence: 0.65,
          toolNames: ["read", "send"],
          findingIds: ["EC-001"],
          proofTypes: ["static-chain"],
          proofArtifacts: [],
          stages: [],
          summary: "Static chain only.",
          whatWorked: [],
          whatDidNotWork: ["No chamber artifact."],
        },
      ],
    };

    expect(buildChamberProofRecords({ reportId: "report-1", killChainSummary: summary })).toEqual([]);
    expect(
      writeChamberProofBundle({
        reportId: "report-1",
        killChainSummary: summary,
        outputDir: freshDir(),
      }),
    ).toBeUndefined();
  });

  test("writes chamber-proofs.jsonl and returns a summary", () => {
    const dir = freshDir();
    const capture = join(dir, "requests.jsonl");
    writeFileSync(capture, "chamber-fuzz-0-deadbeef\n", "utf-8");

    const bundle = writeChamberProofBundle({
      reportId: "report-1",
      killChainSummary: summaryWithArtifact(capture),
      outputDir: join(dir, "proofs"),
      writtenAt: "2026-05-06T00:00:00.000Z",
    });

    expect(bundle).toBeDefined();
    expect(bundle!.proofCount).toBe(1);
    expect(bundle!.missingArtifactCount).toBe(0);
    expect(bundle!.proofFile).toBe(join(dir, "proofs", "chamber-proofs.jsonl"));

    const lines = readFileSync(bundle!.proofFile, "utf-8").trim().split("\n");
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]).proofId).toBe("KC-SSRF-001-PROOF-1");
  });
});
