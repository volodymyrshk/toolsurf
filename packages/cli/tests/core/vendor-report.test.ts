import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { writeVendorReport } from "../../src/core/vendor-report.js";
import { Severity, type ScanReport } from "../../src/types/index.js";

const TMP_DIR = join(import.meta.dir, ".tmp-vendor-report");

afterEach(() => {
  rmSync(TMP_DIR, { recursive: true, force: true });
});

function makeReport(verified: boolean): ScanReport {
  const captureDir = join(TMP_DIR, "captures", "http");
  mkdirSync(captureDir, { recursive: true });
  const captureFile = join(captureDir, "requests.jsonl");
  writeFileSync(captureFile, JSON.stringify({ path: "/ssrf-probe" }) + "\n", "utf-8");

  return {
    version: "1.0.0",
    id: "12345678-1234-1234-1234-123456789abc",
    timestamp: "2026-05-03T00:00:00.000Z",
    durationMs: 1,
    cliVersion: "test",
    scannerCommit: "abcdef1234567890abcdef1234567890abcdef12",
    transport: { type: "stdio", protocol: "mcp" },
    server: {
      serverInfo: { name: "target", version: "1.0.0" },
      protocolVersion: "test",
      capabilities: {},
      tools: [],
      resources: [],
      prompts: [],
      protocol: "mcp",
    },
    modules: [],
    findings: [
      {
        id: "CHAMBER-HTTP-001",
        module: "chamber-evidence",
        severity: Severity.CRITICAL,
        title: "Tool issued outbound HTTP",
        description: "Captured fake-http callback.",
        evidence: {
          captureFile,
          sample: [{ path: "/ssrf-probe" }],
          verifiedBy: "chamber-capture",
        },
        remediation: "Block outbound access.",
        cweId: "CWE-918",
      },
    ],
    summary: {
      totalChecks: 1,
      passed: 0,
      warnings: 0,
      checksWithFailStatus: 1,
      skipped: 0,
      errors: 0,
      findingsBySeverity: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      securityScore: 0,
      rawScore: 0,
      penaltyPoints: 100,
    },
    chamberReachability: {
      status: verified ? "verified" : "unverified",
      verified,
      checkedAt: "2026-05-03T00:00:00.000Z",
      method: verified ? "tool-call" : "none",
      reason: verified ? "Target fetched healthcheck." : "No healthcheck callback.",
    },
    chamberSummary: {
      runDir: TMP_DIR,
      networkName: "test_net",
      captureRoot: join(TMP_DIR, "captures"),
      captures: {
        http: { count: 1, capturePath: captureFile },
        dns: { count: 0 },
        smtp: { count: 0 },
        metadata: { count: 0 },
        netflow: { count: 0 },
      },
      confirmedExfil: [],
      ipiRelays: [],
      severityCounts: { critical: 1, high: 0, medium: 0, low: 0 },
    },
    chamberProofBundle: {
      version: 1,
      proofFile: join(TMP_DIR, "proofs", "chamber-proofs.jsonl"),
      proofCount: 1,
      missingArtifactCount: 0,
      writtenAt: "2026-05-03T00:00:00.000Z",
    },
    killChainSummary: {
      chains: [
        {
          id: "KC-SSRF-001",
          title: "Attacker-controlled outbound request reached chamber sensors",
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
              path: captureFile,
              findingIds: ["CHAMBER-HTTP-001"],
              downloadable: true,
              canary: "/ssrf-probe",
            },
          ],
          stages: [],
          summary: "Artifact-backed chamber callback.",
          whatWorked: [],
          whatDidNotWork: [],
        },
      ],
      total: 1,
      completed: 1,
      partial: 0,
      blocked: 0,
      highestSeverity: Severity.CRITICAL,
      proofTypes: ["outbound-http-callback"],
    },
  };
}

describe("vendor report reachability gate", () => {
  test("refuses disclosure artifacts when chamber reachability is unverified", () => {
    const result = writeVendorReport(makeReport(false), {
      outputDir: join(TMP_DIR, "vendor"),
      vendor: "Vendor",
      repo: "org/repo",
      commitSha: "abcdef1234567890abcdef1234567890abcdef12",
    });

    expect(result.manifests.length).toBe(0);
    expect(result.skipped.length).toBe(1);
    expect(result.skipped[0].findingId).toBe("CHAMBER-HTTP-001");
    expect(existsSync(join(TMP_DIR, "vendor", "index.json"))).toBe(true);
    const index = JSON.parse(readFileSync(join(TMP_DIR, "vendor", "index.json"), "utf-8"));
    expect(index.skipped.length).toBe(1);
  });

  test("emits artifacts when chamber reachability is verified", () => {
    const result = writeVendorReport(makeReport(true), {
      outputDir: join(TMP_DIR, "vendor"),
      vendor: "Vendor",
      repo: "org/repo",
      commitSha: "abcdef1234567890abcdef1234567890abcdef12",
    });

    expect(result.manifests.length).toBe(1);
    expect(result.skipped.length).toBe(0);
    expect(existsSync(result.manifests[0].manifestPath)).toBe(true);
    expect(existsSync(result.manifests[0].scriptPath)).toBe(true);

    const manifest = readFileSync(result.manifests[0].manifestPath, "utf-8");
    expect(manifest).toContain("kill_chain:");
    expect(manifest).toContain("proof_bundle:");
    expect(manifest).toContain("chamber-proofs.jsonl");
    expect(manifest).toContain("KC-SSRF-001");
    expect(manifest).toContain("KC-SSRF-001-PROOF-1");

    const index = JSON.parse(readFileSync(join(TMP_DIR, "vendor", "index.json"), "utf-8"));
    expect(index.chamberProofBundle.proofFile).toContain("chamber-proofs.jsonl");
  });

  test("skips verified chamber findings that are not linked to completed proof artifacts", () => {
    const report = makeReport(true);
    report.killChainSummary = {
      chains: [
        {
          id: "KC-IPI-001",
          title: "Hostile chamber content was relayed into scanner-visible output",
          status: "partial",
          impact: "ipi-relay",
          severity: Severity.HIGH,
          confidence: 0.75,
          protocol: "mcp",
          toolNames: ["fetch"],
          findingIds: ["CHAMBER-HTTP-001"],
          proofTypes: ["static-chain"],
          proofArtifacts: [],
          stages: [],
          summary: "Partial only.",
          whatWorked: [],
          whatDidNotWork: ["No second-order callback."],
        },
      ],
      total: 1,
      completed: 0,
      partial: 1,
      blocked: 0,
      highestSeverity: Severity.HIGH,
      proofTypes: ["static-chain"],
    };

    const result = writeVendorReport(report, {
      outputDir: join(TMP_DIR, "vendor"),
      vendor: "Vendor",
      repo: "org/repo",
      commitSha: "abcdef1234567890abcdef1234567890abcdef12",
    });

    expect(result.manifests.length).toBe(0);
    expect(result.skipped.length).toBe(1);
    expect(result.skipped[0].reason).toContain("No completed kill-chain proof artifact");
  });
});
