import { describe, expect, test, beforeAll, afterAll } from "bun:test";
import { buildKillChains } from "../../src/core/kill-chain.js";
import { Severity, type Finding, type ScanReport, type ServerCapabilities } from "../../src/types/index.js";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";

// Temp directory with real capture files so captureFileIsSubstantive() passes.
const TMP_CAPTURES = "/tmp/toolsurf-kill-chain-test-captures";
const HTTP_CAPTURE = join(TMP_CAPTURES, "http", "requests.jsonl");
const IPI_CAPTURE  = join(TMP_CAPTURES, "http", "ipi-action.jsonl");

beforeAll(() => {
  mkdirSync(join(TMP_CAPTURES, "http"), { recursive: true });
  writeFileSync(HTTP_CAPTURE, '{"path":"/__chamber-healthcheck/test","client":"172.30.0.2"}\n');
  writeFileSync(IPI_CAPTURE,  '{"path":"/ipi-action/test","client":"172.30.0.2"}\n');
});

afterAll(() => {
  try { rmSync(TMP_CAPTURES, { recursive: true, force: true }); } catch { /* ignore */ }
});

function capabilities(): ServerCapabilities {
  return {
    serverInfo: { name: "target", version: "1.0.0" },
    protocolVersion: "test",
    capabilities: {},
    tools: [
      {
        name: "fetch",
        inputSchema: {
          type: "object",
          properties: { url: { type: "string" } },
        },
      },
    ],
    resources: [],
    prompts: [],
    protocol: "mcp",
  };
}

function finding(
  id: string,
  severity: Severity,
  evidence: Record<string, unknown> = {},
): Finding {
  return {
    id,
    module: "test",
    severity,
    title: id,
    description: "test finding",
    evidence,
    remediation: "fix",
    confidence: 0.9,
    toolName: "fetch",
  };
}

function chamberSummary(): NonNullable<ScanReport["chamberSummary"]> {
  return {
    runDir: "/tmp/chamber",
    networkName: "scanner-test-net",
    captureRoot: "/tmp/chamber/captures",
    captures: {
      http: { count: 1, capturePath: "/tmp/chamber/captures/http/requests.jsonl" },
      dns: { count: 0, capturePath: "/tmp/chamber/captures/dns/queries.jsonl" },
      smtp: { count: 0, capturePath: "/tmp/chamber/captures/smtp/sessions.jsonl" },
      metadata: { count: 0, capturePath: "/tmp/chamber/captures/metadata/requests.jsonl" },
      netflow: { count: 0, capturePath: "/tmp/chamber/captures/netflow/flows.jsonl" },
    },
    confirmedExfil: [],
    ipiRelays: [],
    severityCounts: { critical: 0, high: 0, medium: 0, low: 0 },
  };
}

describe("kill-chain synthesis", () => {
  test("builds a completed outbound chain from chamber HTTP evidence", () => {
    const summary = buildKillChains({
      reportId: "report-1",
      protocol: "mcp",
      capabilities: capabilities(),
      findings: [
        finding("CHAMBER-HTTP-001", Severity.CRITICAL, {
          captureFile: HTTP_CAPTURE,
          eventCount: 1,
          canaryTokens: ["chamber-fuzz-1"],
          verifiedBy: "chamber-capture",
        }),
      ],
    });

    expect(summary.completed).toBe(1);
    expect(summary.chains[0].id).toBe("KC-SSRF-001");
    expect(summary.chains[0].status).toBe("complete");
    expect(summary.chains[0].proofTypes).toContain("outbound-http-callback");
    expect(summary.chains[0].proofArtifacts[0].path).toBe(HTTP_CAPTURE);
    expect(summary.chains[0].confidence).toBeUndefined();
    expect(summary.chains[0].toolNames).toContain("fetch");
  });

  test("keeps poison-token IPI relay partial until a second sensor action is captured", () => {
    const summary = buildKillChains({
      reportId: "report-2",
      protocol: "mcp",
      capabilities: capabilities(),
      findings: [
        finding("CHAMBER-IPI-RELAY-001", Severity.HIGH, {
          hits: [
            {
              tool: "fetch",
              poisonToken: "POISON-ABCDEF1234567890",
              excerpt: "POISON-ABCDEF1234567890",
            },
          ],
          verifiedBy: "chamber-capture-and-relay",
        }),
      ],
    });

    expect(summary.partial).toBe(1);
    expect(summary.chains[0].id).toBe("KC-IPI-001");
    expect(summary.chains[0].impact).toBe("ipi-relay");
    expect(summary.chains[0].status).toBe("partial");
    expect(summary.chains[0].proofTypes).toEqual(["static-chain"]);
    expect(summary.chains[0].confidence).toBeGreaterThan(0);
  });

  test("completes IPI only when a second-order chamber action has an artifact", () => {
    const summary = buildKillChains({
      reportId: "report-2b",
      protocol: "mcp",
      capabilities: capabilities(),
      findings: [
        finding("CHAMBER-IPI-RELAY-001", Severity.HIGH, {
          hits: [{ tool: "fetch", poisonToken: "POISON-ABCDEF1234567890" }],
          verifiedBy: "chamber-capture-and-relay",
        }),
        finding("CHAMBER-IPI-ACTION-001", Severity.CRITICAL, {
          captureFile: IPI_CAPTURE,
          verifiedBy: "chamber-ipi-action",
        }),
      ],
    });

    expect(summary.completed).toBe(1);
    expect(summary.chains[0].status).toBe("complete");
    expect(summary.chains[0].proofTypes).toContain("agent-triggered-callback");
    expect(summary.chains[0].proofArtifacts[0].path).toBe(IPI_CAPTURE);
    expect(summary.chains[0].confidence).toBeUndefined();
  });

  test("keeps cross-tool exfiltration partial when only static evidence exists", () => {
    const summary = buildKillChains({
      reportId: "report-3",
      protocol: "mcp",
      capabilities: capabilities(),
      findings: [
        finding("EC-002-fetch", Severity.HIGH, {
          sourceCapabilities: ["read-filesystem"],
          sinkCapabilities: ["send-http"],
        }),
      ],
    });

    expect(summary.partial).toBe(1);
    expect(summary.chains[0].id).toBe("KC-EXFIL-001");
    expect(summary.chains[0].status).toBe("partial");
    expect(summary.chains[0].proofTypes).toEqual(["static-chain"]);
  });

  test("builds an exfiltration chain directly from active chamber canary evidence", () => {
    const summary = buildKillChains({
      reportId: "report-3b",
      protocol: "mcp",
      capabilities: capabilities(),
      chamberSummary: chamberSummary(),
      findings: [
        finding("AF-CHAMBER-HTTP", Severity.CRITICAL, {
          sink: "http",
          captures: [{ tool: "fetch", sink: "http", canary: "chamber-fuzz-1" }],
          verifiedBy: "chamber-capture",
        }),
      ],
    });

    expect(summary.completed).toBe(2);
    const ssrf = summary.chains.find((chain) => chain.id === "KC-SSRF-001");
    const exfil = summary.chains.find((chain) => chain.id === "KC-EXFIL-001");
    expect(ssrf?.proofArtifacts[0].path).toBe("/tmp/chamber/captures/http/requests.jsonl");
    expect(exfil?.proofArtifacts[0].path).toBe("/tmp/chamber/captures/http/requests.jsonl");
    expect(ssrf?.confidence).toBeUndefined();
    expect(exfil?.confidence).toBeUndefined();
  });

  test("downgrades chamber signals to partial when no proof artifact is linked", () => {
    const summary = buildKillChains({
      reportId: "report-3c",
      protocol: "mcp",
      capabilities: capabilities(),
      findings: [
        finding("AF-CHAMBER-HTTP", Severity.CRITICAL, {
          sink: "http",
          captures: [{ tool: "fetch", sink: "http", canary: "chamber-fuzz-1" }],
          verifiedBy: "chamber-capture",
        }),
      ],
    });

    expect(summary.completed).toBe(0);
    expect(summary.partial).toBe(2);
    expect(summary.chains.every((chain) => chain.proofArtifacts.length === 0)).toBe(true);
  });

  test("marks chamber-backed negative evidence as blocked when reachability is unverified", () => {
    const summary = buildKillChains({
      reportId: "report-4",
      protocol: "mcp",
      capabilities: capabilities(),
      findings: [],
      chamberReachability: {
        status: "unverified",
        verified: false,
        checkedAt: "2026-05-03T00:00:00.000Z",
        method: "tool-call",
        captureFile: "/tmp/chamber/captures/http/requests.jsonl",
        reason: "No healthcheck callback.",
      },
    });

    expect(summary.blocked).toBe(1);
    expect(summary.chains[0].id).toBe("KC-CHAMBER-BLOCKED-001");
    expect(summary.chains[0].status).toBe("blocked");
  });

  test("returns no chains when the report has no relevant signals", () => {
    const summary = buildKillChains({
      reportId: "report-5",
      protocol: "mcp",
      capabilities: capabilities(),
      findings: [],
    });

    expect(summary.total).toBe(0);
    expect(summary.highestSeverity).toBe("NONE");
  });
});
