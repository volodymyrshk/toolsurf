import { describe, expect, test } from "bun:test";
import {
  buildEgressMatrix,
  classifyVariant,
  formatDestinationLabel,
  formatSinkLabel,
  type EgressDestination,
} from "../../src/core/egress-matrix.js";
import { Severity, type Finding } from "../../src/types/finding.js";

function captureFinding(
  id: string,
  captures: Array<{
    sink: string;
    payloadVariant: string;
    canary?: string;
    tool?: string;
  }>,
): Finding {
  return {
    id,
    module: "active-fuzzer",
    severity: Severity.CRITICAL,
    title: "test",
    description: "test",
    evidence: { captures },
  };
}

describe("classifyVariant", () => {
  test("maps IMDS variants to cloud-metadata", () => {
    expect(classifyVariant("imds-aws")).toBe("cloud-metadata");
    expect(classifyVariant("imds-aws-v2-token")).toBe("cloud-metadata");
    expect(classifyVariant("imds-gcp")).toBe("cloud-metadata");
    expect(classifyVariant("imds-azure")).toBe("cloud-metadata");
  });

  test("maps localhost / file-scheme variants to localhost", () => {
    expect(classifyVariant("internal-port-scan-localhost-ssh")).toBe("localhost");
    expect(classifyVariant("internal-port-scan-localhost-redis")).toBe("localhost");
    expect(classifyVariant("file-scheme")).toBe("localhost");
  });

  test("maps rfc1918 internal-port-scan to rfc1918", () => {
    expect(classifyVariant("internal-port-scan-rfc1918")).toBe("rfc1918");
  });

  test("maps userinfo / fragment confusion to public-internet", () => {
    expect(classifyVariant("userinfo-confusion")).toBe("public-internet");
    expect(classifyVariant("fragment-confusion")).toBe("public-internet");
  });

  test("maps dns variants to dns", () => {
    expect(classifyVariant("dns-rebind")).toBe("dns");
    expect(classifyVariant("dns-canary-resolve")).toBe("dns");
  });

  test("maps chamber-direct evasion variants to chamber-direct", () => {
    expect(classifyVariant("plain")).toBe("chamber-direct");
    expect(classifyVariant("decimal-ip")).toBe("chamber-direct");
    expect(classifyVariant("hex-ip")).toBe("chamber-direct");
    expect(classifyVariant("ipv6-mapped")).toBe("chamber-direct");
    expect(classifyVariant("padded-long")).toBe("chamber-direct");
  });

  test("returns unclassified for unknown variants", () => {
    expect(classifyVariant("totally-new-variant-xyz")).toBe("unclassified");
  });
});

describe("buildEgressMatrix", () => {
  test("builds a dense grid covering every destination × sink pair", () => {
    const matrix = buildEgressMatrix([]);
    expect(matrix.destinations.length).toBeGreaterThan(0);
    expect(matrix.sinks.length).toBeGreaterThan(0);
    expect(matrix.cells.length).toBe(matrix.destinations.length);
    for (const row of matrix.cells) {
      expect(row.length).toBe(matrix.sinks.length);
    }
  });

  test("empty findings → every cell is Blocked", () => {
    const matrix = buildEgressMatrix([]);
    expect(matrix.verifiedCellCount).toBe(0);
    expect(matrix.reachedDestinations).toEqual([]);
    expect(matrix.activeSinks).toEqual([]);
    for (const row of matrix.cells) {
      for (const cell of row) {
        expect(cell.verified).toBe(false);
        expect(cell.canaries).toEqual([]);
      }
    }
  });

  test("plain variant + http sink lights up Chamber-Direct × fake-http", () => {
    const finding = captureFinding("AF-CHAMBER-HTTP", [
      {
        sink: "http",
        payloadVariant: "plain",
        canary: "chamber-fuzz-0-abcd",
        tool: "fetch",
      },
    ]);
    const matrix = buildEgressMatrix([finding]);
    const cdRow = matrix.destinations.indexOf("chamber-direct");
    const httpCol = matrix.sinks.indexOf("http");
    const cell = matrix.cells[cdRow][httpCol];
    expect(cell.verified).toBe(true);
    expect(cell.canaries).toEqual(["chamber-fuzz-0-abcd"]);
    expect(matrix.verifiedCellCount).toBe(1);
    expect(matrix.reachedDestinations).toContain("chamber-direct");
  });

  test("imds-aws + metadata sink lights up Cloud-Metadata × fake-metadata", () => {
    const finding = captureFinding("AF-CHAMBER-METADATA", [
      {
        sink: "metadata",
        payloadVariant: "imds-aws",
        canary: "chamber-escalate-1-xyz",
        tool: "fetch",
      },
    ]);
    const matrix = buildEgressMatrix([finding]);
    const row = matrix.destinations.indexOf("cloud-metadata");
    const col = matrix.sinks.indexOf("metadata");
    expect(matrix.cells[row][col].verified).toBe(true);
    expect(matrix.cells[row][col].canaries).toContain("chamber-escalate-1-xyz");
  });

  test("dedupes canaries across multiple findings hitting the same cell", () => {
    const f1 = captureFinding("AF-CHAMBER-DNS", [
      { sink: "dns", payloadVariant: "dns-rebind", canary: "C1" },
    ]);
    const f2 = captureFinding("AF-CHAMBER-DNS-2", [
      { sink: "dns", payloadVariant: "dns-rebind", canary: "C1" },
      { sink: "dns", payloadVariant: "dns-rebind", canary: "C2" },
    ]);
    const matrix = buildEgressMatrix([f1, f2]);
    const row = matrix.destinations.indexOf("dns");
    const col = matrix.sinks.indexOf("dns");
    expect(matrix.cells[row][col].canaries).toEqual(["C1", "C2"]);
  });

  test("ignores findings whose IDs are not chamber-related", () => {
    const finding: Finding = {
      id: "SSRF-010-fetch",
      module: "ssrf-detection",
      severity: Severity.HIGH,
      title: "test",
      description: "test",
      evidence: {
        captures: [{ sink: "http", payloadVariant: "imds-aws", canary: "C1" }],
      },
    };
    const matrix = buildEgressMatrix([finding]);
    expect(matrix.verifiedCellCount).toBe(0);
  });

  test("activeSinks reflects the sinks that recorded canaries", () => {
    const f = captureFinding("AF-CHAMBER-HTTP", [
      { sink: "http", payloadVariant: "plain", canary: "C1" },
      { sink: "dns", payloadVariant: "dns-rebind", canary: "C2" },
    ]);
    const matrix = buildEgressMatrix([f]);
    expect(matrix.activeSinks).toEqual(["http", "dns"]);
  });

  test("rows order is stable across runs", () => {
    const seen: EgressDestination[] = [];
    for (let i = 0; i < 3; i++) {
      const m = buildEgressMatrix([]);
      seen.push(...m.destinations);
    }
    // Three runs concatenate to triple the row count if order is stable.
    const single = buildEgressMatrix([]).destinations;
    expect(seen).toEqual([...single, ...single, ...single]);
  });
});

describe("label formatters", () => {
  test("destination labels are auditor-friendly strings", () => {
    expect(formatDestinationLabel("chamber-direct")).toBe("Chamber-Direct");
    expect(formatDestinationLabel("cloud-metadata")).toBe("Cloud Metadata");
    expect(formatDestinationLabel("rfc1918")).toBe("RFC1918/Internal");
  });

  test("sink labels match chamber service names", () => {
    expect(formatSinkLabel("http")).toBe("fake-http");
    expect(formatSinkLabel("metadata")).toBe("fake-metadata");
    expect(formatSinkLabel("dns")).toBe("fake-dns");
    expect(formatSinkLabel("smtp")).toBe("fake-smtp");
    expect(formatSinkLabel("netflow")).toBe("netflow");
  });
});
