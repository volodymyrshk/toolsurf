import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ChamberEvidenceModule } from "../../src/modules/chamber-evidence.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ModuleContext } from "../../src/types/index.js";

const TMP_DIRS: string[] = [];

function tmpFile(name: string): string {
  const dir = mkdtempSync(join(tmpdir(), "scanner-chamber-evidence-"));
  TMP_DIRS.push(dir);
  return join(dir, name);
}

function makeContext(chamber?: ModuleContext["chamber"]): ModuleContext {
  return {
    capabilities: {
      serverInfo: { name: "test-server", version: "1.0.0" },
      protocolVersion: "2025-11-05",
      capabilities: {},
      tools: [],
      resources: [],
      prompts: [],
    },
    activeMode: true,
    verbose: false,
    probeDelay: 0,
    chamber,
  };
}

afterEach(() => {
  for (const dir of TMP_DIRS.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("ChamberEvidenceModule", () => {
  const mod = new ChamberEvidenceModule();

  test("module metadata is correct", () => {
    expect(mod.id).toBe("chamber-evidence");
    expect(mod.mode).toBe("active");
  });

  test("skips when no chamber is configured", async () => {
    const results = await mod.run(makeContext());

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe(CheckStatus.SKIP);
  });

  test("passes when chamber has no captures", async () => {
    const http = tmpFile("http.jsonl");
    writeFileSync(http, "", "utf-8");

    const results = await mod.run(makeContext({
      fakeHttpUrl: "http://172.30.0.10:8080",
      fakeMetadataUrl: "http://172.30.0.12",
      fakeDnsHost: "172.30.0.53",
      captures: { http },
    }));

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe(CheckStatus.PASS);
  });

  test("emits critical HTTP finding with canary correlation", async () => {
    const http = tmpFile("http.jsonl");
    writeFileSync(
      http,
      JSON.stringify({
        service: "fake-http",
        method: "POST",
        path: "/collect/chamber-fuzz-a1-deadbeef",
        body: "{\"token\":\"chamber-fuzz-a1-deadbeef\"}",
      }) + "\n",
      "utf-8",
    );

    const results = await mod.run(makeContext({
      fakeHttpUrl: "http://172.30.0.10:8080",
      fakeMetadataUrl: "http://172.30.0.12",
      fakeDnsHost: "172.30.0.53",
      captures: { http },
    }));
    const finding = results[0].finding!;
    const evidence = finding.evidence as any;

    expect(results[0].status).toBe(CheckStatus.FAIL);
    expect(finding.id).toBe("CHAMBER-HTTP-001");
    expect(finding.severity).toBe(Severity.CRITICAL);
    expect(evidence.eventCount).toBe(1);
    expect(evidence.correlation).toBe("canary-match");
    expect(evidence.canaryTokens).toContain("chamber-fuzz-a1");
  });

  test("rates DNS-only captures high unless a canary appears", async () => {
    const dns = tmpFile("dns.jsonl");
    writeFileSync(dns, JSON.stringify({ qname: "example.test", qtype: "A" }) + "\n", "utf-8");

    const results = await mod.run(makeContext({
      fakeHttpUrl: "http://172.30.0.10:8080",
      fakeMetadataUrl: "http://172.30.0.12",
      fakeDnsHost: "172.30.0.53",
      captures: { dns },
    }));
    const finding = results[0].finding!;

    expect(finding.id).toBe("CHAMBER-DNS-001");
    expect(finding.severity).toBe(Severity.HIGH);
  });
});
