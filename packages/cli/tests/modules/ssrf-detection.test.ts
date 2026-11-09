import { describe, test, expect } from "bun:test";
import { SsrfDetectionModule } from "../../src/modules/ssrf-detection.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ModuleContext, ToolInfo } from "../../src/types/index.js";
import { mkdtempSync, writeFileSync, appendFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

function makeContext(
  tools: ToolInfo[],
  callTool?: ModuleContext["callTool"]
): ModuleContext {
  return {
    capabilities: {
      serverInfo: { name: "test-server", version: "1.0.0" },
      protocolVersion: "2025-11-05",
      capabilities: {},
      tools,
      resources: [],
      prompts: [],
    },
    callTool,
    activeMode: !!callTool,
    verbose: false,
    probeDelay: 0,
  };
}

describe("SsrfDetectionModule", () => {
  const mod = new SsrfDetectionModule();

  test("module metadata is correct", () => {
    expect(mod.id).toBe("ssrf-detection");
    expect(mod.mode).toBe("active");
  });

  const urlTool: ToolInfo = {
    name: "fetch_data",
    description: "Fetches data from a URL",
    inputSchema: { type: "object", properties: { url: { type: "string", format: "uri" } } }
  };

  test("detects tools with URL parameters", async () => {
    const results = await mod.run(makeContext([urlTool]));
    const check = results.find(r => r.id === "SSRF-001");
    // Should WARN since there's no callTool but we found a URL param
    expect(check?.status).toBe(CheckStatus.WARN);
    expect(check?.finding?.severity).toBe(Severity.LOW);
  });

  test("active probe detects SSRF loopback", async () => {
    let receivedPayloads: string[] = [];
    
    const callTool = async (_name: string, args: Record<string, unknown>) => {
      receivedPayloads.push(args.url as string);
      const url = args.url as string;
      if (url.includes("127.0.0.1") || url.includes("localhost") || url.toLowerCase().includes("127.0.0.1")) {
        return "SUCCESS HTML BODY DATA";
      }
      if (url.includes("[::1]")) {
        return "SUCCESS HTML BODY DATA";
      }
      throw new Error("Blocked");
    };

    const results = await mod.run(makeContext([urlTool], callTool));
    const ssrfResult = results.find(r => r.id.startsWith("SSRF-010-"));
    expect(ssrfResult?.status).toBe(CheckStatus.FAIL);
    expect(ssrfResult?.finding?.severity).toBe(Severity.HIGH);
    expect(receivedPayloads.length).toBeGreaterThan(0);
  });

  test("uses detonation chamber probes as verified capture sinks", async () => {
    const receivedPayloads: string[] = [];

    const callTool = async (_name: string, args: Record<string, unknown>) => {
      const url = args.url as string;
      receivedPayloads.push(url);
      if (url.startsWith("http://172.30.0.10:8080")) {
        return '{"captured": true, "service": "fake-http"}';
      }
      throw new Error("Blocked");
    };

    const context = makeContext([urlTool], callTool);
    context.chamber = {
      runDir: "/tmp/chamber",
      networkName: "test_chamber_net",
      fakeHttpUrl: "http://172.30.0.10:8080",
      fakeMetadataUrl: "http://172.30.0.12",
      fakeDnsHost: "172.30.0.53",
      captures: {
        http: "/tmp/chamber/captures/http/requests.jsonl",
        metadata: "/tmp/chamber/captures/metadata/requests.jsonl",
      },
    };

    const results = await mod.run(context);
    const ssrfResult = results.find(r => r.id === "SSRF-010-fetch_data");

    expect(receivedPayloads[0]).toBe("http://172.30.0.10:8080/ssrf-probe");
    expect(ssrfResult?.status).toBe(CheckStatus.FAIL);
    expect(ssrfResult?.finding?.severity).toBe(Severity.HIGH);
    const evidence = ssrfResult?.finding?.evidence as any;
    expect(evidence.successfulProbes[0].category).toBe("chamber-http");
    expect(evidence.successfulProbes[0].captureFile).toBe("/tmp/chamber/captures/http/requests.jsonl");
  });

  test("treats chamber capture growth as proof even when response is reformatted", async () => {
    const dir = mkdtempSync(join(tmpdir(), "scanner-chamber-"));
    const captureFile = join(dir, "requests.jsonl");
    writeFileSync(captureFile, "", "utf-8");

    const callTool = async (_name: string, args: Record<string, unknown>) => {
      if (String(args.url).startsWith("http://172.30.0.10:8080")) {
        appendFileSync(captureFile, '{"path":"/ssrf-probe"}\n', "utf-8");
        return "fetched 12 bytes";
      }
      throw new Error("Blocked");
    };

    const context = makeContext([urlTool], callTool);
    context.chamber = {
      fakeHttpUrl: "http://172.30.0.10:8080",
      fakeMetadataUrl: "http://172.30.0.12",
      fakeDnsHost: "172.30.0.53",
      captures: { http: captureFile },
    };

    const results = await mod.run(context);
    const ssrfResult = results.find(r => r.id === "SSRF-010-fetch_data");
    const evidence = ssrfResult?.finding?.evidence as any;

    expect(ssrfResult?.status).toBe(CheckStatus.FAIL);
    expect(evidence.successfulProbes[0].captureLinesBefore).toBe(0);
    expect(evidence.successfulProbes[0].captureLinesAfter).toBe(1);
  });

  test("active probe fails if all rejected", async () => {
    const callTool = async () => { throw new Error("Blocked by filter"); };
    const results = await mod.run(makeContext([urlTool], callTool));
    const ssrfResult = results.find(r => r.id.startsWith("SSRF-010-"));
    expect(ssrfResult?.status).toBe(CheckStatus.PASS);
  });
});
