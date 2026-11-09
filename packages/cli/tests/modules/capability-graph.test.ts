import { describe, test, expect } from "bun:test";
import { ToolCapabilityGraphModule } from "../../src/modules/capability-graph.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ModuleContext, ToolInfo } from "../../src/types/index.js";

function makeContext(tools: ToolInfo[]): ModuleContext {
  return {
    capabilities: {
      serverInfo: { name: "test-server", version: "1.0.0" },
      protocolVersion: "2025-11-05",
      capabilities: {},
      tools,
      resources: [],
      prompts: [],
    },
    activeMode: false,
    verbose: false,
    probeDelay: 0,
  };
}

describe("ToolCapabilityGraphModule", () => {
  const mod = new ToolCapabilityGraphModule();

  test("module metadata is correct", () => {
    expect(mod.id).toBe("capability-graph");
    expect(mod.mode).toBe("passive");
  });

  test("skips if no tools", async () => {
    const results = await mod.run(makeContext([]));
    expect(results.length).toBe(1);
    expect(results[0].status).toBe(CheckStatus.PASS);
  });

  test("categorizes tools correctly", async () => {
    const tools: ToolInfo[] = [
      { name: "read_file", description: "reads a file", inputSchema: {} },
      { name: "write", description: "writes data", inputSchema: {} },
      { name: "curl", description: "fetches HTTP", inputSchema: {} },
      { name: "bash", description: "executes bash", inputSchema: {} },
      { name: "magic_tool", description: "does magic", inputSchema: {} },
    ];

    const results = await mod.run(makeContext(tools));
    const result = results[0];
    expect(result.status).toBe(CheckStatus.PASS);
    
    const evidence = result.finding?.evidence as any;
    expect(evidence.graphNodes["file-read"]).toContain("read_file");
    expect(evidence.graphNodes["file-write"]).toContain("write");
    expect(evidence.graphNodes["network-fetch"]).toContain("curl");
    expect(evidence.graphNodes["command-execution"]).toContain("bash");
    expect(evidence.graphNodes["unknown"]).toContain("magic_tool");
  });
});
