import { describe, test, expect } from "bun:test";
import { SupplyChainAnalysisModule } from "../../src/modules/supply-chain-analysis.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ModuleContext, ToolInfo } from "../../src/types/index.js";

function makeContext(
  serverName: string,
  version: string,
  tools: ToolInfo[] = [],
  resources: ModuleContext["capabilities"]["resources"] = [],
  prompts: ModuleContext["capabilities"]["prompts"] = []
): ModuleContext {
  return {
    capabilities: {
      serverInfo: { name: serverName, version },
      protocolVersion: "2025-11-05",
      capabilities: {},
      tools,
      resources,
      prompts,
    },
    activeMode: false,
    verbose: false,
  };
}

const dummyTool: ToolInfo = {
  name: "test_tool",
  description: "A test tool",
  inputSchema: { type: "object", properties: {} },
};

const annotatedTool: ToolInfo = {
  name: "safe_tool",
  description: "A safe tool",
  annotations: { readOnlyHint: true },
  inputSchema: { type: "object", properties: {} },
};

const destructiveTool: ToolInfo = {
  name: "delete_all",
  description: "Destroy everything",
  annotations: { destructiveHint: true },
  inputSchema: { type: "object", properties: {} },
};

describe("SupplyChainAnalysisModule", () => {
  const module = new SupplyChainAnalysisModule();

  test("module metadata is correct", () => {
    expect(module.id).toBe("supply-chain-analysis");
    expect(module.mode).toBe("passive");
    expect(module.version).toBe("2.0.0");
  });

  describe("typosquatting (SC-001)", () => {
    test("passes for legitimate server names", async () => {
      const context = makeContext("my-custom-server", "1.0.0", [dummyTool]);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "SC-001");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.PASS);
    });

    test("warns on names close to popular packages", async () => {
      // "mcp-servar" is 1 edit from "mcp-server"
      const context = makeContext("mcp-servar", "1.0.0", [dummyTool]);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "SC-001");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.WARN);
      expect(check!.finding?.severity).toBe(Severity.HIGH);
    });

    test("warns on suspicious naming patterns", async () => {
      const context = makeContext("unofficial-official-server", "1.0.0", [dummyTool]);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "SC-001");
      expect(check!.status).toBe(CheckStatus.WARN);
    });

    test("warns on debug/test suffixes", async () => {
      const context = makeContext("server-debug", "1.0.0", [dummyTool]);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "SC-001");
      expect(check!.status).toBe(CheckStatus.WARN);
    });
  });

  describe("metadata (SC-002)", () => {
    test("passes for proper metadata", async () => {
      const context = makeContext("proper-server", "1.2.3", [dummyTool]);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "SC-002");
      expect(check!.status).toBe(CheckStatus.PASS);
    });

    test("warns on placeholder metadata", async () => {
      const context = makeContext("unknown", "0.0.0", [dummyTool]);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "SC-002");
      expect(check!.status).toBe(CheckStatus.WARN);
    });

    test("warns on dev indicators", async () => {
      const context = makeContext("my-server-localhost", "1.0.0", [dummyTool]);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "SC-002");
      expect(check!.status).toBe(CheckStatus.WARN);
    });
  });

  describe("capability sprawl (SC-003)", () => {
    test("passes for reasonable tool counts", async () => {
      const context = makeContext("server", "1.0.0", [dummyTool, annotatedTool]);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "SC-003");
      expect(check!.status).toBe(CheckStatus.PASS);
    });

    test("does not duplicate annotation-only concerns already covered by TP-006", async () => {
      const tools = Array.from({ length: 5 }, (_, i) => ({
        ...dummyTool,
        name: `tool_${i}`,
      }));
      const context = makeContext("server", "1.0.0", tools);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "SC-003");
      expect(check!.status).toBe(CheckStatus.PASS);
      expect(check!.finding).toBeUndefined();
      expect(check!.message).toContain("TP-006");
    });

    test("warns when most tools are destructive", async () => {
      const tools = Array.from({ length: 6 }, (_, i) => ({
        ...destructiveTool,
        name: `destroy_${i}`,
      }));
      const context = makeContext("server", "1.0.0", tools);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "SC-003");
      expect(check!.status).toBe(CheckStatus.WARN);
    });
  });

  describe("version (SC-004)", () => {
    test("passes for semver versions", async () => {
      const context = makeContext("server", "2.1.0", [dummyTool]);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "SC-004");
      expect(check!.status).toBe(CheckStatus.PASS);
    });

    test("flags non-semver versions", async () => {
      const context = makeContext("server", "latest", [dummyTool]);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "SC-004");
      expect(check!.status).toBe(CheckStatus.WARN);
    });
  });

  describe("tool count (SC-005)", () => {
    test("passes with at least one tool", async () => {
      const context = makeContext("server", "1.0.0", [dummyTool]);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "SC-005");
      expect(check!.status).toBe(CheckStatus.PASS);
    });

    test("warns with zero tools", async () => {
      const context = makeContext("server", "1.0.0", []);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "SC-005");
      expect(check!.status).toBe(CheckStatus.WARN);
    });
  });
});
