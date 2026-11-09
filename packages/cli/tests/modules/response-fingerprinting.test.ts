import { describe, test, expect } from "bun:test";
import { ResponseFingerprintingModule } from "../../src/modules/response-fingerprinting.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ModuleContext, ToolInfo } from "../../src/types/index.js";

function makeContext(
  tools: ToolInfo[],
  callTool?: (name: string, args: Record<string, unknown>) => Promise<unknown>
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

const basicTool: ToolInfo = {
  name: "echo",
  description: "Echo input",
  inputSchema: {
    type: "object",
    properties: {
      message: { type: "string" },
    },
    required: ["message"],
  },
};

describe("ResponseFingerprintingModule", () => {
  const module = new ResponseFingerprintingModule();

  test("module metadata is correct", () => {
    expect(module.id).toBe("response-fingerprinting");
    expect(module.mode).toBe("active");
    expect(module.version).toBe("1.0.0");
  });

  test("skips all checks without callTool", async () => {
    const context = makeContext([basicTool]);
    const results = await module.run(context);

    expect(results.length).toBe(3);
    expect(results.every((r) => r.status === CheckStatus.SKIP)).toBe(true);
  });

  describe("determinism (RF-001)", () => {
    test("passes when tool returns consistent responses", async () => {
      const callTool = async () => '{"result": "hello"}';
      const context = makeContext([basicTool], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "RF-001");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.PASS);
    });

    test("warns when tool returns varying responses", async () => {
      let counter = 0;
      const callTool = async () => {
        counter++;
        // Each call returns structurally different data
        return JSON.stringify({ result: "x".repeat(counter * 100) });
      };
      const context = makeContext([basicTool], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "RF-001");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.WARN);
      expect(check!.finding?.cweId).toBe("CWE-656");
    });

    test("ignores expected variance (timestamps, UUIDs)", async () => {
      let counter = 0;
      const callTool = async () => {
        counter++;
        return JSON.stringify({
          result: "data",
          timestamp: `2024-01-0${counter}T12:00:00Z`,
          id: `550e8400-e29b-41d4-a716-44665544000${counter}`,
        });
      };
      const context = makeContext([basicTool], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "RF-001");
      expect(check!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("timing variance (RF-002)", () => {
    test("passes with consistent timing", async () => {
      const callTool = async () => "fast";
      const context = makeContext([basicTool], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "RF-002");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("stateful behavior (RF-003)", () => {
    test("passes when tool is stateless", async () => {
      const callTool = async () => '{"status": "ok"}';
      const context = makeContext([basicTool], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "RF-003");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.PASS);
    });

    test("detects monotonically growing responses", async () => {
      let accumulator = "";
      const callTool = async () => {
        accumulator += "data_chunk_";
        return accumulator;
      };
      const context = makeContext([basicTool], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "RF-003");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.FAIL);
      expect(check!.finding?.severity).toBe(Severity.HIGH);
    });
  });
});
