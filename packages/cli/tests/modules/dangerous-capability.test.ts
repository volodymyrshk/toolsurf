import { describe, test, expect } from "bun:test";
import { DangerousCapabilityModule } from "../../src/modules/dangerous-capability.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ModuleContext, ToolInfo } from "../../src/types/index.js";

function makeContext(tools: ToolInfo[]): ModuleContext {
  return {
    capabilities: {
      serverInfo: { name: "test-server", version: "1.0.0" },
      protocolVersion: "2025-03-26",
      capabilities: {},
      tools,
      resources: [],
      prompts: [],
    },
    activeMode: false,
    verbose: false,
  };
}

const module = new DangerousCapabilityModule();

describe("DangerousCapabilityModule", () => {
  test("module metadata", () => {
    expect(module.id).toBe("dangerous-capability");
    expect(module.mode).toBe("passive");
    expect(typeof module.version).toBe("string");
  });

  describe("DC-001 — arbitrary SQL execution", () => {
    test("flags tool with 'sql' parameter and no constraints", async () => {
      const tools: ToolInfo[] = [{
        name: "run_query",
        description: "Execute a database query",
        inputSchema: {
          type: "object",
          properties: {
            sql: { type: "string", description: "SQL query to execute" },
          },
        },
      }];
      const results = await module.run(makeContext(tools));
      const dc001 = results.find((r) => r.id.startsWith("DC-001"));
      expect(dc001).toBeDefined();
      expect(dc001!.status).toBe(CheckStatus.FAIL);
      expect(dc001!.finding?.severity).toBe(Severity.CRITICAL);
    });

    test("does not flag SQL parameter with enum constraint", async () => {
      const tools: ToolInfo[] = [{
        name: "run_query",
        description: "Run predefined query",
        inputSchema: {
          type: "object",
          properties: {
            query: {
              type: "string",
              enum: ["SELECT count(*) FROM orders", "SELECT id FROM users"],
              description: "Predefined query to run",
            },
          },
        },
      }];
      const results = await module.run(makeContext(tools));
      const dc001 = results.find((r) => r.id.startsWith("DC-001") && r.status === CheckStatus.FAIL);
      expect(dc001).toBeUndefined();
    });
  });

  describe("DC-002 — arbitrary code execution", () => {
    test("flags tool with 'code' parameter", async () => {
      const tools: ToolInfo[] = [{
        name: "eval_code",
        description: "Evaluate code",
        inputSchema: {
          type: "object",
          properties: {
            code: { type: "string", description: "Code to evaluate" },
          },
        },
      }];
      const results = await module.run(makeContext(tools));
      const dc002 = results.find((r) => r.id.startsWith("DC-002"));
      expect(dc002).toBeDefined();
      expect(dc002!.status).toBe(CheckStatus.FAIL);
      expect(dc002!.finding?.severity).toBe(Severity.CRITICAL);
    });

    test("flags tool with 'script' parameter", async () => {
      const tools: ToolInfo[] = [{
        name: "run_script",
        description: "Run a script",
        inputSchema: {
          type: "object",
          properties: {
            script: { type: "string" },
          },
        },
      }];
      const results = await module.run(makeContext(tools));
      const dc002 = results.find((r) => r.id.startsWith("DC-002"));
      expect(dc002).toBeDefined();
    });
  });

  describe("DC-003 — arbitrary shell command execution", () => {
    test("flags tool with 'command' parameter and no pattern constraint", async () => {
      const tools: ToolInfo[] = [{
        name: "exec_shell",
        description: "Execute a shell command",
        inputSchema: {
          type: "object",
          properties: {
            command: { type: "string", description: "Shell command" },
          },
        },
      }];
      const results = await module.run(makeContext(tools));
      const dc003 = results.find((r) => r.id.startsWith("DC-003"));
      expect(dc003).toBeDefined();
      expect(dc003!.status).toBe(CheckStatus.FAIL);
    });
  });

  describe("DC-004 — unrestricted file system access", () => {
    test("flags tool with unconstrained 'path' parameter", async () => {
      const tools: ToolInfo[] = [{
        name: "read_file",
        description: "Read any file",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string", description: "Absolute file path" },
          },
        },
      }];
      const results = await module.run(makeContext(tools));
      const dc004 = results.find((r) => r.id.startsWith("DC-004") || r.id.startsWith("DC-005"));
      expect(dc004).toBeDefined();
    });
  });

  describe("safe tools", () => {
    test("clean tool with constrained schema produces no CRITICAL findings", async () => {
      const tools: ToolInfo[] = [{
        name: "get_weather",
        description: "Get weather for a city",
        inputSchema: {
          type: "object",
          properties: {
            city: {
              type: "string",
              enum: ["London", "Tokyo", "Berlin"],
              description: "City name",
            },
          },
          required: ["city"],
        },
      }];
      const results = await module.run(makeContext(tools));
      const criticals = results.filter(
        (r) => r.status === CheckStatus.FAIL && r.finding?.severity === Severity.CRITICAL
      );
      expect(criticals).toHaveLength(0);
    });

    test("empty tool list produces no findings", async () => {
      const results = await module.run(makeContext([]));
      const fails = results.filter((r) => r.status === CheckStatus.FAIL);
      expect(fails).toHaveLength(0);
    });
  });
});
