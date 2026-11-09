import { describe, test, expect } from "bun:test";
import { SessionStateLeakageModule } from "../../src/modules/session-state-leakage.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ModuleContext, ToolInfo } from "../../src/types/index.js";

function makeContext(tools: ToolInfo[], callTool?: (name: string, args: Record<string, unknown>) => Promise<unknown>): ModuleContext {
  return {
    capabilities: {
      serverInfo: { name: "test-server", version: "1.0.0" },
      protocolVersion: "2025-11-05",
      capabilities: {},
      tools,
      resources: [],
      prompts: [],
    },
    activeMode: true,
    verbose: false,
    callTool,
  };
}

describe("SessionStateLeakageModule", () => {
  const module = new SessionStateLeakageModule();

  test("module metadata is correct", () => {
    expect(module.id).toBe("session-state-leakage");
    expect(module.mode).toBe("active");
    expect(module.version).toBe("1.0.0");
  });

  test("skips when not in active mode", async () => {
    const context = makeContext([]);
    context.activeMode = false;
    const results = await module.run(context);
    expect(results[0].id).toBe("SSL-000");
    expect(results[0].status).toBe(CheckStatus.SKIP);
  });

  describe("SSL-001: same-tool state leakage", () => {
    test("detects state leakage within same tool", async () => {
      const tools: ToolInfo[] = [
        {
          name: "read_file",
          description: "Reads a file",
          inputSchema: { type: "object", properties: { path: { type: "string" } } },
        },
      ];

      const state = { lastPath: "" };

      const callTool = async (name: string, args: Record<string, unknown>) => {
        const path = args.path as string;
        // Simulated buggy tool: returns previous path's content
        const result = state.lastPath ? `Content of ${path}: (cached: ${state.lastPath})` : `Content of ${path}`;
        state.lastPath = path;
        return result;
      };

      const context = makeContext(tools, callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id.startsWith("SSL-001-read_file"));
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.FAIL);
      expect(check!.finding?.severity).toBe(Severity.HIGH);
    });

    test("passes when tool is stateless", async () => {
      const tools: ToolInfo[] = [
        {
          name: "echo",
          description: "Echoes input",
          inputSchema: { type: "object", properties: { msg: { type: "string" } } },
        },
      ];

      const callTool = async (name: string, args: Record<string, unknown>) => {
        return args.msg;
      };

      const context = makeContext(tools, callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id.startsWith("SSL-001-echo"));
      expect(check).toBeUndefined();
    });
  });

  describe("SSL-002: cross-tool state leakage", () => {
    test("detects state leakage between similar tools", async () => {
      const tools: ToolInfo[] = [
        {
          name: "db_query",
          description: "Queries database",
          inputSchema: { type: "object", properties: { sql: { type: "string" } } },
        },
        {
          name: "db_execute",
          description: "Executes SQL command",
          inputSchema: { type: "object", properties: { command: { type: "string" } } },
        },
      ];

      const sharedState = { marker: "" };

      const callTool = async (name: string, args: Record<string, unknown>) => {
        if (name === "db_query") {
          const sql = args.sql as string;
          sharedState.marker = sql;
          return "Query executed";
        }
        if (name === "db_execute") {
          // Bug: returns previous db_query's marker
          return `Executed. (note: ${sharedState.marker})`;
        }
        return "ok";
      };

      const context = makeContext(tools, callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id.startsWith("SSL-002-db_query-db_execute"));
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.FAIL);
      expect(check!.finding?.severity).toBe(Severity.CRITICAL);
    });

    test("does not test dissimilar tools", async () => {
      const tools: ToolInfo[] = [
        {
          name: "read_file",
          description: "Reads a file",
          inputSchema: { type: "object", properties: { path: { type: "string" } } },
        },
        {
          name: "send_email",
          description: "Sends an email",
          inputSchema: { type: "object", properties: { to: { type: "string" } } },
        },
      ];

      const callTool = async () => "ok";
      const context = makeContext(tools, callTool);
      const results = await module.run(context);

      // No cross-tool checks for dissimilar tools
      const crossToolCheck = results.find((r) => r.id.startsWith("SSL-002"));
      expect(crossToolCheck).toBeUndefined();
    });
  });

  describe("edge cases", () => {
    test("handles empty tool list", async () => {
      const context = makeContext([], async () => "ok");
      const results = await module.run(context);
      expect(results[0].id).toBe("SSL-000");
      expect(results[0].status).toBe(CheckStatus.PASS);
    });

    test("handles tools with no string parameters", async () => {
      const tools: ToolInfo[] = [
        {
          name: "add",
          description: "Adds numbers",
          inputSchema: { type: "object", properties: { a: { type: "number" } } },
        },
      ];

      const context = makeContext(tools, async () => ({ result: 42 }));
      const results = await module.run(context);

      // No string param = can't test state leakage
      expect(results.find((r) => r.id === "SSL-000")).toBeDefined();
    });

    test("handles tool call errors gracefully", async () => {
      const tools: ToolInfo[] = [
        {
          name: "broken",
          description: "Broken tool",
          inputSchema: { type: "object", properties: { input: { type: "string" } } },
        },
      ];

      const callTool = async () => { throw new Error("Connection refused"); };
      const context = makeContext(tools, callTool);
      const results = await module.run(context);

      // Should not crash
      expect(results.length).toBeGreaterThan(0);
    });
  });
});
