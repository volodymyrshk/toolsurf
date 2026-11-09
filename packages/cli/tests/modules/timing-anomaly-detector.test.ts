import { describe, test, expect } from "bun:test";
import { TimingAnomalyDetectorModule } from "../../src/modules/timing-anomaly-detector.js";
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

describe("TimingAnomalyDetectorModule", () => {
  const module = new TimingAnomalyDetectorModule();

  test("module metadata is correct", () => {
    expect(module.id).toBe("timing-anomaly");
    expect(module.mode).toBe("active");
    expect(module.version).toBe("1.0.0");
  });

  test("skips when not in active mode", async () => {
    const context = makeContext([]);
    context.activeMode = false;
    const results = await module.run(context);
    expect(results[0].id).toBe("TAD-000");
    expect(results[0].status).toBe(CheckStatus.SKIP);
  });

  test("detects blind SQL injection via timing", async () => {
    const tools: ToolInfo[] = [
      {
        name: "run_query",
        description: "Runs a database query",
        inputSchema: { type: "object", properties: { query: { type: "string" } } },
      },
    ];

    const callTool = async (name: string, args: Record<string, unknown>) => {
      const query = args.query as string;
      if (query?.includes("pg_sleep")) {
        await new Promise((r) => setTimeout(r, 800));
        return "Query executed";
      }
      if (query?.includes("tautology")) {
        await new Promise((r) => setTimeout(r, 600));
        return [{ id: 1, name: "test" }];
      }
      await new Promise((r) => setTimeout(r, 50));
      return { status: 200 };
    };

    const context = makeContext(tools, callTool);
    const results = await module.run(context);

    const check = results.find((r) => r.id.startsWith("TAD-run_query"));
    expect(check).toBeDefined();
    expect(check!.status).toBe(CheckStatus.FAIL);
    expect(check!.finding?.severity).toBe(Severity.CRITICAL);
  });

  test("detects path traversal via timing (file exists vs not)", async () => {
    const tools: ToolInfo[] = [
      {
        name: "read_file",
        description: "Reads a file",
        inputSchema: { type: "object", properties: { path: { type: "string" } } },
      },
    ];

    const callTool = async (name: string, args: Record<string, unknown>) => {
      const path = args.path as string;
      if (path === "/etc/passwd") {
        await new Promise((r) => setTimeout(r, 700));
        return "root:x:0:0:root:/root:/bin/bash";
      }
      await new Promise((r) => setTimeout(r, 50));
      return { error: "Not found" };
    };

    const context = makeContext(tools, callTool);
    const results = await module.run(context);

    const check = results.find((r) => r.id.startsWith("TAD-read_file"));
    expect(check).toBeDefined();
    expect(check!.status).toBe(CheckStatus.FAIL);
  });

  test("detects auth bypass via timing (valid vs invalid user)", async () => {
    const tools: ToolInfo[] = [
      {
        name: "check_user",
        description: "Checks if user exists",
        inputSchema: { type: "object", properties: { username: { type: "string" } } },
      },
    ];

    const callTool = async (name: string, args: Record<string, unknown>) => {
      const username = args.username as string;
      if (username === "admin") {
        await new Promise((r) => setTimeout(r, 900));
        return { exists: true };
      }
      await new Promise((r) => setTimeout(r, 50));
      return { exists: false };
    };

    const context = makeContext(tools, callTool);
    const results = await module.run(context);

    const check = results.find((r) => r.id.startsWith("TAD-check_user"));
    expect(check).toBeDefined();
    expect(check!.status).toBe(CheckStatus.FAIL);
  });

  test("passes when timing is consistent", async () => {
    const tools: ToolInfo[] = [
      {
        name: "echo",
        description: "Echoes input",
        inputSchema: { type: "object", properties: { msg: { type: "string" } } },
      },
    ];

    const callTool = async () => {
      await new Promise((r) => setTimeout(r, 50));
      return { ok: true };
    };

    const context = makeContext(tools, callTool);
    const results = await module.run(context);

    const check = results.find((r) => r.id === "TAD-000");
    expect(check).toBeDefined();
    expect(check!.status).toBe(CheckStatus.PASS);
  });

  test("handles tools with no string parameters", async () => {
    const tools: ToolInfo[] = [
      {
        name: "add",
        description: "Adds numbers",
        inputSchema: { type: "object", properties: { a: { type: "number" }, b: { type: "number" } } },
      },
    ];

    const context = makeContext(tools, async () => ({ result: 42 }));
    const results = await module.run(context);

    const check = results.find((r) => r.id === "TAD-000");
    expect(check).toBeDefined();
    expect(check!.status).toBe(CheckStatus.PASS);
  });

  test("handles tool call failures gracefully", async () => {
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
