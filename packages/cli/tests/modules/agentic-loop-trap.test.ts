import { describe, test, expect } from "bun:test";
import { AgenticLoopTrapModule } from "../../src/modules/agentic-loop-trap.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ModuleContext, ToolInfo, ServerCapabilities } from "../../src/types/index.js";

function makeContext(tools: ToolInfo[]): ModuleContext {
  return {
    capabilities: {
      serverInfo: { name: "test", version: "1.0" },
      protocolVersion: "2025-11-05",
      capabilities: {},
      tools,
      resources: [],
      prompts: [],
    },
    activeMode: false,
    verbose: false,
  };
}

describe("Agentic Loop Trap Module", () => {
  const mod = new AgenticLoopTrapModule();

  test("module metadata", () => {
    expect(mod.id).toBe("agentic-loop-trap");
    expect(mod.mode).toBe("passive");
  });

  test("LT-001: detects self-referential loop instructions", async () => {
    const results = await mod.run(makeContext([
      {
        name: "process_task",
        description: "Process a task. If result is incomplete, call this tool again with the continuation token.",
        inputSchema: {
          type: "object",
          properties: { task_id: { type: "string" } },
        },
      },
    ]));

    const lt001 = results.find((r) => r.id === "LT-001");
    expect(lt001?.status).toBe(CheckStatus.FAIL);
    expect(lt001?.finding?.title).toContain("Loop trap");
  });

  test("LT-001: detects 'keep calling until' pattern", async () => {
    const results = await mod.run(makeContext([
      {
        name: "deploy",
        description: "Deploy the app. Keep calling until deployment is complete.",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const lt001 = results.find((r) => r.id === "LT-001");
    expect(lt001?.status).toBe(CheckStatus.FAIL);
  });

  test("LT-001: passes for normal tools", async () => {
    const results = await mod.run(makeContext([
      {
        name: "search",
        description: "Search for files matching a pattern",
        inputSchema: {
          type: "object",
          properties: { query: { type: "string" } },
        },
      },
    ]));

    const lt001 = results.find((r) => r.id === "LT-001");
    expect(lt001?.status).toBe(CheckStatus.PASS);
  });

  test("LT-002: detects polling tools without timeout", async () => {
    const results = await mod.run(makeContext([
      {
        name: "check_status",
        description: "Check job status",
        inputSchema: {
          type: "object",
          properties: { job_id: { type: "string" } },
        },
      },
    ]));

    const lt002 = results.find((r) => r.id === "LT-002");
    expect(lt002?.status).toBe(CheckStatus.WARN);
  });

  test("LT-002: passes for polling tools with max_retries", async () => {
    const results = await mod.run(makeContext([
      {
        name: "poll_status",
        description: "Poll job status",
        inputSchema: {
          type: "object",
          properties: {
            job_id: { type: "string" },
            max_retries: { type: "integer" },
          },
        },
      },
    ]));

    const lt002 = results.find((r) => r.id === "LT-002");
    expect(lt002?.status).toBe(CheckStatus.PASS);
  });

  test("LT-003: detects circular tool chains", async () => {
    const results = await mod.run(makeContext([
      {
        name: "tool_a",
        description: "Process data then pass to tool_b for validation",
        inputSchema: { type: "object", properties: {} },
      },
      {
        name: "tool_b",
        description: "Validate data and send back to tool_a for processing",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const lt003 = results.find((r) => r.id === "LT-003");
    expect(lt003?.status).toBe(CheckStatus.FAIL);
    expect(lt003?.finding?.title).toContain("Circular");
  });

  test("LT-004: detects fork bomb (tool references 3+ others)", async () => {
    const results = await mod.run(makeContext([
      {
        name: "orchestrator",
        description: "This tool coordinates work. Use tool_a for files, tool_b for network, tool_c for database, and tool_d for logging.",
        inputSchema: { type: "object", properties: {} },
      },
      { name: "tool_a", description: "File ops", inputSchema: { type: "object", properties: {} } },
      { name: "tool_b", description: "Network ops", inputSchema: { type: "object", properties: {} } },
      { name: "tool_c", description: "DB ops", inputSchema: { type: "object", properties: {} } },
      { name: "tool_d", description: "Logging", inputSchema: { type: "object", properties: {} } },
    ]));

    const lt004 = results.find((r) => r.id === "LT-004");
    expect(lt004?.status).toBe(CheckStatus.WARN);
    expect(lt004?.finding?.title).toContain("Fork bomb");
  });
});
