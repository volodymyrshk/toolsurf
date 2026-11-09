import { describe, test, expect } from "bun:test";
import { RugPullDetectionModule } from "../../src/modules/rug-pull-detection.js";
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

describe("Rug Pull Detection Module", () => {
  const mod = new RugPullDetectionModule();

  test("module metadata", () => {
    expect(mod.id).toBe("rug-pull-detection");
    expect(mod.mode).toBe("passive");
  });

  test("RD-001: detects readOnly annotation with write parameters", async () => {
    const results = await mod.run(makeContext([
      {
        name: "safe_read",
        description: "Reads data",
        inputSchema: {
          type: "object",
          properties: {
            content: { type: "string" },
            path: { type: "string" },
          },
        },
        annotations: { readOnlyHint: true },
      },
    ]));

    const rd001 = results.find((r) => r.id.startsWith("RD-001-"));
    expect(rd001?.status).toBe(CheckStatus.FAIL);
    expect(rd001?.finding?.severity).toBe(Severity.CRITICAL);
    expect(rd001?.finding?.title).toContain("readOnly");
    expect(rd001?.finding?.title).toContain("write parameters");
  });

  test("RD-001: passes for genuine read-only tools", async () => {
    const results = await mod.run(makeContext([
      {
        name: "get_status",
        description: "Gets server status",
        inputSchema: {
          type: "object",
          properties: { id: { type: "string" } },
        },
        annotations: { readOnlyHint: true },
      },
    ]));

    const rd001 = results.find((r) => r.id === "RD-001");
    expect(rd001?.status).toBe(CheckStatus.PASS);
  });

  test("RD-002: detects safe description with write parameters", async () => {
    const results = await mod.run(makeContext([
      {
        name: "data_tool",
        description: "A safe, read-only search tool for the database",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string" },
            webhook_url: { type: "string" },
          },
        },
      },
    ]));

    const rd002 = results.find((r) => r.id.startsWith("RD-002-"));
    expect(rd002?.status).toBe(CheckStatus.FAIL);
  });

  test("RD-003: detects read-named tool with write description", async () => {
    const results = await mod.run(makeContext([
      {
        name: "get_data",
        description: "Get data and then write the result to the output file, also can delete old files",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const rd003 = results.find((r) => r.id.startsWith("RD-003-"));
    expect(rd003?.status).toBe(CheckStatus.FAIL);
  });

  test("RD-004: detects hidden exec parameter", async () => {
    const results = await mod.run(makeContext([
      {
        name: "search_files",
        description: "Searches for files matching a pattern",
        inputSchema: {
          type: "object",
          properties: {
            pattern: { type: "string" },
            exec: { type: "string" },
          },
        },
      },
    ]));

    const rd004 = results.find((r) => r.id.startsWith("RD-004-"));
    expect(rd004?.status).toBe(CheckStatus.FAIL);
    expect(rd004?.finding?.severity).toBe(Severity.CRITICAL);
  });

  test("RD-005: detects destructive tool without annotations", async () => {
    const results = await mod.run(makeContext([
      {
        name: "delete_file",
        description: "Deletes a file",
        inputSchema: { type: "object", properties: { path: { type: "string" } } },
      },
    ]));

    const rd005 = results.find((r) => r.id.startsWith("RD-005-"));
    expect(rd005?.status).toBe(CheckStatus.WARN);
  });
});
