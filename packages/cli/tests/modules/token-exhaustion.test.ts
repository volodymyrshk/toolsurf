import { describe, test, expect } from "bun:test";
import { TokenExhaustionModule } from "../../src/modules/token-exhaustion.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ModuleContext, ToolInfo, ServerCapabilities } from "../../src/types/index.js";

function makeContext(tools: ToolInfo[], llmOutputTokenLimit?: number): ModuleContext {
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
    llmOutputTokenLimit,
  };
}

describe("Token Exhaustion Module", () => {
  const mod = new TokenExhaustionModule();

  test("module metadata", () => {
    expect(mod.id).toBe("token-exhaustion");
    expect(mod.mode).toBe("passive");
  });

  test("TE-001: detects unbounded strings", async () => {
    const results = await mod.run(makeContext([
      {
        name: "process_data",
        description: "Process data",
        inputSchema: {
          type: "object",
          properties: {
            content: { type: "string" }, // no maxLength
            query: { type: "string" },   // no maxLength
          },
        },
      },
    ]));

    const te001 = results.find((r) => r.id === "TE-001");
    expect(te001?.status).toBe(CheckStatus.FAIL);
    expect(te001?.finding?.severity).toBe(Severity.HIGH); // 'content' is a high-risk param
  });

  test("TE-001: passes for constrained strings", async () => {
    const results = await mod.run(makeContext([
      {
        name: "search",
        description: "Search",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string", maxLength: 500 },
            mode: { type: "string", enum: ["fast", "thorough"] },
          },
        },
      },
    ]));

    const te001 = results.find((r) => r.id === "TE-001");
    expect(te001?.status).toBe(CheckStatus.PASS);
  });

  test("TE-001: caps LLM-generated argument estimates for URL-like params", async () => {
    const results = await mod.run(makeContext([
      {
        name: "fetch",
        description: "Fetch a URL",
        inputSchema: {
          type: "object",
          properties: {
            url: { type: "string", format: "uri" },
            max_length: { type: "integer", default: 5000 },
          },
        },
      },
    ], 4096));

    const te001 = results.find((r) => r.id === "TE-001");
    expect(te001?.status).toBe(CheckStatus.WARN);
    expect(te001?.finding?.severity).toBe(Severity.LOW);
    expect(te001?.finding?.description).not.toContain("5MB string");
    expect(te001?.finding?.description).not.toContain("$12.50");
    expect((te001?.finding?.evidence.llmGeneratedArgumentCap as any).maxOutputTokens).toBe(4096);
    expect(te001?.finding?.evidence.responseLimitParams).toEqual(["max_length"]);
  });

  test("TE-001/TE-002: detects deeply nested unbounded properties", async () => {
    const results = await mod.run(makeContext([
      {
        name: "nested_data",
        description: "Nested data",
        inputSchema: {
          type: "object",
          properties: {
            level1: {
              type: "object",
              properties: {
                level2: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      deep_string: { type: "string" },
                      deep_array: { type: "array" }
                    }
                  }
                }
              }
            }
          }
        }
      }
    ]));

    const te001 = results.find((r) => r.id === "TE-001");
    expect(te001?.status).toBe(CheckStatus.FAIL);
    
    const te002 = results.find((r) => r.id === "TE-002");
    expect(te002?.status).toBe(CheckStatus.FAIL);
  });

  test("TE-002: detects unbounded arrays", async () => {
    const results = await mod.run(makeContext([
      {
        name: "bulk_process",
        description: "Process items",
        inputSchema: {
          type: "object",
          properties: {
            items: { type: "array", items: { type: "string" } }, // no maxItems
          },
        },
      },
    ]));

    const te002 = results.find((r) => r.id === "TE-002");
    expect(te002?.status).toBe(CheckStatus.FAIL);
  });

  test("TE-003: detects wildcard schemas", async () => {
    const results = await mod.run(makeContext([
      {
        name: "do_anything",
        description: "Does anything",
        inputSchema: { type: "object" }, // no properties at all
      },
    ]));

    const te003 = results.find((r) => r.id === "TE-003");
    expect(te003?.status).toBe(CheckStatus.FAIL);
  });

  test("TE-004: detects read tools without limits", async () => {
    const results = await mod.run(makeContext([
      {
        name: "read_file",
        description: "Read a file",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string" },
          },
        },
      },
    ]));

    const te004 = results.find((r) => r.id === "TE-004");
    expect(te004?.status).toBe(CheckStatus.WARN);
  });

  test("TE-004: passes for read tools with limit param", async () => {
    const results = await mod.run(makeContext([
      {
        name: "read_file",
        description: "Read a file",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string" },
            max_lines: { type: "integer" },
          },
        },
      },
    ]));

    const te004 = results.find((r) => r.id === "TE-004");
    expect(te004?.status).toBe(CheckStatus.PASS);
  });

  test("TE-005: calculates context tax", async () => {
    // Create many tools to exceed threshold
    const tools: ToolInfo[] = Array.from({ length: 30 }, (_, i) => ({
      name: `tool_${i}`,
      description: `A tool that does something useful for use case ${i} with detailed description`,
      inputSchema: {
        type: "object",
        properties: {
          param1: { type: "string", description: "First parameter" },
          param2: { type: "string", description: "Second parameter" },
          param3: { type: "integer", description: "Third parameter" },
        },
      },
    }));

    const results = await mod.run(makeContext(tools));
    const te005 = results.find((r) => r.id === "TE-005");
    expect(te005?.message).toContain("tokens");
  });
});
