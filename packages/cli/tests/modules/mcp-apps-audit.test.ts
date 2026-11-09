import { describe, test, expect } from "bun:test";
import { McpAppsAuditModule } from "../../src/modules/mcp-apps-audit.js";
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

const module = new McpAppsAuditModule();

describe("McpAppsAuditModule", () => {
  test("module metadata", () => {
    expect(module.id).toBe("mcp-apps-audit");
    expect(module.mode).toBe("passive");
    expect(typeof module.version).toBe("string");
  });

  describe("MA-001 — HTML-returning tools (XSS surface)", () => {
    test("flags tool that returns HTML content type", async () => {
      const tools: ToolInfo[] = [{
        name: "render_widget",
        description: "Render an interactive HTML widget to display in the chat interface",
        inputSchema: {
          type: "object",
          properties: { widget_id: { type: "string" } },
        },
      }];
      const results = await module.run(makeContext(tools));
      const ma001 = results.find((r) => r.id.startsWith("MA-001") && r.status === CheckStatus.WARN);
      expect(ma001).toBeDefined();
    });

    test("flags tool description mentioning HTML output", async () => {
      const tools: ToolInfo[] = [{
        name: "generate_dashboard",
        description: "Returns an HTML dashboard for display in the MCP Apps iframe",
        inputSchema: { type: "object", properties: {} },
      }];
      const results = await module.run(makeContext(tools));
      const warn = results.find((r) => r.status === CheckStatus.WARN);
      expect(warn).toBeDefined();
    });
  });

  describe("MA-002 — iframe security", () => {
    test("flags tool that embeds an unsandboxed iframe", async () => {
      const tools: ToolInfo[] = [{
        name: "embed_content",
        description: "Embed external content using an iframe with allowfullscreen",
        inputSchema: {
          type: "object",
          properties: { url: { type: "string" } },
        },
      }];
      const results = await module.run(makeContext(tools));
      const ma002 = results.find(
        (r) => (r.id.startsWith("MA-001") || r.id.startsWith("MA-002")) && r.status === CheckStatus.WARN
      );
      expect(ma002).toBeDefined();
    });
  });

  describe("MA-004 — external resource loading", () => {
    test("flags tool loading from external CDN in description", async () => {
      const tools: ToolInfo[] = [{
        name: "load_chart",
        description: "Loads Chart.js from cdnjs.cloudflare.com and renders a chart",
        inputSchema: { type: "object", properties: { data: { type: "string" } } },
      }];
      const results = await module.run(makeContext(tools));
      const warn = results.find((r) => r.status === CheckStatus.WARN);
      expect(warn).toBeDefined();
    });
  });

  describe("safe tools", () => {
    test("non-HTML tool with no external resources produces no MCP Apps findings", async () => {
      const tools: ToolInfo[] = [{
        name: "calculate_sum",
        description: "Returns the sum of two numbers",
        inputSchema: {
          type: "object",
          properties: {
            a: { type: "number" },
            b: { type: "number" },
          },
        },
      }];
      const results = await module.run(makeContext(tools));
      const fails = results.filter((r) => r.status === CheckStatus.FAIL);
      expect(fails).toHaveLength(0);
    });

    test("empty tool list produces no findings", async () => {
      const results = await module.run(makeContext([]));
      const fails = results.filter((r) => r.status === CheckStatus.FAIL);
      expect(fails).toHaveLength(0);
    });
  });
});
