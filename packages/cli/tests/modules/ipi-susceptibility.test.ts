import { describe, test, expect } from "bun:test";
import { IpiSusceptibilityModule } from "../../src/modules/ipi-susceptibility.js";
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

const module = new IpiSusceptibilityModule();

describe("IpiSusceptibilityModule", () => {
  test("module metadata", () => {
    expect(module.id).toBe("ipi-susceptibility");
    expect(module.mode).toBe("passive");
    expect(typeof module.version).toBe("string");
  });

  describe("IPI-001 — web content vectors", () => {
    test("flags URL-fetching tool as IPI vector", async () => {
      const tools: ToolInfo[] = [{
        name: "fetch_url",
        description: "Fetch and return the content of any URL",
        inputSchema: {
          type: "object",
          properties: { url: { type: "string" } },
        },
      }];
      const results = await module.run(makeContext(tools));
      const ipi001 = results.find((r) => r.id.startsWith("IPI-001") && r.status === CheckStatus.FAIL);
      expect(ipi001).toBeDefined();
    });

    test("flags web scraping tool", async () => {
      const tools: ToolInfo[] = [{
        name: "scrape_website",
        description: "Scrape content from a website",
        inputSchema: {
          type: "object",
          properties: { website: { type: "string" } },
        },
      }];
      const results = await module.run(makeContext(tools));
      const webCheck = results.find((r) => r.status === CheckStatus.FAIL);
      expect(webCheck).toBeDefined();
    });
  });

  describe("IPI-002 — user-generated content vectors", () => {
    test("flags email-reading tool", async () => {
      const tools: ToolInfo[] = [{
        name: "read_emails",
        description: "Read emails from inbox",
        inputSchema: {
          type: "object",
          properties: { folder: { type: "string" } },
        },
      }];
      const results = await module.run(makeContext(tools));
      const ipi002 = results.find((r) => r.id.startsWith("IPI-002") && r.status === CheckStatus.WARN);
      expect(ipi002).toBeDefined();
    });

    test("flags GitHub issue reading tool", async () => {
      const tools: ToolInfo[] = [{
        name: "get_issues",
        description: "Get GitHub issues from a repository",
        inputSchema: {
          type: "object",
          properties: { repo: { type: "string" } },
        },
      }];
      const results = await module.run(makeContext(tools));
      const webCheck = results.find((r) => r.status === CheckStatus.WARN);
      expect(webCheck).toBeDefined();
    });
  });

  describe("IPI-003 — database content vectors", () => {
    test("flags database query tool that returns user content", async () => {
      const tools: ToolInfo[] = [{
        name: "query_database",
        description: "Query the database and return results",
        inputSchema: {
          type: "object",
          properties: { table: { type: "string" } },
        },
      }];
      const results = await module.run(makeContext(tools));
      const warn = results.find((r) => r.status === CheckStatus.WARN);
      expect(warn).toBeDefined();
    });
  });

  describe("IPI-005 — compound IPI exposure", () => {
    test("flags server with both input vectors and exfiltration sinks", async () => {
      const tools: ToolInfo[] = [
        {
          name: "fetch_url",
          description: "Fetch URL content",
          inputSchema: { type: "object", properties: { url: { type: "string" } } },
        },
        {
          name: "read_emails",
          description: "Read emails from inbox",
          inputSchema: { type: "object", properties: { folder: { type: "string" } } },
        },
        {
          name: "send_email",
          description: "Send an email to any address",
          inputSchema: {
            type: "object",
            properties: {
              to: { type: "string" },
              body: { type: "string" },
            },
          },
        },
      ];
      const results = await module.run(makeContext(tools));
      const ipi005 = results.find((r) => r.id.startsWith("IPI-005") && r.status === CheckStatus.FAIL);
      expect(ipi005).toBeDefined();
      // 2 unique vectors (web + ugc) → HIGH; CRITICAL requires 3+ vector types
      expect(ipi005!.finding?.severity).toBe(Severity.HIGH);
    });
  });

  describe("safe tools", () => {
    test("read-only deterministic tools produce no IPI findings", async () => {
      const tools: ToolInfo[] = [{
        name: "get_weather",
        description: "Returns temperature for a city from a static API",
        inputSchema: {
          type: "object",
          properties: {
            city: { type: "string", enum: ["London", "Tokyo"] },
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
