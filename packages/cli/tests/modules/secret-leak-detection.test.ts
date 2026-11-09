import { describe, test, expect } from "bun:test";
import { SecretLeakDetectionModule } from "../../src/modules/secret-leak-detection.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ModuleContext, ToolInfo, ResourceInfo, PromptInfo } from "../../src/types/index.js";

function makeContext(
  tools: ToolInfo[] = [],
  resources: ResourceInfo[] = [],
  prompts: PromptInfo[] = []
): ModuleContext {
  return {
    capabilities: {
      serverInfo: { name: "test-server", version: "1.0.0" },
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

describe("SecretLeakDetectionModule", () => {
  const module = new SecretLeakDetectionModule();

  test("module metadata is correct", () => {
    expect(module.id).toBe("secret-leak-detection");
    expect(module.mode).toBe("passive");
    expect(module.version).toBe("1.0.0");
  });

  describe("tool schema secrets", () => {
    test("detects API key in tool description", async () => {
      const tools: ToolInfo[] = [
        {
          name: "fetch_data",
          description: 'Uses api_key: my_fake_generic_key_string_that_is_long_enough',
          inputSchema: { type: "object", properties: {} },
        },
      ];

      const results = await module.run(makeContext(tools));
      const check = results.find((r) => r.id === "SL-001");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.FAIL);
      expect(check!.finding?.cweId).toBe("CWE-798");
    });

    test("detects AWS access key in schema", async () => {
      const tools: ToolInfo[] = [
        {
          name: "s3_upload",
          description: "Upload to S3",
          inputSchema: {
            type: "object",
            properties: {
              key: { type: "string", default: "AKIAIOSFODNN7EXAMPLE" },
            },
          },
        },
      ];

      const results = await module.run(makeContext(tools));
      const check = results.find((r) => r.id === "SL-001");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.FAIL);
    });

    test("detects GitHub token in description", async () => {
      const tools: ToolInfo[] = [
        {
          name: "github_api",
          description: "Auth with ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn",
          inputSchema: { type: "object", properties: {} },
        },
      ];

      const results = await module.run(makeContext(tools));
      const check = results.find((r) => r.id === "SL-001");
      expect(check!.status).toBe(CheckStatus.FAIL);
      expect(check!.finding?.severity).toBe(Severity.CRITICAL);
    });

    test("detects OpenAI project key in description", async () => {
      const tools: ToolInfo[] = [
        {
          name: "openai_proxy",
          description: "Uses default key sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz for outbound calls",
          inputSchema: { type: "object", properties: {} },
        },
      ];

      const results = await module.run(makeContext(tools));
      const check = results.find((r) => r.id === "SL-001");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.FAIL);
      expect(check!.finding?.severity).toBe(Severity.CRITICAL);
    });

    test("passes when no secrets in tools", async () => {
      const tools: ToolInfo[] = [
        {
          name: "get_weather",
          description: "Gets weather for a location",
          inputSchema: {
            type: "object",
            properties: { city: { type: "string" } },
          },
        },
      ];

      const results = await module.run(makeContext(tools));
      const check = results.find((r) => r.id === "SL-001");
      expect(check!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("resource URI secrets", () => {
    test("detects credentials embedded in URI", async () => {
      const resources: ResourceInfo[] = [
        {
          uri: "postgres://admin:SuperSecret123@db.example.com:5432/mydb",
          name: "database",
          description: "Production database",
        },
      ];

      const results = await module.run(makeContext([], resources));
      const check = results.find((r) => r.id === "SL-002");
      expect(check!.status).toBe(CheckStatus.FAIL);
      expect(check!.finding?.severity).toBe(Severity.HIGH);
    });

    test("passes when no secrets in URIs", async () => {
      const resources: ResourceInfo[] = [
        {
          uri: "file:///data/reports",
          name: "reports",
        },
      ];

      const results = await module.run(makeContext([], resources));
      const check = results.find((r) => r.id === "SL-002");
      expect(check!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("prompt description secrets", () => {
    test("detects secret in prompt description", async () => {
      const prompts: PromptInfo[] = [
        {
          name: "api_query",
          description: 'Use Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c for auth',
        },
      ];

      const results = await module.run(makeContext([], [], prompts));
      const check = results.find((r) => r.id === "SL-003");
      expect(check!.status).toBe(CheckStatus.FAIL);
    });

    test("passes when no secrets in prompts", async () => {
      const prompts: PromptInfo[] = [
        {
          name: "greeting",
          description: "A friendly greeting template",
        },
      ];

      const results = await module.run(makeContext([], [], prompts));
      const check = results.find((r) => r.id === "SL-003");
      expect(check!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("schema default secrets", () => {
    test("detects secret in default value", async () => {
      const tools: ToolInfo[] = [
        {
          name: "connect",
          description: "Connect to service",
          inputSchema: {
            type: "object",
            properties: {
              token: {
                type: "string",
                default: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn",
              },
            },
          },
        },
      ];

      const results = await module.run(makeContext(tools));
      const check = results.find((r) => r.id === "SL-004");
      expect(check!.status).toBe(CheckStatus.FAIL);
    });

    test("passes when defaults are safe", async () => {
      const tools: ToolInfo[] = [
        {
          name: "search",
          description: "Search",
          inputSchema: {
            type: "object",
            properties: {
              query: { type: "string", default: "hello world" },
            },
          },
        },
      ];

      const results = await module.run(makeContext(tools));
      const check = results.find((r) => r.id === "SL-004");
      expect(check!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("edge cases", () => {
    test("handles empty capabilities", async () => {
      const results = await module.run(makeContext());
      expect(results.length).toBe(4); // 4 checks
      const failed = results.filter((r) => r.status === CheckStatus.FAIL);
      expect(failed.length).toBe(0);
    });

    test("handles tools with no description", async () => {
      const tools: ToolInfo[] = [
        {
          name: "bare_tool",
          inputSchema: { type: "object" },
        },
      ];

      const results = await module.run(makeContext(tools));
      expect(results.length).toBeGreaterThan(0);
    });
  });
});
