import { describe, test, expect } from "bun:test";
import { ContextExtractionModule } from "../../src/modules/context-extraction.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ModuleContext, ToolInfo, PromptInfo } from "../../src/types/index.js";

function makeContext(
  tools: ToolInfo[],
  prompts: PromptInfo[] = []
): ModuleContext {
  return {
    capabilities: {
      serverInfo: { name: "test-server", version: "1.0.0" },
      protocolVersion: "2025-11-05",
      capabilities: {},
      tools,
      resources: [],
      prompts,
    },
    activeMode: false,
    verbose: false,
  };
}

describe("ContextExtractionModule", () => {
  const module = new ContextExtractionModule();

  test("module metadata is correct", () => {
    expect(module.id).toBe("context-extraction");
    expect(module.mode).toBe("passive");
    expect(module.version).toBe("1.0.0");
  });

  describe("outbound data sinks", () => {
    test("detects messaging sinks (email, slack, webhook)", async () => {
      const tools: ToolInfo[] = [
        {
          name: "send_email",
          description: "Sends an email",
          inputSchema: {
            type: "object",
            properties: {
              to: { type: "string" },
              body: { type: "string" },
            },
          },
        },
        {
          name: "post_to_slack",
          description: "Posts a message to Slack",
          inputSchema: {
            type: "object",
            properties: { message: { type: "string" } },
          },
        },
      ];

      const results = await module.run(makeContext(tools));
      const sinkCheck = results.find((r) => r.id === "CE-001");

      expect(sinkCheck).toBeDefined();
      expect(sinkCheck!.status).toBe(CheckStatus.WARN);
      expect(sinkCheck!.finding?.severity).toBe(Severity.MEDIUM);
    });

    test("passes when no outbound sinks exist", async () => {
      const tools: ToolInfo[] = [
        {
          name: "get_weather",
          description: "Gets weather data",
          inputSchema: { type: "object", properties: {} },
        },
      ];

      const results = await module.run(makeContext(tools));
      const sinkCheck = results.find((r) => r.id === "CE-001");

      expect(sinkCheck).toBeDefined();
      expect(sinkCheck!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("context access tools", () => {
    test("detects credential-access tools as HIGH severity", async () => {
      const tools: ToolInfo[] = [
        {
          name: "get_env_variable",
          description: "Gets an environment variable",
          inputSchema: {
            type: "object",
            properties: { name: { type: "string" } },
          },
        },
      ];

      const results = await module.run(makeContext(tools));
      const accessCheck = results.find((r) => r.id === "CE-002");

      expect(accessCheck).toBeDefined();
      expect(accessCheck!.status).toBe(CheckStatus.FAIL);
      expect(accessCheck!.finding?.severity).toBe(Severity.HIGH);
    });

    test("detects conversation history access", async () => {
      const tools: ToolInfo[] = [
        {
          name: "conversation-history",
          description: "Retrieves the conversation history",
          inputSchema: { type: "object", properties: {} },
        },
      ];

      const results = await module.run(makeContext(tools));
      const accessCheck = results.find((r) => r.id === "CE-002");

      expect(accessCheck).toBeDefined();
      expect(accessCheck!.status).toBe(CheckStatus.WARN);
      expect(accessCheck!.finding?.severity).toBe(Severity.LOW);
    });

    test("passes when no context-access tools exist", async () => {
      const tools: ToolInfo[] = [
        {
          name: "calculate",
          description: "Performs math",
          inputSchema: { type: "object", properties: {} },
        },
      ];

      const results = await module.run(makeContext(tools));
      const accessCheck = results.find((r) => r.id === "CE-002");

      expect(accessCheck).toBeDefined();
      expect(accessCheck!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("cross-tool exfiltration chains", () => {
    test("detects complete exfil chain (context reader + outbound sink)", async () => {
      const tools: ToolInfo[] = [
        {
          name: "context-reader",
          description: "Gets conversation context",
          inputSchema: { type: "object", properties: {} },
        },
        {
          name: "send_webhook",
          description: "Sends data to a webhook",
          inputSchema: {
            type: "object",
            properties: {
              url: { type: "string" },
              payload: { type: "string" },
            },
          },
        },
      ];

      const results = await module.run(makeContext(tools));
      const chainCheck = results.find((r) => r.id === "CE-003");

      expect(chainCheck).toBeDefined();
      expect(chainCheck!.status).toBe(CheckStatus.FAIL);
      expect(chainCheck!.finding?.severity).toBe(Severity.HIGH);
      expect(chainCheck!.finding?.description).toContain("chain these tools");
    });

    test("no chain when only sinks exist (no source)", async () => {
      const tools: ToolInfo[] = [
        {
          name: "send_email",
          description: "Sends an email",
          inputSchema: { type: "object", properties: {} },
        },
      ];

      const results = await module.run(makeContext(tools));
      const chainCheck = results.find((r) => r.id === "CE-003");

      expect(chainCheck).toBeDefined();
      expect(chainCheck!.status).toBe(CheckStatus.PASS);
    });

    test("no chain when only sources exist (no sink)", async () => {
      const tools: ToolInfo[] = [
        {
          name: "get_env_variable",
          description: "Gets env vars",
          inputSchema: { type: "object", properties: {} },
        },
      ];

      const results = await module.run(makeContext(tools));
      const chainCheck = results.find((r) => r.id === "CE-003");

      expect(chainCheck).toBeDefined();
      expect(chainCheck!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("exfiltration-capable parameters", () => {
    test("detects user-controlled destination parameters", async () => {
      const tools: ToolInfo[] = [
        {
          name: "forward_data",
          description: "Forwards data",
          inputSchema: {
            type: "object",
            properties: {
              destination: { type: "string" },
              payload: { type: "string" },
            },
          },
        },
      ];

      const results = await module.run(makeContext(tools));
      const paramCheck = results.find((r) => r.id === "CE-004");

      expect(paramCheck).toBeDefined();
      expect(paramCheck!.status).toBe(CheckStatus.WARN);
      expect(paramCheck!.finding?.severity).toBe(Severity.MEDIUM);
    });

    test("passes when no exfil params exist", async () => {
      const tools: ToolInfo[] = [
        {
          name: "calculate",
          description: "Does math",
          inputSchema: {
            type: "object",
            properties: {
              expression: { type: "string" },
            },
          },
        },
      ];

      const results = await module.run(makeContext(tools));
      const paramCheck = results.find((r) => r.id === "CE-004");

      expect(paramCheck).toBeDefined();
      expect(paramCheck!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("prompt exposure", () => {
    test("flags sensitive prompt names", async () => {
      const prompts: PromptInfo[] = [
        {
          name: "system_admin_prompt",
          description: "Admin system prompt",
        },
        {
          name: "debug_config",
          description: "Debug configuration prompt",
        },
      ];

      const results = await module.run(makeContext([], prompts));
      const promptCheck = results.find((r) => r.id === "CE-005");

      expect(promptCheck).toBeDefined();
      expect(promptCheck!.status).toBe(CheckStatus.WARN);
      expect(promptCheck!.finding?.severity).toBe(Severity.MEDIUM);
    });

    test("passes when prompts have safe names", async () => {
      const prompts: PromptInfo[] = [
        {
          name: "greeting",
          description: "A greeting template",
        },
      ];

      const results = await module.run(makeContext([], prompts));
      const promptCheck = results.find((r) => r.id === "CE-005");

      expect(promptCheck).toBeDefined();
      expect(promptCheck!.status).toBe(CheckStatus.PASS);
    });

    test("passes when no prompts exist", async () => {
      const results = await module.run(makeContext([]));
      const promptCheck = results.find((r) => r.id === "CE-005");

      expect(promptCheck).toBeDefined();
      expect(promptCheck!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("edge cases", () => {
    test("handles empty tool list", async () => {
      const results = await module.run(makeContext([]));
      expect(results.length).toBeGreaterThan(0);

      const failed = results.filter((r) => r.status === CheckStatus.FAIL);
      expect(failed.length).toBe(0);
    });

    test("handles tools with no input schema properties", async () => {
      const tools: ToolInfo[] = [
        {
          name: "send_notification",
          description: "Sends a notification",
          inputSchema: { type: "object" },
        },
      ];

      const results = await module.run(makeContext(tools));
      // Should not crash
      expect(results.length).toBeGreaterThan(0);
    });
  });
});
