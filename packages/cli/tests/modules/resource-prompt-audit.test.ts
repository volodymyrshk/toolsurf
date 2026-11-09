import { describe, test, expect } from "bun:test";
import { ResourcePromptAuditModule } from "../../src/modules/resource-prompt-audit.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ModuleContext, ResourceInfo, PromptInfo } from "../../src/types/index.js";

function makeContext(
  resources: ResourceInfo[] = [],
  prompts: PromptInfo[] = []
): ModuleContext {
  return {
    capabilities: {
      serverInfo: { name: "test-server", version: "1.0.0" },
      protocolVersion: "2025-11-05",
      capabilities: {},
      tools: [],
      resources,
      prompts,
    },
    activeMode: false,
    verbose: false,
  };
}

describe("ResourcePromptAuditModule", () => {
  const module = new ResourcePromptAuditModule();

  test("module metadata is correct", () => {
    expect(module.id).toBe("resource-prompt-audit");
    expect(module.mode).toBe("passive");
    expect(module.version).toBe("1.0.0");
  });

  describe("resource URI patterns", () => {
    test("flags overly-broad file patterns", async () => {
      const resources: ResourceInfo[] = [
        { uri: "file:///", name: "root", description: "Root filesystem" },
      ];

      const results = await module.run(makeContext(resources));
      const check = results.find((r) => r.id === "RP-001");
      expect(check!.status).toBe(CheckStatus.FAIL);
      expect(check!.finding?.severity).toBe(Severity.HIGH);
    });

    test("flags wildcard resource patterns", async () => {
      const resources: ResourceInfo[] = [
        { uri: "file:///data/**", name: "data", description: "All data files" },
      ];

      const results = await module.run(makeContext(resources));
      const check = results.find((r) => r.id === "RP-001");
      expect(check!.status).toBe(CheckStatus.FAIL);
    });

    test("warns on parameterized URIs", async () => {
      const resources: ResourceInfo[] = [
        { uri: "file:///docs/{filename}", name: "docs" },
      ];

      const results = await module.run(makeContext(resources));
      const check = results.find((r) => r.id === "RP-001");
      expect(check!.status).toBe(CheckStatus.WARN);
    });

    test("passes on specific URIs", async () => {
      const resources: ResourceInfo[] = [
        { uri: "file:///data/config.json", name: "config" },
      ];

      const results = await module.run(makeContext(resources));
      const check = results.find((r) => r.id === "RP-001");
      expect(check!.status).toBe(CheckStatus.PASS);
    });

    test("passes when no resources", async () => {
      const results = await module.run(makeContext());
      const check = results.find((r) => r.id === "RP-001");
      expect(check!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("sensitive resource exposure", () => {
    test("detects .env file exposure", async () => {
      const resources: ResourceInfo[] = [
        { uri: "file:///app/.env", name: "env", description: "Environment config" },
      ];

      const results = await module.run(makeContext(resources));
      const check = results.find((r) => r.id === "RP-002");
      expect(check!.status).toBe(CheckStatus.FAIL);
      expect(check!.finding?.severity).toBe(Severity.HIGH);
    });

    test("detects private key exposure", async () => {
      const resources: ResourceInfo[] = [
        { uri: "file:///certs/server.key", name: "cert" },
      ];

      const results = await module.run(makeContext(resources));
      const check = results.find((r) => r.id === "RP-002");
      expect(check!.status).toBe(CheckStatus.FAIL);
    });

    test("detects .git exposure", async () => {
      const resources: ResourceInfo[] = [
        { uri: "file:///repo/.git/config", name: "git-config" },
      ];

      const results = await module.run(makeContext(resources));
      const check = results.find((r) => r.id === "RP-002");
      expect(check!.status).toBe(CheckStatus.FAIL);
    });

    test("passes on safe resources", async () => {
      const resources: ResourceInfo[] = [
        { uri: "file:///data/reports/summary.txt", name: "summary" },
      ];

      const results = await module.run(makeContext(resources));
      const check = results.find((r) => r.id === "RP-002");
      expect(check!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("prompt injection surface", () => {
    test("flags prompts with freeform text arguments", async () => {
      const prompts: PromptInfo[] = [
        {
          name: "generate",
          description: "Generate content",
          arguments: [
            { name: "input", description: "User input text", required: true },
          ],
        },
      ];

      const results = await module.run(makeContext([], prompts));
      const check = results.find((r) => r.id === "RP-003");
      expect(check!.status).toBe(CheckStatus.WARN);
      expect(check!.finding?.severity).toBe(Severity.MEDIUM);
    });

    test("passes on prompts with structured arguments", async () => {
      const prompts: PromptInfo[] = [
        {
          name: "report",
          description: "Generate report",
          arguments: [
            { name: "format", description: "Output format", required: true },
            { name: "year", description: "Year to report on", required: true },
          ],
        },
      ];

      const results = await module.run(makeContext([], prompts));
      const check = results.find((r) => r.id === "RP-003");
      expect(check!.status).toBe(CheckStatus.PASS);
    });

    test("passes when no prompts", async () => {
      const results = await module.run(makeContext());
      const check = results.find((r) => r.id === "RP-003");
      expect(check!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("prompt argument validation", () => {
    test("flags prompts with many optional args", async () => {
      const prompts: PromptInfo[] = [
        {
          name: "flexible",
          description: "Very flexible prompt",
          arguments: [
            { name: "a", required: false },
            { name: "b", required: false },
            { name: "c", required: false },
            { name: "d", required: false },
          ],
        },
      ];

      const results = await module.run(makeContext([], prompts));
      const check = results.find((r) => r.id === "RP-004");
      expect(check!.status).toBe(CheckStatus.WARN);
    });

    test("passes on well-structured prompts", async () => {
      const prompts: PromptInfo[] = [
        {
          name: "query",
          description: "Run a query",
          arguments: [
            { name: "table", required: true },
            { name: "limit", required: false },
          ],
        },
      ];

      const results = await module.run(makeContext([], prompts));
      const check = results.find((r) => r.id === "RP-004");
      expect(check!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("attack surface", () => {
    test("warns on large attack surface", async () => {
      const resources: ResourceInfo[] = Array.from({ length: 15 }, (_, i) => ({
        uri: `file:///data/file${i}`,
        name: `file${i}`,
      }));
      const prompts: PromptInfo[] = Array.from({ length: 10 }, (_, i) => ({
        name: `prompt${i}`,
        description: `Prompt ${i}`,
      }));

      const results = await module.run(makeContext(resources, prompts));
      const check = results.find((r) => r.id === "RP-005");
      expect(check!.status).toBe(CheckStatus.WARN);
    });

    test("passes on small attack surface", async () => {
      const resources: ResourceInfo[] = [
        { uri: "file:///config.json", name: "config" },
      ];

      const results = await module.run(makeContext(resources));
      const check = results.find((r) => r.id === "RP-005");
      expect(check!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("edge cases", () => {
    test("handles empty capabilities", async () => {
      const results = await module.run(makeContext());
      expect(results.length).toBe(5); // 5 checks
      const failed = results.filter((r) => r.status === CheckStatus.FAIL);
      expect(failed.length).toBe(0);
    });
  });
});
