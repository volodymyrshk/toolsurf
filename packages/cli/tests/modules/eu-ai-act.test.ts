import { describe, test, expect } from "bun:test";
import { EuAiActModule } from "../../src/modules/eu-ai-act.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ModuleContext, ToolInfo } from "../../src/types/index.js";

function makeContext(tools: ToolInfo[], serverName = "test-server", version = "1.0.0"): ModuleContext {
  return {
    capabilities: {
      serverInfo: { name: serverName, version },
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

const module = new EuAiActModule();

// Destructive tool with no annotation is the canonical EU AI Act Art.9 violation.
// Name uses hyphen (non-word char) so \bdelete\b matches; description starts with
// "Delete" (whole word before space) to satisfy the word-boundary regex.
const unAnnotatedDestructiveTool: ToolInfo = {
  name: "delete-records",
  description: "Delete all records from the database permanently",
  inputSchema: {
    type: "object",
    properties: { confirm: { type: "boolean" } },
  },
};

const wellAnnotatedSafeTool: ToolInfo = {
  name: "get_weather",
  description: "Returns weather data for a specified city. Read-only, no side effects.",
  inputSchema: {
    type: "object",
    properties: {
      city: { type: "string", enum: ["London", "Tokyo", "Berlin"] },
    },
    required: ["city"],
  },
  annotations: { readOnlyHint: true },
};

describe("EuAiActModule", () => {
  test("module metadata", () => {
    expect(module.id).toBe("eu-ai-act");
    expect(module.mode).toBe("passive");
    expect(typeof module.version).toBe("string");
  });

  describe("EUAI-001 — Art. 9 Risk Management", () => {
    test("flags destructive tools without risk annotations", async () => {
      const results = await module.run(makeContext([unAnnotatedDestructiveTool]));
      const euai001 = results.find(
        (r) => r.id.startsWith("EUAI-001") && r.status === CheckStatus.WARN
      );
      expect(euai001).toBeDefined();
    });
  });

  describe("EUAI-003 — Art. 13 Transparency", () => {
    test("flags server with missing or minimal serverInfo", async () => {
      const results = await module.run(makeContext([wellAnnotatedSafeTool], "", ""));
      const euai003 = results.find(
        (r) => r.id.startsWith("EUAI-003") && r.status === CheckStatus.WARN
      );
      expect(euai003).toBeDefined();
    });
  });

  describe("EUAI-000 — overall verdict", () => {
    test("non-conformant server produces a verdict finding", async () => {
      const results = await module.run(makeContext([unAnnotatedDestructiveTool]));
      const verdict = results.find((r) => r.id === "EUAI-000");
      expect(verdict).toBeDefined();
    });

    test("verdict finding has expected severity level", async () => {
      const results = await module.run(makeContext([unAnnotatedDestructiveTool]));
      const verdict = results.find((r) => r.id === "EUAI-000" && r.status === CheckStatus.FAIL);
      if (verdict) {
        expect([Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]).toContain(
          verdict.finding?.severity
        );
      }
    });
  });

  describe("conformant server", () => {
    test("well-annotated safe server produces no CRITICAL EU AI Act violations", async () => {
      const results = await module.run(makeContext(
        [wellAnnotatedSafeTool],
        "weather-api-v2",
        "2.1.0"
      ));
      const criticals = results.filter(
        (r) => r.status === CheckStatus.FAIL && r.finding?.severity === Severity.CRITICAL
      );
      expect(criticals).toHaveLength(0);
    });
  });

  describe("edge cases", () => {
    test("empty tool list runs without error", async () => {
      const results = await module.run(makeContext([]));
      expect(Array.isArray(results)).toBe(true);
    });
  });
});
