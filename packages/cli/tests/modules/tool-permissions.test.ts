import { describe, test, expect } from "bun:test";
import { ToolPermissionsModule } from "../../src/modules/tool-permissions.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ModuleContext, ServerCapabilities, ToolInfo } from "../../src/types/index.js";
import vulnerableFixture from "../fixtures/vulnerable-tools.json";
import safeFixture from "../fixtures/safe-tools.json";

function makeContext(tools: ToolInfo[]): ModuleContext {
  return {
    capabilities: {
      serverInfo: { name: "test-server", version: "1.0.0" },
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

describe("ToolPermissionsModule", () => {
  const module = new ToolPermissionsModule();

  test("module metadata is correct", () => {
    expect(module.id).toBe("tool-permissions");
    expect(module.mode).toBe("passive");
    expect(module.version).toBe("1.0.0");
  });

  describe("with vulnerable tools", () => {
    test("detects dangerous tool names", async () => {
      const context = makeContext(vulnerableFixture.tools as ToolInfo[]);
      const results = await module.run(context);

      // Should find command-execution pattern (execute_command)
      const cmdExecCheck = results.find(
        (r) => r.id === "TP-003-command-execution"
      );
      expect(cmdExecCheck).toBeDefined();
      expect(cmdExecCheck!.status).toBe(CheckStatus.FAIL);
      expect(cmdExecCheck!.finding?.severity).toBe(Severity.HIGH);
    });

    test("detects destructive tool patterns", async () => {
      const context = makeContext(vulnerableFixture.tools as ToolInfo[]);
      const results = await module.run(context);

      const destructiveCheck = results.find(
        (r) => r.id === "TP-003-destructive"
      );
      expect(destructiveCheck).toBeDefined();
      expect(destructiveCheck!.status).toBe(CheckStatus.WARN);
    });

    test("detects missing descriptions", async () => {
      const context = makeContext(vulnerableFixture.tools as ToolInfo[]);
      const results = await module.run(context);

      const descCheck = results.find((r) => r.id === "TP-002");
      expect(descCheck).toBeDefined();
      expect(descCheck!.status).toBe(CheckStatus.WARN);
      expect(descCheck!.finding?.evidence).toEqual({
        tools: ["undescribed_tool"],
      });
    });

    test("detects contradictory annotations (delete_record marked readOnly)", async () => {
      const context = makeContext(vulnerableFixture.tools as ToolInfo[]);
      const results = await module.run(context);

      const annotationCheck = results.find((r) => r.id === "TP-007");
      expect(annotationCheck).toBeDefined();
      expect(annotationCheck!.status).toBe(CheckStatus.FAIL);
      expect(annotationCheck!.finding?.severity).toBe(Severity.HIGH);
    });

    test("detects additionalProperties: true", async () => {
      const context = makeContext(vulnerableFixture.tools as ToolInfo[]);
      const results = await module.run(context);

      const additionalCheck = results.find((r) => r.id === "TP-008");
      expect(additionalCheck).toBeDefined();
      expect(additionalCheck!.status).toBe(CheckStatus.WARN);
      const evidence = additionalCheck!.finding?.evidence as Record<string, unknown>;
      expect(evidence.tools).toEqual(["fetch_url"]);
    });

    test("detects unconstrained path parameter", async () => {
      const context = makeContext(vulnerableFixture.tools as ToolInfo[]);
      const results = await module.run(context);

      const schemaCheck = results.find(
        (r) => r.id === "TP-005-read_file"
      );
      expect(schemaCheck).toBeDefined();
      expect(schemaCheck!.status).toBe(CheckStatus.WARN);
      expect(schemaCheck!.finding?.severity).toBe(Severity.MEDIUM);
    });

    test("detects unconstrained generic params on state-modifying tools", async () => {
      const context = makeContext([
        {
          name: "update_profile",
          description: "Update a user profile with free-form content",
          inputSchema: {
            type: "object",
            properties: {
              name: { type: "string", maxLength: 100 },
              bio: { type: "string" },
              settings: { type: "object" },
            },
          },
        },
      ]);
      const results = await module.run(context);

      const schemaCheck = results.find((r) => r.id === "TP-005-update_profile");
      expect(schemaCheck).toBeDefined();
      expect(schemaCheck!.status).toBe(CheckStatus.WARN);
      expect(schemaCheck!.finding?.severity).toBe(Severity.MEDIUM);
      const evidence = schemaCheck!.finding?.evidence as Record<string, unknown>;
      const parameters = evidence.parameters as Array<Record<string, unknown>>;
      expect(parameters.some((p) => p.param === "bio")).toBe(true);
      expect(parameters.some((p) => p.param === "settings")).toBe(true);
    });

    test("generates findings with remediation guidance", async () => {
      const context = makeContext(vulnerableFixture.tools as ToolInfo[]);
      const results = await module.run(context);

      const findings = results
        .filter((r) => r.finding)
        .map((r) => r.finding!);

      expect(findings.length).toBeGreaterThan(0);

      for (const finding of findings) {
        expect(finding.remediation).toBeTruthy();
        expect(finding.module).toBe("tool-permissions");
        expect(finding.id).toBeTruthy();
        expect(Object.values(Severity)).toContain(finding.severity);
      }
    });
  });

  describe("with safe tools", () => {
    test("passes all checks for well-constrained tools", async () => {
      const context = makeContext(safeFixture.tools as ToolInfo[]);
      const results = await module.run(context);

      const failedChecks = results.filter(
        (r) => r.status === CheckStatus.FAIL
      );
      expect(failedChecks.length).toBe(0);
    });

    test("produces no HIGH/CRITICAL findings", async () => {
      const context = makeContext(safeFixture.tools as ToolInfo[]);
      const results = await module.run(context);

      const findings = results
        .filter((r) => r.finding)
        .map((r) => r.finding!);

      const highSeverity = findings.filter(
        (f) =>
          f.severity === Severity.HIGH || f.severity === Severity.CRITICAL
      );
      expect(highSeverity.length).toBe(0);
    });

    test("shows PASS for all major check categories", async () => {
      const context = makeContext(safeFixture.tools as ToolInfo[]);
      const results = await module.run(context);

      const descCheck = results.find((r) => r.id === "TP-002");
      expect(descCheck?.status).toBe(CheckStatus.PASS);

      const nameCheck = results.find((r) => r.id === "TP-003");
      expect(nameCheck?.status).toBe(CheckStatus.PASS);

      const additionalCheck = results.find((r) => r.id === "TP-008");
      expect(additionalCheck?.status).toBe(CheckStatus.PASS);
    });
  });

  describe("edge cases", () => {
    test("handles empty tool list", async () => {
      const context = makeContext([]);
      const results = await module.run(context);

      const countCheck = results.find((r) => r.id === "TP-001");
      expect(countCheck?.status).toBe(CheckStatus.PASS);
      expect(countCheck?.message).toContain("No tools");
    });

    test("handles tool with no inputSchema", async () => {
      const tools: ToolInfo[] = [
        {
          name: "bare_tool",
          description: "A tool with no schema",
          inputSchema: {} as Record<string, unknown>,
        },
      ];
      const context = makeContext(tools);
      const results = await module.run(context);

      // Should not crash
      expect(results.length).toBeGreaterThan(0);
    });

    test("handles more than 20 tools (large attack surface)", async () => {
      const manyTools: ToolInfo[] = Array.from({ length: 25 }, (_, i) => ({
        name: `tool_${i}`,
        description: `Tool number ${i}`,
        inputSchema: {
          type: "object",
          properties: { data: { type: "string" } },
        },
        annotations: { readOnlyHint: true },
      }));

      const context = makeContext(manyTools);
      const results = await module.run(context);

      const countCheck = results.find((r) => r.id === "TP-001");
      expect(countCheck?.status).toBe(CheckStatus.WARN);
      expect(countCheck?.finding?.severity).toBe(Severity.LOW);
    });
  });
});
