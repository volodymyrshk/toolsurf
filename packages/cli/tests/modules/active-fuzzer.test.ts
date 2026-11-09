import { describe, test, expect } from "bun:test";
import { ActiveFuzzerModule } from "../../src/modules/active-fuzzer.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ModuleContext, ToolInfo } from "../../src/types/index.js";

function makeContext(
  tools: ToolInfo[],
  callTool?: ModuleContext["callTool"]
): ModuleContext {
  return {
    capabilities: {
      serverInfo: { name: "test-server", version: "1.0.0" },
      protocolVersion: "2025-11-05",
      capabilities: {},
      tools,
      resources: [],
      prompts: [],
    },
    callTool,
    activeMode: !!callTool,
    verbose: false,
    probeDelay: 0, // No delay in tests
  };
}

// ─── Helper: tools with various parameter types ──────────────────────────────

const commandTool: ToolInfo = {
  name: "run_command",
  description: "Runs a shell command",
  inputSchema: {
    type: "object",
    properties: {
      command: { type: "string" },
    },
  },
};

const fileTool: ToolInfo = {
  name: "read_file",
  description: "Reads a file from disk",
  inputSchema: {
    type: "object",
    properties: {
      path: { type: "string" },
    },
  },
};

const queryTool: ToolInfo = {
  name: "run_query",
  description: "Runs a database query",
  inputSchema: {
    type: "object",
    properties: {
      query: { type: "string" },
    },
  },
};

const htmlTool: ToolInfo = {
  name: "render_template",
  description: "Renders an HTML template",
  inputSchema: {
    type: "object",
    properties: {
      template: { type: "string" },
    },
  },
};

const safeTool: ToolInfo = {
  name: "get_weather",
  description: "Gets weather data",
  inputSchema: {
    type: "object",
    properties: {
      city: { type: "string" },
    },
  },
};

const noSchemaTool: ToolInfo = {
  name: "bare_tool",
  description: "A tool with no schema properties",
  inputSchema: { type: "object" },
};

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("ActiveFuzzerModule", () => {
  const module = new ActiveFuzzerModule();

  test("module metadata is correct", () => {
    expect(module.id).toBe("active-fuzzer");
    expect(module.name).toBe("Active Parameter Fuzzing");
    expect(module.mode).toBe("active");
    expect(module.version).toBe("1.0.0");
  });

  describe("without callTool (passive context)", () => {
    test("skips all checks when callTool is not provided", async () => {
      const context = makeContext([commandTool, fileTool, queryTool]);
      const results = await module.run(context);

      // Should return SKIP for each strategy
      expect(results.length).toBeGreaterThan(0);
      for (const check of results) {
        expect(check.status).toBe(CheckStatus.SKIP);
        expect(check.message).toContain("--active");
      }
    });
  });

  describe("PEAV pre-flight integration", () => {
    test("does not skip tools that PEAV already marked as suspicious", async () => {
      let calls = 0;
      const callTool = async () => {
        calls++;
        return "uid=1000(user) gid=1000(user) groups=1000(user)";
      };

      const context = makeContext([commandTool], callTool);
      context.peavEvidenceTools = new Set(["run_command"]);

      const results = await module.run(context);

      expect(calls).toBeGreaterThan(0);
      const cmdCheck = results.find((r) => r.id === "AF-001-run_command");
      expect(cmdCheck).toBeDefined();
      expect(cmdCheck!.status).toBe(CheckStatus.FAIL);
    });

    test("keeps deprecated peavSkipTools as a priority signal, not a suppressor", async () => {
      let calls = 0;
      const callTool = async () => {
        calls++;
        return "root:x:0:0:root:/root:/bin/bash";
      };

      const context = makeContext([fileTool], callTool);
      context.peavSkipTools = new Set(["read_file"]);

      const results = await module.run(context);

      expect(calls).toBeGreaterThan(0);
      const pathCheck = results.find((r) => r.id === "AF-002-read_file");
      expect(pathCheck).toBeDefined();
      expect(pathCheck!.status).toBe(CheckStatus.FAIL);
    });
  });

  describe("command injection (AF-001)", () => {
    test("detects command injection when tool responds with command output", async () => {
      const callTool = async (_name: string, _args: Record<string, unknown>) => {
        // Simulate a server that executes the command and returns output
        return "uid=1000(user) gid=1000(user) groups=1000(user)";
      };

      const context = makeContext([commandTool], callTool);
      const results = await module.run(context);

      const cmdCheck = results.find((r) => r.id === "AF-001-run_command");
      expect(cmdCheck).toBeDefined();
      expect(cmdCheck!.status).toBe(CheckStatus.FAIL);
      expect(cmdCheck!.finding?.severity).toBe(Severity.CRITICAL);
      expect(cmdCheck!.finding?.cweId).toBe("CWE-78");
      expect(cmdCheck!.finding?.toolName).toBe("run_command");
    });

    test("passes when tool rejects command injection payloads", async () => {
      const callTool = async (_name: string, _args: Record<string, unknown>) => {
        return "Invalid command: input rejected";
      };

      const context = makeContext([commandTool], callTool);
      const results = await module.run(context);

      const cmdCheck = results.find((r) => r.id === "AF-001-run_command");
      expect(cmdCheck).toBeDefined();
      expect(cmdCheck!.status).toBe(CheckStatus.PASS);
    });

    test("passes when no command-susceptible tools exist", async () => {
      const callTool = async () => "ok";
      const context = makeContext([safeTool], callTool);
      const results = await module.run(context);

      const cmdCheck = results.find((r) => r.id === "AF-001");
      expect(cmdCheck).toBeDefined();
      expect(cmdCheck!.status).toBe(CheckStatus.PASS);
      expect(cmdCheck!.message).toContain("No tools");
    });
  });

  describe("path traversal (AF-002)", () => {
    test("detects path traversal when tool returns file contents", async () => {
      const callTool = async (_name: string, args: Record<string, unknown>) => {
        const path = args.path as string;
        if (path.includes("etc/passwd")) {
          return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin";
        }
        return "File not found";
      };

      const context = makeContext([fileTool], callTool);
      const results = await module.run(context);

      const pathCheck = results.find((r) => r.id === "AF-002-read_file");
      expect(pathCheck).toBeDefined();
      expect(pathCheck!.status).toBe(CheckStatus.FAIL);
      expect(pathCheck!.finding?.severity).toBe(Severity.HIGH);
      expect(pathCheck!.finding?.cweId).toBe("CWE-22");
    });

    test("passes when tool properly rejects traversal payloads", async () => {
      const callTool = async () => {
        throw new Error("Path validation failed: directory traversal not allowed");
      };

      const context = makeContext([fileTool], callTool);
      const results = await module.run(context);

      const pathCheck = results.find((r) => r.id === "AF-002-read_file");
      expect(pathCheck).toBeDefined();
      expect(pathCheck!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("SQL injection (AF-003)", () => {
    test("detects SQL injection when tool returns SQL error", async () => {
      const callTool = async (_name: string, args: Record<string, unknown>) => {
        const query = args.query as string;
        if (query.includes("'")) {
          return 'Error: You have an error in your SQL syntax near "OR \'1\'=\'1" at line 1 (mysql)';
        }
        return "[]";
      };

      const context = makeContext([queryTool], callTool);
      const results = await module.run(context);

      const sqlCheck = results.find((r) => r.id === "AF-003-run_query");
      expect(sqlCheck).toBeDefined();
      expect(sqlCheck!.status).toBe(CheckStatus.FAIL);
      expect(sqlCheck!.finding?.severity).toBe(Severity.CRITICAL);
      expect(sqlCheck!.finding?.cweId).toBe("CWE-89");
    });

    test("passes when tool uses parameterized queries", async () => {
      const callTool = async () => {
        return "[]"; // Empty result set, no error leakage
      };

      const context = makeContext([queryTool], callTool);
      const results = await module.run(context);

      const sqlCheck = results.find((r) => r.id === "AF-003-run_query");
      expect(sqlCheck).toBeDefined();
      expect(sqlCheck!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("XSS reflection (AF-004)", () => {
    test("detects XSS when tool reflects payload without escaping", async () => {
      const callTool = async (_name: string, args: Record<string, unknown>) => {
        // Simulate a tool that reflects input unescaped
        return `<div>Result: ${args.template}</div>`;
      };

      const context = makeContext([htmlTool], callTool);
      const results = await module.run(context);

      const xssCheck = results.find((r) => r.id === "AF-004-render_template");
      expect(xssCheck).toBeDefined();
      expect(xssCheck!.status).toBe(CheckStatus.FAIL);
      expect(xssCheck!.finding?.severity).toBe(Severity.HIGH);
      expect(xssCheck!.finding?.cweId).toBe("CWE-79");
    });

    test("passes when tool sanitizes all XSS vectors", async () => {
      const callTool = async (_name: string, _args: Record<string, unknown>) => {
        // Simulate a tool that sanitizes input and does not reflect it raw
        return `<div>Result: [sanitized input]</div>`;
      };

      const context = makeContext([htmlTool], callTool);
      const results = await module.run(context);

      const xssCheck = results.find((r) => r.id === "AF-004-render_template");
      expect(xssCheck).toBeDefined();
      expect(xssCheck!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("server crash and response-size evidence", () => {
    test("emits AF-010 when a fuzzed payload triggers a 5xx response", async () => {
      const callTool = async (_name: string, args: Record<string, unknown>) => {
        if (args.command === "benign_baseline_test") {
          return { status: 200, body: "ok" };
        }
        return { status: 500, classification: "SERVER_ERROR", body: "Internal Server Error" };
      };

      const context = makeContext([commandTool], callTool);
      const results = await module.run(context);

      const crashCheck = results.find((r) => r.id === "AF-010-run_command");
      expect(crashCheck).toBeDefined();
      expect(crashCheck!.status).toBe(CheckStatus.FAIL);
      expect(crashCheck!.finding?.severity).toBe(Severity.HIGH);
      expect(crashCheck!.finding?.cweId).toBe("CWE-248");
      const evidence = crashCheck!.finding?.evidence as any;
      expect(evidence.successfulPayloads[0].classification).toBe("server-crash");
    });

    test("emits AF-011 when a fuzzed payload expands response size by 10x", async () => {
      const callTool = async (_name: string, args: Record<string, unknown>) => {
        if (args.query === "benign_baseline_test") {
          return "small result";
        }
        return "customer,email,token\n" + "leaked@example.com,secret,value\n".repeat(200);
      };

      const context = makeContext([queryTool], callTool);
      const results = await module.run(context);

      const sizeCheck = results.find((r) => r.id === "AF-011-run_query");
      expect(sizeCheck).toBeDefined();
      expect(sizeCheck!.status).toBe(CheckStatus.FAIL);
      expect(sizeCheck!.finding?.severity).toBe(Severity.HIGH);
      expect(sizeCheck!.finding?.cweId).toBe("CWE-200");
      const evidence = sizeCheck!.finding?.evidence as any;
      expect(evidence.successfulPayloads[0].responseSize.ratio).toBeGreaterThanOrEqual(10);
    });
  });

  describe("oversized input (AF-006)", () => {
    test("detects missing length limits when server accepts oversized input", async () => {
      const callTool = async () => {
        return "Processed successfully";
      };

      const context = makeContext([safeTool], callTool);
      const results = await module.run(context);

      const oversizedCheck = results.find((r) => r.id === "AF-006-get_weather");
      expect(oversizedCheck).toBeDefined();
      expect(oversizedCheck!.status).toBe(CheckStatus.WARN);
      expect(oversizedCheck!.finding?.severity).toBe(Severity.MEDIUM);
      expect(oversizedCheck!.finding?.cweId).toBe("CWE-400");
    });

    test("passes when server rejects oversized input", async () => {
      const callTool = async () => {
        return "Validation error: input exceeds maximum length";
      };

      const context = makeContext([safeTool], callTool);
      const results = await module.run(context);

      const oversizedCheck = results.find((r) => r.id === "AF-006-get_weather");
      expect(oversizedCheck).toBeDefined();
      expect(oversizedCheck!.status).toBe(CheckStatus.PASS);
    });

    test("limits oversized testing to default maxFuzzTargets (10)", async () => {
      const manyTools: ToolInfo[] = Array.from({ length: 15 }, (_, i) => ({
        name: `tool_${i}`,
        description: `Tool ${i}`,
        inputSchema: {
          type: "object",
          properties: { data: { type: "string" } },
        },
      }));

      const callTool = async () => "ok";
      const context = makeContext(manyTools, callTool);
      const results = await module.run(context);

      const oversizedChecks = results.filter((r) => r.id.startsWith("AF-006-"));
      // Default maxFuzzTargets is 10, so with 15 tools only 10 should be tested
      expect(oversizedChecks.length).toBe(10);
    });
  });

  describe("error handling", () => {
    test("handles tool call errors gracefully (does not crash)", async () => {
      const callTool = async () => {
        throw new Error("Connection refused");
      };

      const context = makeContext(
        [commandTool, fileTool, queryTool, htmlTool, safeTool],
        callTool
      );

      // Should not throw
      const results = await module.run(context);
      expect(results.length).toBeGreaterThan(0);

      // All strategies should PASS since errors mean payloads were blocked
      const failedChecks = results.filter((r) => r.status === CheckStatus.FAIL);
      expect(failedChecks.length).toBe(0);
    });

    test("handles mixed responses (some payloads succeed, some fail)", async () => {
      let callCount = 0;
      const callTool = async (_name: string, _args: Record<string, unknown>) => {
        callCount++;
        if (callCount === 1) {
          return "normal benign response"; // Baseline Call
        }
        if (callCount === 2) {
          return "uid=0(root) gid=0(root)"; // Command injection hit
        }
        throw new Error("Blocked");
      };

      const context = makeContext([commandTool], callTool);
      const results = await module.run(context);

      const cmdCheck = results.find((r) => r.id === "AF-001-run_command");
      expect(cmdCheck).toBeDefined();
      expect(cmdCheck!.status).toBe(CheckStatus.FAIL);
      // Should only report 1 successful payload
      const evidence = cmdCheck!.finding?.evidence as Record<string, unknown>;
      const payloads = evidence.successfulPayloads as unknown[];
      expect(payloads.length).toBe(1);
    });
  });

  describe("edge cases", () => {
    test("handles empty tool list", async () => {
      const callTool = async () => "ok";
      const context = makeContext([], callTool);
      const results = await module.run(context);

      // Should have pass results for each strategy + oversized
      expect(results.length).toBeGreaterThan(0);
      for (const check of results) {
        expect(check.status).toBe(CheckStatus.PASS);
      }
    });

    test("handles tools with no inputSchema properties", async () => {
      const callTool = async () => "ok";
      const context = makeContext([noSchemaTool], callTool);
      const results = await module.run(context);

      // Should not crash; all strategies should pass (no matching params)
      expect(results.length).toBeGreaterThan(0);
      const failedChecks = results.filter((r) => r.status === CheckStatus.FAIL);
      expect(failedChecks.length).toBe(0);
    });

    test("produces findings with all required fields", async () => {
      const callTool = async () => {
        return "root:x:0:0:root:/root:/bin/bash";
      };

      const context = makeContext([fileTool], callTool);
      const results = await module.run(context);

      const findings = results.filter((r) => r.finding).map((r) => r.finding!);
      expect(findings.length).toBeGreaterThan(0);

      for (const finding of findings) {
        expect(finding.id).toBeTruthy();
        expect(finding.module).toBe("active-fuzzer");
        expect(finding.severity).toBeTruthy();
        expect(finding.title).toBeTruthy();
        expect(finding.description).toBeTruthy();
        expect(finding.remediation).toBeTruthy();
        expect(finding.cweId).toBeTruthy();
        expect(Object.values(Severity)).toContain(finding.severity);
      }
    });
  });
});
