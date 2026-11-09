import { describe, test, expect } from "bun:test";
import { AuthBoundaryTestingModule } from "../../src/modules/auth-boundary-testing.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ModuleContext, ToolInfo } from "../../src/types/index.js";

function makeContext(
  tools: ToolInfo[],
  callTool?: (name: string, args: Record<string, unknown>) => Promise<unknown>
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
    probeDelay: 0,
  };
}

const fileTool: ToolInfo = {
  name: "read_file",
  description: "Read a file",
  inputSchema: {
    type: "object",
    properties: {
      path: { type: "string", description: "File path" },
    },
    required: ["path"],
  },
};

const queryTool: ToolInfo = {
  name: "query_db",
  description: "Query the database",
  inputSchema: {
    type: "object",
    properties: {
      sql: { type: "string", description: "SQL query" },
    },
    required: ["sql"],
  },
};

const readOnlyTool: ToolInfo = {
  name: "get_info",
  description: "Get information",
  annotations: { readOnlyHint: true },
  inputSchema: {
    type: "object",
    properties: {
      query: { type: "string" },
    },
    required: ["query"],
  },
};

describe("AuthBoundaryTestingModule", () => {
  const module = new AuthBoundaryTestingModule();

  test("module metadata is correct", () => {
    expect(module.id).toBe("auth-boundary-testing");
    expect(module.mode).toBe("active");
    expect(module.version).toBe("1.0.0");
  });

  test("skips all checks without callTool", async () => {
    const context = makeContext([fileTool, queryTool]);
    const results = await module.run(context);

    expect(results.length).toBe(3);
    expect(results.every((r) => r.status === CheckStatus.SKIP)).toBe(true);
  });

  describe("cross-tool leakage (AB-001)", () => {
    test("passes when tools don't leak cross-tool data", async () => {
      const callTool = async () => '{"result": "safe data"}';
      const context = makeContext([fileTool, queryTool], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "AB-001");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.PASS);
    });

    test("passes with fewer than 2 tools", async () => {
      const callTool = async () => "ok";
      const context = makeContext([fileTool], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "AB-001");
      expect(check!.status).toBe(CheckStatus.PASS);
      expect(check!.message).toContain("Fewer than 2");
    });

    test("fails when tools leak data about other tools", async () => {
      const callTool = async (_name: string, args: Record<string, unknown>) => {
        const path = String(args.path ?? args.sql ?? "");
        if (path.includes("query_db")) {
          return JSON.stringify({ tool: "query_db", data: "leaked connection string" });
        }
        return '{"result": "normal"}';
      };
      const context = makeContext([fileTool, queryTool], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "AB-001");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.FAIL);
      expect(check!.finding?.severity).toBe(Severity.HIGH);
    });
  });

  describe("privilege escalation (AB-002)", () => {
    test("passes when read-only tools reject write operations", async () => {
      const callTool = async () => '{"status": "read-only response"}';
      const context = makeContext([readOnlyTool], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "AB-002");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.PASS);
    });

    test("warns when read-only tools perform write operations", async () => {
      const callTool = async (_name: string, args: Record<string, unknown>) => {
        const query = String(args.query ?? "");
        if (query === "DELETE") {
          return '{"result": "3 records deleted and removed from the system"}';
        }
        return '{"status": "ok"}';
      };
      const context = makeContext([readOnlyTool], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "AB-002");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.WARN);
      expect(check!.finding?.cweId).toBe("CWE-269");
    });

    test("passes when no read-only tools exist", async () => {
      const callTool = async () => "ok";
      const context = makeContext([fileTool], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "AB-002");
      expect(check!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("resource boundaries (AB-003)", () => {
    test("passes when tools enforce path boundaries", async () => {
      const callTool = async (_name: string, args: Record<string, unknown>) => {
        const path = String(args.path ?? "");
        if (path.startsWith("/etc/") || path.startsWith("/proc/")) {
          throw new Error("Access denied");
        }
        return '{"content": "safe file content"}';
      };
      const context = makeContext([fileTool], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "AB-003");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.PASS);
    });

    test("fails when tools allow out-of-scope access", async () => {
      const callTool = async (_name: string, args: Record<string, unknown>) => {
        const path = String(args.path ?? "");
        if (path === "/etc/shadow") {
          return "root:$6$hash:19000:0:99999:7:::";
        }
        return '{"content": "normal"}';
      };
      const context = makeContext([fileTool], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "AB-003");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.FAIL);
      expect(check!.finding?.severity).toBe(Severity.CRITICAL);
    });

    test("passes when no path/resource params exist", async () => {
      const callTool = async () => "ok";
      const context = makeContext([queryTool], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "AB-003");
      expect(check!.status).toBe(CheckStatus.PASS);
    });
  });
});
