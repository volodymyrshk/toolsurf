import { describe, test, expect } from "bun:test";
import { ToolShadowingModule } from "../../src/modules/tool-shadowing.js";
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

const toolWithRequired: ToolInfo = {
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

const readOnlyTool: ToolInfo = {
  name: "get_status",
  description: "Get system status",
  annotations: { readOnlyHint: true },
  inputSchema: {
    type: "object",
    properties: {
      target: { type: "string", description: "Target system" },
    },
    required: ["target"],
  },
};

describe("ToolShadowingModule", () => {
  const module = new ToolShadowingModule();

  test("module metadata is correct", () => {
    expect(module.id).toBe("tool-shadowing");
    expect(module.mode).toBe("active");
    expect(module.version).toBe("1.0.0");
  });

  test("skips all checks without callTool", async () => {
    const context = makeContext([toolWithRequired]);
    const results = await module.run(context);

    expect(results.length).toBe(3);
    expect(results.every((r) => r.status === CheckStatus.SKIP)).toBe(true);
  });

  describe("schema honesty (TS-001)", () => {
    test("passes when tools correctly reject invalid input", async () => {
      const callTool = async (_name: string, args: Record<string, unknown>) => {
        if (!args.path || typeof args.path !== "string") {
          throw new Error("Invalid input");
        }
        return "OK";
      };
      const context = makeContext([toolWithRequired], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "TS-001");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.PASS);
    });

    test("fails when tools accept invalid input", async () => {
      // Tool that accepts anything without validation
      const callTool = async () => "accepted";
      const context = makeContext([toolWithRequired], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "TS-001");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.FAIL);
      expect(check!.finding?.severity).toBe(Severity.MEDIUM);
      expect(check!.finding?.cweId).toBe("CWE-20");
    });

    test("passes with no tools having required params", async () => {
      const noRequiredTool: ToolInfo = {
        name: "ping",
        description: "Ping",
        inputSchema: { type: "object", properties: {} },
      };
      const callTool = async () => "ok";
      const context = makeContext([noRequiredTool], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "TS-001");
      expect(check!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("read-only honesty (TS-002)", () => {
    test("passes when read-only tools return no mutation signals", async () => {
      const callTool = async () => '{"status": "ok", "data": [1, 2, 3]}';
      const context = makeContext([readOnlyTool], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "TS-002");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.PASS);
    });

    test("warns when read-only tools return mutation signals", async () => {
      const callTool = async () =>
        '{"message": "File created successfully, record updated and saved"}';
      const context = makeContext([readOnlyTool], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "TS-002");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.WARN);
      expect(check!.finding?.severity).toBe(Severity.HIGH);
    });

    test("passes when no readOnlyHint tools exist", async () => {
      const callTool = async () => "ok";
      const context = makeContext([toolWithRequired], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "TS-002");
      expect(check!.status).toBe(CheckStatus.PASS);
    });
  });

  describe("undeclared params (TS-003)", () => {
    test("passes when undeclared params have no effect", async () => {
      const callTool = async () => "consistent response";
      const context = makeContext([toolWithRequired], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "TS-003");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.PASS);
    });

    test("fails when undeclared params change behavior", async () => {
      let callCount = 0;
      const callTool = async (_name: string, args: Record<string, unknown>) => {
        callCount++;
        // Respond differently when __debug is passed
        if (args.__debug) {
          return "DEBUG MODE: internal state dump with extra data and detailed information that is much longer than normal";
        }
        return "ok";
      };
      const context = makeContext([toolWithRequired], callTool);
      const results = await module.run(context);

      const check = results.find((r) => r.id === "TS-003");
      expect(check).toBeDefined();
      expect(check!.status).toBe(CheckStatus.FAIL);
      expect(check!.finding?.severity).toBe(Severity.HIGH);
      expect(check!.finding?.cweId).toBe("CWE-912");
    });
  });
});
