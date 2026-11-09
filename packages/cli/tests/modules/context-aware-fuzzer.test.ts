import { describe, test, expect } from "bun:test";
import { ContextAwareFuzzerModule } from "../../src/modules/context-aware-fuzzer.js";
import { CheckStatus } from "../../src/types/index.js";
import type { ModuleContext, ToolInfo } from "../../src/types/index.js";

function makeContext(tools: ToolInfo[], callTool?: (name: string, args: Record<string, unknown>) => Promise<unknown>): ModuleContext {
  return {
    capabilities: {
      serverInfo: { name: "test-server", version: "1.0.0" },
      protocolVersion: "2025-11-05",
      capabilities: {},
      tools,
      resources: [],
      prompts: [],
    },
    activeMode: true,
    verbose: false,
    callTool,
  };
}

describe("ContextAwareFuzzerModule", () => {
  const module = new ContextAwareFuzzerModule();

  test("module metadata is correct", () => {
    expect(module.id).toBe("context-aware-fuzzer");
    expect(module.mode).toBe("active");
    expect(module.version).toBe("1.0.0");
  });

  test("classifies filesystem tools", async () => {
    const tools: ToolInfo[] = [
      {
        name: "read_file",
        description: "Reads a file from disk",
        inputSchema: { type: "object", properties: { path: { type: "string" } } },
      },
    ];

    const callTool = async (name: string, args: Record<string, unknown>) => {
      const path = args.path as string;
      if (path?.includes("/etc/passwd")) {
        return "root:x:0:0:root:/root:/bin/bash";
      }
      return { status: 404, body: "Not found" };
    };

    const context = makeContext(tools, callTool);
    const results = await module.run(context);

    // Debug: log all result IDs
    console.log("Results:", results.map(r => ({ id: r.id, status: r.status })));

    const check = results.find((r) => r.id.startsWith("CAF-FILESYSTEM"));
    expect(check).toBeDefined();
    expect(check!.status).toBe(CheckStatus.FAIL);
  });

  test("classifies network tools", async () => {
    const tools: ToolInfo[] = [
      {
        name: "fetch_url",
        description: "Fetches content from a URL",
        inputSchema: { type: "object", properties: { url: { type: "string" } } },
      },
    ];

    const callTool = async (name: string, args: Record<string, unknown>) => {
      const url = args.url as string;
      if (url?.includes("169.254.169.254")) {
        return { amiId: "ami-12345", instanceId: "i-12345" };
      }
      return { status: 403 };
    };

    const context = makeContext(tools, callTool);
    const results = await module.run(context);

    const check = results.find((r) => r.id.startsWith("CAF-NETWORK"));
    expect(check).toBeDefined();
    expect(check!.status).toBe(CheckStatus.FAIL);
  });

  test("passes clean tools", async () => {
    const tools: ToolInfo[] = [
      {
        name: "add_numbers",
        description: "Adds two numbers",
        inputSchema: { type: "object", properties: { a: { type: "number" }, b: { type: "number" } } },
      },
    ];

    const context = makeContext(tools, async () => ({ result: 42 }));
    const results = await module.run(context);

    // No string param = no payloads = no findings
    const check = results.find((r) => r.id === "CAF-000");
    expect(check).toBeDefined();
    expect(check!.status).toBe(CheckStatus.PASS);
  });
});
