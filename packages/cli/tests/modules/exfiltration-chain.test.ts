import { describe, test, expect } from "bun:test";
import { ExfiltrationChainModule } from "../../src/modules/exfiltration-chain.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ModuleContext, ToolInfo, ServerCapabilities } from "../../src/types/index.js";

function makeContext(tools: ToolInfo[]): ModuleContext {
  return {
    capabilities: {
      serverInfo: { name: "test", version: "1.0" },
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

describe("Exfiltration Chain Module", () => {
  const mod = new ExfiltrationChainModule();

  test("module metadata", () => {
    expect(mod.id).toBe("exfiltration-chain");
    expect(mod.mode).toBe("passive");
  });

  test("EC-001: detects file read + HTTP send chain", async () => {
    const results = await mod.run(makeContext([
      {
        name: "read_file",
        description: "Read a file",
        inputSchema: {
          type: "object",
          properties: { path: { type: "string" } },
        },
      },
      {
        name: "fetch_url",
        description: "Send data to a URL",
        inputSchema: {
          type: "object",
          properties: { url: { type: "string" }, data: { type: "string" } },
        },
      },
    ]));

    const ec001 = results.find((r) => r.id === "EC-001");
    expect(ec001?.status).toBe(CheckStatus.FAIL);
    expect(ec001?.finding?.severity).toBe(Severity.CRITICAL);
    expect(ec001?.finding?.title).toContain("Exfiltration chain");
  });

  test("EC-001: passes for read-only servers", async () => {
    const results = await mod.run(makeContext([
      {
        name: "read_file",
        description: "Read a file",
        inputSchema: {
          type: "object",
          properties: { path: { type: "string" } },
        },
      },
      {
        name: "list_dir",
        description: "List directory",
        inputSchema: {
          type: "object",
          properties: { path: { type: "string" } },
        },
      },
    ]));

    const ec001 = results.find((r) => r.id === "EC-001");
    expect(ec001?.status).toBe(CheckStatus.PASS);
  });

  test("EC-002: detects dual-use tool", async () => {
    const results = await mod.run(makeContext([
      {
        name: "file_manager",
        description: "Reads files and sends HTTP requests",
        inputSchema: {
          type: "object",
          properties: {
            filepath: { type: "string" },
            url: { type: "string" },
          },
        },
      },
    ]));

    const ec002 = results.find((r) => r.id === "EC-002");
    expect(ec002?.status).toBe(CheckStatus.FAIL);
    expect(ec002?.finding?.severity).toBe(Severity.CRITICAL);
  });

  test("EC-002: does not treat a pure URL fetcher as critical exfiltration", async () => {
    const results = await mod.run(makeContext([
      {
        name: "fetch",
        description: "Fetches a URL from the internet and returns markdown",
        inputSchema: {
          type: "object",
          properties: {
            url: { type: "string", format: "uri" },
            max_length: { type: "integer", default: 5000 },
          },
        },
      },
    ]));

    const ec002 = results.find((r) => r.id === "EC-002");
    expect(ec002?.status).toBe(CheckStatus.PASS);
    expect(ec002?.finding).toBeUndefined();
  });

  test("EC-003: detects high capability concentration", async () => {
    const results = await mod.run(makeContext([
      {
        name: "exec_code",
        description: "Execute code",
        inputSchema: { type: "object", properties: { code: { type: "string" } } },
      },
      {
        name: "write_file",
        description: "Write a file",
        inputSchema: { type: "object", properties: { content: { type: "string" }, path: { type: "string" } } },
      },
      {
        name: "http_request",
        description: "Send HTTP request",
        inputSchema: { type: "object", properties: { url: { type: "string" } } },
      },
      {
        name: "send_email",
        description: "Send email",
        inputSchema: { type: "object", properties: { to: { type: "string" }, body: { type: "string" } } },
      },
    ]));

    const ec003 = results.find((r) => r.id === "EC-003");
    expect(ec003?.status).toBe(CheckStatus.FAIL);
    expect(ec003?.finding?.severity).toBe(Severity.CRITICAL);
  });
});
