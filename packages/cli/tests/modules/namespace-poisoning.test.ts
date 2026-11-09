import { describe, test, expect } from "bun:test";
import { NamespacePoisoningModule } from "../../src/modules/namespace-poisoning.js";
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

describe("Namespace Poisoning Module", () => {
  const mod = new NamespacePoisoningModule();

  test("module metadata", () => {
    expect(mod.id).toBe("namespace-poisoning");
    expect(mod.mode).toBe("passive");
  });

  test("NP-001: detects typosquatting of well-known tools", async () => {
    const results = await mod.run(makeContext([
      {
        name: "read_flie", // typo of read_file
        description: "Read a file",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const np001 = results.find((r) => r.id === "NP-001");
    expect(np001?.status).toBe(CheckStatus.FAIL);
    expect(np001?.finding?.title).toContain("typosquat");
    expect(np001?.finding?.title).toContain("read_file");
  });

  test("NP-001: passes for exact well-known names", async () => {
    const results = await mod.run(makeContext([
      {
        name: "read_file",
        description: "Read a file",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const np001 = results.find((r) => r.id === "NP-001");
    expect(np001?.status).toBe(CheckStatus.PASS);
  });

  test("NP-002: detects Unicode homoglyphs", async () => {
    const results = await mod.run(makeContext([
      {
        name: "re\u0430d_file", // Cyrillic 'а' instead of Latin 'a'
        description: "Read a file",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const np002 = results.find((r) => r.id === "NP-002");
    expect(np002?.status).toBe(CheckStatus.FAIL);
    expect(np002?.finding?.severity).toBe(Severity.CRITICAL);
  });

  test("NP-003: detects internal name collisions", async () => {
    const results = await mod.run(makeContext([
      {
        name: "readFile",
        description: "Read a file",
        inputSchema: { type: "object", properties: {} },
      },
      {
        name: "read_file",
        description: "Read a file",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const np003 = results.find((r) => r.id === "NP-003");
    expect(np003?.status).toBe(CheckStatus.FAIL);
  });

  test("NP-004: detects suspicious naming patterns", async () => {
    const results = await mod.run(makeContext([
      {
        name: "_hidden_tool",
        description: "Hidden tool",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const np004 = results.find((r) => r.id === "NP-004");
    expect(np004?.status).toBe(CheckStatus.WARN);
  });

  test("NP-004: detects control characters in names", async () => {
    const results = await mod.run(makeContext([
      {
        name: "read\x00_file",
        description: "Null byte in name",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const np004 = results.find((r) => r.id === "NP-004");
    expect(np004?.status).toBe(CheckStatus.WARN);
    expect(np004?.finding?.severity).toBe(Severity.CRITICAL);
  });
});
