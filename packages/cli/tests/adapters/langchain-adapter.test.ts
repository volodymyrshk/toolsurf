import { describe, test, expect } from "bun:test";
import { LangChainAdapter } from "../../src/adapters/langchain-adapter.js";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const TEST_DIR = join(tmpdir(), "toolsurf-langchain-test-" + Date.now());

function setup() {
  mkdirSync(TEST_DIR, { recursive: true });
}
function teardown() {
  rmSync(TEST_DIR, { recursive: true, force: true });
}

describe("LangChain Adapter", () => {
  test("has correct protocol metadata", () => {
    const adapter = new LangChainAdapter();
    expect(adapter.protocol).toBe("langchain-tools");
    expect(adapter.displayName).toBe("LangChain Tools");
  });

  test("parses LangChain tool definitions with schema field", async () => {
    setup();
    try {
      const specFile = join(TEST_DIR, "tools.json");
      writeFileSync(specFile, JSON.stringify([
        {
          name: "calculator",
          description: "Perform calculations",
          schema: {
            type: "object",
            properties: {
              expression: { type: "string", description: "Math expression" },
            },
            required: ["expression"],
          },
        },
      ]));

      const adapter = new LangChainAdapter();
      const caps = await adapter.connect({ params: { specFile } });

      expect(caps.tools.length).toBe(1);
      expect(caps.tools[0].name).toBe("calculator");
      expect(caps.tools[0].sourceProtocol).toBe("langchain-tools");
      expect(caps.tools[0].nativeType).toBe("tool");
      expect(caps.protocol).toBe("langchain-tools");
    } finally {
      teardown();
    }
  });

  test("accepts args field (Python export format)", async () => {
    setup();
    try {
      const specFile = join(TEST_DIR, "tools.json");
      writeFileSync(specFile, JSON.stringify([
        {
          name: "search",
          description: "Web search",
          args: {
            type: "object",
            properties: { query: { type: "string" } },
          },
        },
      ]));

      const adapter = new LangChainAdapter();
      const caps = await adapter.connect({ params: { specFile } });
      expect(caps.tools[0].inputSchema.properties).toBeDefined();
    } finally {
      teardown();
    }
  });

  test("accepts parameters field (OpenAI-compatible format)", async () => {
    setup();
    try {
      const specFile = join(TEST_DIR, "tools.json");
      writeFileSync(specFile, JSON.stringify([
        {
          name: "tool1",
          description: "A tool",
          parameters: {
            type: "object",
            properties: { x: { type: "number" } },
          },
        },
      ]));

      const adapter = new LangChainAdapter();
      const caps = await adapter.connect({ params: { specFile } });
      expect(caps.tools.length).toBe(1);
    } finally {
      teardown();
    }
  });

  test("invoke throws (not supported for LangChain)", async () => {
    const adapter = new LangChainAdapter();
    await expect(adapter.invoke("test", {})).rejects.toThrow("cannot be invoked remotely");
  });

  test("throws on missing spec", async () => {
    const adapter = new LangChainAdapter();
    await expect(adapter.connect({ params: {} })).rejects.toThrow("requires a tool manifest");
  });
});
