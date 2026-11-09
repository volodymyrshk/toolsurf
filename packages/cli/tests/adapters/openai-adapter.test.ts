import { describe, test, expect } from "bun:test";
import { OpenAiAdapter } from "../../src/adapters/openai-adapter.js";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const TEST_DIR = join(tmpdir(), "toolsurf-openai-test-" + Date.now());

function setup() {
  mkdirSync(TEST_DIR, { recursive: true });
}
function teardown() {
  rmSync(TEST_DIR, { recursive: true, force: true });
}

describe("OpenAI Adapter", () => {
  test("has correct protocol metadata", () => {
    const adapter = new OpenAiAdapter();
    expect(adapter.protocol).toBe("openai-functions");
    expect(adapter.displayName).toBe("OpenAI Function Calling");
  });

  test("parses OpenAI tool format (type: function)", async () => {
    setup();
    try {
      const specFile = join(TEST_DIR, "tools.json");
      writeFileSync(specFile, JSON.stringify([
        {
          type: "function",
          function: {
            name: "get_weather",
            description: "Get weather for a location",
            parameters: {
              type: "object",
              properties: {
                location: { type: "string" },
                unit: { type: "string", enum: ["celsius", "fahrenheit"] },
              },
              required: ["location"],
            },
          },
        },
      ]));

      const adapter = new OpenAiAdapter();
      const caps = await adapter.connect({ params: { specFile } });

      expect(caps.tools.length).toBe(1);
      expect(caps.tools[0].name).toBe("get_weather");
      expect(caps.tools[0].description).toBe("Get weather for a location");
      expect(caps.tools[0].sourceProtocol).toBe("openai-functions");
      expect(caps.tools[0].nativeType).toBe("function");
      expect((caps.tools[0].inputSchema.properties as any).location.type).toBe("string");
      expect(caps.protocol).toBe("openai-functions");
    } finally {
      teardown();
    }
  });

  test("parses direct function format (name, description, parameters)", async () => {
    setup();
    try {
      const specFile = join(TEST_DIR, "tools.json");
      writeFileSync(specFile, JSON.stringify([
        {
          name: "search",
          description: "Search the web",
          parameters: {
            type: "object",
            properties: { query: { type: "string" } },
          },
        },
        {
          name: "calculate",
          parameters: {
            type: "object",
            properties: { expression: { type: "string" } },
          },
        },
      ]));

      const adapter = new OpenAiAdapter();
      const caps = await adapter.connect({ params: { specFile } });

      expect(caps.tools.length).toBe(2);
      expect(caps.tools[0].name).toBe("search");
      expect(caps.tools[1].name).toBe("calculate");
      expect(caps.tools[1].description).toBeUndefined();
    } finally {
      teardown();
    }
  });

  test("parses wrapped format ({ tools: [...] })", async () => {
    setup();
    try {
      const specFile = join(TEST_DIR, "tools.json");
      writeFileSync(specFile, JSON.stringify({
        tools: [
          { name: "tool1", description: "First tool", parameters: { type: "object", properties: {} } },
        ],
      }));

      const adapter = new OpenAiAdapter();
      const caps = await adapter.connect({ params: { specFile } });
      expect(caps.tools.length).toBe(1);
      expect(caps.tools[0].name).toBe("tool1");
    } finally {
      teardown();
    }
  });

  test("throws on missing spec", async () => {
    const adapter = new OpenAiAdapter();
    await expect(adapter.connect({ params: {} })).rejects.toThrow("requires a tool manifest");
  });

  test("throws on invalid format", async () => {
    setup();
    try {
      const specFile = join(TEST_DIR, "bad.json");
      writeFileSync(specFile, '"not an array"');

      const adapter = new OpenAiAdapter();
      await expect(adapter.connect({ params: { specFile } })).rejects.toThrow("must be a JSON array");
    } finally {
      teardown();
    }
  });

  test("invoke throws without API key", async () => {
    const adapter = new OpenAiAdapter();
    // Need to connect first to set up internal state
    setup();
    try {
      const specFile = join(TEST_DIR, "tools.json");
      writeFileSync(specFile, JSON.stringify([{ name: "test", parameters: { type: "object" } }]));
      await adapter.connect({ params: { specFile } });
      await expect(adapter.invoke("test", {})).rejects.toThrow("API key");
    } finally {
      teardown();
    }
  });

  test("disconnect cleans up", async () => {
    const adapter = new OpenAiAdapter();
    await adapter.disconnect(); // should not throw
  });
});
