import { describe, test, expect } from "bun:test";
import { McpAdapter } from "../../src/adapters/mcp-adapter.js";

describe("McpAdapter", () => {
  test("has correct protocol metadata", () => {
    const adapter = new McpAdapter();
    expect(adapter.protocol).toBe("mcp");
    expect(adapter.displayName).toBe("MCP (Model Context Protocol)");
  });

  test("invoke throws when not connected", () => {
    const adapter = new McpAdapter();
    expect(adapter.invoke("test", {})).rejects.toThrow("Not connected");
  });

  test("disconnect is safe when not connected", async () => {
    const adapter = new McpAdapter();
    // Should not throw
    await adapter.disconnect();
  });

  test("connect throws on invalid command", async () => {
    const adapter = new McpAdapter();
    try {
      await adapter.connect({
        timeoutMs: 1000,
        verbose: false,
        params: {
          command: "__nonexistent_command_for_test__",
          args: [],
        },
      });
      // Should not reach here
      expect(true).toBe(false);
    } catch (err) {
      // Expected — either spawn failure or timeout
      expect(err).toBeInstanceOf(Error);
    }
  });
});
