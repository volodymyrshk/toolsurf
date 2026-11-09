import { describe, test, expect } from "bun:test";
import { SessionIsolationModule } from "../../src/modules/session-isolation.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ModuleContext, ToolInfo } from "../../src/types/index.js";

function makeContext(
  tools: ToolInfo[],
  callTool?: (name: string, args: Record<string, unknown>) => Promise<unknown>
): ModuleContext {
  return {
    capabilities: {
      serverInfo: { name: "test-server", version: "1.0.0" },
      protocolVersion: "2025-03-26",
      capabilities: {},
      tools,
      resources: [],
      prompts: [],
    },
    activeMode: !!callTool,
    callTool,
    probeDelay: 0,
    verbose: false,
  };
}

const echoTool: ToolInfo = {
  name: "echo_message",
  description: "Echo a message back",
  inputSchema: {
    type: "object",
    properties: { message: { type: "string" } },
  },
};

const module = new SessionIsolationModule();

describe("SessionIsolationModule", () => {
  test("module metadata", () => {
    expect(module.id).toBe("session-isolation");
    expect(module.mode).toBe("active");
    expect(typeof module.version).toBe("string");
  });

  describe("passive mode — skips active checks", () => {
    test("returns no FAIL results when callTool is not provided", async () => {
      const ctx = makeContext([echoTool]);
      const results = await module.run(ctx);
      const fails = results.filter((r) => r.status === CheckStatus.FAIL);
      expect(fails).toHaveLength(0);
    });
  });

  describe("SI-001 — cross-session canary leakage", () => {
    test("passes when session canaries do not leak across calls", async () => {
      const callTool = async (_name: string, args: Record<string, unknown>) => {
        // Isolated: returns only the current session's message
        return { echo: args.message };
      };
      const ctx = makeContext([echoTool], callTool);
      const results = await module.run(ctx);
      const si001 = results.find((r) => r.id.startsWith("SI-001") && r.status === CheckStatus.FAIL);
      expect(si001).toBeUndefined();
    });

    test("flags when response contains a canary from a different session", async () => {
      // Simulates a leaky server that includes all prior messages in every response
      const allMessages: string[] = [];
      const callTool = async (_name: string, args: Record<string, unknown>) => {
        allMessages.push(String(args.message ?? ""));
        // Leaks: every response includes all previous messages
        return { echo: args.message, history: allMessages.join(", ") };
      };
      const ctx = makeContext([echoTool], callTool);
      const results = await module.run(ctx);
      const si001 = results.find((r) => r.id.startsWith("SI-001") && r.status === CheckStatus.FAIL);
      expect(si001).toBeDefined();
      expect(si001!.finding?.severity).toBe(Severity.HIGH);
    });
  });

  describe("SI-002 — state accumulation", () => {
    test("flags response size growing significantly across identical calls", async () => {
      // Track how many times each specific message was seen — SI-001 sends unique
      // canaries so they each count once; SI-002 sends "test_state_check" 3×.
      const seenMessages = new Map<string, number>();
      const callTool = async (_name: string, args: Record<string, unknown>) => {
        const msg = String(args.message ?? "");
        const count = (seenMessages.get(msg) ?? 0) + 1;
        seenMessages.set(msg, count);
        // Simulates state accumulation: response grows with each repeated call for same input
        return { echo: msg, log: "accumulated-entry ".repeat(count * 300) };
      };
      const ctx = makeContext([echoTool], callTool);
      const results = await module.run(ctx);
      // SI-002 reports state accumulation as WARN (not FAIL — it's probabilistic evidence)
      const si002 = results.find((r) => r.id.startsWith("SI-002") && r.status === CheckStatus.WARN);
      expect(si002).toBeDefined();
    });
  });

  describe("edge cases", () => {
    test("callTool errors are handled gracefully", async () => {
      const callTool = async () => { throw new Error("network error"); };
      const ctx = makeContext([echoTool], callTool);
      const results = await module.run(ctx);
      expect(Array.isArray(results)).toBe(true);
    });

    test("no string-param tools → no active probes → no findings", async () => {
      const callTool = async () => ({});
      const noStringTools: ToolInfo[] = [{
        name: "boolean_only",
        description: "Tool with no string params",
        inputSchema: {
          type: "object",
          properties: { flag: { type: "boolean" } },
        },
      }];
      const ctx = makeContext(noStringTools, callTool);
      const results = await module.run(ctx);
      const fails = results.filter((r) => r.status === CheckStatus.FAIL);
      expect(fails).toHaveLength(0);
    });
  });
});
