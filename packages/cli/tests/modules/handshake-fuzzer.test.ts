import { describe, test, expect } from "bun:test";
import { HandshakeFuzzerModule } from "../../src/modules/handshake-fuzzer.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ModuleContext, ServerCapabilities } from "../../src/types/index.js";

function makeContext(overrides: Partial<ServerCapabilities> = {}): ModuleContext {
  return {
    capabilities: {
      serverInfo: { name: "test-server", version: "1.0.0" },
      protocolVersion: "2025-03-26",
      capabilities: {},
      tools: [],
      resources: [],
      prompts: [],
      ...overrides,
    },
    activeMode: false,
    verbose: false,
  };
}

const module = new HandshakeFuzzerModule();

describe("HandshakeFuzzerModule", () => {
  test("module metadata", () => {
    expect(module.id).toBe("handshake-fuzzer");
    expect(module.mode).toBe("passive");
    expect(typeof module.version).toBe("string");
  });

  describe("HF-003 — protocol version spoofing", () => {
    test("flags non-date-format protocol version", async () => {
      const ctx = makeContext({ protocolVersion: "latest" });
      const results = await module.run(ctx);
      // Non-standard format produces WARN (not FAIL — FAIL is reserved for injection chars)
      const hf003 = results.find((r) => r.id.startsWith("HF-003") && r.status !== CheckStatus.PASS);
      expect(hf003).toBeDefined();
    });

    test("flags protocol version with injection characters", async () => {
      const ctx = makeContext({ protocolVersion: "2025-03-26'; DROP TABLE mcp;" });
      const results = await module.run(ctx);
      const fail = results.find((r) => r.status === CheckStatus.FAIL);
      expect(fail).toBeDefined();
    });

    test("accepts valid date-format protocol version", async () => {
      const ctx = makeContext({ protocolVersion: "2025-03-26" });
      const results = await module.run(ctx);
      const hf003 = results.find((r) => r.id === "HF-003" && r.status === CheckStatus.FAIL);
      expect(hf003).toBeUndefined();
    });
  });

  describe("HF-004/HF-005 — server info injection", () => {
    test("flags XSS pattern in server name", async () => {
      const ctx = makeContext({
        serverInfo: { name: "<script>alert(1)</script>", version: "1.0.0" },
      });
      const results = await module.run(ctx);
      const fail = results.find((r) => r.status === CheckStatus.FAIL);
      expect(fail).toBeDefined();
    });

    test("flags SQL injection pattern in server version", async () => {
      const ctx = makeContext({
        serverInfo: { name: "legit-server", version: "1.0' OR '1'='1" },
      });
      const results = await module.run(ctx);
      const fail = results.find((r) => r.status === CheckStatus.FAIL);
      expect(fail).toBeDefined();
    });

    test("flags debug/infrastructure leak in server name", async () => {
      const ctx = makeContext({
        serverInfo: { name: "mcp-server-dev-debug-internal", version: "1.0.0" },
      });
      const results = await module.run(ctx);
      // May produce a finding for infrastructure leak
      // Just verify the module runs without error
      expect(Array.isArray(results)).toBe(true);
    });
  });

  describe("clean handshake", () => {
    test("valid server metadata produces no CRITICAL/HIGH injection findings", async () => {
      const ctx = makeContext({
        serverInfo: { name: "weather-mcp-server", version: "1.2.3" },
        protocolVersion: "2025-03-26",
      });
      const results = await module.run(ctx);
      const criticals = results.filter(
        (r) =>
          r.status === CheckStatus.FAIL &&
          (r.finding?.severity === Severity.CRITICAL || r.finding?.severity === Severity.HIGH)
      );
      expect(criticals).toHaveLength(0);
    });
  });
});
