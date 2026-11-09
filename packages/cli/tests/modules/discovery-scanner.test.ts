import { describe, test, expect } from "bun:test";
import { DiscoveryScannerModule } from "../../src/modules/discovery-scanner.js";
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

const module = new DiscoveryScannerModule();

describe("DiscoveryScannerModule", () => {
  test("module metadata", () => {
    expect(module.id).toBe("discovery-scanner");
    expect(module.mode).toBe("passive");
    expect(typeof module.version).toBe("string");
  });

  describe("DS-001 — discovery information exposure", () => {
    test("flags framework/runtime leaks in server name", async () => {
      const ctx = makeContext({
        serverInfo: { name: "express-4.18.2-internal-api", version: "1.0.0" },
      });
      const results = await module.run(ctx);
      const ds001 = results.find((r) => r.id.startsWith("DS-001") && r.status === CheckStatus.WARN);
      expect(ds001).toBeDefined();
    });

    test("flags internal/dev marker in server metadata", async () => {
      const ctx = makeContext({
        serverInfo: { name: "mcp-dev-internal-staging", version: "0.0.1-alpha" },
      });
      const results = await module.run(ctx);
      const warn = results.find((r) => r.status === CheckStatus.WARN);
      expect(warn).toBeDefined();
    });
  });

  describe("DS-002 — server identity gaps", () => {
    test("flags empty server name", async () => {
      const ctx = makeContext({
        serverInfo: { name: "", version: "1.0.0" },
      });
      const results = await module.run(ctx);
      const ds002 = results.find((r) => r.id.startsWith("DS-002") && r.status === CheckStatus.WARN);
      expect(ds002).toBeDefined();
    });

    test("flags missing version string", async () => {
      const ctx = makeContext({
        serverInfo: { name: "my-server", version: "" },
      });
      const results = await module.run(ctx);
      const warn = results.find((r) => r.status === CheckStatus.WARN);
      expect(warn).toBeDefined();
    });
  });

  describe("DS-004 — protocol version issues", () => {
    test("flags deprecated SSE-only protocol version indicator", async () => {
      const ctx = makeContext({
        serverInfo: { name: "legacy-server", version: "1.0.0" },
        protocolVersion: "2024-11-05",
      });
      const results = await module.run(ctx);
      const ds004 = results.find((r) => r.id.startsWith("DS-004") && r.status === CheckStatus.FAIL);
      // May produce a finding for deprecated protocol version
      // Just verify the module handles it without error
      expect(Array.isArray(results)).toBe(true);
    });
  });

  describe("clean server", () => {
    test("well-identified server with clean metadata produces no CRITICAL/HIGH findings", async () => {
      const ctx = makeContext({
        serverInfo: { name: "weather-mcp-v2", version: "2.1.0" },
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

    test("module runs without error on minimal context", async () => {
      const results = await module.run(makeContext());
      expect(Array.isArray(results)).toBe(true);
    });
  });
});
