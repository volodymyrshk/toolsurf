import { describe, test, expect } from "bun:test";
import { TransportSecurityModule } from "../../src/modules/transport-security.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ModuleContext, ServerCapabilities } from "../../src/types/index.js";

function makeContext(overrides: Partial<ServerCapabilities> = {}): ModuleContext {
  return {
    capabilities: {
      serverInfo: { name: "test-server", version: "1.0.0" },
      protocolVersion: "2025-11-05",
      capabilities: { tools: { listChanged: false } },
      tools: [],
      resources: [],
      prompts: [],
      ...overrides,
    },
    activeMode: false,
    verbose: false,
  };
}

describe("TransportSecurityModule", () => {
  const module = new TransportSecurityModule();

  test("module metadata is correct", () => {
    expect(module.id).toBe("transport-security");
    expect(module.mode).toBe("passive");
  });

  test("passes for a minimal safe server", async () => {
    const context = makeContext();
    const results = await module.run(context);

    const failed = results.filter((r) => r.status === CheckStatus.FAIL);
    expect(failed.length).toBe(0);
  });

  test("detects sampling capability as HIGH risk", async () => {
    const context = makeContext({
      capabilities: {
        tools: {},
        sampling: { enabled: true },
      },
    });

    const results = await module.run(context);
    const samplingCheck = results.find((r) => r.id === "TS-002");

    expect(samplingCheck).toBeDefined();
    expect(samplingCheck!.status).toBe(CheckStatus.FAIL);
    expect(samplingCheck!.finding?.severity).toBe(Severity.HIGH);
  });

  test("detects roots capability", async () => {
    const context = makeContext({
      capabilities: {
        tools: {},
        roots: { listChanged: true },
      },
    });

    const results = await module.run(context);
    const rootsCheck = results.find((r) => r.id === "TS-003");

    expect(rootsCheck).toBeDefined();
    expect(rootsCheck!.status).toBe(CheckStatus.WARN);
    expect(rootsCheck!.finding?.severity).toBe(Severity.MEDIUM);
  });

  test("detects dynamic tool list changes", async () => {
    const context = makeContext({
      capabilities: {
        tools: { listChanged: true },
      },
    });

    const results = await module.run(context);
    const tlcCheck = results.find((r) => r.id === "TS-004");

    expect(tlcCheck).toBeDefined();
    expect(tlcCheck!.status).toBe(CheckStatus.WARN);
    expect(tlcCheck!.finding?.severity).toBe(Severity.MEDIUM);
    expect(tlcCheck!.finding?.description).toContain("rug pull");
  });

  test("detects sensitive resource URIs", async () => {
    const context = makeContext({
      resources: [
        { uri: "config://env/secrets", name: "Environment Secrets" },
        { uri: "file:///home/user/.aws/credentials", name: "AWS Creds" },
      ],
    });

    const results = await module.run(context);
    const resourceCheck = results.find((r) => r.id === "TS-005");

    expect(resourceCheck).toBeDefined();
    expect(resourceCheck!.status).toBe(CheckStatus.FAIL);
    expect(resourceCheck!.finding?.severity).toBe(Severity.HIGH);
  });

  test("recognizes known protocol versions", async () => {
    const context = makeContext({ protocolVersion: "2025-11-05" });
    const results = await module.run(context);
    const protoCheck = results.find((r) => r.id === "TS-006");

    expect(protoCheck).toBeDefined();
    expect(protoCheck!.status).toBe(CheckStatus.PASS);
  });

  test("flags unknown protocol versions", async () => {
    const context = makeContext({ protocolVersion: "9999-01-01" });
    const results = await module.run(context);
    const protoCheck = results.find((r) => r.id === "TS-006");

    expect(protoCheck).toBeDefined();
    expect(protoCheck!.status).toBe(CheckStatus.WARN);
  });

  test("warns on empty capabilities", async () => {
    const context = makeContext({ capabilities: {} });
    const results = await module.run(context);
    const capCheck = results.find((r) => r.id === "TS-001");

    expect(capCheck).toBeDefined();
    expect(capCheck!.status).toBe(CheckStatus.WARN);
  });
});
