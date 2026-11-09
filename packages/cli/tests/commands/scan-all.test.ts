import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { writeFileSync, unlinkSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { loadRegistry, outputFleetSummary, runWithConcurrency } from "../../src/commands/scan-all.js";
import type { ScanReport, ReportSummary, Finding } from "../../src/types/index.js";
import { Severity } from "../../src/types/index.js";

const TEST_DIR = join(import.meta.dir, "../.tmp-scan-all");

function makeTempFile(name: string, content: string): string {
  const path = join(TEST_DIR, name);
  writeFileSync(path, content, "utf-8");
  return path;
}

function makeFinding(overrides: Partial<Finding>): Finding {
  return {
    id: "TEST-001",
    module: "test-module",
    severity: Severity.MEDIUM,
    title: "Test finding",
    description: "A test finding",
    evidence: {},
    remediation: "Fix it",
    ...overrides,
  };
}

function makeReport(
  score: number,
  findings: Finding[] = []
): ScanReport {
  return {
    version: "1.0.0",
    id: "test-report",
    timestamp: new Date().toISOString(),
    durationMs: 1000,
    cliVersion: "0.1.0-alpha.1",
    transport: { type: "stdio", command: "test", args: [] },
    server: {
      serverInfo: { name: "test-server", version: "1.0.0" },
      protocolVersion: "2025-11-05",
      capabilities: {},
      tools: [],
      resources: [],
      prompts: [],
    },
    modules: [],
    findings,
    summary: {
      totalChecks: 10,
      passed: 8,
      warnings: 1,
      failed: 1,
      skipped: 0,
      errors: 0,
      findingsBySeverity: {
        CRITICAL: findings.filter((f) => f.severity === Severity.CRITICAL).length,
        HIGH: findings.filter((f) => f.severity === Severity.HIGH).length,
        MEDIUM: findings.filter((f) => f.severity === Severity.MEDIUM).length,
        LOW: findings.filter((f) => f.severity === Severity.LOW).length,
        INFO: 0,
      },
      securityScore: score,
    },
  };
}

describe("scan-all Registry Loader", () => {
  beforeEach(() => {
    mkdirSync(TEST_DIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  test("loads valid registry file", () => {
    const path = makeTempFile(
      "valid.json",
      JSON.stringify({
        servers: [
          { name: "server-a", command: "npx server-a" },
          { name: "server-b", command: "node server-b.js" },
        ],
      })
    );

    const registry = loadRegistry(path);
    expect(registry.servers).toHaveLength(2);
    expect(registry.servers[0].name).toBe("server-a");
    expect(registry.servers[1].command).toBe("node server-b.js");
  });

  test("loads registry with defaults", () => {
    const path = makeTempFile(
      "defaults.json",
      JSON.stringify({
        servers: [{ name: "s1", command: "cmd1" }],
        defaults: {
          active: true,
          profile: "enterprise",
          compliance: ["all"],
        },
      })
    );

    const registry = loadRegistry(path);
    expect(registry.defaults?.active).toBe(true);
    expect(registry.defaults?.profile).toBe("enterprise");
    expect(registry.defaults?.compliance).toEqual(["all"]);
  });

  test("loads registry with per-server overrides", () => {
    const path = makeTempFile(
      "overrides.json",
      JSON.stringify({
        servers: [
          {
            name: "custom",
            command: "node server.js",
            active: true,
            profile: "enterprise",
            compliance: ["nist"],
            modules: ["tool-permissions"],
            timeout: 60000,
          },
        ],
      })
    );

    const registry = loadRegistry(path);
    const server = registry.servers[0];
    expect(server.active).toBe(true);
    expect(server.profile).toBe("enterprise");
    expect(server.compliance).toEqual(["nist"]);
    expect(server.modules).toEqual(["tool-permissions"]);
    expect(server.timeout).toBe(60000);
  });

  test("throws on missing file", () => {
    expect(() => loadRegistry("/nonexistent/path.json")).toThrow(
      "Registry file not found"
    );
  });

  test("throws on invalid JSON", () => {
    const path = makeTempFile("bad.json", "not json {{{");
    expect(() => loadRegistry(path)).toThrow("Invalid JSON");
  });

  test("throws on missing servers array", () => {
    const path = makeTempFile(
      "noservers.json",
      JSON.stringify({ defaults: {} })
    );
    expect(() => loadRegistry(path)).toThrow('"servers" array');
  });

  test("throws on server without name", () => {
    const path = makeTempFile(
      "noname.json",
      JSON.stringify({
        servers: [{ command: "some-cmd" }],
      })
    );
    expect(() => loadRegistry(path)).toThrow('"name" string field');
  });

  test("throws on server without command", () => {
    const path = makeTempFile(
      "nocmd.json",
      JSON.stringify({
        servers: [{ name: "server-a" }],
      })
    );
    expect(() => loadRegistry(path)).toThrow('"command" string field');
  });

  test("throws on invalid profile name", () => {
    const path = makeTempFile(
      "badprofile.json",
      JSON.stringify({
        servers: [
          { name: "s1", command: "cmd1", profile: "superfast" },
        ],
      })
    );
    expect(() => loadRegistry(path)).toThrow('invalid profile "superfast"');
  });

  test("accepts empty servers array", () => {
    const path = makeTempFile(
      "empty.json",
      JSON.stringify({ servers: [] })
    );
    const registry = loadRegistry(path);
    expect(registry.servers).toHaveLength(0);
  });
});

describe("Fleet Summary Output", () => {
  test("handles all successful results", () => {
    const results = [
      {
        name: "server-a",
        command: "cmd-a",
        report: makeReport(92, [makeFinding({ severity: Severity.LOW })]),
      },
      {
        name: "server-b",
        command: "cmd-b",
        report: makeReport(78, [
          makeFinding({ id: "F1", severity: Severity.HIGH }),
          makeFinding({ id: "F2", severity: Severity.MEDIUM }),
        ]),
      },
    ];

    // Should not throw
    expect(() => outputFleetSummary(results)).not.toThrow();
  });

  test("handles mixed success and failure", () => {
    const results = [
      {
        name: "ok-server",
        command: "cmd-ok",
        report: makeReport(85),
      },
      {
        name: "bad-server",
        command: "cmd-bad",
        error: "Connection timeout",
      },
    ];

    expect(() => outputFleetSummary(results)).not.toThrow();
  });

  test("handles all failures", () => {
    const results = [
      { name: "fail-1", command: "cmd-1", error: "Error 1" },
      { name: "fail-2", command: "cmd-2", error: "Error 2" },
    ];

    expect(() => outputFleetSummary(results)).not.toThrow();
  });

  test("handles empty results", () => {
    expect(() => outputFleetSummary([])).not.toThrow();
  });
});

describe("scan-all concurrency helper", () => {
  test("preserves result order while running workers concurrently", async () => {
    let running = 0;
    let maxRunning = 0;
    const results = await runWithConcurrency([30, 10, 20, 5], 2, async (delay, index) => {
      running++;
      maxRunning = Math.max(maxRunning, running);
      await new Promise((resolve) => setTimeout(resolve, delay));
      running--;
      return `result-${index}`;
    });

    expect(results).toEqual(["result-0", "result-1", "result-2", "result-3"]);
    expect(maxRunning).toBeLessThanOrEqual(2);
    expect(maxRunning).toBeGreaterThan(1);
  });
});
