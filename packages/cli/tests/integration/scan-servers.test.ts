/**
 * Integration tests — scan real MCP servers end-to-end.
 *
 * These tests require network access and npx to install MCP servers.
 * They verify the entire pipeline: connect → enumerate → analyze → score → report.
 *
 * Run with: bun test tests/integration/
 * Timeout: 60s per server (network + npx install time)
 */
import { describe, test, expect } from "bun:test";
import { execSync } from "node:child_process";

const CLI = "bun run src/index.ts";
const TIMEOUT = 60_000;
const RUN_INTEGRATION = process.env.RUN_INTEGRATION_TESTS === "true";

interface ScanResult {
  version: string;
  server: {
    serverInfo: { name: string; version: string };
    tools: unknown[];
    resources: unknown[];
    prompts: unknown[];
  };
  summary: {
    securityScore: number;
    totalChecks: number;
    passed: number;
    warnings: number;
    failed: number;
    findingsBySeverity: Record<string, number>;
  };
  findings: Array<{
    id: string;
    severity: string;
    module: string;
  }>;
}

function scanServer(serverCmd: string): ScanResult {
  let output = "";
  try {
    output = execSync(
      `${CLI} scan --server "${serverCmd}" --accept --ci`,
      {
        cwd: process.cwd(),
        encoding: "utf-8",
        stdio: ["pipe", "pipe", "pipe"],
      }
    );
  } catch (err: any) {
    if (err.stdout) {
      output = err.stdout.toString();
    } else {
      throw err;
    }
  }
  return JSON.parse(output);
}

describe.skipIf(!RUN_INTEGRATION)("Integration: Real MCP Server Scans", () => {
  test(
    "scans @modelcontextprotocol/server-filesystem",
    () => {
      const result = scanServer(
        "npx -y @modelcontextprotocol/server-filesystem /tmp"
      );

      // Verify basic structure
      expect(result.version).toBe("1.0.0");
      expect(result.server.serverInfo.name).toContain("filesystem");
      expect(result.server.tools.length).toBeGreaterThan(5);

      // Well-maintained server should score 50+
      expect(result.summary.securityScore).toBeGreaterThanOrEqual(50);

      // Should run at least 30 checks across all modules
      expect(result.summary.totalChecks).toBeGreaterThanOrEqual(30);

      // Filesystem server has no CRITICAL issues
      expect(result.summary.findingsBySeverity.CRITICAL ?? 0).toBe(0);

      // Should have <= 5 FAIL checks (stricter scanner now catches unconstrained arrays/strings properly)
      expect(result.summary.failed).toBeLessThanOrEqual(5);
    },
    TIMEOUT
  );

  test(
    "scans @modelcontextprotocol/server-memory",
    () => {
      const result = scanServer(
        "npx -y @modelcontextprotocol/server-memory"
      );

      expect(result.server.serverInfo.name).toContain("memory");
      expect(result.server.tools.length).toBeGreaterThan(3);

      // Memory server should score relatively well
      expect(result.summary.securityScore).toBeGreaterThanOrEqual(50);

      // No CRITICAL
      expect(result.summary.findingsBySeverity.CRITICAL ?? 0).toBe(0);
    },
    TIMEOUT
  );

  test(
    "scans @modelcontextprotocol/server-everything",
    () => {
      const result = scanServer(
        "npx -y @modelcontextprotocol/server-everything"
      );

      expect(result.server.serverInfo.name).toContain("everything");
      expect(result.server.tools.length).toBeGreaterThan(5);
      // Everything server exercises all features — expect prompts and resources too
      expect(result.server.prompts.length).toBeGreaterThan(0);
      expect(result.server.resources.length).toBeGreaterThan(0);

      // Everything server is intentionally broad — lower score expected
      expect(result.summary.securityScore).toBeLessThan(80);

      // Should have findings
      expect(result.findings.length).toBeGreaterThan(0);
    },
    TIMEOUT
  );

  test(
    "produces valid JSON with all required fields",
    () => {
      const result = scanServer(
        "npx -y @modelcontextprotocol/server-filesystem /tmp"
      );

      // Top-level fields
      expect(result).toHaveProperty("version");
      expect(result).toHaveProperty("server");
      expect(result).toHaveProperty("modules");
      expect(result).toHaveProperty("findings");
      expect(result).toHaveProperty("summary");
      expect(result).toHaveProperty("transport");

      // Summary fields
      expect(result.summary).toHaveProperty("securityScore");
      expect(result.summary).toHaveProperty("totalChecks");
      expect(result.summary).toHaveProperty("passed");
      expect(result.summary).toHaveProperty("warnings");
      expect(result.summary).toHaveProperty("failed");
      expect(result.summary).toHaveProperty("findingsBySeverity");

      // Score is 0-100
      expect(result.summary.securityScore).toBeGreaterThanOrEqual(0);
      expect(result.summary.securityScore).toBeLessThanOrEqual(100);
    },
    TIMEOUT
  );
});
