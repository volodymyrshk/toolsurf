import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  chamberConfigFromManifest,
  finalizeChamberReachability,
  isChamberHealthcheckEvent,
  verifyChamberReachability,
} from "../../src/core/chamber-runtime.js";
import { createChamberRun } from "../../src/core/detonation-chamber.js";
import { Severity, type ServerCapabilities } from "../../src/types/index.js";

function capabilitiesWithUrlTool(): ServerCapabilities {
  return {
    serverInfo: { name: "target", version: "1.0.0" },
    protocolVersion: "test",
    capabilities: {},
    tools: [
      {
        name: "fetch_url",
        description: "Fetch a URL",
        inputSchema: {
          type: "object",
          properties: {
            url: { type: "string" },
          },
        },
      },
    ],
    resources: [],
    prompts: [],
    protocol: "mcp",
  };
}

describe("chamber runtime", () => {
  test("builds probe config from a chamber manifest", () => {
    const dir = mkdtempSync(join(tmpdir(), "scanner-chamber-runtime-"));
    try {
      const manifest = createChamberRun({ outputDir: dir, runId: "rt-test" });
      const config = chamberConfigFromManifest(manifest);

      expect(config.runDir).toBe(manifest.runDir);
      expect(config.networkName).toBe(manifest.network.name);
      expect(config.fakeHttpUrl).toBe("http://172.30.0.10:8080");
      expect(config.captures?.http).toBe(manifest.captures.http);
      expect(config.fakeServiceIps).toContain("172.30.0.10");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("verifies reachability when a URL-like tool causes fake-http capture growth", async () => {
    const dir = mkdtempSync(join(tmpdir(), "scanner-chamber-runtime-"));
    try {
      const manifest = createChamberRun({ outputDir: dir, runId: "health-ok" });
      const chamber = chamberConfigFromManifest(manifest);

      const result = await verifyChamberReachability({
        capabilities: capabilitiesWithUrlTool(),
        chamber,
        timeoutMs: 50,
        callTool: async (_name, args) => {
          writeFileSync(
            manifest.captures.http,
            JSON.stringify({ path: new URL(String(args.url)).pathname }) + "\n",
            "utf-8",
          );
          return { ok: true };
        },
      });

      expect(result.status).toBe("verified");
      expect(result.verified).toBe(true);
      expect(result.toolName).toBe("fetch_url");
      expect(result.paramName).toBe("url");
      expect(result.probeUrl).toContain("/__chamber-healthcheck/");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("returns not-testable when no URL-like parameter exists", async () => {
    const dir = mkdtempSync(join(tmpdir(), "scanner-chamber-runtime-"));
    try {
      const manifest = createChamberRun({ outputDir: dir, runId: "health-skip" });
      const capabilities = capabilitiesWithUrlTool();
      capabilities.tools[0].inputSchema = {
        type: "object",
        properties: { query: { type: "string" } },
      };

      const result = await verifyChamberReachability({
        capabilities,
        chamber: chamberConfigFromManifest(manifest),
        callTool: async () => ({ ok: true }),
      });

      expect(result.status).toBe("not-testable");
      expect(result.verified).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("healthcheck events are recognizable so evidence synthesis can ignore them", () => {
    expect(isChamberHealthcheckEvent({ path: "/__chamber-healthcheck/abc" })).toBe(true);
    expect(isChamberHealthcheckEvent({ path: "/ssrf-probe" })).toBe(false);
  });

  test("finalizes reachability as verified when a chamber-backed finding exists", () => {
    const result = finalizeChamberReachability(
      {
        status: "unverified",
        verified: false,
        checkedAt: "2026-05-03T00:00:00.000Z",
        method: "tool-call",
        reason: "No healthcheck callback.",
      },
      [
        {
          id: "CHAMBER-HTTP-001",
          module: "chamber-evidence",
          severity: Severity.CRITICAL,
          title: "Captured",
          description: "Captured",
          evidence: { verifiedBy: "chamber-capture", captureFile: "/tmp/requests.jsonl" },
          remediation: "Fix",
        },
      ],
    );

    expect(result?.status).toBe("verified");
    expect(result?.verified).toBe(true);
    expect(result?.method).toBe("chamber-finding");
  });
});
