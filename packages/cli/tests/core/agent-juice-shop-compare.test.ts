import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { existsSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { runAgentJuiceShopComparison } from "../../src/core/agent-juice-shop-compare.js";

const TMP_DIR = join(import.meta.dir, "../.tmp-agent-juice-shop-compare");

describe("Agent Juice Shop comparison harness", () => {
  beforeEach(() => {
    rmSync(TMP_DIR, { recursive: true, force: true });
    mkdirSync(TMP_DIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(TMP_DIR, { recursive: true, force: true });
  });

  test("records dry-run transcripts for pinned competitor commands", () => {
    const configPath = join(TMP_DIR, "competitors.json");
    writeFileSync(
      configPath,
      JSON.stringify({
        corpusDir: "data/agent-juice-shop",
        tools: [
          {
            name: "mcp-scan",
            command: "mcp-scan scan data/agent-juice-shop",
            versionCommand: "mcp-scan --version",
          },
        ],
      }),
      "utf-8"
    );

    const manifest = runAgentJuiceShopComparison({
      configPath,
      outputDir: TMP_DIR,
      dryRun: true,
      runId: "test-run",
    });

    expect(existsSync(join(manifest.runDir, "comparison.manifest.json"))).toBe(true);
    expect(manifest.transcripts).toHaveLength(1);
    expect(manifest.transcripts[0].dryRun).toBe(true);
    expect(readFileSync(manifest.transcripts[0].stdoutFile, "utf-8")).toContain("[dry-run]");
  });

  test("auto-creates a missing config path instead of throwing ENOENT", () => {
    const configPath = join(TMP_DIR, "nested", "competitors.json");
    const manifest = runAgentJuiceShopComparison({
      configPath,
      outputDir: join(TMP_DIR, "out"),
      dryRun: true,
      runId: "missing-config",
    });

    expect(existsSync(configPath)).toBe(true);
    expect(manifest.transcripts.length).toBeGreaterThan(0);
  });
});
