import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { createTargetAudit } from "../../src/core/target-connector.js";

const TMP_DIR = join(import.meta.dir, "../.tmp-target-connector");

describe("target connector", () => {
  beforeEach(() => {
    rmSync(TMP_DIR, { recursive: true, force: true });
  });

  afterEach(() => {
    rmSync(TMP_DIR, { recursive: true, force: true });
  });

  test("writes target manifest and chamber references without executing by default", () => {
    const manifest = createTargetAudit({
      repo: "https://example.com/vendor/payments-mcp.git",
      commit: "abc123",
      outputDir: TMP_DIR,
      protocol: "mcp",
      buildCommand: "npm ci && npm run build",
      runCommand: "node dist/index.js",
      scanTarget: "node dist/index.js",
      chamber: true,
      targetPorts: ["127.0.0.1:3100:3100"],
      targetReadWrite: true,
    });

    expect(manifest.executionMode).toBe("planned");
    expect(manifest.name).toBe("payments-mcp");
    expect(manifest.commit).toBe("abc123");
    expect(manifest.chamber?.manifest).toBeDefined();
    expect(existsSync(manifest.artifacts.manifest)).toBe(true);
    expect(existsSync(manifest.chamber!.manifest)).toBe(true);

    const raw = JSON.parse(readFileSync(manifest.artifacts.manifest, "utf-8"));
    expect(raw.commands.build).toContain("npm ci");
    expect(raw.chamber.fakeMetadataUrl).toBe("http://172.30.0.12");
    const chamberCompose = readFileSync(join(manifest.chamber!.runDir, "docker-compose.yml"), "utf-8");
    expect(chamberCompose).toContain("\"127.0.0.1:3100:3100\"");
    expect(chamberCompose).not.toContain("read_only: true");
  });
});
