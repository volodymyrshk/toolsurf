import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { executeAuditRepo } from "../../src/commands/audit-repo.js";

const TMP_DIR = join(import.meta.dir, ".tmp-audit-repo-command");

afterEach(() => {
  rmSync(TMP_DIR, { recursive: true, force: true });
  process.exitCode = 0;
});

describe("audit-repo command", () => {
  test("dry-run writes a manifest without cloning or building", async () => {
    const originalLog = console.log;
    console.log = () => {};

    try {
      const manifest = await executeAuditRepo({
        repo: "https://github.com/vendor/fetch-mcp.git",
        outputDir: TMP_DIR,
        image: "scanner-fetch:local",
        dryRun: true,
      });

      expect(manifest.status).toBe("planned");
      expect(manifest.scan.target).toBe("docker run --rm -i scanner-fetch:local");
      expect(existsSync(manifest.artifacts.manifest)).toBe(true);

      const parsed = JSON.parse(readFileSync(manifest.artifacts.manifest, "utf-8"));
      expect(parsed.docker.buildEnabled).toBe(false);
      expect(parsed.chamber.enabled).toBe(true);
      expect(existsSync(join(TMP_DIR, "checkout"))).toBe(false);
    } finally {
      console.log = originalLog;
    }
  });
});
