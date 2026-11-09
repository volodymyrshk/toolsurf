import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { executeAgentJuiceShopCompare } from "../../src/commands/agent-juice-shop-compare.js";

const TMP_DIR = join(import.meta.dir, ".tmp-agent-juice-shop-compare-command");

afterEach(() => {
  rmSync(TMP_DIR, { recursive: true, force: true });
});

describe("agent-juice-shop-compare command", () => {
  test("writes init config to a nested file path", async () => {
    const originalLog = console.log;
    console.log = () => {};

    try {
      const outputPath = join(TMP_DIR, "data", "agent-juice-shop", "competitors.json");
      await executeAgentJuiceShopCompare({ init: outputPath });

      expect(existsSync(outputPath)).toBe(true);
      const parsed = JSON.parse(readFileSync(outputPath, "utf-8"));
      expect(Array.isArray(parsed.tools)).toBe(true);
    } finally {
      console.log = originalLog;
    }
  });
});
