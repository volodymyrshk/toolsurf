import { afterEach, describe, expect, test } from "bun:test";
import { rmSync } from "node:fs";
import { join } from "node:path";
import { executeChamber } from "../../src/commands/chamber.js";

const TMP_DIR = join(import.meta.dir, ".tmp-chamber-command");

afterEach(() => {
  rmSync(TMP_DIR, { recursive: true, force: true });
  process.exitCode = 0;
});

describe("chamber command", () => {
  test("rejects placeholder target images before docker compose runs", async () => {
    const originalError = console.error;
    let stderr = "";
    console.error = (message?: unknown) => {
      stderr += String(message ?? "") + "\n";
    };

    try {
      const result = await executeChamber({
        action: "up",
        outputDir: TMP_DIR,
        targetImage: "your-org/your-target:latest",
        targetCommand: "node dist/server.js",
        targetPorts: ["127.0.0.1:3100:3100"],
      });

      expect(result).toBeUndefined();
      expect(process.exitCode).toBe(2);
      expect(stderr).toContain("Refusing placeholder target image");
      expect(stderr).toContain("docker build -t scanner-target:local");
    } finally {
      console.error = originalError;
    }
  });
});
