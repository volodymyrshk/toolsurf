import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const TMP_DIR = join(import.meta.dir, ".tmp-validate-scan-reports");
const VALIDATOR = join(import.meta.dir, "..", "..", "..", "..", "scripts", "validate-scan-reports.mjs");

afterEach(() => {
  rmSync(TMP_DIR, { recursive: true, force: true });
});

function writeReport(file: string, report: Record<string, unknown>) {
  mkdirSync(TMP_DIR, { recursive: true });
  writeFileSync(join(TMP_DIR, file), JSON.stringify(report, null, 2), "utf-8");
}

function runValidator(...args: string[]) {
  return spawnSync("node", [VALIDATOR, ...args], {
    cwd: join(import.meta.dir, "..", "..", "..", ".."),
    encoding: "utf-8",
  });
}

describe("validate-scan-reports", () => {
  test("passes when summary severity counts match top-level findings", () => {
    writeReport("ok.json", {
      findings: [
        { id: "critical-1", severity: "CRITICAL" },
        { id: "high-1", severity: "HIGH" },
        { id: "info-1", severity: "INFO" },
      ],
      summary: {
        findingsBySeverity: {
          CRITICAL: 1,
          HIGH: 1,
          MEDIUM: 0,
          LOW: 0,
          INFO: 1,
        },
      },
    });

    const result = runValidator(TMP_DIR);

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("mismatched=0");
    expect(result.stdout).toContain("findings=3(C=1,H=1,M=0,L=0,I=1)");
    expect(result.stderr).toBe("");
  });

  test("fails and reports the file when summary severity counts drift", () => {
    writeReport("mismatch.json", {
      findings: [
        { id: "critical-1", severity: "CRITICAL" },
        { id: "low-1", severity: "LOW" },
      ],
      summary: {
        findingsBySeverity: {
          CRITICAL: 0,
          HIGH: 1,
          MEDIUM: 0,
          LOW: 1,
          INFO: 0,
        },
      },
    });

    const result = runValidator(TMP_DIR);

    expect(result.status).toBe(1);
    expect(result.stdout).toContain("MISMATCH");
    expect(result.stdout).toContain("mismatch.json");
    expect(result.stdout).toContain("mismatched=1");
    expect(result.stdout).toContain("findings=2(C=1,H=0,M=0,L=1,I=0)");
    expect(result.stdout).toContain("summary=2(C=0,H=1,M=0,L=1,I=0)");
  });
});
