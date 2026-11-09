import { afterEach, describe, expect, test } from "bun:test";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import { executeReproCheck } from "../../src/commands/repro-check.js";

const TMP_DIR = join(import.meta.dir, ".tmp-repro-check");

afterEach(() => {
  rmSync(TMP_DIR, { recursive: true, force: true });
});

function writeManifest(options: {
  scriptBody?: string;
  expectedOutput?: string;
  executable?: boolean;
} = {}): string {
  mkdirSync(join(TMP_DIR, "scripts"), { recursive: true });
  const scriptPath = join(TMP_DIR, "scripts", "repro.sh");
  writeFileSync(
    scriptPath,
    options.scriptBody ?? "#!/bin/sh\necho annotation-gap-confirmed\n",
    "utf-8",
  );
  if (options.executable !== false) {
    chmodSync(scriptPath, 0o755);
  }

  const expectedOutput = options.expectedOutput ?? "annotation-gap-confirmed";
  const manifestPath = join(TMP_DIR, "finding.yaml");
  writeFileSync(
    manifestPath,
    [
      "finding_id: paypal-2026-05-001",
      "target:",
      "  vendor: PayPal",
      "  repo: paypal/mcp",
      "  commit_sha: 0123456789abcdef0123456789abcdef01234567",
      "  file: src/tools.ts",
      "  line: 42",
      "class:",
      "  cwe: CWE-285",
      "  owasp_llm: LLM05 supply-chain vulnerabilities",
      "  our_taxonomy: agent-tool.annotation.destructive-gap",
      "cvss:",
      "  score: 8.1",
      "impact: A financial action can be misclassified as read-only by downstream agents.",
      "reproduction:",
      "  preconditions:",
      "    - Target is checked out at the tested commit",
      "  steps:",
      "    - Run the reproduction script",
      "  script: ./scripts/repro.sh",
      `  expected_output: ${expectedOutput}`,
      "patch_suggestion: Set destructiveHint=true and require explicit user confirmation.",
      "",
    ].join("\n"),
    "utf-8",
  );

  return manifestPath;
}

async function runReproCheck(options: Parameters<typeof executeReproCheck>[0]) {
  const originalLog = console.log;
  const originalError = console.error;
  const originalWarn = console.warn;
  const originalExitCode = process.exitCode;
  let output = "";

  console.log = (message?: unknown) => {
    output += String(message ?? "") + "\n";
  };
  console.error = () => {};
  console.warn = () => {};

  try {
    await executeReproCheck(options);
    return { output, exitCode: process.exitCode };
  } finally {
    console.log = originalLog;
    console.error = originalError;
    console.warn = originalWarn;
    process.exitCode = originalExitCode ?? 0;
  }
}

describe("repro-check command", () => {
  test("--init prints a valid finding.yaml template", async () => {
    const { output } = await runReproCheck({ init: true });
    const parsed = parse(output);

    expect(parsed.finding_id).toBe("vendor-2026-05-001");
    expect(parsed.reproduction.script).toContain("repro-vendor-2026-05-001.sh");
  });

  test("--dry-run validates the manifest without executing the script", async () => {
    const marker = join(TMP_DIR, "executed.txt");
    const manifestPath = writeManifest({
      scriptBody: `#!/bin/sh\necho touched > ${JSON.stringify(marker)}\necho annotation-gap-confirmed\n`,
    });

    const { output, exitCode } = await runReproCheck({
      manifestPath,
      dryRun: true,
      json: true,
    });
    const report = JSON.parse(output);

    expect(report.status).toBe("PASS");
    expect(report.scriptPath).toBe(join(TMP_DIR, "scripts", "repro.sh"));
    expect(existsSync(marker)).toBe(false);
    expect(exitCode).toBe(0);
  });

  test("passes when the script exits cleanly and emits expected output", async () => {
    const manifestPath = writeManifest();

    const { output, exitCode } = await runReproCheck({
      manifestPath,
      json: true,
    });
    const report = JSON.parse(output);

    expect(report.status).toBe("PASS");
    expect(report.findingId).toBe("paypal-2026-05-001");
    expect(report.expectedOutputMatched).toBe(true);
    expect(report.stdout).toContain("annotation-gap-confirmed");
    expect(exitCode).toBe(0);
  });

  test("fails when expected output is missing", async () => {
    const manifestPath = writeManifest({ expectedOutput: "different-marker" });

    const { output, exitCode } = await runReproCheck({
      manifestPath,
      json: true,
    });
    const report = JSON.parse(output);

    expect(report.status).toBe("FAIL");
    expect(report.expectedOutputMatched).toBe(false);
    expect(report.errors).toContain("reproduction.expected_output was not found in stdout/stderr");
    expect(exitCode).toBe(3);
  });

  test("errors when the reproduction script is not executable", async () => {
    const manifestPath = writeManifest({ executable: false });

    const { output, exitCode } = await runReproCheck({
      manifestPath,
      json: true,
    });
    const report = JSON.parse(output);

    expect(report.status).toBe("ERROR");
    expect(report.errors).toContain("reproduction.script exists but is not executable");
    expect(exitCode).toBe(2);
  });

  test("errors when finding.yaml is missing", async () => {
    const missingManifest = join(TMP_DIR, "missing.yaml");

    const { output, exitCode } = await runReproCheck({
      manifestPath: missingManifest,
      json: true,
    });
    const report = JSON.parse(output);

    expect(report.status).toBe("ERROR");
    expect(report.errors[0]).toContain("ENOENT");
    expect(exitCode).toBe(2);
  });
});
