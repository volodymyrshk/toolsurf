import { accessSync, constants } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import chalk from "chalk";
import {
  findingManifestTemplate,
  loadFindingManifest,
  resolveManifestPath,
  validateFindingManifest,
} from "../core/finding-manifest.js";

const execFileAsync = promisify(execFile);

export interface ReproCheckOptions {
  manifestPath?: string;
  init?: boolean;
  json?: boolean;
  dryRun?: boolean;
  timeoutMs?: number;
}

interface ReproCheckReport {
  status: "PASS" | "FAIL" | "ERROR";
  findingId?: string;
  manifestPath?: string;
  scriptPath?: string;
  exitCode?: number;
  durationMs?: number;
  expectedOutputMatched?: boolean;
  stdout?: string;
  stderr?: string;
  errors?: string[];
  warnings?: string[];
}

function trimOutput(value: string, max = 12_000): string {
  return value.length <= max ? value : value.slice(0, max) + "\n[truncated]";
}

function outputJson(report: ReproCheckReport): void {
  console.log(JSON.stringify(report, null, 2));
}

function outputTerminal(report: ReproCheckReport): void {
  console.log();
  console.log(chalk.bold("  Reproduction Check"));
  console.log(chalk.dim("  " + "-".repeat(30)));
  console.log();

  const statusColor =
    report.status === "PASS" ? chalk.green :
    report.status === "FAIL" ? chalk.red :
    chalk.yellow;

  console.log(`  Status:   ${statusColor(report.status)}`);
  if (report.findingId) console.log(`  Finding:  ${report.findingId}`);
  if (report.scriptPath) console.log(`  Script:   ${report.scriptPath}`);
  if (report.durationMs !== undefined) console.log(`  Duration: ${report.durationMs}ms`);
  if (report.expectedOutputMatched !== undefined) {
    console.log(`  Expected: ${report.expectedOutputMatched ? chalk.green("matched") : chalk.red("not matched")}`);
  }

  if (report.warnings?.length) {
    console.log();
    console.log(chalk.yellow("  Warnings:"));
    for (const warning of report.warnings) console.log(chalk.yellow(`    - ${warning}`));
  }

  if (report.errors?.length) {
    console.log();
    console.log(chalk.red("  Errors:"));
    for (const error of report.errors) console.log(chalk.red(`    - ${error}`));
  }

  if (report.stdout) {
    console.log();
    console.log(chalk.bold("  stdout"));
    console.log(chalk.dim(report.stdout));
  }

  if (report.stderr) {
    console.log();
    console.log(chalk.bold("  stderr"));
    console.log(chalk.dim(report.stderr));
  }

  console.log();
}

async function runManifest(options: ReproCheckOptions): Promise<ReproCheckReport> {
  if (!options.manifestPath) {
    return { status: "ERROR", errors: ["Missing finding.yaml path"] };
  }

  let loaded;
  try {
    loaded = loadFindingManifest(options.manifestPath);
  } catch (err) {
    return {
      status: "ERROR",
      manifestPath: options.manifestPath,
      errors: String(err instanceof Error ? err.message : err).split("\n"),
    };
  }

  const { manifest, manifestPath, baseDir } = loaded;
  const validation = validateFindingManifest(manifest, baseDir);
  const scriptPath = resolveManifestPath(baseDir, manifest.reproduction.script);

  if (options.dryRun) {
    return {
      status: "PASS",
      findingId: manifest.finding_id,
      manifestPath,
      scriptPath,
      warnings: validation.warnings,
    };
  }

  try {
    accessSync(scriptPath, constants.X_OK);
  } catch {
    return {
      status: "ERROR",
      findingId: manifest.finding_id,
      manifestPath,
      scriptPath,
      errors: ["reproduction.script exists but is not executable"],
      warnings: validation.warnings,
    };
  }

  const started = Date.now();
  try {
    const { stdout, stderr } = await execFileAsync(scriptPath, [], {
      cwd: baseDir,
      timeout: options.timeoutMs ?? 120_000,
      maxBuffer: 10 * 1024 * 1024,
      env: {
        ...process.env,
        TOOLSURF_FINDING_ID: manifest.finding_id,
        TOOLSURF_TARGET_COMMIT: manifest.target.commit_sha,
      },
    });
    const durationMs = Date.now() - started;
    const combined = `${stdout}\n${stderr}`;
    const expected = manifest.reproduction.expected_output?.trim();
    const expectedOutputMatched = expected ? combined.includes(expected) : undefined;
    const status = expectedOutputMatched === false ? "FAIL" : "PASS";

    return {
      status,
      findingId: manifest.finding_id,
      manifestPath,
      scriptPath,
      exitCode: 0,
      durationMs,
      expectedOutputMatched,
      stdout: trimOutput(stdout),
      stderr: trimOutput(stderr),
      warnings: validation.warnings,
      errors: status === "FAIL" ? ["reproduction.expected_output was not found in stdout/stderr"] : undefined,
    };
  } catch (err) {
    const durationMs = Date.now() - started;
    const error = err as {
      code?: number | string;
      stdout?: string;
      stderr?: string;
      signal?: string;
      message?: string;
    };

    return {
      status: "FAIL",
      findingId: manifest.finding_id,
      manifestPath,
      scriptPath,
      exitCode: typeof error.code === "number" ? error.code : undefined,
      durationMs,
      stdout: trimOutput(error.stdout ?? ""),
      stderr: trimOutput(error.stderr ?? ""),
      warnings: validation.warnings,
      errors: [
        error.signal === "SIGTERM"
          ? `reproduction script timed out after ${options.timeoutMs ?? 120_000}ms`
          : error.message ?? "reproduction script failed",
      ],
    };
  }
}

export async function executeReproCheck(options: ReproCheckOptions): Promise<void> {
  if (options.init) {
    console.log(findingManifestTemplate());
    return;
  }

  const report = await runManifest(options);

  if (options.json) {
    outputJson(report);
  } else {
    outputTerminal(report);
  }

  if (report.status === "PASS") {
    process.exitCode = 0;
  } else if (report.status === "FAIL") {
    process.exitCode = 3;
  } else {
    process.exitCode = 2;
  }
}
