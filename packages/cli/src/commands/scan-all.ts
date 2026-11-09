/**
 * scan-all Command — Fleet-wide MCP server scanning.
 *
 * Reads a registry JSON file defining multiple servers, scans each
 * using executeScan(), and produces a fleet-level summary with
 * per-server scores and aggregated findings.
 *
 * Designed for enterprise environments with many MCP servers.
 */

import { readFileSync, existsSync, mkdirSync } from "node:fs";
import chalk from "chalk";
import { executeScan, type ScanOptions } from "./scan.js";
import { printBanner } from "../core/reporter.js";
import { resolveProfile, isProfileName, type ProfileName } from "../core/profiles.js";
import type { ScanReport, ProtocolType } from "../types/index.js";

// ─── Registry Types ──────────────────────────────────────────────────────────

export interface RegistryServerEntry {
  /** Human-readable server name */
  name: string;
  /** Server command to spawn or URL to connect to */
  command: string;
  /** Transport type override */
  transport?: "stdio" | "streamable-http";
  /** Protocol adapter to use (default: mcp) */
  protocol?: ProtocolType;
  /** Per-server active override */
  active?: boolean;
  /** Per-server profile override */
  profile?: ProfileName;
  /** Per-server compliance override */
  compliance?: string[];
  /** Per-server module filter */
  modules?: string[];
  /** Per-server timeout override */
  timeout?: number;
}

export interface RegistryFile {
  /** List of servers to scan */
  servers: RegistryServerEntry[];
  /** Default options applied to all servers (overridden by per-server values) */
  defaults?: {
    active?: boolean;
    profile?: ProfileName;
    compliance?: string[];
    timeout?: number;
    format?: "terminal" | "json" | "html" | "markdown";
  };
}

export interface ScanAllOptions {
  registry: string;
  format?: string;
  active?: boolean;
  outputDir?: string;
  profile?: string;
  accept?: boolean;
  /** Pass --slim to each scan: strips raw schemas and deduplicates module data (~85% smaller) */
  slim?: boolean;
  /** Number of servers to scan per batch before pausing for cleanup (default: unlimited) */
  batchSize?: number;
  /** Number of passive scans to run in parallel (active scans are serialized) */
  concurrency?: number;
}

interface ServerResult {
  name: string;
  command: string;
  report?: ScanReport;
  error?: string;
}

interface IndexedServerResult extends ServerResult {
  index: number;
}

// ─── Registry Loader ─────────────────────────────────────────────────────────

export function loadRegistry(filePath: string): RegistryFile {
  if (!existsSync(filePath)) {
    throw new Error(`Registry file not found: ${filePath}`);
  }

  const content = readFileSync(filePath, "utf-8");
  let data: unknown;

  try {
    data = JSON.parse(content);
  } catch {
    throw new Error(`Invalid JSON in registry file: ${filePath}`);
  }

  const registry = data as Record<string, unknown>;

  if (!registry.servers || !Array.isArray(registry.servers)) {
    throw new Error('Registry file must contain a "servers" array');
  }

  for (let i = 0; i < registry.servers.length; i++) {
    const entry = registry.servers[i] as Record<string, unknown>;
    if (!entry.name || typeof entry.name !== "string") {
      throw new Error(`Server at index ${i} must have a "name" string field`);
    }
    if (!entry.command || typeof entry.command !== "string") {
      throw new Error(`Server at index ${i} must have a "command" string field`);
    }
    if (entry.profile && !isProfileName(entry.profile as string)) {
      throw new Error(
        `Server "${entry.name}" has invalid profile "${entry.profile}". Available: quick, standard, enterprise`
      );
    }
  }

  return registry as unknown as RegistryFile;
}

// ─── Command Execution ──────────────────────────────────────────────────────

export async function executeScanAll(options: ScanAllOptions): Promise<void> {
  printBanner("Fleet Scan");

  const registry = loadRegistry(options.registry);
  const servers = registry.servers;
  const defaults = registry.defaults ?? {};

  console.log(chalk.bold(`  Registry: `) + chalk.white(options.registry));
  console.log(chalk.bold(`  Servers:  `) + chalk.white(String(servers.length)));
  console.log();

  // Prepare output directory
  if (options.outputDir) {
    if (!existsSync(options.outputDir)) {
      mkdirSync(options.outputDir, { recursive: true });
    }
  }

  const scanOptionsByIndex = servers.map((entry) =>
    resolveScanOptions(entry, defaults, options)
  );
  const requestedConcurrency = normalizeConcurrency(options.concurrency);
  const hasActiveScans = scanOptionsByIndex.some((scanOpts) => scanOpts.active);
  const concurrency = hasActiveScans ? 1 : requestedConcurrency;
  const batchSize = options.batchSize && options.batchSize > 0
    ? options.batchSize
    : Math.max(servers.length, 1);

  if (requestedConcurrency > 1) {
    if (hasActiveScans) {
      console.log(chalk.yellow("  Active fleet scans are serialized to keep probe side effects isolated."));
    } else {
      console.log(chalk.dim(`  Concurrency: ${concurrency}`));
    }
    console.log();
  }

  const results: IndexedServerResult[] = [];

  for (let batchStart = 0; batchStart < servers.length; batchStart += batchSize) {
    const batch = servers
      .slice(batchStart, batchStart + batchSize)
      .map((entry, offset) => ({
        entry,
        index: batchStart + offset,
        scanOpts: scanOptionsByIndex[batchStart + offset],
      }));

    const batchResults = await runWithConcurrency(batch, concurrency, async ({ entry, index, scanOpts }) => {
      console.log(
        chalk.bold(`  [${index + 1}/${servers.length}] `) +
          chalk.cyan(entry.name)
      );
      console.log(chalk.dim(`  Command: ${entry.command}`));
      console.log();

      try {
        const report = await executeScan(scanOpts);
        console.log();
        return {
          index,
          name: entry.name,
          command: entry.command,
          report: (report as any) ?? undefined,
        };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(chalk.red(`  Error scanning "${entry.name}": ${message}`));
        return { index, name: entry.name, command: entry.command, error: message };
      } finally {
        if (index < servers.length - 1) {
          console.log(chalk.dim("  " + "─".repeat(60)));
          console.log();
        }
      }
    });

    results.push(...batchResults);

    // Batch pause: after every batchSize servers, pause for GC and cleanup
    const batchEnd = Math.min(batchStart + batch.length, servers.length);
    if (batchEnd < servers.length) {
      console.log(
        chalk.yellow(`  ⏸  Batch ${Math.floor(batchEnd / batchSize)} complete (${batch.length} servers). `) +
        chalk.yellow(`Pausing 3s for cleanup...`)
      );
      // Force garbage collection if exposed, then wait
      if (global.gc) global.gc();
      await new Promise((resolve) => setTimeout(resolve, 3_000));
      console.log(chalk.dim("  Resuming...\n"));
    }
  }

  // ── Fleet Summary ────────────────────────────────────────────────────────
  results.sort((a, b) => a.index - b.index);
  outputFleetSummary(results, options.outputDir);
}

// ─── Fleet Summary ───────────────────────────────────────────────────────────

export function outputFleetSummary(
  results: ServerResult[],
  outputDir?: string
): void {
  const successful = results.filter((r) => r.report);
  const failed = results.filter((r) => r.error);

  console.log();
  console.log(
    chalk.bold.cyan(
      "  ╭─────────────────────────────────────────────────────────────╮"
    )
  );
  console.log(
    chalk.bold.cyan("  │") +
      chalk.bold("  FLEET SUMMARY") +
      " ".repeat(46) +
      chalk.bold.cyan("│")
  );
  console.log(
    chalk.bold.cyan(
      "  ╰─────────────────────────────────────────────────────────────╯"
    )
  );
  console.log();

  // Per-server scores
  if (successful.length > 0) {
    const maxNameLen = Math.max(...successful.map((r) => r.name.length), 20);

    for (const r of successful) {
      const score = r.report!.summary.securityScore;
      const findings = r.report!.findings.length;
      const scoreColor =
        score >= 80 ? chalk.green : score >= 50 ? chalk.yellow : chalk.red;
      const scoreStr = scoreColor.bold(`${String(score).padStart(3)}/100`);
      const nameStr = r.name.padEnd(maxNameLen);
      const findingStr = chalk.dim(`${findings} finding(s)`);

      console.log(`    ${scoreStr}  ${nameStr}  ${findingStr}`);
    }
    console.log();
  }

  // Fleet-wide aggregated score
  if (successful.length > 0) {
    const avgScore = Math.round(
      successful.reduce((sum, r) => sum + r.report!.summary.securityScore, 0) /
        successful.length
    );
    const totalFindings = successful.reduce(
      (sum, r) => sum + r.report!.findings.length,
      0
    );
    const criticals = successful.reduce(
      (sum, r) => sum + (r.report!.summary.findingsBySeverity.CRITICAL ?? 0),
      0
    );
    const highs = successful.reduce(
      (sum, r) => sum + (r.report!.summary.findingsBySeverity.HIGH ?? 0),
      0
    );

    const avgColor =
      avgScore >= 80 ? chalk.green : avgScore >= 50 ? chalk.yellow : chalk.red;

    console.log(
      chalk.bold("    Fleet Score:    ") + avgColor.bold(`${avgScore}/100`)
    );
    console.log(
      chalk.bold("    Total Findings: ") +
        `${totalFindings}` +
        chalk.dim(` (${chalk.red(`${criticals} critical`)}, ${chalk.red(`${highs} high`)})`)
    );
    console.log();
  }

  // Failed servers
  if (failed.length > 0) {
    console.log(chalk.red(`    ${failed.length} server(s) failed:`));
    for (const r of failed) {
      console.log(chalk.red(`      ${r.name}: ${r.error}`));
    }
    console.log();
  }

  // Top findings across fleet
  const allFindings = successful.flatMap((r) =>
    r.report!.findings.map((f) => ({ ...f, serverName: r.name }))
  );

  const sevOrder: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFO: 4,
  };

  allFindings.sort(
    (a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9)
  );

  const worst = allFindings.slice(0, 5);
  if (worst.length > 0) {
    console.log(chalk.bold("    Top Findings Across Fleet:"));
    console.log();
    for (const f of worst) {
      const sev =
        f.severity === "CRITICAL"
          ? chalk.bgRed.white(` ${f.severity.padEnd(8)} `)
          : f.severity === "HIGH"
            ? chalk.red(` ${f.severity.padEnd(8)} `)
            : f.severity === "MEDIUM"
              ? chalk.yellow(` ${f.severity.padEnd(8)} `)
              : chalk.dim(` ${f.severity.padEnd(8)} `);
      console.log(
        `      ${sev} ${f.title} ${chalk.dim(`[${(f as any).serverName}]`)}`
      );
    }
    console.log();
  }

  // Bottom line
  console.log(
    chalk.dim(
      `    ${successful.length} scanned, ${failed.length} failed`
    )
  );

  if (outputDir) {
    console.log(chalk.dim(`    Reports saved to: ${outputDir}/`));
  }

  console.log();
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function sanitizeFilename(name: string): string {
  return name.replace(/[^a-zA-Z0-9_-]/g, "_");
}

function resolveScanOptions(
  entry: RegistryServerEntry,
  defaults: RegistryFile["defaults"],
  options: ScanAllOptions,
): ScanOptions {
  // Resolve profile for this server (entry > defaults > CLI)
  const profileName =
    entry.profile ?? defaults?.profile ?? options.profile;
  const profileDefaults =
    profileName && isProfileName(profileName)
      ? resolveProfile(profileName)
      : null;

  // Build scan options with merge order: entry > defaults > profile > CLI
  return {
    server: entry.command,
    transport: entry.transport ?? "stdio",
    protocol: entry.protocol,
    format: (options.format ?? defaults?.format ?? "terminal") as ScanOptions["format"],
    active:
      entry.active ??
      defaults?.active ??
      profileDefaults?.active ??
      options.active ??
      false,
    verbose: false,
    timeout: entry.timeout ?? defaults?.timeout ?? 30000,
    compliance:
      entry.compliance ?? defaults?.compliance ?? profileDefaults?.compliance,
    modules: entry.modules,
    // Disable interactive features in fleet mode
    tui: false,
    autofix: false,
    executiveSummary: false,
    slim: options.slim,
    output: options.outputDir
      ? `${options.outputDir}/${sanitizeFilename(entry.name)}.json`
      : undefined,
  };
}

function normalizeConcurrency(value?: number): number {
  if (!value || !Number.isFinite(value)) return 1;
  return Math.max(1, Math.floor(value));
}

export async function runWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const limit = Math.max(1, Math.floor(concurrency));
  const results = new Array<R>(items.length);
  let nextIndex = 0;

  async function runWorker(): Promise<void> {
    while (nextIndex < items.length) {
      const index = nextIndex++;
      results[index] = await worker(items[index], index);
    }
  }

  const workers = Array.from({ length: Math.min(limit, items.length) }, runWorker);
  await Promise.all(workers);
  return results;
}
