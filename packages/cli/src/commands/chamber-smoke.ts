import { join } from "node:path";
import chalk from "chalk";
import { ChamberRuntime } from "../core/chamber-runtime.js";
import type { ChamberTargetSpec } from "../core/detonation-chamber.js";
import type { OutputFormat } from "../core/reporter.js";
import { presetToTargetProfile } from "../core/target-profile.js";
import type { ProtocolType } from "../adapters/types.js";
import { executeScan } from "./scan.js";

/**
 * One-shot end-to-end chamber smoke test.
 *
 * Brings up a fresh detonation chamber, runs an active scan against the
 * supplied target with chamber probes wired in, then tears the chamber down.
 *
 * The command is intentionally opinionated:
 *   - --active is forced on (the chamber is pointless for a passive scan).
 *   - --scan-mode is full-active by default.
 *   - chamberRunDir is auto-detected from the runtime created here.
 *   - reachability + chamberSummary land in the saved report unconditionally.
 */
export interface ChamberSmokeCommandOptions {
  server: string;
  protocol?: ProtocolType;
  transport?: "stdio" | "streamable-http";
  format?: OutputFormat;
  output?: string;
  outputDir?: string;
  name?: string;
  verbose?: boolean;
  keepChamber?: boolean;
  targetImage?: string;
  targetCommand?: string;
  targetPort?: string;
  targetReadWrite?: boolean;
  vendorReport?: string;
  vendorReportAllowUnverified?: boolean;
  vendorName?: string;
  vendorRepo?: string;
  vendorCommit?: string;
  vendorChannel?: string;
  dataClassification?: "none" | "pii" | "phi" | "pci" | "secrets" | "all";
  context?: "production" | "sandboxed";
  modules?: string[];
  probeTimeout?: number;
  probeDelay?: number;
  timeout?: number;
  llmOutputTokenLimit?: number;
  /** Enable interactive TUI dashboard with live module progress. */
  tui?: boolean;
  /**
   * If set, mints a host workdir at `<chamber-run>/workdir/` and bind-mounts
   * it into the target so the state-oracle module can diff filesystem
   * mutations. Default: off — keeps existing scans unchanged.
   */
  stateOracle?: boolean;
}

export async function executeChamberSmoke(
  options: ChamberSmokeCommandOptions,
): Promise<void> {
  const protocol = options.protocol ?? "mcp";
  const transport = options.transport ?? "stdio";
  const name = options.name ?? `smoke-${Date.now().toString(36)}`;
  const outputDir = options.outputDir ?? "data/detonation-chamber";

  // For HTTP-shaped targets the chamber compose hosts the target service,
  // so we need a target spec. stdio MCP targets are launched outside the
  // chamber by `docker run -i` — applyChamberToConnectParams attaches the
  // chamber network at scan time.
  const target = buildTargetSpec(options);

  const runtime = ChamberRuntime.create({
    name,
    outputDir,
    target,
    ...(options.stateOracle ? { workdir: { enabled: true } } : {}),
  });

  console.log(chalk.bold(chalk.red("Chamber Smoke Test")));
  console.log(chalk.dim("  ─".repeat(36)));
  console.log(chalk.dim(`  Chamber run dir:  ${runtime.manifest.runDir}`));
  console.log(chalk.dim(`  Fake HTTP:        ${runtime.manifest.services.fakeHttp.url}`));
  console.log(chalk.dim(`  Target:           ${options.server}`));
  console.log();

  let started = false;
  try {
    runtime.start();
    started = true;
    console.log(chalk.green("  ✓ Chamber containers up"));
    console.log();

    const reportPath =
      options.output ??
      join(runtime.manifest.runDir, "smoke-report.research.json");

    const report = await executeScan({
      server: options.server,
      protocol,
      transport,
      format: options.format ?? "terminal",
      active: true,
      tui: options.tui,
      verbose: options.verbose ?? false,
      modules: options.modules,
      timeout: options.timeout ?? 30000,
      probeTimeout: options.probeTimeout ?? 5000,
      probeDelay: options.probeDelay ?? 100,
      llmOutputTokenLimit: options.llmOutputTokenLimit ?? 8192,
      output: reportPath,
      compliance: ["all"],
      scanMode: "full-active",
      targetProfile: presetToTargetProfile("ci"),
      targetProfilePreset: "ci",
      chamberRunDir: runtime.manifest.runDir,
      context: options.context ?? "sandboxed",
      dataClassification: options.dataClassification ?? "none",
      vendorReport: options.vendorReport,
      vendorName: options.vendorName,
      vendorRepo: options.vendorRepo,
      vendorCommit: options.vendorCommit,
      vendorChannel: options.vendorChannel,
    });

    if (!report) {
      throw new Error("Scan did not return a report (likely connection failure).");
    }

    printSmokeVerdict(report, reportPath);
  } finally {
    if (started && !options.keepChamber) {
      try {
        await runtime.stopAndRemoveNetwork();
        console.log();
        console.log(chalk.dim("  Chamber stopped"));
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(chalk.red(`  Chamber cleanup failed: ${message}`));
        process.exitCode = 4;
      }
    } else if (started) {
      console.log();
      console.log(chalk.yellow(`  Chamber kept running: ${runtime.manifest.runDir}`));
      console.log(
        chalk.dim(
          `  Tear down with: bun run src/index.ts chamber down --run-dir ${runtime.manifest.runDir}`,
        ),
      );
    }
  }
}

function buildTargetSpec(
  options: ChamberSmokeCommandOptions,
): ChamberTargetSpec | undefined {
  // stdio MCP targets do not run as a chamber compose service.
  if (
    (options.protocol ?? "mcp") === "mcp" &&
    (options.transport ?? "stdio") === "stdio"
  ) {
    return undefined;
  }

  if (!options.targetImage && !options.targetCommand) {
    return undefined;
  }

  return {
    image: options.targetImage,
    command: options.targetCommand,
    ports: options.targetPort ? [options.targetPort] : undefined,
    readOnly: options.targetReadWrite ? false : undefined,
  };
}

function printSmokeVerdict(report: { chamberReachability?: { status?: string; verified?: boolean; reason?: string }; chamberSummary?: { confirmedExfil?: unknown[]; ipiRelays?: unknown[] }; findings?: { id: string }[] }, reportPath: string): void {
  const reach = report.chamberReachability;
  const chamberFindings = (report.findings ?? []).filter(
    (f) => f.id.startsWith("CHAMBER-") || f.id.startsWith("AF-CHAMBER"),
  );

  console.log();
  console.log(chalk.bold("Smoke verdict"));
  console.log(chalk.dim("  ─".repeat(36)));

  const reachLabel = reach?.verified
    ? chalk.green("verified")
    : reach?.status
    ? chalk.yellow(reach.status)
    : chalk.red("missing");
  console.log(`  Chamber reachability:   ${reachLabel}`);
  if (!reach?.verified && reach?.reason) {
    console.log(chalk.dim(`    ${reach.reason}`));
  }

  console.log(`  Chamber-backed findings: ${chamberFindings.length}`);
  if (report.chamberSummary?.confirmedExfil?.length) {
    console.log(`  Confirmed exfil events: ${report.chamberSummary.confirmedExfil.length}`);
  }
  if (report.chamberSummary?.ipiRelays?.length) {
    console.log(`  IPI relays caught:      ${report.chamberSummary.ipiRelays.length}`);
  }

  console.log(chalk.dim(`  Report: ${reportPath}`));

  if (!reach?.verified && chamberFindings.length === 0) {
    console.log();
    console.log(
      chalk.yellow(
        "  Chamber wired in but target produced no captured callbacks.\n" +
          "  Either the target has no URL-accepting tools, or it could not\n" +
          "  reach the chamber network. Check that the target image actually\n" +
          "  exists locally and that connect params show --network <chamber>.",
      ),
    );
  }
}
