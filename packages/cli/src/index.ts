#!/usr/bin/env node

import { Command } from "commander";
import chalk from "chalk";
import { executeScan, executeDryRun } from "./commands/scan.js";
import { executeScanSource } from "./commands/scan-source.js";
import { executeAuditLocal } from "./commands/audit-local.js";
import { executeBadge } from "./commands/badge.js";
import { executeDiff } from "./commands/diff.js";
import { executeHook } from "./commands/hook.js";
import { executeMock } from "./commands/mock.js";
import { executeReproCheck } from "./commands/repro-check.js";
import { executeAgentJuiceShop } from "./commands/agent-juice-shop.js";
import { executeAgentJuiceShopCompare } from "./commands/agent-juice-shop-compare.js";
import { executeChamber } from "./commands/chamber.js";
import { executeChamberSmoke } from "./commands/chamber-smoke.js";
import { executeAuditTarget } from "./commands/audit-target.js";
import { executeAuditRepo } from "./commands/audit-repo.js";
import { ensureAcceptance, forceAcceptance } from "./core/acceptance.js";
import { createAllModules } from "./core/module-catalog.js";
import { printBanner } from "./core/reporter.js";
import { loadConfig, loadCustomPayloads, loadIgnoreList } from "./core/config.js";
import { resolveProfile, isProfileName, type ProfileDefaults } from "./core/profiles.js";
import {
  parseTargetProfilePreset,
  presetToTargetProfile,
  type TargetProfilePreset,
} from "./core/target-profile.js";
import { isProtocolType } from "./adapters/registry.js";
import type { ProtocolType } from "./adapters/types.js";

import { CLI_VERSION } from "./version.js";

const program = new Command();

program
  .name("toolsurf")
  .description(
    "Security audit tool for AI agent tool interfaces.\n" +
      "Actively stress-tests MCP servers, OpenAI functions, LangChain tools, REST APIs, and more."
  )
  .version(CLI_VERSION)
  .addHelpText("beforeAll", () => {
    // Show banner on --help
    printBanner(`v${CLI_VERSION}`);
    return "";
  });

// ─── scan command ──────────────────────────────────────────────────────────────
program
  .command("scan")
  .description("Scan an AI agent tool interface for security vulnerabilities")
  .requiredOption(
    "-s, --server <command>",
    'Server command or URL to scan (e.g., "npx -y @modelcontextprotocol/server-filesystem /tmp")'
  )
  .option(
    "-t, --transport <type>",
    "Transport type (stdio or streamable-http)",
    "stdio"
  )
  .option(
    "--protocol <type>",
    "Protocol adapter (mcp, openai-functions, langchain-tools, rest-api, graphql, grpc, a2a)",
    "mcp"
  )
  .option(
    "-f, --format <format>",
    "Output format (terminal, json, html, markdown, latex, csv, research-json, or pgfplots)",
    "terminal"
  )
  .option(
    "-p, --profile <name>",
    "Scan profile: quick (passive only), standard (passive+active), enterprise (full suite)"
  )
  .option(
    "--active",
    "Enable active scanning modules (makes tool calls to the server)",
    false
  )
  .option(
    "-m, --modules <modules...>",
    "Run specific modules only (space-separated module IDs)"
  )
  .option("-v, --verbose", "Enable verbose output", false)
  .option(
    "--timeout <ms>",
    "Connection timeout in milliseconds",
    "30000"
  )
  .option(
    "--ci",
    "CI mode: no color, no progress, JSON output, non-zero exit on findings",
    false
  )
  .option(
    "-o, --output <file>",
    "Save report to file (use .sarif extension for SARIF format)"
  )
  .option(
    "--probe-timeout <ms>",
    "Timeout per active probe in milliseconds",
    "5000"
  )
  .option(
    "--probe-delay <ms>",
    "Delay between active probes in milliseconds",
    "100"
  )
  .option(
    "--llm-output-token-limit <tokens>",
    "Max output tokens the deployed LLM can emit in one response; caps token-exhaustion argument estimates",
    "8192"
  )
  .option(
    "--min-severity <level>",
    "Only show findings at or above this level (CRITICAL, HIGH, MEDIUM, LOW)"
  )
  .option(
    "--min-confidence <number>",
    "Only show findings at or above this confidence (0.0-1.0, e.g., 0.8 for CI/CD)"
  )
  .option(
    "--compliance <frameworks...>",
    "Enable compliance mapping (nist, soc2, asvs, hipaa, pci-dss, iso27001, fedramp, gdpr, or all)"
  )
  .option(
    "--data-classification <class>",
    "Declared data class for the target: none|pii|phi|pci|secrets|all. Gates HIPAA/PCI/GDPR mapping. Default: none.",
    "none"
  )
  .option(
    "--payloads <file>",
    "Load custom fuzzing payloads from a JSON file"
  )
  .option(
    "--config <file>",
    "Path to config file (default: .toolsurfrc.json)"
  )
  .option(
    "--accept",
    "Accept the legal notice (for non-interactive environments)",
    false
  )
  .option(
    "--tui",
    "Enable interactive TUI dashboard with live progress",
    false
  )
  .option(
    "--autofix",
    "Show auto-fix suggestions with code patches for findings",
    false
  )
  .option(
    "--executive-summary",
    "Include executive summary for non-technical stakeholders",
    false
  )
  .option(
    "--rules <file>",
    "Load custom policy rules from a YAML/JSON file"
  )
  .option(
    "--fail-below <score>",
    "Exit non-zero if security score is below this threshold (0-100)"
  )
  .option(
    "--plugin <paths...>",
    "Load custom audit module plugins (paths to .js/.ts files)"
  )
  .option(
    "--no-plugins",
    "Disable auto-discovery of plugins from ~/.toolsurf/plugins/"
  )
  .option(
    "--scan-mode <mode>",
    "Scan mode: passive-only, safe-active, or full-active (aliases: passive, safe, full)"
  )
  .option(
    "--target-profile <profile>",
    "Target profile: ide, ci, or production (adjusts risk thresholds)"
  )
  .option(
    "--slim",
    "Produce slim research-JSON output (strips raw schemas, ~85% size reduction)",
    false
  )
  .option(
    "--context <ctx>",
    "Target context: production (default) or sandboxed (embeds non-comparable disclaimer)"
  )
  .option(
    "--chamber-run-dir <dir>",
    "Use an existing detonation chamber run for active exploit probes and capture evidence"
  )
  .option(
    "--vendor-report <dir>",
    "Write per-finding vendor disclosure artifacts (finding.yaml + repro.sh) to <dir>; chamber-backed findings only"
  )
  .option("--vendor-name <name>", "Vendor name baked into finding.yaml (overrides scan target inference)")
  .option("--vendor-repo <repo>", "Vendor repo baked into finding.yaml (e.g. org/repo)")
  .option("--vendor-commit <sha>", "Commit SHA baked into finding.yaml (e.g. for paper / disclosure pinning)")
  .option("--vendor-channel <email>", "Vendor security disclosure channel (security@vendor.com)")
  .option(
    "--dry-run",
    "Validate config and reachability without connecting or running modules",
    false
  )
  .action(async (opts) => {
    // Load config file
    const config = loadConfig(opts.config);

    // ── Validate protocol ──────────────────────────────────────────────
    const protocol = opts.protocol as string;
    if (!isProtocolType(protocol)) {
      console.error(
        chalk.red(`  Unknown protocol "${protocol}". Available: mcp, openai-functions, langchain-tools, rest-api, graphql, grpc, a2a`)
      );
      process.exit(1);
    }

    // ── Resolve profile defaults ────────────────────────────────────────
    const profileName = opts.profile ?? config.profile;
    let profileDefaults: ProfileDefaults | null = null;
    if (profileName) {
      if (!isProfileName(profileName)) {
        console.error(
          chalk.red(`  Unknown profile "${profileName}". Available: quick, standard, enterprise`)
        );
        process.exit(1);
      }
      profileDefaults = resolveProfile(profileName);
    }

    // ── Smart defaults: auto-enable features in interactive terminals ───
    const isInteractive = process.stdout.isTTY && !opts.ci && !process.env.CI;
    const userPassedFlag = (flag: string) => process.argv.includes(flag);

    // ── Merge: profile < config < CLI flags (most specific wins) ────────
    const format = opts.format !== "terminal" ? opts.format : (config.format ?? "terminal");
    const active = opts.active || config.active || profileDefaults?.active || false;
    const compliance = opts.compliance ?? config.compliance ?? profileDefaults?.compliance;
    const minSeverity = (opts.minSeverity ?? config.minSeverity ?? profileDefaults?.minSeverity)?.toUpperCase();
    const modules = opts.modules ?? config.modules;
    const verbose = opts.verbose || config.verbose || profileDefaults?.verbose || false;
    const timeout = opts.timeout !== "30000" ? parseInt(opts.timeout, 10) : (config.timeout ?? 30000);
    const probeTimeout = opts.probeTimeout !== "5000" ? parseInt(opts.probeTimeout, 10) : (config.probeTimeout ?? 5000);
    const probeDelay = opts.probeDelay !== "100" ? parseInt(opts.probeDelay, 10) : (config.probeDelay ?? 100);
    const llmOutputTokenLimit = opts.llmOutputTokenLimit !== "8192"
      ? parseInt(opts.llmOutputTokenLimit, 10)
      : (config.llmOutputTokenLimit ?? 8192);

    // Smart defaults: TUI, autofix, executive-summary auto-enable in TTY
    // unless user explicitly passed --no-tui style (not possible with Commander boolean, so just check argv)
    const tui = userPassedFlag("--tui")
      ? opts.tui
      : (profileDefaults?.tui ?? (isInteractive ? true : false));
    const autofix = userPassedFlag("--autofix")
      ? opts.autofix
      : (profileDefaults?.autofix ?? (isInteractive ? true : false));
    const executiveSummary = userPassedFlag("--executive-summary")
      ? opts.executiveSummary
      : (profileDefaults?.executiveSummary ?? (isInteractive ? true : false));

    // Load custom payloads
    const payloadsFile = opts.payloads ?? config.payloads;
    const customPayloads = payloadsFile ? loadCustomPayloads(payloadsFile) : undefined;

    let targetProfile;
    let targetProfilePreset: TargetProfilePreset | undefined;
    if (opts.targetProfile) {
      try {
        targetProfilePreset = parseTargetProfilePreset(opts.targetProfile);
        targetProfile = presetToTargetProfile(targetProfilePreset);
      } catch (err) {
        console.error(chalk.red(`  ${err instanceof Error ? err.message : err}`));
        process.exit(1);
      }
    }

    // Load ignore list
    const ignoreList = loadIgnoreList(config.ignore);

    // Handle acceptance
    if (opts.accept || opts.ci) {
      forceAcceptance();
    } else {
      const accepted = await ensureAcceptance();
      if (!accepted) {
        process.exit(1);
      }
    }

    // CI mode overrides
    const finalFormat = opts.ci ? "json" : format;
    const finalVerbose = opts.ci ? false : verbose;

    // Dry-run: validate without executing
    if (opts.dryRun) {
      await executeDryRun({
        server: opts.server,
        transport: opts.transport as "stdio" | "streamable-http",
        protocol: protocol as ProtocolType,
        format: finalFormat as "terminal" | "json" | "html" | "markdown" | "latex" | "csv" | "research-json" | "pgfplots",
        active,
        modules,
        verbose: finalVerbose,
        timeout,
        llmOutputTokenLimit,
        output: opts.output,
        rules: opts.rules,
        scanMode: opts.scanMode,
        targetProfile,
        chamberRunDir: opts.chamberRunDir,
      });
      return;
    }

    await executeScan({
      server: opts.server,
      transport: opts.transport as "stdio" | "streamable-http",
      protocol: protocol as ProtocolType,
      format: finalFormat as
        | "terminal"
        | "json"
        | "html"
        | "markdown"
        | "latex"
        | "csv"
        | "research-json"
        | "pgfplots",
      active,
      modules,
      verbose: finalVerbose,
      timeout,
      output: opts.output,
      compliance,
      probeTimeout,
      probeDelay,
      llmOutputTokenLimit,
      minSeverity,
      customPayloads,
      ignoreList: ignoreList.size > 0 ? ignoreList : undefined,
      tui: tui && !opts.ci,
      autofix,
      executiveSummary,
      rules: opts.rules,
      failBelow: opts.failBelow ? parseInt(opts.failBelow, 10) : undefined,
      minConfidence: opts.minConfidence ? parseFloat(opts.minConfidence) : undefined,
      plugins: opts.plugin,
      scoringConfig: profileDefaults?.severityWeights
        ? {
            severityWeights: profileDefaults.severityWeights,
            diminishingFactor: profileDefaults.diminishingFactor,
            maxModuleImpact: profileDefaults.maxModuleImpact,
          }
        : undefined,
      // P3-18 [§ARCH]: Wire scan-mode / target-profile / slim / context CLI flags
      scanMode: opts.scanMode,
      targetProfile,
      targetProfilePreset,
      chamberRunDir: opts.chamberRunDir,
      slim: opts.slim || false,
      context: opts.context as "production" | "sandboxed" | undefined,
      dataClassification: opts.dataClassification as
        | "none" | "pii" | "phi" | "pci" | "secrets" | "all"
        | undefined,
      vendorReport: opts.vendorReport,
      vendorName: opts.vendorName,
      vendorRepo: opts.vendorRepo,
      vendorCommit: opts.vendorCommit,
      vendorChannel: opts.vendorChannel,
    });
  });

// ─── scan-all command ────────────────────────────────────────────────────────
program
  .command("scan-all")
  .description("Scan multiple servers/endpoints defined in a registry file")
  .requiredOption(
    "-r, --registry <file>",
    "Path to registry JSON file defining servers to scan"
  )
  .option(
    "-f, --format <format>",
    "Output format for individual reports (terminal, json, html, markdown)",
    "terminal"
  )
  .option("--active", "Enable active scanning for all servers", false)
  .option(
    "-p, --profile <name>",
    "Default scan profile for all servers (quick, standard, enterprise)"
  )
  .option("-o, --output-dir <dir>", "Save individual reports to directory")
  .option(
    "--batch-size <n>",
    "Servers per batch before pausing for cleanup (prevents disk/memory exhaustion)"
  )
  .option(
    "--concurrency <n>",
    "Number of passive scans to run in parallel (active scans are serialized)",
    "1"
  )
  .option(
    "--accept",
    "Accept the legal notice (for non-interactive environments)",
    false
  )
  .action(async (opts) => {
    if (opts.accept) {
      forceAcceptance();
    } else {
      const accepted = await ensureAcceptance();
      if (!accepted) {
        process.exit(1);
      }
    }

    const { executeScanAll } = await import("./commands/scan-all.js");
    await executeScanAll({
      registry: opts.registry,
      format: opts.format,
      active: opts.active,
      outputDir: opts.outputDir,
      profile: opts.profile,
      accept: opts.accept,
      batchSize: opts.batchSize ? parseInt(opts.batchSize, 10) : undefined,
      concurrency: opts.concurrency ? parseInt(opts.concurrency, 10) : undefined,
    });
  });

// ─── chamber command ────────────────────────────────────────────────────────
program
  .command("chamber <action>")
  .description("Create or operate a Docker detonation chamber for exploit verification")
  .option("--name <name>", "Chamber run name", "scanner-chamber")
  .option("--output-dir <dir>", "Directory for chamber artifacts", "data/detonation-chamber")
  .option("--run-dir <dir>", "Existing chamber run directory for down/logs")
  .option("--target-image <image>", "Optional target container image to attach")
  .option("--target-build <dir>", "Optional target build context to attach")
  .option("--target-dockerfile <file>", "Dockerfile for --target-build")
  .option("--target-command <command>", "Command for the optional target container")
  .option("--target-port <mapping...>", "Publish target port mapping, e.g. 127.0.0.1:3100:3100")
  .option("--target-read-write", "Disable read-only filesystem for the target container", false)
  .option("--no-docker", "Generate artifacts without running docker compose")
  .action(async (action, opts) => {
    if (!["init", "up", "down", "logs"].includes(action)) {
      console.error(chalk.red(`  Unknown chamber action "${action}". Available: init, up, down, logs`));
      process.exitCode = 1;
      return;
    }

    await executeChamber({
      action,
      name: opts.name,
      outputDir: opts.outputDir,
      runDir: opts.runDir,
      runDocker: opts.docker,
      targetImage: opts.targetImage,
      targetBuild: opts.targetBuild,
      targetDockerfile: opts.targetDockerfile,
      targetCommand: opts.targetCommand,
      targetPorts: opts.targetPort,
      targetReadWrite: opts.targetReadWrite,
    });
  });

// ─── chamber-smoke command ──────────────────────────────────────────────────
// One-shot chamber smoke: brings a fresh chamber up, runs a full-active scan
// against the target with chamber probes wired in, then tears the chamber
// down. Replaces the manual `chamber up + scan + chamber down` shell pipeline.
program
  .command("chamber-smoke")
  .description("Run a one-shot chamber smoke test: chamber up + active scan + verdict + chamber down")
  .requiredOption(
    "-s, --server <command-or-url>",
    "Target to scan (stdio command for MCP, URL for HTTP-shaped protocols)"
  )
  .option("-p, --protocol <type>", "Protocol adapter (mcp, openai-functions, langchain-tools, rest-api, graphql, grpc, a2a)", "mcp")
  .option("-t, --transport <type>", "Transport for MCP targets (stdio or streamable-http)", "stdio")
  .option("-f, --format <format>", "Stdout format (terminal, json, research-json)", "terminal")
  .option("-o, --output <file>", "Save the scan report to this path (default: <chamber-run-dir>/smoke-report.research.json)")
  .option("--name <name>", "Chamber run name", "smoke")
  .option("--output-dir <dir>", "Directory for chamber artifacts", "data/detonation-chamber")
  .option("-v, --verbose", "Verbose scanner output", false)
  .option("--keep-chamber", "Leave chamber containers running after the scan", false)
  .option("--target-image <image>", "Container image for the chamber-hosted target service (HTTP/gRPC only)")
  .option("--target-command <command>", "Command for the chamber-hosted target service")
  .option("--target-port <mapping>", "Publish target port mapping (e.g. 127.0.0.1:5002:5002) — required for HTTP/gRPC")
  .option("--target-read-write", "Disable read-only filesystem on the chamber target", false)
  .option("--vendor-report <dir>", "Write per-finding vendor disclosure artifacts to <dir>")
  .option(
    "--vendor-report-allow-unverified",
    "Emit vendor artifacts even when chamber reachability is not verified",
    false,
  )
  .option("--vendor-name <name>", "Vendor name baked into finding.yaml")
  .option("--vendor-repo <repo>", "Vendor repo baked into finding.yaml")
  .option("--vendor-commit <sha>", "Commit SHA baked into finding.yaml")
  .option("--vendor-channel <email>", "Vendor security disclosure channel")
  .option("--data-classification <class>", "Declared target data class: none|pii|phi|pci|secrets|all", "none")
  .option("--context <ctx>", "Target context: production or sandboxed (default: sandboxed)")
  .option("--probe-timeout <ms>", "Timeout per active probe in milliseconds", "5000")
  .option("--probe-delay <ms>", "Delay between active probes in milliseconds", "100")
  .option("--timeout <ms>", "Connection timeout in milliseconds", "30000")
  .option("--llm-output-token-limit <tokens>", "Max output tokens the deployed LLM can emit in one response", "8192")
  .option("-m, --modules <modules...>", "Run specific module IDs only (space-separated)")
  .option("--tui", "Enable interactive TUI dashboard with live module progress", false)
  .option(
    "--state-oracle",
    "Mint a chamber workdir and bind-mount it into the target so the state-oracle module can diff filesystem mutations",
    false,
  )
  .option("--accept", "Accept the legal notice (for non-interactive environments)", false)
  .action(async (opts) => {
    if (!isProtocolType(opts.protocol)) {
      console.error(
        chalk.red(`  Unknown protocol "${opts.protocol}". Available: mcp, openai-functions, langchain-tools, rest-api, graphql, grpc, a2a`)
      );
      process.exitCode = 1;
      return;
    }

    if (opts.accept || opts.ci) {
      forceAcceptance();
    } else {
      const accepted = await ensureAcceptance();
      if (!accepted) {
        process.exit(1);
      }
    }

    await executeChamberSmoke({
      server: opts.server,
      protocol: opts.protocol as ProtocolType,
      transport: opts.transport as "stdio" | "streamable-http",
      format: opts.format as
        | "terminal"
        | "json"
        | "research-json"
        | undefined,
      output: opts.output,
      name: opts.name,
      outputDir: opts.outputDir,
      verbose: opts.verbose,
      keepChamber: opts.keepChamber,
      targetImage: opts.targetImage,
      targetCommand: opts.targetCommand,
      targetPort: opts.targetPort,
      targetReadWrite: opts.targetReadWrite,
      vendorReport: opts.vendorReport,
      vendorReportAllowUnverified: opts.vendorReportAllowUnverified,
      vendorName: opts.vendorName,
      vendorRepo: opts.vendorRepo,
      vendorCommit: opts.vendorCommit,
      vendorChannel: opts.vendorChannel,
      dataClassification: opts.dataClassification as
        | "none" | "pii" | "phi" | "pci" | "secrets" | "all"
        | undefined,
      context: opts.context as "production" | "sandboxed" | undefined,
      modules: opts.modules,
      probeTimeout: opts.probeTimeout ? parseInt(opts.probeTimeout, 10) : undefined,
      probeDelay: opts.probeDelay ? parseInt(opts.probeDelay, 10) : undefined,
      timeout: opts.timeout ? parseInt(opts.timeout, 10) : undefined,
      llmOutputTokenLimit: opts.llmOutputTokenLimit ? parseInt(opts.llmOutputTokenLimit, 10) : undefined,
      tui: opts.tui,
      stateOracle: opts.stateOracle,
    });
  });

// ─── audit-target command ───────────────────────────────────────────────────
program
  .command("audit-target <repo>")
  .description("Create a reproducible target manifest for vendor/repo disclosure scans")
  .option("--commit <sha>", "Commit SHA to pin")
  .option("--name <name>", "Target name override")
  .option("--protocol <type>", "Protocol adapter (mcp, openai-functions, langchain-tools, rest-api, graphql, grpc, a2a)")
  .option("--build <command>", "Build command to run after checkout")
  .option("--run <command>", "Target run command to record or execute in the chamber")
  .option("--scan-target <target>", "Scanner target URL or command to record")
  .option("--output-dir <dir>", "Directory for target artifacts")
  .option("--chamber", "Create a detonation chamber for this target", false)
  .option("--chamber-output-dir <dir>", "Directory for chamber artifacts")
  .option("--target-image <image>", "Container image for chamber target service")
  .option("--target-port <mapping...>", "Publish chamber target port mapping, e.g. 127.0.0.1:3100:3100")
  .option("--target-read-write", "Disable read-only filesystem for the chamber target container", false)
  .option("--execute", "Clone/checkout/build the target instead of only planning", false)
  .action(async (repo, opts) => {
    if (opts.protocol && !isProtocolType(opts.protocol)) {
      console.error(
        chalk.red(`  Unknown protocol "${opts.protocol}". Available: mcp, openai-functions, langchain-tools, rest-api, graphql, grpc, a2a`)
      );
      process.exitCode = 1;
      return;
    }

    await executeAuditTarget({
      repo,
      commit: opts.commit,
      name: opts.name,
      outputDir: opts.outputDir,
      protocol: opts.protocol as ProtocolType | undefined,
      buildCommand: opts.build,
      runCommand: opts.run,
      scanTarget: opts.scanTarget,
      chamber: opts.chamber,
      chamberOutputDir: opts.chamberOutputDir,
      targetImage: opts.targetImage,
      targetPorts: opts.targetPort,
      targetReadWrite: opts.targetReadWrite,
      execute: opts.execute,
    });
  });

// ─── audit-repo command ─────────────────────────────────────────────────────
program
  .command("audit-repo <repo>")
  .description("Clone a repo, build a target image, run it through the detonation chamber, and save a full-active scan report")
  .option("--commit <sha>", "Commit SHA to pin")
  .option("--name <name>", "Target name override")
  .option("--output-dir <dir>", "Directory for audit artifacts")
  .option("--protocol <type>", "Protocol adapter (mcp, openai-functions, langchain-tools, rest-api, graphql, grpc, a2a)", "mcp")
  .option("--transport <type>", "Transport type for MCP targets (stdio or streamable-http)", "stdio")
  .option("--image <image>", "Use a prebuilt Docker image instead of building from the repo")
  .option("--dockerfile <path>", "Repo-relative Dockerfile path")
  .option("--build-context <path>", "Repo-relative Docker build context (default: checkout root)")
  .option("--target-command <command>", "Command/args appended after the Docker image for stdio scans")
  .option("--target-port <mapping>", "Publish target port mapping for HTTP/gRPC scans (e.g. 127.0.0.1:5002:5002)")
  .option("--scan-target <target>", "Explicit scanner target command or URL")
  .option("--no-build", "Skip Docker build; requires --image or --scan-target")
  .option("--no-chamber", "Run the scan without creating a detonation chamber")
  .option("--keep-chamber", "Leave chamber containers running after the scan", false)
  .option("--scan-mode <mode>", "Scan mode: passive-only, safe-active, or full-active", "full-active")
  .option("-f, --format <format>", "Output format for stdout (terminal, json, markdown, research-json, etc.)", "terminal")
  .option("--timeout <ms>", "Connection timeout in milliseconds", "30000")
  .option("--probe-timeout <ms>", "Timeout per active probe in milliseconds", "5000")
  .option("--probe-delay <ms>", "Delay between active probes in milliseconds", "100")
  .option("--llm-output-token-limit <tokens>", "Max output tokens the deployed LLM can emit in one response", "8192")
  .option("--data-classification <class>", "Declared target data class: none|pii|phi|pci|secrets|all", "none")
  .option("--slim", "Save slim research JSON report", false)
  .option("--fail-on-findings", "Preserve non-zero scan exit code when findings are present", false)
  .option("--dry-run", "Write the audit plan without cloning/building/scanning", false)
  .option("--verbose", "Verbose scanner output", false)
  .option("--accept", "Accept the legal notice (for non-interactive environments)", false)
  .option(
    "--vendor-report <dir>",
    "Write per-finding vendor disclosure artifacts (finding.yaml + repro.sh) to <dir>; default: <audit-output-dir>/vendor-report",
  )
  .option("--vendor-name <name>", "Vendor name baked into finding.yaml")
  .option("--vendor-channel <email>", "Vendor security disclosure channel (security@vendor.com)")
  .option("--tui", "Enable interactive TUI dashboard with live module progress", false)
  .action(async (repo, opts) => {
    if (opts.protocol && !isProtocolType(opts.protocol)) {
      console.error(
        chalk.red(`  Unknown protocol "${opts.protocol}". Available: mcp, openai-functions, langchain-tools, rest-api, graphql, grpc, a2a`)
      );
      process.exitCode = 1;
      return;
    }
    if (!["passive-only", "safe-active", "full-active"].includes(opts.scanMode)) {
      console.error(chalk.red(`  Unknown scan mode "${opts.scanMode}". Available: passive-only, safe-active, full-active`));
      process.exitCode = 1;
      return;
    }

    if (opts.accept || opts.dryRun) {
      forceAcceptance();
    } else {
      const accepted = await ensureAcceptance();
      if (!accepted) {
        process.exit(1);
      }
    }

    await executeAuditRepo({
      repo,
      commit: opts.commit,
      name: opts.name,
      outputDir: opts.outputDir,
      protocol: opts.protocol as ProtocolType,
      transport: opts.transport as "stdio" | "streamable-http",
      image: opts.image,
      dockerfile: opts.dockerfile,
      buildContext: opts.buildContext,
      targetCommand: opts.targetCommand,
      scanTarget: opts.scanTarget,
      build: opts.build,
      chamber: opts.chamber,
      keepChamber: opts.keepChamber,
      scanMode: opts.scanMode,
      format: opts.format,
      timeout: parseInt(opts.timeout, 10),
      probeTimeout: parseInt(opts.probeTimeout, 10),
      probeDelay: parseInt(opts.probeDelay, 10),
      llmOutputTokenLimit: parseInt(opts.llmOutputTokenLimit, 10),
      dataClassification: opts.dataClassification,
      slim: opts.slim,
      failOnFindings: opts.failOnFindings,
      dryRun: opts.dryRun,
      verbose: opts.verbose,
      vendorReport: opts.vendorReport,
      vendorName: opts.vendorName,
      vendorChannel: opts.vendorChannel,
      targetPort: opts.targetPort,
      tui: opts.tui,
    });
  });

// ─── audit-local command ─────────────────────────────────────────────────────
program
  .command("audit-local")
  .description("Discover and scan all AI agent servers from local IDE configs")
  .option(
    "--active",
    "Enable active scanning modules (makes tool calls to servers)",
    false
  )
  .option(
    "--compliance <frameworks...>",
    "Enable compliance mapping (nist, soc2, asvs, hipaa, pci-dss, iso27001, fedramp, gdpr, or all)"
  )
  .option(
    "-o, --output <dir>",
    "Save individual reports to directory"
  )
  .option(
    "--timeout <ms>",
    "Connection timeout per server in milliseconds",
    "30000"
  )
  .option(
    "--accept",
    "Accept the legal notice (for non-interactive environments)",
    false
  )
  .action(async (opts) => {
    // Handle acceptance
    if (opts.accept) {
      forceAcceptance();
    } else {
      const accepted = await ensureAcceptance();
      if (!accepted) {
        process.exit(1);
      }
    }

    await executeAuditLocal({
      active: opts.active,
      compliance: opts.compliance,
      outputDir: opts.output,
      timeout: parseInt(opts.timeout, 10),
    });
  });

// ─── scan-source command ────────────────────────────────────────────────────────
program
  .command("scan-source")
  .description("Static analysis of server source code (pre-deployment security)")
  .argument("<path>", "Directory or file to scan")
  .option(
    "-f, --format <format>",
    "Output format (terminal or json)",
    "terminal"
  )
  .option(
    "--min-severity <level>",
    "Only show findings at or above this level (CRITICAL, HIGH, MEDIUM, LOW)"
  )
  .option(
    "--runtime-tools <file>",
    "JSON tools/list or scan report to diff against source-declared tools"
  )
  .action(async (path, opts) => {
    await executeScanSource({
      path,
      format: opts.format as "terminal" | "json",
      minSeverity: opts.minSeverity,
      runtimeToolsPath: opts.runtimeTools,
    });
  });

// ─── badge command ──────────────────────────────────────────────────────────────
program
  .command("badge")
  .description("Generate an SVG score badge for READMEs and dashboards")
  .option("--score <number>", "Security score (0-100)")
  .option("-i, --input <file>", "Read score from a JSON report file")
  .option("-o, --output <file>", "Save SVG to file (default: stdout)")
  .option("--label <text>", "Badge label", "ToolSurf")
  .action((opts) => {
    executeBadge({
      score: opts.score !== undefined ? parseInt(opts.score, 10) : undefined,
      input: opts.input,
      output: opts.output,
      label: opts.label,
    });
  });

// ─── diff command ───────────────────────────────────────────────────────────────
program
  .command("diff <baseline> <current>")
  .description("Compare two scan reports and show new/fixed findings")
  .action((baseline, current) => {
    executeDiff(baseline, current);
  });

// ─── list-modules command ──────────────────────────────────────────────────────
program
  .command("list-modules")
  .description("List all available audit modules")
  .action(() => {
    printBanner("Available Audit Modules");

    const allModules = createAllModules();

    console.log();
    console.log(chalk.bold("  Scan Profiles:"));
    console.log(chalk.dim("    quick       ") + "Passive checks only, fast (~5s)");
    console.log(chalk.dim("    standard    ") + "Passive + active probes (~30s)");
    console.log(chalk.dim("    enterprise  ") + "Full suite with compliance, TUI, autofix, summary (~60s)");
    console.log();
    console.log(chalk.bold(`  Modules (${allModules.length} total):`));

    // Group by mode for display
    const passive = allModules.filter((m) => m.mode === "passive");
    const active = allModules.filter((m) => m.mode === "active");

    console.log();
    console.log(chalk.green.bold("  Passive modules:"));
    for (const m of passive) {
      const id = chalk.bold(m.id.padEnd(36));
      console.log(`    ${id} ${m.description}  ${chalk.green("[passive]")}`);
    }

    console.log();
    console.log(chalk.red.bold("  Active modules:"));
    for (const m of active) {
      const id = chalk.bold(m.id.padEnd(36));
      console.log(`    ${id} ${m.description}  ${chalk.red("[active]")}`);
    }

    console.log();
    console.log(chalk.dim("  Active modules require ") + chalk.bold("--active") + chalk.dim(" or ") + chalk.bold("--profile standard/enterprise") + chalk.dim(" to enable."));
    console.log();
  });

// ─── hook command ──────────────────────────────────────────────────────────────
program
  .command("hook <action>")
  .description("Manage git pre-commit hook (install or uninstall)")
  .action((action) => {
    executeHook(action);
  });

// ─── hardening-check command ─────────────────────────────────────────────────
program
  .command("hardening-check")
  .description("Verify instrument meets research-readiness criteria")
  .option("-v, --verbose", "Show details for passing checks too")
  .action(async (opts) => {
    const { runHardeningCheck } = await import("./commands/hardening-check.js");
    await runHardeningCheck({ verbose: opts.verbose });
  });

// ─── agent-juice-shop command ────────────────────────────────────────────────
program
  .command("agent-juice-shop")
  .description("Run the Agent Juice Shop multiprotocol benchmark corpus")
  .option(
    "-f, --format <format>",
    "Output format (terminal, json, or markdown)",
    "terminal"
  )
  .option("-o, --output <file>", "Save benchmark report to file")
  .option("--fail-on-miss", "Exit non-zero if any expected benchmark signal is missed", false)
  .action(async (opts) => {
    await executeAgentJuiceShop({
      format: opts.format as "terminal" | "json" | "markdown",
      output: opts.output,
      failOnMiss: opts.failOnMiss,
    });
  });

// ─── agent-juice-shop-compare command ───────────────────────────────────────
program
  .command("agent-juice-shop-compare")
  .description("Record pinned competitor transcripts against the Agent Juice Shop corpus")
  .option("--config <file>", "JSON config with competitor commands")
  .option("-o, --output-dir <dir>", "Directory for comparison transcripts")
  .option("--dry-run", "Write transcript plan without executing competitor commands", false)
  .option("--init [file]", "Print or write a comparison config template")
  .action(async (opts) => {
    await executeAgentJuiceShopCompare({
      config: opts.config,
      outputDir: opts.outputDir,
      dryRun: opts.dryRun,
      init: opts.init,
    });
  });

// ─── repro-check command ─────────────────────────────────────────────────────
program
  .command("repro-check [finding-yaml]")
  .description("Validate finding.yaml and run its reproduction script")
  .option("--init", "Print a finding.yaml template")
  .option("--json", "Output machine-readable JSON")
  .option("--dry-run", "Validate the manifest and script path without executing the script")
  .option("--timeout <ms>", "Reproduction script timeout in milliseconds", "120000")
  .action(async (manifestPath, opts) => {
    await executeReproCheck({
      manifestPath,
      init: opts.init,
      json: opts.json,
      dryRun: opts.dryRun,
      timeoutMs: parseInt(opts.timeout, 10),
    });
  });

// ─── init command ──────────────────────────────────────────────────────────────
program
  .command("init")
  .description("Create a .toolsurfrc.json config file in the current directory")
  .action(async () => {
    const { writeFileSync, existsSync } = await import("node:fs");
    const path = ".toolsurfrc.json";
    if (existsSync(path)) {
      console.log(chalk.yellow(`  ${path} already exists`));
      return;
    }

    const template = {
      profile: "standard",
      format: "terminal",
      active: false,
      compliance: [],
      modules: [],
      ignore: [],
      timeout: 30000,
      probeTimeout: 5000,
      probeDelay: 100,
    };

    writeFileSync(path, JSON.stringify(template, null, 2) + "\n", "utf-8");
    console.log(chalk.green(`  Created ${path}`));
  });

// ─── mock command ────────────────────────────────────────────────────────────
program
  .command("mock")
  .description("Start a standalone MCP shadow proxy for safe active scanning")
  .requiredOption(
    "--schema <path>",
    "Path to a JSON file containing server capabilities (tool schemas)"
  )
  .option("--port <number>", "Port to listen on", "3100")
  .option(
    "-f, --format <format>",
    "Output format for call log (json or terminal)",
    "terminal"
  )
  .action(async (opts) => {
    await executeMock({
      schema: opts.schema,
      port: parseInt(opts.port, 10),
      format: opts.format,
    });
  });

// ─── Default action: wizard when no command is given ─────────────────────────
program.action(async () => {
  // Only launch wizard in interactive terminals
  if (!process.stdin.isTTY) {
    program.help();
    return;
  }

  const { runWizard } = await import("./core/wizard.js");
  const result = await runWizard();

  if (!result.confirmed || !result.server) {
    return;
  }

  // Handle acceptance
  const accepted = await ensureAcceptance();
  if (!accepted) {
    process.exit(1);
  }

  // Resolve profile
  const profileDefaults = resolveProfile(result.profile);

  await executeScan({
    server: result.server,
    transport: "stdio",
    format: result.format,
    active: profileDefaults.active,
    verbose: profileDefaults.verbose,
    timeout: 30000,
    output: result.output,
    compliance: profileDefaults.compliance,
    tui: profileDefaults.tui,
    autofix: profileDefaults.autofix,
    executiveSummary: profileDefaults.executiveSummary,
    minSeverity: profileDefaults.minSeverity,
    scoringConfig: profileDefaults.severityWeights
      ? {
          severityWeights: profileDefaults.severityWeights,
          diminishingFactor: profileDefaults.diminishingFactor,
          maxModuleImpact: profileDefaults.maxModuleImpact,
        }
      : undefined,
  });
});

// ─── Parse and execute ─────────────────────────────────────────────────────────
program.parse();
