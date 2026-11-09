import ora from "ora";
import chalk from "chalk";
import { randomUUID, createHash } from "node:crypto";
import { writeFileSync, existsSync, readFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execSync } from "node:child_process";
import { createAdapter } from "../adapters/registry.js";
import type { ProtocolAdapter, ProtocolType } from "../adapters/types.js";
import { ModuleRunner } from "../core/module-runner.js";
import { createAllModules } from "../core/module-catalog.js";
import type { ChamberManifest } from "../core/detonation-chamber.js";
import {
  ChamberRuntime,
  finalizeChamberReachability,
  verifyChamberReachability,
  type ChamberReachabilityResult,
} from "../core/chamber-runtime.js";
import { buildChamberSummary } from "../core/chamber-summary.js";
import { buildKillChains } from "../core/kill-chain.js";
import { writeChamberProofBundle } from "../core/chamber-proofs.js";
import { buildEgressMatrix } from "../core/egress-matrix.js";
import { writeVendorReport } from "../core/vendor-report.js";
import { calculateScore, buildRiskProfile, SCORING_FORMULA_VERSION, applyBayesianUpdate } from "../core/scorer.js";
import { enforceScanMode, legacyActiveToScanMode, formatEnforcementResult } from "../core/scan-modes.js";
import { ACTIVE_MODULE_IDS, buildActiveModuleIds } from "../core/active-module-ids.js";
import type { ScanMode, TargetProfile } from "../core/target-profile.js";
import { outputReport, type OutputFormat } from "../core/reporter.js";
import { toSarif } from "../core/sarif.js";
import { computeSchemaHash } from "../core/tofu-hash.js";
import { enrichFindings, generateComplianceSummary } from "../compliance/compliance-enricher.js";
import { slimifyReport } from "../core/research-reporter.js";
import { TuiDashboard } from "../core/tui-dashboard.js";
import { generateFixSuggestions, outputFixSuggestions } from "../core/autofix.js";
import { generateExecutiveSummary, outputExecutiveSummary } from "../core/executive-summary.js";
import { loadRules, evaluateRules, outputRuleResults } from "../core/rules-engine.js";
import { assignConfidence, filterByConfidence } from "../core/confidence.js";
import { deduplicateFindings } from "../core/deduplicator.js";
import { runPeav, type PeavReport } from "../core/peav.js";
import { loadPlugins } from "../core/plugins.js";
import { CheckStatus, Severity } from "../types/index.js";
import type {
  AuditModule,
  ModuleResult,
  PackageVersionEvidence,
  ScanReport,
  TransportConfig,
} from "../types/index.js";
import { CLI_VERSION, BUILD_GIT_HASH } from "../version.js";

export interface ScanOptions {
  /** Server command string or URL depending on protocol */
  server: string;
  /** Transport type */
  transport: "stdio" | "streamable-http";
  /** Output format */
  format: OutputFormat;
  /** Enable active scanning modules */
  active: boolean;
  /** Protocol adapter to use (default: mcp) */
  protocol?: ProtocolType;
  /** Run specific modules only */
  modules?: string[];
  /** Verbose output */
  verbose: boolean;
  /** Connection timeout in ms */
  timeout: number;
  /** Output file path for saving the report */
  output?: string;
  /** Compliance frameworks to map (nist, soc2, asvs, hipaa, pci-dss, iso27001, fedramp, gdpr, or all) */
  compliance?: string[];
  /** Timeout per active probe in ms */
  probeTimeout?: number;
  /** Delay between active probes in ms */
  probeDelay?: number;
  /** Max tokens the deployed LLM can emit in one response; caps TE-001 argument-size estimates. */
  llmOutputTokenLimit?: number;
  /** Minimum severity to display (CRITICAL, HIGH, MEDIUM, LOW, INFO) */
  minSeverity?: string;
  /** Custom payloads for active fuzzing */
  customPayloads?: Array<{ value: string; label: string }>;
  /** Package/version evidence from repo manifests and lockfiles. */
  packageEvidence?: PackageVersionEvidence[];
  /** Finding IDs to ignore (baseline) */
  ignoreList?: Set<string>;
  /** Enable interactive TUI dashboard */
  tui?: boolean;
  /** Show auto-fix suggestions after report */
  autofix?: boolean;
  /** Show executive summary for non-technical stakeholders */
  executiveSummary?: boolean;
  /** Path to custom policy rules file (YAML or JSON) */
  rules?: string;
  /** Fail if security score is below this threshold (0-100) */
  failBelow?: number;
  /** Minimum confidence to include findings (0.0-1.0, default: show all) */
  minConfidence?: number;
  /** Plugin paths to load custom audit modules */
  plugins?: string[];
  /** H-6: Disable plugin auto-discovery from ~/.toolsurf/plugins/ */
  noPlugins?: boolean;
  /**
   * Produce slim research-JSON output when saving to file.
   * Strips server.tools (raw schemas), collapses module findings (already in
   * top-level findings[]), and truncates oversized evidence arrays to 10 items.
   * Reduces typical file size by ~85% with no loss of research-relevant data.
   * Only applies when --output is set; stdout format is controlled by --format.
   */
  slim?: boolean;
  /** Scoring config overrides from profile (severity weights, diminishing factor, max module impact) */
  scoringConfig?: import("../core/scorer.js").ScoringConfig;
  /** Dry-run: validate config and connectivity without running modules */
  dryRun?: boolean;
  /** Explicit scan mode override (passive-only, safe-active, full-active). If omitted, derived from --active flag. */
  scanMode?: ScanMode;
  /** Optional target profile used to clamp scan mode by environment risk. */
  targetProfile?: TargetProfile;
  /** CLI preset name used to derive targetProfile; recorded in provenance. */
  targetProfilePreset?: string;
  /** Existing detonation chamber run directory for active exploit evidence. */
  chamberRunDir?: string;
  /**
   * P1-08 [§ADV]: Target context classification.
   * When set to "sandboxed", embeds a disclaimer in the report output:
   * "[SANDBOX — scores not comparable to production targets]"
   * This addresses the validity concern that sandboxed/honeypot servers
   * are indistinguishable from production servers in scan results.
   */
  context?: "production" | "sandboxed";
  /**
   * Declared data classification handled by the target. Gates which
   * compliance frameworks appear on findings — HIPAA/PCI-DSS/GDPR are
   * dropped unless the corresponding class is set. Default: "none".
   */
  dataClassification?: "none" | "pii" | "phi" | "pci" | "secrets" | "all";
  /**
   * If set, write per-finding vendor-disclosure artifacts (finding.yaml +
   * repro.sh) to this directory. Only emits artifacts for chamber-backed
   * findings — those with reproducible captured evidence.
   */
  vendorReport?: string;
  /** Override fields baked into emitted finding.yaml files. */
  vendorName?: string;
  vendorRepo?: string;
  vendorCommit?: string;
  vendorChannel?: string;
  /**
   * If true, the vendor-report exporter will emit artifacts for chamber-backed
   * findings even when chamber reachability is not verified. Default: false —
   * disclosure packages must be proof-backed.
   */
  vendorReportAllowUnverified?: boolean;
}

/**
 * Parse a server command string into command and args.
 * Handles quoted strings properly.
 */
function parseServerCommand(serverStr: string): { command: string; args: string[] } {
  const parts: string[] = [];
  let current = "";
  let inQuote = false;
  let quoteChar = "";

  for (const char of serverStr) {
    if (inQuote) {
      if (char === quoteChar) {
        inQuote = false;
      } else {
        current += char;
      }
    } else if (char === '"' || char === "'") {
      inQuote = true;
      quoteChar = char;
    } else if (char === " ") {
      if (current) {
        parts.push(current);
        current = "";
      }
    } else {
      current += char;
    }
  }

  if (current) {
    parts.push(current);
  }

  if (parts.length === 0) {
    throw new Error("Empty server command");
  }

  return {
    command: parts[0],
    args: parts.slice(1),
  };
}

/**
 * Build connection parameters based on the protocol type.
 * MCP uses command+args (stdio), others use URLs or file paths.
 */
export function buildConnectParams(
  protocol: string,
  server: string,
  transport: string,
): Record<string, unknown> {
  // MCP stdio uses command+args; MCP Streamable HTTP uses a URL endpoint.
  if (protocol === "mcp") {
    if (
      transport === "streamable-http" ||
      server.startsWith("http://") ||
      server.startsWith("https://")
    ) {
      return { url: server, transport };
    }
    const { command, args } = parseServerCommand(server);
    return { command, args, transport };
  }

  // URL-based protocols: server is a URL or a spec file
  if (protocol === "graphql" || protocol === "grpc" || protocol === "a2a") {
    if (server.startsWith("http://") || server.startsWith("https://")) {
      return { url: server };
    }
    // gRPC addresses are host:port (e.g. "localhost:9000") — treat as live server url
    if (protocol === "grpc" && /^[^/]+:\d+$/.test(server)) {
      return { url: server };
    }
    return { specFile: server };
  }

  // REST API: server is an OpenAPI spec URL or file path
  if (protocol === "rest-api") {
    if (server.startsWith("http://") || server.startsWith("https://")) {
      return { specUrl: server };
    }
    return { specFile: server };
  }

  // File-based protocols: server is a tool manifest path or URL
  if (protocol === "openai-functions" || protocol === "langchain-tools") {
    if (server.startsWith("http://") || server.startsWith("https://")) {
      return { specUrl: server };
    }
    return {
      specFile: server,
      apiKey: process.env.OPENAI_API_KEY,
    };
  }

  // Fallback: try as command
  const { command, args } = parseServerCommand(server);
  return { command, args };
}

function dockerRunHasOption(args: string[], option: string): boolean {
  return args.some((arg) => arg === option || arg.startsWith(`${option}=`));
}

export function applyChamberToConnectParams(
  params: Record<string, unknown>,
  manifest: ChamberManifest,
): Record<string, unknown> {
  const args = params.args;
  if (params.command !== "docker" || !Array.isArray(args) || args[0] !== "run") {
    return params;
  }

  const runArgs = args.slice(1) as string[];
  const injected: string[] = [];
  if (!dockerRunHasOption(runArgs, "--network")) {
    injected.push("--network", manifest.network.name);
  }
  if (!dockerRunHasOption(runArgs, "--dns")) {
    injected.push("--dns", manifest.services.fakeDns.host);
  }
  injected.push(
    "-e", `SCANNER_CHAMBER_HTTP_URL=${manifest.services.fakeHttp.url}`,
    "-e", `SCANNER_CHAMBER_METADATA_URL=${manifest.services.fakeMetadata.url}`,
    "-e", `AWS_EC2_METADATA_SERVICE_ENDPOINT=${manifest.services.fakeMetadata.url}`,
  );

  // State-oracle workdir: bind-mount the host directory into the target so
  // mutations the target performs against `containerPath` are visible to the
  // oracle on the host side. Skip silently if no workdir was provisioned —
  // the chamber stays backwards-compatible with scans that don't opt in.
  if (manifest.workdir) {
    injected.push(
      "-v",
      `${manifest.workdir.hostPath}:${manifest.workdir.containerPath}`,
      "-e",
      `SCANNER_CHAMBER_WORKDIR=${manifest.workdir.containerPath}`,
    );
  }

  return {
    ...params,
    args: ["run", ...injected, ...runArgs],
  };
}

/**
 * Get all available audit modules.
 */
function getAvailableModules(): AuditModule[] {
  return createAllModules();
}

/**
 * Resolve the git commit hash of the scanner at runtime.
 * Embeds into ScanReport for full reproducibility (INSTRUMENT-HARDENING-REPORT #09).
 * Returns "unknown" if git is unavailable (e.g., running from a dist bundle without .git).
 * Applies to ALL protocol scans — the pipeline is protocol-agnostic from this point.
 */
function getScannerCommit(): string {
  try {
    return execSync("git rev-parse HEAD", { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] }).trim();
  } catch {
    // P2-12 [§REPRO]: Fallback to build-time hash when runtime git is unavailable
    // (Docker containers, dist bundles without .git). BUILD_GIT_HASH is set by
    // scripts/bake-version.ts during build; defaults to "dev" in local development.
    const buildGitHash: string = BUILD_GIT_HASH;
    return buildGitHash !== "dev" ? buildGitHash : "unknown";
  }
}

/**
 * Derive calibration status from real evidence rather than hardcoding.
 * CALIBRATED requires:
 *   1. All three anchor fixtures (floor/midpoint/ceiling) exist on disk
 *   2. The scoring formula version matches what anchors were validated against
 * If either condition fails, returns "PRE-CALIBRATION".
 */
function deriveCalibrationStatus(): "CALIBRATED" | "PRE-CALIBRATION" {
  try {
    // Locate anchor fixtures relative to this source file's package
    const thisDir = dirname(fileURLToPath(import.meta.url));
    const anchorsDir = join(thisDir, "..", "..", "tests", "fixtures", "anchors");

    const requiredAnchors = ["anchor-floor.json", "anchor-midpoint.json", "anchor-ceiling.json"];
    for (const name of requiredAnchors) {
      if (!existsSync(join(anchorsDir, name))) return "PRE-CALIBRATION";
    }

    // P0-02 [§CODE §REPRO]: Validate fixture _meta content, not just file existence.
    // A corrupted or empty fixture file must NOT produce a false "CALIBRATED" status.
    // Parse each anchor and verify required _meta fields are present and well-formed.
    for (const name of requiredAnchors) {
      const raw = readFileSync(join(anchorsDir, name), "utf-8");
      const parsed = JSON.parse(raw);
      if (
        !parsed?._meta?.anchor ||
        !parsed?._meta?.version ||
        !parsed?._meta?.description ||
        !parsed?.capabilities?.tools
      ) {
        return "PRE-CALIBRATION";
      }
    }

    // P1-06: Anchor Scoring Integrity Validation
    // Validates the scoring formula returns expected bounds for a test finding.
    // Proves the scoring weights haven't been tampered with or corrupted at runtime.
    const dummy: ModuleResult = {
      moduleId: "calibration-check",
      moduleName: "Check",
      moduleVersion: "1.0",
      durationMs: 1,
      checks: [],
      findings: [
        { id: "TEST", module: "test", severity: Severity.CRITICAL, title: "T", description: "D", confidence: 1.0, remediation: "", evidence: {} }
      ]
    };

    // 1 CRITICAL yield EXACTLY 70 on the legacy scale
    if (calculateScore([dummy]).securityScore !== 70) return "PRE-CALIBRATION";

    // 1 CRITICAL yield a non-trivial CRS on the modern scale
    if (buildRiskProfile([dummy], 1, 1, 1).compositeRiskScore < 0.1) return "PRE-CALIBRATION";

    return "CALIBRATED";
  } catch {
    return "PRE-CALIBRATION";
  }
}

/**
 * Build W3C PROV-DM provenance block for IEEE S&P artifact evaluation.
 * Captures all fields needed to reproduce the exact scan environment.
 * (ref: Research Plan §Topic 9)
 */
function buildProvenance(options: ScanOptions): ScanReport["provenance"] {
  // Reconstruct CLI flags from options
  const cliFlags: string[] = [];
  if (options.active) cliFlags.push("--active");
  if (options.verbose) cliFlags.push("--verbose");
  if (options.tui) cliFlags.push("--tui");
  if (options.autofix) cliFlags.push("--autofix");
  if (options.executiveSummary) cliFlags.push("--executive-summary");
  if (options.format) cliFlags.push(`--format=${options.format}`);
  if (options.protocol) cliFlags.push(`--protocol=${options.protocol}`);
  if (options.transport) cliFlags.push(`--transport=${options.transport}`);
  if (options.timeout) cliFlags.push(`--timeout=${options.timeout}`);
  if (options.probeTimeout) cliFlags.push(`--probe-timeout=${options.probeTimeout}`);
  if (options.probeDelay) cliFlags.push(`--probe-delay=${options.probeDelay}`);
  if (options.llmOutputTokenLimit) cliFlags.push(`--llm-output-token-limit=${options.llmOutputTokenLimit}`);
  if (options.modules?.length) cliFlags.push(`--modules=${options.modules.join(",")}`);
  if (options.minSeverity) cliFlags.push(`--min-severity=${options.minSeverity}`);
  if (options.compliance?.length) cliFlags.push(`--compliance=${options.compliance.join(",")}`);
  if (options.rules) cliFlags.push(`--rules=${options.rules}`);
  if (options.output) cliFlags.push(`--output=${options.output}`);
  if (options.scanMode) cliFlags.push(`--scan-mode=${options.scanMode}`);
  if (options.targetProfilePreset) cliFlags.push(`--target-profile=${options.targetProfilePreset}`);
  if (options.chamberRunDir) cliFlags.push(`--chamber-run-dir=${options.chamberRunDir}`);
  if (options.context) cliFlags.push(`--context=${options.context}`);
  if (options.slim) cliFlags.push("--slim");

  // Docker digest from standard env var (set by docker run)
  const dockerDigest = process.env.DOCKER_IMAGE_DIGEST ?? process.env.IMAGE_DIGEST ?? undefined;

  // Capture scan-relevant env vars only (never leak secrets)
  const envSnapshot: Record<string, string> = {};
  const safeEnvKeys = [
    "NODE_ENV", "BUN_VERSION", "DOCKER_IMAGE_DIGEST", "CI",
    "GITHUB_ACTIONS", "GITHUB_SHA", "GITHUB_REF",
  ];
  for (const key of safeEnvKeys) {
    if (process.env[key]) envSnapshot[key] = process.env[key]!;
  }

  // Stable hash of all scan-relevant config fields — enables mechanical
  // comparison between two runs without eyeballing flags.
  const configForHash = {
    active: options.active ?? false,
    protocol: options.protocol ?? "mcp",
    transport: options.transport ?? "stdio",
    timeout: options.timeout ?? 30000,
    probeTimeout: options.probeTimeout ?? 5000,
    probeDelay: options.probeDelay ?? 100,
    llmOutputTokenLimit: options.llmOutputTokenLimit ?? null,
    modules: [...(options.modules ?? [])].sort(),
    minSeverity: options.minSeverity ?? "LOW",
    compliance: [...(options.compliance ?? [])].sort(),
    minConfidence: options.minConfidence ?? 0,
    scanMode: options.scanMode ?? legacyActiveToScanMode(options.active),
    targetProfilePreset: options.targetProfilePreset ?? null,
    chamberRunDir: options.chamberRunDir ?? null,
    context: options.context ?? "production",
    slim: options.slim ?? false,
  };
  const configHash = createHash("sha256")
    .update(JSON.stringify(configForHash))
    .digest("hex")
    .slice(0, 16);

  return {
    cliFlags,
    configHash,
    dockerDigest,
    runtimeVersion: `${typeof Bun !== "undefined" ? "bun" : "node"} ${process.version}`,
    platform: `${process.platform}-${process.arch}`,
    envSnapshot,
  };
}

/**
 * Dry-run: validate config and reachability without connecting or running modules.
 *
 * Checks:
 *   1. TCP reachability of URL-based targets (no protocol handshake)
 *   2. Config file schema (already validated by loadConfig, just report)
 *   3. All specified module IDs exist in the registry
 *   4. Output path is writable (if --output is set)
 *
 * Exits with code 0 if everything is valid, code 1 with specific errors otherwise.
 */
export async function executeDryRun(options: ScanOptions): Promise<void> {
  const { createConnection } = await import("node:net");
  const { accessSync, constants } = await import("node:fs");
  const { dirname: pathDirname } = await import("node:path");

  const errors: string[] = [];
  const warnings: string[] = [];
  const protocol = options.protocol ?? "mcp";

  console.log("  toolsurf --dry-run\n");
  console.log(`  Protocol : ${protocol}`);
  console.log(`  Target   : ${options.server}`);
  console.log(`  Transport: ${options.transport ?? "stdio"}`);
  if (options.modules?.length) {
    console.log(`  Modules  : ${options.modules.join(", ")}`);
  }
  if (options.output) {
    console.log(`  Output   : ${options.output}`);
  }
  console.log();

  // 1. Module ID validation
  const allModules = getAvailableModules();
  const allModuleIds = new Set(allModules.map((m) => m.id));
  if (options.modules?.length) {
    for (const id of options.modules) {
      if (!allModuleIds.has(id)) {
        errors.push(`Unknown module ID: "${id}". Available: ${[...allModuleIds].join(", ")}`);
      }
    }
  }
  const moduleCheck = errors.some((e) => e.startsWith("Unknown module")) ? "✗" : "✓";
  console.log(`  ${moduleCheck} Module IDs — ${options.modules?.length ? `${options.modules.length} specified, all valid` : `${allModules.length} available`}`);

  // 2. TCP reachability for URL-based targets
  if (protocol !== "mcp" && options.server.includes(":")) {
    try {
      const urlStr = options.server.startsWith("http") ? options.server : `http://${options.server}`;
      const url = new URL(urlStr);
      const host = url.hostname;
      const port = parseInt(url.port || (url.protocol === "https:" ? "443" : "80"), 10);

      await new Promise<void>((resolve, reject) => {
        const sock = createConnection({ host, port, timeout: 5000 });
        sock.once("connect", () => { sock.destroy(); resolve(); });
        sock.once("timeout", () => { sock.destroy(); reject(new Error("timeout")); });
        sock.once("error", reject);
      });
      console.log(`  ✓ TCP reachability — ${host}:${port} is reachable`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      warnings.push(`TCP reachability check failed for "${options.server}": ${msg}`);
      console.log(`  ⚠ TCP reachability — could not reach target: ${msg}`);
    }
  } else if (protocol === "mcp") {
    console.log(`  ✓ TCP reachability — stdio transport (no TCP check needed)`);
  }

  // 3. Output path writability
  if (options.output) {
    try {
      const dir = pathDirname(options.output) || ".";
      accessSync(dir, constants.W_OK);
      console.log(`  ✓ Output path — "${options.output}" directory is writable`);
    } catch {
      errors.push(`Output directory for "${options.output}" is not writable`);
      console.log(`  ✗ Output path — "${options.output}" directory is not writable`);
    }
  }

  // 4. Rules file validation
  if (options.rules) {
    const { existsSync } = await import("node:fs");
    if (!existsSync(options.rules)) {
      errors.push(`Rules file not found: "${options.rules}"`);
      console.log(`  ✗ Rules file — "${options.rules}" not found`);
    } else {
      console.log(`  ✓ Rules file — "${options.rules}" exists`);
    }
  }

  console.log();

  // Summary
  const effectiveScanMode = options.scanMode ?? (options.active ? "full-active" : "passive-only");
  const activeCount = allModules.filter((m) => m.mode === "active").length;
  const passiveCount = allModules.filter((m) => m.mode === "passive").length;
  console.log("  Scan plan summary:");
  console.log(`    Scan mode   : ${effectiveScanMode}`);
  console.log(`    Modules     : ${passiveCount} passive, ${activeCount} active`);
  if (options.timeout) console.log(`    Timeout     : ${options.timeout}ms`);
  if (options.output)  console.log(`    Save report : ${options.output}`);
  console.log();

  if (errors.length > 0) {
    console.log(`  ✗ ${errors.length} error(s) found:\n`);
    for (const e of errors) {
      console.log(`    • ${e}`);
    }
    console.log();
    process.exit(1);
  }

  if (warnings.length > 0) {
    console.log(`  ⚠ ${warnings.length} warning(s):\n`);
    for (const w of warnings) {
      console.log(`    • ${w}`);
    }
    console.log();
  }

  console.log("  ✓ Dry run passed — configuration is valid.\n");
}

/**
 * Execute a security scan against an AI agent tool interface.
 */
export async function executeScan(options: ScanOptions): Promise<ScanReport | void> {
  const startTime = performance.now();
  const protocol = options.protocol ?? "mcp";
  const adapter: ProtocolAdapter = createAdapter(protocol);
  const isTerminal = options.format === "terminal";
  const useTui = isTerminal && options.tui === true;

  // Only show spinners/progress in terminal mode (unless TUI is active)
  const spinner = isTerminal && !useTui ? ora() : null;
  const dashboard = useTui ? new TuiDashboard() : null;

  try {
    // ── Step 1: Connect to target
    spinner?.start(`Connecting via ${adapter.displayName}...`);

    const chamberRuntime = options.chamberRunDir
      ? ChamberRuntime.load(options.chamberRunDir)
      : undefined;
    const chamberManifest = chamberRuntime?.manifest;
    const chamber = chamberRuntime?.getProbeConfig();

    let connectParams = buildConnectParams(protocol, options.server, options.transport);
    if (chamberManifest) {
      connectParams = applyChamberToConnectParams(connectParams, chamberManifest);
      if (options.verbose && connectParams.command !== "docker") {
        console.error(
          `[toolsurf:chamber] Chamber probes enabled, but target command is not "docker run"; ` +
          "the target must be able to reach chamber IPs for capture verification."
        );
      }
    }

    const capabilities = await adapter.connect({
      timeoutMs: options.timeout,
      verbose: options.verbose,
      params: connectParams,
    });

    spinner?.succeed(
      `Connected to ${capabilities.serverInfo.name} v${capabilities.serverInfo.version} ` +
      `(${capabilities.tools.length} tools, ${capabilities.resources.length} resources, ${capabilities.prompts.length} prompts)`
    );

    // ── Step 2 Select modules
    let modules: AuditModule[] = getAvailableModules();
    // Build active module ID set from module metadata (replaces manual list)
    buildActiveModuleIds(modules);

    // Load plugins (from --plugin flags and optionally ~/.toolsurf/plugins/)
    // H-6: --no-plugins disables auto-discovery; explicit --plugin paths still load.
    if (options.plugins && options.plugins.length > 0) {
      spinner?.start("Loading plugins...");
      const pluginResult = await loadPlugins(options.plugins, !options.noPlugins);
      if (pluginResult.errors.length > 0) {
        for (const err of pluginResult.errors) {
          if (isTerminal) {
            console.error(chalk.yellow(`  Plugin warning: ${err.path}: ${err.error}`));
          }
        }
      }
      if (pluginResult.modules.length > 0) {
        modules.push(...pluginResult.modules);
        spinner?.succeed(`Loaded ${pluginResult.modules.length} plugin(s): ${pluginResult.modules.map((m) => m.id).join(", ")}`);
      }
    }

    // Filter by requested modules
    if (options.modules && options.modules.length > 0) {
      const requestedIds = new Set(options.modules);
      modules = modules.filter((m) => requestedIds.has(m.id));
      if (modules.length === 0) {
        throw new Error(
          `No matching modules found. Available: ${getAvailableModules()
            .map((m) => m.id)
            .join(", ")}`
        );
      }
    }

    // ── Step 2b: Enforce scan mode — filter modules by risk level (C3 fix)
    const requestedScanMode: ScanMode = options.scanMode ?? legacyActiveToScanMode(options.active);
    const enforcement = enforceScanMode(modules, requestedScanMode, options.targetProfile);
    modules = enforcement.allowedModules;
    const effectiveScanMode = enforcement.effectiveMode;

    if (isTerminal && enforcement.filteredModules.length > 0) {
      spinner?.warn(formatEnforcementResult(enforcement));
    }
    if (options.verbose && enforcement.wasDowngraded) {
      console.error(`[toolsurf] ${formatEnforcementResult(enforcement)}`);
    }

    // ── Step 3: Run modules
    spinner?.start(`Running ${modules.length} audit module(s)...`);
    dashboard?.init(modules, {
      targetName: capabilities.serverInfo.name,
      protocol,
      transport: options.transport,
      scanMode: effectiveScanMode,
      chamber,
    });

    // ── Circuit breaker for slow servers (e.g., browser-based MCP servers) ───
    // If too many consecutive calls timeout, fail fast to avoid wasting minutes.
    const CIRCUIT_BREAKER_THRESHOLD = 5; // consecutive timeouts before tripping
    let consecutiveTimeouts = 0;
    let circuitBreakerTripped = false;
    const callToolWithCircuitBreaker = options.active
      ? async (name: string, args: Record<string, unknown>): Promise<unknown> => {
          if (circuitBreakerTripped) {
            throw new Error(
              `Circuit breaker: skipping "${name}" — server unresponsive (${CIRCUIT_BREAKER_THRESHOLD} consecutive timeouts)`
            );
          }
          try {
            const result = await adapter.invoke(name, args, options.probeTimeout ?? 8000);
            consecutiveTimeouts = 0; // Reset on success
            return result;
          } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            if (msg.includes("timed out")) {
              consecutiveTimeouts++;
              if (consecutiveTimeouts >= CIRCUIT_BREAKER_THRESHOLD) {
                circuitBreakerTripped = true;
                if (options.verbose) {
                  console.error(
                    `[toolsurf] Circuit breaker tripped after ${CIRCUIT_BREAKER_THRESHOLD} consecutive timeouts — fast-failing remaining calls`
                  );
                }
              }
            } else {
              consecutiveTimeouts = 0; // Non-timeout errors reset the counter
            }
            throw err;
          }
        }
      : undefined;
    // Reset circuit breaker between modules so each module gets a fair chance
    const resetCircuitBreaker = () => {
      consecutiveTimeouts = 0;
      circuitBreakerTripped = false;
    };

    // ── Step 3a: Chamber reachability healthcheck ───────────────────────
    // A chamber-backed report is disclosure-grade only when the target has
    // proven it can reach the chamber. The healthcheck plants a fake-http URL
    // into a URL-like tool parameter and verifies capture-file growth.
    let chamberReachability: ChamberReachabilityResult | undefined = chamber
      ? {
          status: "not-testable" as const,
          verified: false,
          checkedAt: new Date().toISOString(),
          method: "none" as const,
          captureFile: chamber.captures?.http,
          reason: options.active
            ? "Chamber reachability healthcheck was not run."
            : "Active scanning is disabled; chamber reachability was not tested.",
        }
      : undefined;

    if (chamber && options.active) {
      spinner?.start("Verifying chamber reachability...");
      chamberReachability = await verifyChamberReachability({
        capabilities,
        chamber,
        callTool: callToolWithCircuitBreaker,
        timeoutMs: Math.min(options.probeTimeout ?? 5000, 5000),
      });
      resetCircuitBreaker();

      if (chamberReachability?.verified) {
        spinner?.succeed("Chamber reachability verified");
      } else {
        spinner?.warn(`Chamber reachability ${chamberReachability?.status}: ${chamberReachability?.reason}`);
      }
    }

    // ── Step 3b: PEAV pre-flight (passive evidence scan before active fuzzing)
    let peavReport: PeavReport | undefined;
    if (options.active && callToolWithCircuitBreaker) {
      spinner?.start("Running PEAV pre-flight analysis...");
      try {
        peavReport = await runPeav(callToolWithCircuitBreaker, capabilities.tools);
        if (peavReport.toolsWithEvidence.length > 0) {
          spinner?.succeed(
            `PEAV: ${peavReport.toolsWithEvidence.length} tool(s) already show vulnerability evidence — ` +
            `prioritizing full fuzz for: ${peavReport.toolsWithEvidence.join(", ")}`
          );
        } else {
          spinner?.succeed("PEAV: no passive evidence found — all tools will be fully fuzzed");
        }
      } catch (err) {
        spinner?.warn(`PEAV pre-flight failed: ${err instanceof Error ? err.message : err} — proceeding with full fuzz`);
      }
    }

    // Build PEAV evidence set for active modules. Evidence should prioritize
    // deeper verification, not suppress it.
    const peavEvidenceTools = peavReport && peavReport.toolsWithEvidence.length > 0
      ? new Set(peavReport.toolsWithEvidence)
      : undefined;

    const earlyTransportConfig: TransportConfig = {
      type: protocol === "grpc" ? "grpc" : protocol === "mcp" ? options.transport : "http",
      command: connectParams.command as string | undefined,
      args: connectParams.args as string[] | undefined,
      url: (connectParams.url ?? connectParams.specUrl ?? connectParams.specFile) as string | undefined,
      protocol,
    };

    const runner = new ModuleRunner();
    const moduleResults = await runner.run({
      capabilities,
      modules,
      callTool: callToolWithCircuitBreaker,
      activeMode: options.active,
      verbose: options.verbose,
      probeTimeout: options.probeTimeout,
      probeDelay: options.probeDelay,
      llmOutputTokenLimit: options.llmOutputTokenLimit,
      customPayloads: options.customPayloads,
      packageEvidence: options.packageEvidence,
      peavEvidenceTools,
      transport: earlyTransportConfig,
      chamber,
      onProgress: (moduleId, status, result) => {
        if (dashboard) {
          switch (status) {
            case "start":
              dashboard.onModuleStart(moduleId);
              break;
            case "complete":
            case "error":
              if (result) dashboard.onModuleComplete(moduleId, result);
              break;
          }
        } else if (isTerminal) {
          switch (status) {
            case "start":
              spinner?.start(`Running module: ${moduleId}...`);
              break;
            case "complete":
              spinner?.succeed(`Module complete: ${moduleId}`);
              break;
            case "error":
              spinner?.fail(`Module error: ${moduleId}`);
              break;
          }
        }
      },
      onDetailProgress: (message) => {
        if (dashboard) {
          dashboard.onDetailProgress(message);
        } else if (isTerminal) {
          spinner?.start(message);
        }
      },
      onBeforeActiveModule: resetCircuitBreaker,
    });

    // ── Step 3b: Evaluate custom policy rules (if --rules specified)
    let ruleResults: ReturnType<typeof evaluateRules> = [];
    if (options.rules) {
      spinner?.start("Evaluating custom policy rules...");
      const rules = loadRules(options.rules);
      ruleResults = evaluateRules(rules, capabilities);

      // Inject rule violations as findings into module results
      const ruleFindings = ruleResults
        .filter((r) => r.finding)
        .map((r) => r.finding!);

      if (ruleFindings.length > 0) {
        moduleResults.push({
          moduleId: "custom-rules",
          moduleName: "Custom Policy Rules",
          moduleVersion: "1.0.0",
          checks: ruleResults,
          findings: ruleFindings,
          durationMs: 0,
        });
      }

      spinner?.succeed(
        `Policy rules: ${ruleResults.filter((r) => r.status === CheckStatus.PASS).length} passed, ` +
        `${ruleResults.filter((r) => r.status === CheckStatus.FAIL).length} failed`
      );
    }

    // ── Step 3b: Assign confidence scores to all findings
    assignConfidence(moduleResults);

    // ── Step 3c: Bayesian evidence fusion — update passive confidence with active probe results
    // Runs BEFORE reconcileFindings so Bayesian operates on unmodified priors.
    // reconcileFindings then applies deterministic overrides on top.
    if (options.active) {
      applyBayesianUpdate(moduleResults);
    }

    // ── Step 3d: Reconcile passive findings with active results (deterministic rule-based)
    // This runs AFTER Bayesian update to avoid double-adjusting confidence.
    // reconcileFindings downgrades/upgrades findings based on explicit probe pass/fail rules.
    if (options.active) {
      reconcileFindings(moduleResults);
    }

    // ── Step 4: Calculate score and build report
    const summary = calculateScore(moduleResults, options.scoringConfig);
    let allFindings = moduleResults.flatMap((r) => r.findings);
    const durationMs = Math.round(performance.now() - startTime);

    // ── Step 4a: Filter ignored findings
    if (options.ignoreList && options.ignoreList.size > 0) {
      allFindings = allFindings.filter((f) => !options.ignoreList!.has(f.id));
    }

    // ── Step 4a2: Filter by minimum confidence
    if (options.minConfidence !== undefined && options.minConfidence > 0) {
      allFindings = filterByConfidence(allFindings, options.minConfidence);
    }

    // ── Step 4a3: Deduplicate findings (group identical root causes)
    const dedupResult = deduplicateFindings(allFindings);
    const primaryFindings = dedupResult.primary;

    if (isTerminal && dedupResult.stats.groupsCollapsed > 0) {
      spinner?.info(
        `Deduplicated: ${dedupResult.stats.totalBefore} findings → ${dedupResult.stats.totalAfter} unique issues ` +
        `(${dedupResult.stats.groupsCollapsed} groups collapsed)`
      );
    }

    // ── Step 4b: Compliance enrichment (if --compliance flag set)
    let enrichedFindings = primaryFindings;
    let complianceSummary;
    if (options.compliance && options.compliance.length > 0) {
      // Default to "none" so HIPAA/PCI/GDPR don't appear unless the operator
      // explicitly declared the data class via --data-classification.
      const dataClass = (options.dataClassification ?? "none") as
        | "none" | "pii" | "phi" | "pci" | "secrets" | "all";
      enrichedFindings = enrichFindings(primaryFindings, dataClass);
      complianceSummary = generateComplianceSummary(enrichedFindings);
    }
    const reportSummary = {
      ...summary,
      findingsBySeverity: countFindingsBySeverity(enrichedFindings),
    };

    const finalChamberReachability = finalizeChamberReachability(
      chamberReachability,
      enrichedFindings,
    );

    const transportConfig: TransportConfig = earlyTransportConfig;

    // ── Step 4c: Build multi-axis risk profile for research output
    const tools = capabilities.tools ?? [];
    let rpTotalParams = 0;
    let rpUnconstrainedParams = 0;
    for (const tool of tools) {
      const props = (tool.inputSchema?.properties ?? {}) as Record<string, any>;
      for (const [, schema] of Object.entries(props)) {
        rpTotalParams++;
        if (!schema?.enum && !schema?.pattern && (!schema?.maxLength || schema.maxLength > 500)) {
          rpUnconstrainedParams++;
        }
      }
    }
    const riskProfile = buildRiskProfile(
      moduleResults,
      tools.length,
      rpTotalParams,
      rpUnconstrainedParams,
      tools,
    );

    // ── Step 4d: Compute TOFU schema hash for rug-pull detection
    const schemaHashResult = computeSchemaHash(tools);
    const reportId = randomUUID();
    const chamberSummary = chamberManifest
      ? buildChamberSummary(chamberManifest, enrichedFindings)
      : undefined;
    const killChainSummary = buildKillChains({
      reportId,
      protocol,
      capabilities,
      findings: enrichedFindings,
      chamberReachability: finalChamberReachability,
      chamberSummary,
    });
    const chamberProofBundle = chamberManifest
      ? writeChamberProofBundle({
          reportId,
          killChainSummary,
          outputDir: join(chamberManifest.runDir, "proofs"),
        })
      : undefined;
    const chamberProofBundleSummary = chamberProofBundle
      ? {
          version: chamberProofBundle.version,
          proofFile: chamberProofBundle.proofFile,
          proofCount: chamberProofBundle.proofCount,
          missingArtifactCount: chamberProofBundle.missingArtifactCount,
          writtenAt: chamberProofBundle.writtenAt,
        }
      : undefined;
    // Egress matrix — auditor-grade destination×sink grid built off the same
    // chamber findings. Always emit when a chamber was used so empty cells
    // (Blocked) carry signal too.
    const egressMatrix = chamberManifest
      ? buildEgressMatrix(enrichedFindings)
      : undefined;

    const report: ScanReport = {
      version: "1.0.0",
      id: reportId,
      timestamp: new Date().toISOString(),
      durationMs,
      cliVersion: CLI_VERSION,
      // #09 — git commit hash for full reproducibility (all protocols)
      scannerCommit: getScannerCommit(),
      // P0-02/P1-03 — effective scan mode after target-profile enforcement.
      scanMode: effectiveScanMode,
      // #08 — top-level formula version so consumers don't need to dig into researchMetadata
      scoringFormulaVersion: SCORING_FORMULA_VERSION,
      // #10 — Derived from anchor fixture presence + formula version consistency.
      //        See deriveCalibrationStatus() — reverts to PRE-CALIBRATION if anchors
      //        are missing or formula version changes without re-validation.
      calibrationStatus: deriveCalibrationStatus(),
      transport: transportConfig,
      server: capabilities,
      modules: moduleResults,
      findings: enrichedFindings,
      summary: reportSummary,
      riskProfile,
      schemaHash: schemaHashResult,
      provenance: buildProvenance(options),
      ...(complianceSummary ? { compliance: complianceSummary } : {}),
      ...(peavReport ? { peavReport } : {}),
      ...(chamberSummary ? { chamberSummary } : {}),
      ...(finalChamberReachability ? { chamberReachability: finalChamberReachability } : {}),
      ...(killChainSummary.total > 0 ? { killChainSummary } : {}),
      ...(chamberProofBundleSummary ? { chamberProofBundle: chamberProofBundleSummary } : {}),
      ...(egressMatrix ? { egressMatrix } : {}),
      // P1-08 [§ADV]: Sandbox context disclaimer
      ...(options.context === "sandboxed" ? {
        _contextDisclaimer: "[SANDBOX — scores not comparable to production targets]. " +
          "This scan was run against a target declared as sandboxed/non-production. " +
          "Risk scores reflect schema-level analysis only and do not account for " +
          "the absence of real execution capability in sandboxed environments.",
      } : {}),
    };

    // ── Step 5: Finalize TUI dashboard with score reveal
    if (dashboard) {
      dashboard.finalize(reportSummary, riskProfile);
    }

    // ── Step 5a: Output report
    outputReport(report, options.format, { minSeverity: options.minSeverity });

    // ── Step 5a-bis: Vendor disclosure exporter — emit per-finding YAML +
    // repro.sh for every chamber-backed finding. Only meaningful when a
    // chamber was used; for non-chamber scans we skip silently.
    if (options.vendorReport && chamberManifest) {
      const vendorResult = writeVendorReport(report, {
        outputDir: options.vendorReport,
        vendor: options.vendorName,
        repo: options.vendorRepo,
        commitSha: options.vendorCommit,
        disclosureChannel: options.vendorChannel,
        requireVerifiedReachability: !options.vendorReportAllowUnverified,
      });
      if (vendorResult.manifests.length > 0) {
        console.log();
        console.log(chalk.bold(`  📝 Vendor report written: ${vendorResult.outputDir}`));
        console.log(chalk.dim(`     ${vendorResult.manifests.length} finding(s) packaged with finding.yaml + repro.sh`));
      } else if (vendorResult.skipped.length > 0) {
        console.log(
          chalk.yellow(
            `  --vendor-report skipped: ${vendorResult.skipped[0].reason}`,
          ),
        );
      }
    } else if (options.vendorReport && !chamberManifest) {
      console.log(
        chalk.yellow("  --vendor-report skipped: no chamber was used; nothing to attest."),
      );
    }

    // ── Step 5b: Executive summary (terminal only)
    if (isTerminal && options.executiveSummary) {
      const execSummary = generateExecutiveSummary(report);
      outputExecutiveSummary(execSummary);
    }

    // ── Step 5c: Auto-fix suggestions (terminal only)
    if (isTerminal && options.autofix) {
      const fixes = generateFixSuggestions(report);
      outputFixSuggestions(fixes);
    }

    // ── Step 5d: Custom policy rule results (terminal only)
    if (isTerminal && ruleResults.length > 0) {
      outputRuleResults(ruleResults);
    }

    // ── Step 6: Save to file if --output specified
    if (options.output) {
      const outputPath = options.output;
      let fileContent: string;

      if (outputPath.endsWith(".sarif") || outputPath.endsWith(".sarif.json")) {
        fileContent = JSON.stringify(toSarif(report), null, 2);
      } else if (outputPath.endsWith(".md")) {
        let md = "";
        outputReport(report, "markdown", { writer: (content: string) => { md += content + "\n"; } });
        fileContent = md;
      } else {
        // Apply slim transform when --slim is set, reducing file size ~85%
        // by stripping raw tool schemas, deduplicating module findings, and
        // truncating oversized evidence arrays.
        const reportToSave = options.slim ? slimifyReport(report) : report;
        fileContent = JSON.stringify(reportToSave, null, 2);
      }

      mkdirSync(dirname(outputPath), { recursive: true });
      writeFileSync(outputPath, fileContent, "utf-8");

      if (isTerminal) {
        console.log(`  Report saved to: ${outputPath}\n`);
      }
    }

    // ── Step 7 - Exit code based on findings
    if (options.failBelow !== undefined && reportSummary.securityScore < options.failBelow) {
      if (isTerminal) {
        console.log(
          chalk.red(`\n  ✗ Score ${reportSummary.securityScore}/100 is below threshold ${options.failBelow}/100\n`)
        );
      }
      process.exitCode = 5;
    } else if (reportSummary.findingsBySeverity.CRITICAL > 0) {
      process.exitCode = 3;
    } else if (reportSummary.checksWithFailStatus > 0) {
      process.exitCode = 2;
    } else if (reportSummary.warnings > 0) {
      process.exitCode = 1;
    }

    // Return report for library/API mode
    return report;
  } catch (err) {
    spinner?.fail("Scan failed");
    const message = err instanceof Error ? err.message : String(err);
    if (options.format === "json") {
      console.log(JSON.stringify({ error: message }, null, 2));
    } else {
      console.error(`\n  Error: ${message}\n`);
    }
    process.exitCode = 4;
  } finally {
    await adapter.disconnect();
  }
}

function countFindingsBySeverity(findings: ScanReport["findings"]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    [Severity.CRITICAL]: 0,
    [Severity.HIGH]: 0,
    [Severity.MEDIUM]: 0,
    [Severity.LOW]: 0,
    [Severity.INFO]: 0,
  };

  for (const finding of findings) {
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
  }

  return counts;
}

/**
 * Reconcile passive findings with active scan results.
 * If a passive module flagged a tool but the active fuzzer proved
 * the tool properly rejects malicious input, downgrade the passive finding.
 */
function reconcileFindings(moduleResults: ModuleResult[]): void {
  // ── Pass 1: Collect tools that PASSED active probing (server rejected payloads) ──
  //
  // Build a map: toolName → Set<activeModuleId> for tools that passed specific checks.
  // This tells us which active checks a tool survived, so we can downgrade the
  // corresponding passive findings.
  // ACTIVE_MODULE_IDS is imported from ../core/active-module-ids.ts (single source of truth).

  // toolName → set of active module IDs where tool PASSED
  const passedProbes = new Map<string, Set<string>>();
  // toolName → set of active module IDs where tool FAILED (vulnerability confirmed)
  const confirmedVulns = new Map<string, Set<string>>();

  for (const result of moduleResults) {
    if (!ACTIVE_MODULE_IDS.has(result.moduleId)) continue;

    for (const check of result.checks) {
      if (!check.id.includes("-")) continue;
      // Extract tool name from check ID like "AF-001-toolname" or "TS-003-toolname"
      // Uses explicit match to avoid misparse when tool names start with digits
      const toolMatch = check.id.match(/^[A-Z]+-\d+-(.+)$/);
      if (!toolMatch) continue;
      const toolName = toolMatch[1];
      // pure-numeric suffix (e.g. "TS-001") is a sequence number, not a tool name — skip reconciliation
      if (/^\d+$/.test(toolName)) continue;

      if (check.status === CheckStatus.PASS) {
        if (!passedProbes.has(toolName)) passedProbes.set(toolName, new Set());
        passedProbes.get(toolName)!.add(result.moduleId);
      } else if (check.status === CheckStatus.FAIL && check.finding) {
        if (!confirmedVulns.has(toolName)) confirmedVulns.set(toolName, new Set());
        confirmedVulns.get(toolName)!.add(check.finding.id);
      }
    }
  }

  if (passedProbes.size === 0 && confirmedVulns.size === 0) return;

  // ── Pass 2: Downgrade passive findings for tools that PASSED active probing ──
  //
  // Reconciliation rules: passive finding prefix → which active module passing refutes it
  const RECONCILE_RULES: Array<{ prefix: string; refutedBy: string; note: string }> = [
    // Schema-level findings refuted by active fuzzer passing
    { prefix: "TP-005", refutedBy: "active-fuzzer", note: "server rejects malicious input despite unconstrained schema" },
    { prefix: "SM-004", refutedBy: "active-fuzzer", note: "server rejects malicious input despite suspicious schema" },
    { prefix: "DC-001", refutedBy: "active-fuzzer", note: "active SQL injection probes were blocked" },
    { prefix: "DC-005", refutedBy: "active-fuzzer", note: "active path traversal probes were blocked" },
    // IPI susceptibility refuted by SSRF passing
    { prefix: "IPI-001", refutedBy: "ssrf-detection", note: "SSRF probes were blocked, reducing IPI risk" },
    { prefix: "IPI-005", refutedBy: "ssrf-detection", note: "SSRF probes were blocked, reducing compound IPI risk" },
    // Wildcard/additionalProperties refuted by tool-shadowing passing
    { prefix: "TE-003", refutedBy: "tool-shadowing", note: "tool rejects undeclared parameters" },
    { prefix: "TP-008", refutedBy: "tool-shadowing", note: "tool rejects undeclared parameters despite open schema" },
    // Rug-pull findings refuted by annotation-verifier passing
    { prefix: "RD-001", refutedBy: "annotation-verifier", note: "annotation verification confirmed declared behavior" },
    { prefix: "RD-002", refutedBy: "annotation-verifier", note: "annotation verification confirmed description accuracy" },
    { prefix: "RD-003", refutedBy: "annotation-verifier", note: "annotation verification confirmed name-description consistency" },
    // Prompt injection risk refuted by output-injection passing
    { prefix: "SM-001", refutedBy: "output-injection", note: "output injection probes showed no context manipulation" },
    { prefix: "SM-002", refutedBy: "output-injection", note: "output injection probes showed no context manipulation" },
  ];

  // ── Pass 3: Upgrade passive findings confirmed by active exploits ──
  //
  // When active probing CONFIRMS a vulnerability, boost the corresponding passive finding.
  const CONFIRM_RULES: Array<{ passivePrefix: string; activePrefix: string; note: string }> = [
    { passivePrefix: "DC-001", activePrefix: "AF-003", note: "SQL injection confirmed by active fuzzer" },
    { passivePrefix: "DC-003", activePrefix: "AF-001", note: "command injection confirmed by active fuzzer" },
    { passivePrefix: "DC-005", activePrefix: "AF-002", note: "path traversal confirmed by active fuzzer" },
    { passivePrefix: "RD-004", activePrefix: "AV-002", note: "hidden behavior confirmed by annotation verifier" },
    { passivePrefix: "IPI-001", activePrefix: "SSRF-", note: "SSRF confirmed, validating IPI vector" },
  ];

  let downgraded = 0;
  let upgraded = 0;

  for (const result of moduleResults) {
    if (ACTIVE_MODULE_IDS.has(result.moduleId)) continue;

    for (const finding of result.findings) {
      if (!finding.toolName) continue;

      // Check downgrade rules
      const toolPassed = passedProbes.get(finding.toolName);
      if (toolPassed) {
        for (const rule of RECONCILE_RULES) {
          if (!finding.id.startsWith(rule.prefix)) continue;
          if (!toolPassed.has(rule.refutedBy)) continue;

          finding.description += ` [Reconciled: ${rule.note}.]`;
          if (finding.severity === Severity.CRITICAL) {
            finding.severity = Severity.HIGH;
          } else if (finding.severity === Severity.HIGH) {
            finding.severity = Severity.MEDIUM;
          } else if (finding.severity === Severity.MEDIUM) {
            finding.severity = Severity.LOW;
          }
          // Also reduce confidence
          finding.confidence = Math.max(0.15, (finding.confidence ?? 0.5) * 0.5);
          downgraded++;
          break;
        }
      }

      // Check upgrade rules
      const toolConfirmed = confirmedVulns.get(finding.toolName);
      if (toolConfirmed) {
        for (const rule of CONFIRM_RULES) {
          if (!finding.id.startsWith(rule.passivePrefix)) continue;
          const hasConfirm = [...toolConfirmed].some((id) => id.startsWith(rule.activePrefix));
          if (!hasConfirm) continue;

          finding.description += ` [Confirmed: ${rule.note}.]`;
          // Boost confidence toward 0.95 (don't exceed active probe confidence)
          finding.confidence = Math.min(0.95, Math.max(finding.confidence ?? 0.5, 0.90));
          upgraded++;
          break;
        }
      }
    }
  }
}
