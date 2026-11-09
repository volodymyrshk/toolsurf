import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import type { ProtocolType } from "../types/index.js";
import chalk from "chalk";
import {
  buildAuditImageTag,
  buildDockerScanTarget,
  buildRepoDockerImage,
  cloneRepo,
  createAuditRepoManifest,
  resolveBuildContext,
  resolveDockerfile,
  resolveRepoCommit,
  writeAuditRepoManifest,
  type AuditRepoManifest,
  type AuditRepoOptions,
} from "../core/audit-repo.js";
import { writeRepoPackageEvidenceReport } from "../core/repo-package-evidence.js";
import { ChamberRuntime } from "../core/chamber-runtime.js";
import type { ChamberManifest } from "../core/detonation-chamber.js";
import { presetToTargetProfile } from "../core/target-profile.js";
import type { OutputFormat } from "../core/reporter.js";
import type { ScanMode } from "../types/index.js";
import { executeScan } from "./scan.js";

export interface AuditRepoCommandOptions extends AuditRepoOptions {
  format?: OutputFormat;
  scanMode?: ScanMode;
  timeout?: number;
  probeTimeout?: number;
  probeDelay?: number;
  llmOutputTokenLimit?: number;
  keepChamber?: boolean;
  failOnFindings?: boolean;
  verbose?: boolean;
  slim?: boolean;
  /** Enable interactive TUI dashboard during the wrapped scan. */
  tui?: boolean;
  dataClassification?: "none" | "pii" | "phi" | "pci" | "secrets" | "all";
  /**
   * Docker port mapping for HTTP/gRPC targets. Accepts the same forms
   * `docker compose ports:` accepts:
   *   "127.0.0.1:5002:5002" — bind only to localhost (recommended)
   *   "5002:5002"           — all-interfaces
   *   "5002"                — random host port
   * When set, the chamber compose publishes this port and the scanner
   * connects to `127.0.0.1:<host-port>`.
   */
  targetPort?: string;
}

/**
 * One-shot repo audit:
 *   repo URL -> checkout -> Docker image -> chamber -> full-active scan -> manifest.
 *
 * This is intentionally strict about target inference. Dockerfile discovery is
 * allowed only when it is unambiguous; otherwise the caller must provide
 * --dockerfile or --scan-target so the scanner does not audit the wrong service.
 */
export async function executeAuditRepo(options: AuditRepoCommandOptions): Promise<AuditRepoManifest> {
  let manifest = createAuditRepoManifest(options);
  mkdirSync(manifest.artifacts.outputDir, { recursive: true });
  writeAuditRepoManifest(manifest);

  console.log(chalk.green(`  Repo audit manifest: ${manifest.artifacts.manifest}`));
  console.log(chalk.dim(`  Repo:                ${manifest.repo}`));
  console.log(chalk.dim(`  Checkout:            ${manifest.checkoutDir}`));

  if (options.dryRun) {
    console.log(chalk.yellow("  Planned only. Remove --dry-run to clone/build/scan."));
    return manifest;
  }

  let chamberManifest: ChamberManifest | undefined;
  let chamberRuntime: ChamberRuntime | undefined;
  let chamberStarted = false;

  try {
    if (options.build === false && !options.image && !options.scanTarget) {
      throw new Error("Cannot scan with --no-build unless --image or --scan-target is provided.");
    }

    manifest.status = "running";
    writeAuditRepoManifest(manifest);

    console.log(chalk.dim("  Cloning/checking out target..."));
    cloneRepo(options.repo, manifest.checkoutDir, options.commit);
    manifest.resolvedCommit = resolveRepoCommit(manifest.checkoutDir);

    const dependencyEvidenceFile = join(manifest.artifacts.outputDir, "dependency-evidence.json");
    const dependencyEvidenceReport = writeRepoPackageEvidenceReport(
      manifest.checkoutDir,
      dependencyEvidenceFile,
    );
    manifest.dependencies = {
      evidenceFile: dependencyEvidenceFile,
      packageCount: dependencyEvidenceReport.packageCount,
      exactPackageCount: dependencyEvidenceReport.packages.filter((pkg) => pkg.versionKind === "exact").length,
      sources: [...new Set(dependencyEvidenceReport.packages.map((pkg) => pkg.source))].sort(),
    };
    console.log(chalk.dim(
      `  Dependencies:        ${manifest.dependencies.packageCount} package evidence item(s), ` +
      `${manifest.dependencies.exactPackageCount} exact`,
    ));
    writeAuditRepoManifest(manifest);

    if (!options.image) {
      manifest.docker.image = buildAuditImageTag(manifest.name, manifest.resolvedCommit);
    }

    if (manifest.docker.buildEnabled) {
      const dockerfile = resolveDockerfile(manifest.checkoutDir, options.dockerfile);
      const buildContext = resolveBuildContext(manifest.checkoutDir, options.buildContext, dockerfile);
      manifest.docker.dockerfile = dockerfile;
      manifest.docker.buildContext = buildContext;
      writeAuditRepoManifest(manifest);

      console.log(chalk.dim(`  Building image:       ${manifest.docker.image}`));
      buildRepoDockerImage(buildContext, dockerfile, manifest.docker.image!);
    }

    // Scan-target inference:
    //   - MCP stdio: spawn target inside chamber via `docker run -i`
    //   - HTTP-shaped protocols (rest-api / graphql / a2a / mcp+streamable-http
    //     / openai-functions / langchain-tools): bring target up as a chamber
    //     compose service with --target-port published back to host, then
    //     point the scanner at `http://127.0.0.1:<published-port>`
    //   - gRPC: same as HTTP but address is `host:port` not URL
    const httpProtocols = new Set([
      "rest-api", "graphql", "a2a", "openai-functions", "langchain-tools",
    ]);
    const usesHttpTarget =
      httpProtocols.has(manifest.scan.protocol) ||
      (manifest.scan.protocol === "mcp" && manifest.scan.transport === "streamable-http");
    const usesGrpcTarget = manifest.scan.protocol === "grpc";
    const publishedHostPort = options.targetPort
      ? parsePublishedPort(options.targetPort)
      : undefined;

    if (!options.scanTarget) {
      if (manifest.scan.protocol === "mcp" && manifest.scan.transport === "stdio") {
        manifest.scan.target = buildDockerScanTarget(manifest.docker.image!, options.targetCommand);
      } else if ((usesHttpTarget || usesGrpcTarget) && publishedHostPort) {
        // The chamber compose target service publishes <port> back to host;
        // scanner connects via published port.
        manifest.scan.target = usesGrpcTarget
          ? `127.0.0.1:${publishedHostPort.host}`
          : inferHttpScanUrl(manifest.scan.protocol, publishedHostPort.host);
      }
    }
    if (!manifest.scan.target) {
      throw new Error(
        "Cannot infer scan target for this protocol/transport.\n" +
        "Pass --scan-target <command-or-url>, or for HTTP/gRPC protocols add\n" +
        "  --target-port 127.0.0.1:5002:5002\n" +
        "and the target will be published in the chamber for you.",
      );
    }
    // ──────────────────────────────────────────────────────────────────
    // Helpers used above. Kept as locals so audit-repo.ts owns the URL
    // shape per protocol — buildConnectParams in scan.ts handles the
    // parse, but the inference choice belongs here.
    function inferHttpScanUrl(proto: ProtocolType, hostPort: string): string {
      if (proto === "rest-api") return `http://127.0.0.1:${hostPort}/openapi.json`;
      if (proto === "graphql") return `http://127.0.0.1:${hostPort}/graphql`;
      if (proto === "a2a") return `http://127.0.0.1:${hostPort}/.well-known/agent-card.json`;
      // mcp streamable-http / openai-functions / langchain-tools
      return `http://127.0.0.1:${hostPort}`;
    }
    function parsePublishedPort(spec: string): { host: string; container: string } {
      // Accept formats: "127.0.0.1:5002:5002", "5002:5002", "5002"
      const parts = spec.split(":");
      if (parts.length === 3) return { host: parts[1], container: parts[2] };
      if (parts.length === 2) return { host: parts[0], container: parts[1] };
      return { host: parts[0], container: parts[0] };
    }

    if (options.chamber !== false) {
      // Non-stdio protocols: launch the target inside the chamber compose so
      // it's on the chamber network alongside the fake-* services. stdio
      // targets stay on the docker-run path because they're bound to the
      // scanner's stdio.
      const targetSpec =
        manifest.scan.protocol === "mcp" && manifest.scan.transport === "stdio"
          ? undefined
          : {
              image: manifest.docker.image,
              command: options.targetCommand,
              ports: options.targetPort ? [options.targetPort] : undefined,
              readOnly: false,
            };
      chamberRuntime = ChamberRuntime.create({
        name: manifest.name,
        outputDir: join(manifest.artifacts.outputDir, "chamber"),
        target: targetSpec,
      });
      chamberManifest = chamberRuntime.manifest;
      manifest.chamber = {
        enabled: true,
        runDir: chamberManifest.runDir,
        manifest: join(chamberManifest.runDir, "chamber.manifest.json"),
      };
      writeAuditRepoManifest(manifest);

      console.log(chalk.dim(`  Chamber:             ${chamberManifest.runDir}`));
      chamberRuntime.start();
      chamberStarted = true;
    }

    writeAuditRepoManifest(manifest);
    console.log(chalk.dim(`  Scan target:         ${manifest.scan.target}`));
    console.log(chalk.dim(`  Report:              ${manifest.scan.reportJson}`));

    const scanExitCodeBefore = process.exitCode;
    process.exitCode = undefined;
    const report = await executeScan({
      server: manifest.scan.target,
      protocol: manifest.scan.protocol,
      transport: manifest.scan.transport,
      format: options.format ?? "terminal",
      active: true,
      tui: options.tui,
      verbose: options.verbose ?? false,
      timeout: options.timeout ?? 30000,
      output: manifest.scan.reportJson,
      compliance: ["all"],
      probeTimeout: options.probeTimeout ?? 5000,
      probeDelay: options.probeDelay ?? 100,
      llmOutputTokenLimit: options.llmOutputTokenLimit ?? 8192,
      scanMode: options.scanMode ?? "full-active",
      targetProfile: presetToTargetProfile("ci"),
      targetProfilePreset: "ci",
      chamberRunDir: chamberManifest?.runDir,
      slim: options.slim ?? false,
      context: "sandboxed",
      dataClassification: options.dataClassification ?? "none",
      // Vendor disclosure exporter — passes through from audit-repo CLI flag.
      // Default location is colocated with the audit so all artifacts land
      // under data/repo-audits/<name>/ for clean handoff to the vendor.
      vendorReport:
        options.vendorReport ?? join(dirname(manifest.artifacts.manifest), "vendor-report"),
      vendorName: options.vendorName,
      vendorRepo: options.vendorRepo ?? manifest.repo,
      vendorCommit: options.vendorCommit ?? manifest.resolvedCommit,
      vendorChannel: options.vendorChannel,
      packageEvidence: dependencyEvidenceReport.packages,
    });

    const scanExitCode = process.exitCode;
    if (!report) {
      throw new Error("Scan failed before producing a report.");
    }

    manifest.scan.summary = {
      securityScore: report.summary.securityScore,
      riskLevel: report.riskProfile?.riskLevel ?? "UNKNOWN",
      compositeRiskScore: report.riskProfile?.compositeRiskScore ?? 0,
      findingsBySeverity: report.summary.findingsBySeverity,
    };
    manifest.status = "completed";
    writeAuditRepoManifest(manifest);

    if (!options.failOnFindings && scanExitCode && Number(scanExitCode) >= 1 && Number(scanExitCode) <= 3) {
      process.exitCode = scanExitCodeBefore ?? 0;
    }

    console.log(chalk.green("  Repo audit completed"));
    return manifest;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    manifest.status = "failed";
    manifest.error = message;
    writeAuditRepoManifest(manifest);
    process.exitCode = 4;
    console.error(chalk.red(`  Repo audit failed: ${message}`));
    return manifest;
  } finally {
    if (chamberStarted && chamberRuntime && !options.keepChamber) {
      try {
        await chamberRuntime.stopAndRemoveNetwork();
        console.log(chalk.dim("  Chamber stopped"));
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        process.exitCode = 4;
        console.error(chalk.red(`  Chamber cleanup failed: ${message}`));
      }
    } else if (chamberStarted && chamberRuntime) {
      console.log(chalk.yellow(`  Chamber kept running: ${chamberRuntime.manifest.runDir}`));
    }
  }
}
