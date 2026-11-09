import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { createHash } from "node:crypto";
import {
  sanitizeChamberName,
  type ChamberManifest,
  type ChamberTargetSpec,
} from "./detonation-chamber.js";
import { ChamberRuntime } from "./chamber-runtime.js";
import type { ProtocolType } from "../types/index.js";

export interface AuditTargetOptions {
  repo: string;
  commit?: string;
  name?: string;
  outputDir?: string;
  protocol?: ProtocolType;
  buildCommand?: string;
  runCommand?: string;
  scanTarget?: string;
  chamber?: boolean;
  chamberOutputDir?: string;
  targetImage?: string;
  targetPorts?: string[];
  targetReadWrite?: boolean;
  execute?: boolean;
}

export interface TargetManifest {
  version: "1.0";
  createdAt: string;
  name: string;
  repo: string;
  commit?: string;
  executionMode: "planned" | "executed";
  checkoutDir: string;
  protocol?: ProtocolType;
  commands: {
    build?: string;
    run?: string;
    scanTarget?: string;
  };
  artifacts: {
    manifest: string;
    outputDir: string;
  };
  chamber?: {
    manifest: string;
    runDir: string;
    fakeHttpUrl: string;
    fakeMetadataUrl: string;
    fakeSmtpHost: string;
    fakeDnsHost: string;
  };
}

export function createTargetAudit(options: AuditTargetOptions): TargetManifest {
  const createdAt = new Date().toISOString();
  const name = sanitizeChamberName(options.name ?? inferTargetName(options.repo));
  const outputDir = resolve(options.outputDir ?? join("data", "targets", name));
  const checkoutDir = join(outputDir, "checkout");
  const manifestPath = join(outputDir, "target.manifest.json");

  if (!existsSync(outputDir)) mkdirSync(outputDir, { recursive: true });

  if (options.execute) {
    cloneAndPrepareTarget(options, checkoutDir);
  }

  let chamberManifest: ChamberManifest | undefined;
  if (options.chamber) {
    const target: ChamberTargetSpec | undefined = options.targetImage || options.runCommand
      ? {
          image: options.targetImage,
          buildContext: options.targetImage ? undefined : checkoutDir,
          command: options.runCommand,
          ports: options.targetPorts,
          readOnly: options.targetReadWrite ? false : undefined,
        }
      : undefined;
    chamberManifest = ChamberRuntime.create({
      name,
      outputDir: options.chamberOutputDir ?? join(outputDir, "chamber"),
      target,
    }).manifest;
  }

  const manifest: TargetManifest = {
    version: "1.0",
    createdAt,
    name,
    repo: options.repo,
    commit: options.commit,
    executionMode: options.execute ? "executed" : "planned",
    checkoutDir,
    protocol: options.protocol,
    commands: {
      build: options.buildCommand,
      run: options.runCommand,
      scanTarget: options.scanTarget,
    },
    artifacts: {
      manifest: manifestPath,
      outputDir,
    },
    chamber: chamberManifest
      ? {
          manifest: join(chamberManifest.runDir, "chamber.manifest.json"),
          runDir: chamberManifest.runDir,
          fakeHttpUrl: chamberManifest.services.fakeHttp.url,
          fakeMetadataUrl: chamberManifest.services.fakeMetadata.url,
          fakeSmtpHost: `${chamberManifest.services.fakeSmtp.host}:${chamberManifest.services.fakeSmtp.port}`,
          fakeDnsHost: `${chamberManifest.services.fakeDns.host}:${chamberManifest.services.fakeDns.port}`,
        }
      : undefined,
  };

  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n", "utf-8");
  return manifest;
}

function cloneAndPrepareTarget(options: AuditTargetOptions, checkoutDir: string): void {
  if (!existsSync(checkoutDir)) {
    execFileSync("git", ["clone", options.repo, checkoutDir], { stdio: "inherit" });
  }
  if (options.commit) {
    execFileSync("git", ["-C", checkoutDir, "checkout", options.commit], { stdio: "inherit" });
  }
  if (options.buildCommand) {
    execFileSync("sh", ["-lc", options.buildCommand], { cwd: checkoutDir, stdio: "inherit" });
  }
}

function inferTargetName(repo: string): string {
  const cleaned = repo.replace(/\.git$/i, "");
  const base = basename(cleaned) || "target";
  if (base !== "target") return base;
  return createHash("sha256").update(repo).digest("hex").slice(0, 12);
}
