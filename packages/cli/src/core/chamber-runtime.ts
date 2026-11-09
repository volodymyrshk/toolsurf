import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import type { Finding, ServerCapabilities } from "../types/index.js";
import type { ChamberProbeConfig } from "../types/module.js";
import {
  createChamberRun,
  loadChamberManifest,
  type ChamberManifest,
  type CreateChamberOptions,
} from "./detonation-chamber.js";

export type ChamberReachabilityStatus =
  | "verified"
  | "unverified"
  | "not-testable"
  | "not-configured";

export interface ChamberReachabilityResult {
  status: ChamberReachabilityStatus;
  verified: boolean;
  checkedAt: string;
  method: "tool-call" | "chamber-finding" | "none";
  probeUrl?: string;
  toolName?: string;
  paramName?: string;
  captureFile?: string;
  beforeCount?: number;
  afterCount?: number;
  reason: string;
}

export interface VerifyChamberReachabilityOptions {
  capabilities: ServerCapabilities;
  chamber: ChamberProbeConfig;
  callTool?: (name: string, args: Record<string, unknown>) => Promise<unknown>;
  timeoutMs?: number;
  maxCandidates?: number;
}

interface ReachabilityCandidate {
  toolName: string;
  paramName: string;
}

const URL_PARAM_RE =
  /^(url|uri|endpoint|href|link|src|webhook|callback|callback_url|redirect|host|hostname|fetch_url|request_url|target_url)$/i;

export class ChamberRuntime {
  readonly manifest: ChamberManifest;

  constructor(manifest: ChamberManifest) {
    this.manifest = manifest;
  }

  static create(options: CreateChamberOptions = {}): ChamberRuntime {
    return new ChamberRuntime(createChamberRun(options));
  }

  static load(runDir: string): ChamberRuntime {
    return new ChamberRuntime(loadChamberManifest(runDir));
  }

  getProbeConfig(): ChamberProbeConfig {
    return chamberConfigFromManifest(this.manifest);
  }

  compose(args: string[], stdio: "inherit" | "ignore" = "inherit"): void {
    execFileSync("docker", ["compose", "-f", this.manifest.composeFile, ...args], {
      cwd: this.manifest.runDir,
      stdio,
    });
  }

  start(): void {
    // --wait causes Docker to poll each service's healthcheck before returning,
    // so the scanner won't attempt to connect to a target that isn't ready yet.
    // Falls back to plain -d if --wait is unsupported (Docker < 20.10.16).
    try {
      this.compose(["up", "-d", "--wait", "--wait-timeout", "60"]);
    } catch {
      this.compose(["up", "-d"]);
    }
  }

  logs(): void {
    this.compose(["logs", "--no-color"]);
  }

  stop(): void {
    this.compose(["down", "--remove-orphans"]);
  }

  async stopAndRemoveNetwork(): Promise<void> {
    this.stop();
    await removeChamberNetwork(this.manifest);
  }
}

export function chamberConfigFromManifest(manifest: ChamberManifest): ChamberProbeConfig {
  return {
    runDir: manifest.runDir,
    networkName: manifest.network.name,
    fakeHttpUrl: manifest.services.fakeHttp.url,
    fakeMetadataUrl: manifest.services.fakeMetadata.url,
    fakeDnsHost: manifest.services.fakeDns.host,
    captures: {
      http: manifest.captures.http,
      metadata: manifest.captures.metadata,
      dns: manifest.captures.dns,
      smtp: manifest.captures.smtp,
      netflow: manifest.captures.netflow,
    },
    fakeServiceIps: [
      manifest.services.fakeHttp.ip,
      manifest.services.fakeSmtp.ip,
      manifest.services.fakeMetadata.ip,
      manifest.services.fakeDns.ip,
    ],
    ...(manifest.workdir ? { workdir: manifest.workdir } : {}),
  };
}

export async function verifyChamberReachability(
  options: VerifyChamberReachabilityOptions,
): Promise<ChamberReachabilityResult> {
  const checkedAt = new Date().toISOString();
  const captureFile = options.chamber.captures?.http;

  if (!options.callTool) {
    return {
      status: "not-testable",
      verified: false,
      checkedAt,
      method: "none",
      captureFile,
      reason: "No active callTool function was available for a chamber healthcheck.",
    };
  }

  if (!captureFile) {
    return {
      status: "not-testable",
      verified: false,
      checkedAt,
      method: "none",
      reason: "No fake-http capture file is configured for this chamber.",
    };
  }

  const candidates = findReachabilityCandidates(options.capabilities).slice(
    0,
    options.maxCandidates ?? 3,
  );

  if (candidates.length === 0) {
    return {
      status: "not-testable",
      verified: false,
      checkedAt,
      method: "none",
      captureFile,
      reason: "No URL-like tool parameter was available for chamber reachability verification.",
    };
  }

  const timeoutMs = options.timeoutMs ?? 5_000;

  for (const candidate of candidates) {
    const token = `health-${randomUUID().replace(/-/g, "").slice(0, 12)}`;
    const probeUrl = `${options.chamber.fakeHttpUrl}/__chamber-healthcheck/${token}`;
    const beforeCount = countJsonlLines(captureFile);

    try {
      await options.callTool(candidate.toolName, { [candidate.paramName]: probeUrl });
    } catch {
      // The target may throw after starting the outbound request. Capture
      // growth is the source of truth, so still poll below.
    }

    const afterCount = await waitForCaptureGrowth(captureFile, beforeCount, timeoutMs);
    if (afterCount > beforeCount) {
      return {
        status: "verified",
        verified: true,
        checkedAt,
        method: "tool-call",
        probeUrl,
        toolName: candidate.toolName,
        paramName: candidate.paramName,
        captureFile,
        beforeCount,
        afterCount,
        reason: "Target fetched the chamber fake-http healthcheck URL.",
      };
    }
  }

  return {
    status: "unverified",
    verified: false,
    checkedAt,
    method: "tool-call",
    captureFile,
    beforeCount: countJsonlLines(captureFile),
    afterCount: countJsonlLines(captureFile),
    reason:
      `Probed ${candidates.length} URL-like tool parameter(s), but fake-http recorded no healthcheck callback.`,
  };
}

export function finalizeChamberReachability(
  result: ChamberReachabilityResult | undefined,
  findings: Finding[],
): ChamberReachabilityResult | undefined {
  if (!result || result.verified) return result;

  const chamberBackedFinding = findings.find(isChamberBackedFinding);
  if (!chamberBackedFinding) return result;

  return {
    ...result,
    status: "verified",
    verified: true,
    checkedAt: new Date().toISOString(),
    method: "chamber-finding",
    reason:
      `Verified by chamber-backed finding ${chamberBackedFinding.id}; target produced captured evidence during active probing.`,
  };
}

export function isChamberReachabilityVerified(
  result: ChamberReachabilityResult | undefined,
): boolean {
  return result?.verified === true && result.status === "verified";
}

export function isChamberHealthcheckEvent(event: Record<string, unknown>): boolean {
  const path = String(event.path ?? event.url ?? "");
  return path.includes("/__chamber-healthcheck/");
}

export function countJsonlLines(path: string | undefined): number {
  if (!path || !existsSync(path)) return 0;
  const raw = readFileSync(path, "utf-8").trim();
  return raw === "" ? 0 : raw.split("\n").length;
}

export async function removeChamberNetwork(manifest: ChamberManifest): Promise<void> {
  // docker compose can return before Docker releases the just-emptied network.
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      execFileSync("docker", ["network", "rm", manifest.network.name], {
        stdio: "ignore",
      });
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }
}

function findReachabilityCandidates(capabilities: ServerCapabilities): ReachabilityCandidate[] {
  const out: ReachabilityCandidate[] = [];

  for (const tool of capabilities.tools ?? []) {
    const props = (tool.inputSchema as Record<string, unknown> | undefined)
      ?.properties as Record<string, unknown> | undefined;
    if (!props) continue;

    for (const [paramName, schema] of Object.entries(props)) {
      const s = schema as Record<string, unknown> | undefined;
      if (!s || s.type !== "string") continue;
      if (!URL_PARAM_RE.test(paramName)) continue;
      out.push({ toolName: tool.name, paramName });
      break;
    }
  }

  return out;
}

async function waitForCaptureGrowth(
  captureFile: string,
  beforeCount: number,
  timeoutMs: number,
): Promise<number> {
  const deadline = Date.now() + timeoutMs;
  let latest = countJsonlLines(captureFile);

  while (Date.now() < deadline) {
    latest = countJsonlLines(captureFile);
    if (latest > beforeCount) return latest;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }

  return latest;
}

function isChamberBackedFinding(finding: Finding): boolean {
  if (!(finding.id.startsWith("CHAMBER-") || finding.id.startsWith("AF-CHAMBER"))) {
    return false;
  }

  const evidence = (finding.evidence ?? {}) as Record<string, unknown>;
  return (
    evidence.verifiedBy === "chamber-capture" ||
    evidence.verifiedBy === "chamber-netflow" ||
    Array.isArray(evidence.captures) ||
    Array.isArray(evidence.hits) ||
    typeof evidence.captureFile === "string"
  );
}
