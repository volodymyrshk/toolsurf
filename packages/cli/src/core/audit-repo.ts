import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { sanitizeChamberName } from "./detonation-chamber.js";
import type { ProtocolType } from "../types/index.js";

export interface AuditRepoOptions {
  repo: string;
  commit?: string;
  name?: string;
  outputDir?: string;
  protocol?: ProtocolType;
  transport?: "stdio" | "streamable-http";
  image?: string;
  dockerfile?: string;
  buildContext?: string;
  targetCommand?: string;
  scanTarget?: string;
  build?: boolean;
  chamber?: boolean;
  dryRun?: boolean;
  // Forwarded to executeScan
  format?: import("./reporter.js").OutputFormat;
  verbose?: boolean;
  timeout?: number;
  probeTimeout?: number;
  probeDelay?: number;
  llmOutputTokenLimit?: number;
  scanMode?: import("../types/index.js").ScanMode;
  slim?: boolean;
  failOnFindings?: boolean;
  dataClassification?: "none" | "pii" | "phi" | "pci" | "secrets" | "all";
  // Vendor disclosure exporter knobs
  vendorReport?: string;
  vendorName?: string;
  vendorRepo?: string;
  vendorCommit?: string;
  vendorChannel?: string;
}

export interface AuditRepoManifest {
  version: "1.0";
  createdAt: string;
  status: "planned" | "running" | "completed" | "failed";
  name: string;
  repo: string;
  requestedCommit?: string;
  resolvedCommit?: string;
  checkoutDir: string;
  docker: {
    image?: string;
    dockerfile?: string;
    buildContext?: string;
    buildEnabled: boolean;
  };
  scan: {
    protocol: ProtocolType;
    transport: "stdio" | "streamable-http";
    target: string;
    reportJson: string;
    summary?: {
      securityScore: number;
      riskLevel: string;
      compositeRiskScore: number;
      findingsBySeverity: Record<string, number>;
    };
  };
  chamber?: {
    enabled: boolean;
    runDir?: string;
    manifest?: string;
  };
  dependencies?: {
    evidenceFile: string;
    packageCount: number;
    exactPackageCount: number;
    sources: string[];
  };
  artifacts: {
    outputDir: string;
    manifest: string;
  };
  error?: string;
}

export function inferRepoAuditName(repo: string): string {
  const cleaned = repo.replace(/[?#].*$/, "").replace(/\.git$/i, "");
  const base = basename(cleaned) || "repo";
  if (base !== "repo") return sanitizeChamberName(base);
  return createHash("sha256").update(repo).digest("hex").slice(0, 12);
}

export function buildRepoAuditOutputDir(repo: string, outputDir?: string, name?: string): string {
  const targetName = sanitizeChamberName(name ?? inferRepoAuditName(repo));
  return resolve(outputDir ?? join("data", "repo-audits", targetName));
}

export function buildAuditImageTag(name: string, commit?: string): string {
  const safeName = sanitizeChamberName(name).replace(/_/g, "-");
  const suffix = (commit ?? "planned").slice(0, 12).toLowerCase().replace(/[^a-f0-9]/g, "");
  return `scanner-audit-${safeName}:${suffix || "local"}`;
}

export function buildDockerScanTarget(image: string, targetCommand?: string): string {
  return ["docker", "run", "--rm", "-i", image, targetCommand?.trim()]
    .filter(Boolean)
    .join(" ");
}

export function createAuditRepoManifest(
  options: AuditRepoOptions,
  overrides: Partial<AuditRepoManifest> = {},
): AuditRepoManifest {
  const name = sanitizeChamberName(options.name ?? inferRepoAuditName(options.repo));
  const outputDir = buildRepoAuditOutputDir(options.repo, options.outputDir, name);
  const checkoutDir = join(outputDir, "checkout");
  const manifestPath = join(outputDir, "audit-repo.manifest.json");
  const reportJson = join(outputDir, "report.research.json");
  const protocol = options.protocol ?? "mcp";
  const transport = options.transport ?? "stdio";
  const image = options.image ?? buildAuditImageTag(name, overrides.resolvedCommit ?? options.commit);
  const target = options.scanTarget ?? (protocol === "mcp" && transport === "stdio"
    ? buildDockerScanTarget(image, options.targetCommand)
    : "");

  return {
    version: "1.0",
    createdAt: new Date().toISOString(),
    status: "planned",
    name,
    repo: options.repo,
    requestedCommit: options.commit,
    checkoutDir,
    docker: {
      image,
      dockerfile: options.dockerfile,
      buildContext: options.buildContext,
      buildEnabled: options.build !== false && !options.image,
    },
    scan: {
      protocol,
      transport,
      target,
      reportJson,
    },
    chamber: options.chamber === false ? undefined : { enabled: true },
    artifacts: {
      outputDir,
      manifest: manifestPath,
    },
    ...overrides,
  };
}

export function writeAuditRepoManifest(manifest: AuditRepoManifest): void {
  if (!existsSync(manifest.artifacts.outputDir)) {
    mkdirSync(manifest.artifacts.outputDir, { recursive: true });
  }
  writeFileSync(manifest.artifacts.manifest, JSON.stringify(manifest, null, 2) + "\n", "utf-8");
}

export function cloneRepo(repo: string, checkoutDir: string, commit?: string): void {
  if (!existsSync(checkoutDir)) {
    execFileSync("git", ["clone", repo, checkoutDir], { stdio: "inherit" });
  }
  if (commit) {
    execFileSync("git", ["-C", checkoutDir, "checkout", commit], { stdio: "inherit" });
  }
}

export function resolveRepoCommit(checkoutDir: string): string {
  return execFileSync("git", ["-C", checkoutDir, "rev-parse", "HEAD"], {
    encoding: "utf-8",
  }).trim();
}

export function resolveDockerfile(checkoutDir: string, dockerfile?: string): string {
  if (dockerfile) {
    const path = resolve(checkoutDir, dockerfile);
    if (!existsSync(path)) {
      throw new Error(
        `--dockerfile path not found: ${path}\n` +
        `Drop the --dockerfile flag and the scanner will auto-detect, or pass a real repo-relative path.`,
      );
    }
    return path;
  }

  // Auto-detect: prefer Dockerfile at root, then unique match anywhere.
  const rootDockerfile = join(checkoutDir, "Dockerfile");
  if (existsSync(rootDockerfile)) return rootDockerfile;

  const candidates = findDockerfiles(checkoutDir);
  if (candidates.length === 1) return candidates[0];
  if (candidates.length > 1) {
    const preview = candidates
      .slice(0, 10)
      .map((candidate) => `  - ${relativeToRepo(checkoutDir, candidate)}`)
      .join("\n");
    const suffix = candidates.length > 10 ? `\n  ... and ${candidates.length - 10} more` : "";
    throw new Error(
      `Multiple Dockerfiles found in repo. Pass --dockerfile <repo-relative-path> to pick one.\n${preview}${suffix}`,
    );
  }

  // No Dockerfile at all — try to synthesize one from package.json / pyproject.toml.
  const synthesized = synthesizeDockerfile(checkoutDir);
  if (synthesized) {
    if (process.env.SCANNER_VERBOSE) {
      console.error(
        `[toolsurf:audit-repo] No Dockerfile in repo; synthesized one at ${synthesized}`,
      );
    }
    return synthesized;
  }

  throw new Error(
    `No Dockerfile found in repo and no package.json / pyproject.toml to synthesize one from.\n` +
    `Pass --image <prebuilt-image> for an already-built image, or add a Dockerfile to the repo.`,
  );
}

function relativeToRepo(checkoutDir: string, path: string): string {
  const root = resolve(checkoutDir);
  const abs = resolve(path);
  return abs.startsWith(root + "/") ? abs.slice(root.length + 1) : abs;
}

/**
 * Synthesize a deterministic Dockerfile from a repo's package.json or
 * pyproject.toml. Writes the Dockerfile to a `.scanner/` directory inside
 * the checkout (so the synth is visible and reproducible). Returns the
 * absolute path or `undefined` when no manifest can be detected.
 *
 * Detection priority:
 *   1. pyproject.toml with `[project.scripts]` or a single console-script
 *      → uv-based image
 *   2. pyproject.toml without scripts → install `.` and run `python -m <pkg>`
 *      where `<pkg>` is derived from `[project].name`
 *   3. package.json with `bin` field → npm install + node `bin`
 *   4. package.json with `main` → npm install + node `main`
 *   5. None of the above → undefined
 *
 * The synthesized Dockerfile is intentionally simple. It's enough to make
 * `audit-repo` work on the long tail of MCP repos that don't ship one,
 * not a production base image.
 */
export function synthesizeDockerfile(checkoutDir: string): string | undefined {
  const pyproject = join(checkoutDir, "pyproject.toml");
  const packageJson = join(checkoutDir, "package.json");

  let dockerfile: string | undefined;
  if (existsSync(pyproject)) {
    dockerfile = renderPyprojectDockerfile(pyproject);
  } else if (existsSync(packageJson)) {
    dockerfile = renderPackageJsonDockerfile(packageJson);
  }

  if (!dockerfile) return undefined;

  const synthDir = join(checkoutDir, ".scanner");
  if (!existsSync(synthDir)) mkdirSync(synthDir, { recursive: true });
  const out = join(synthDir, "Dockerfile.synth");
  writeFileSync(out, dockerfile, "utf-8");
  return out;
}

function renderPyprojectDockerfile(pyprojectPath: string): string | undefined {
  const raw = readFileSync(pyprojectPath, "utf-8");
  // Cheap TOML parse — we only need [project].name and [project.scripts].
  // Pulling in a TOML lib for ~5 fields would bloat the bundle.
  const nameMatch = raw.match(/^\s*name\s*=\s*"([^"]+)"/m);
  const projectName = nameMatch?.[1];
  const scriptsMatch = raw.match(/^\[project\.scripts\]\s*$([\s\S]*?)(?=^\[|\Z)/m);
  const firstScript = scriptsMatch?.[1].match(/^\s*([\w-]+)\s*=\s*"/m)?.[1];

  const entry =
    firstScript ??
    (projectName ? `python -m ${projectName.replace(/[-]/g, "_")}` : undefined);
  if (!entry) return undefined;

  // uv-based image — fast resolves and reproducible builds. Falls back to
  // pip if uv isn't available.
  return [
    `# Synthesized by toolsurf audit-repo (no Dockerfile in repo).`,
    `FROM python:3.12-slim-bookworm`,
    `WORKDIR /app`,
    `RUN pip install --no-cache-dir uv`,
    `COPY . /app`,
    `RUN uv pip install --system --no-cache .`,
    `ENV PYTHONUNBUFFERED=1`,
    `ENTRYPOINT ["${entry}"]`,
    "",
  ].join("\n");
}

function renderPackageJsonDockerfile(packageJsonPath: string): string | undefined {
  let pkg: { name?: string; main?: string; bin?: string | Record<string, string>; scripts?: Record<string, string> };
  try {
    pkg = JSON.parse(readFileSync(packageJsonPath, "utf-8"));
  } catch {
    return undefined;
  }

  let entry: string | undefined;
  if (typeof pkg.bin === "string") {
    entry = `node ${pkg.bin.replace(/^\.\//, "")}`;
  } else if (pkg.bin && typeof pkg.bin === "object") {
    const first = Object.values(pkg.bin)[0];
    if (typeof first === "string") entry = `node ${first.replace(/^\.\//, "")}`;
  }
  if (!entry && pkg.scripts?.start) {
    entry = `npm start`;
  }
  if (!entry && pkg.main) {
    entry = `node ${pkg.main.replace(/^\.\//, "")}`;
  }
  if (!entry) return undefined;

  // Use Node 22 LTS. Run `npm install` (not `ci`) because many MCP repos
  // don't ship lockfiles. Build step runs only when `scripts.build` exists.
  const buildLine = pkg.scripts?.build ? `RUN npm run build` : "";

  return [
    `# Synthesized by toolsurf audit-repo (no Dockerfile in repo).`,
    `FROM node:22-alpine`,
    `WORKDIR /app`,
    `COPY . /app`,
    `RUN npm install --no-audit --no-fund`,
    buildLine,
    `ENV NODE_ENV=production`,
    `ENTRYPOINT [${entry.split(" ").map((p) => `"${p}"`).join(", ")}]`,
    "",
  ].filter(Boolean).join("\n");
}

/**
 * Resolve the build-context directory.
 *
 * Defaulting strategy:
 *   - If `--build-context` is explicit, use it.
 *   - Else if a non-root `--dockerfile` is set, default the context to the
 *     Dockerfile's parent directory. Most Dockerfiles in monorepos
 *     (e.g. `src/fetch/Dockerfile` in modelcontextprotocol/servers) use
 *     `COPY ./uv.lock ./` or `--mount=type=bind,source=uv.lock` — both
 *     assume the build context is the directory the Dockerfile lives in,
 *     not the repo root. Defaulting to the parent eliminates the most
 *     common "uv.lock not found" / "pyproject.toml not found" failure.
 *   - Else use the checkout root.
 */
export function resolveBuildContext(
  checkoutDir: string,
  buildContext?: string,
  dockerfilePath?: string,
): string {
  if (buildContext) return resolve(checkoutDir, buildContext);
  if (dockerfilePath) {
    const dockerfileDir = resolve(dirname(dockerfilePath));
    // Only narrow the context if the Dockerfile is NOT directly at the
    // checkout root — then the parent IS the checkout, so stay there.
    if (dockerfileDir !== resolve(checkoutDir)) {
      return dockerfileDir;
    }
  }
  return checkoutDir;
}

export function buildRepoDockerImage(buildContextDir: string, dockerfile: string, image: string): void {
  execFileSync("docker", ["build", "-t", image, "-f", dockerfile, buildContextDir], {
    stdio: "inherit",
  });
}

function findDockerfiles(rootDir: string): string[] {
  const ignored = new Set([
    ".git",
    "node_modules",
    "dist",
    "build",
    ".next",
    "coverage",
    "vendor",
  ]);
  const found: string[] = [];

  function walk(dir: string, depth: number): void {
    if (depth > 4) return;
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (ignored.has(entry.name)) continue;
      const fullPath = join(dir, entry.name);
      if (entry.isFile() && entry.name === "Dockerfile") {
        found.push(fullPath);
      } else if (entry.isDirectory()) {
        let stats;
        try {
          stats = statSync(fullPath);
        } catch {
          continue;
        }
        if (stats.isDirectory()) walk(fullPath, depth + 1);
      }
    }
  }

  walk(rootDir, 0);
  return found.sort();
}
