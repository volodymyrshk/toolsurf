import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { basename, dirname, join, relative } from "node:path";
import type { PackageVersionEvidence } from "../types/index.js";

export interface RepoPackageEvidenceReport {
  version: "1.0";
  generatedAt: string;
  rootDir: string;
  packageCount: number;
  packages: PackageVersionEvidence[];
}

const IGNORED_DIRS = new Set([
  ".git",
  ".scanner",
  "node_modules",
  "dist",
  "build",
  ".next",
  "coverage",
  "vendor",
  "__pycache__",
]);

const MANIFEST_FILES = new Set([
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "requirements.txt",
  "pyproject.toml",
  "uv.lock",
  "go.mod",
  "pom.xml",
]);

export function collectRepoPackageEvidence(rootDir: string): PackageVersionEvidence[] {
  const files = findManifestFiles(rootDir);
  const evidence: PackageVersionEvidence[] = [];

  for (const file of files) {
    const rel = relative(rootDir, file);
    const name = basename(file);
    if (!name) continue;

    try {
      switch (name) {
        case "package.json":
          evidence.push(...parsePackageJson(file, rel));
          break;
        case "package-lock.json":
          evidence.push(...parsePackageLock(file, rel));
          break;
        case "pnpm-lock.yaml":
          evidence.push(...parsePnpmLock(file, rel));
          break;
        case "yarn.lock":
          evidence.push(...parseYarnLock(file, rel));
          break;
        case "requirements.txt":
          evidence.push(...parseRequirements(file, rel));
          break;
        case "pyproject.toml":
          evidence.push(...parsePyproject(file, rel));
          break;
        case "uv.lock":
          evidence.push(...parseUvLock(file, rel));
          break;
        case "go.mod":
          evidence.push(...parseGoMod(file, rel));
          break;
        case "pom.xml":
          evidence.push(...parsePomXml(file, rel));
          break;
      }
    } catch {
      // Bad manifests should not abort repo audit. Other modules still scan.
    }
  }

  return dedupePackageEvidence(evidence);
}

export function writeRepoPackageEvidenceReport(rootDir: string, outputPath: string): RepoPackageEvidenceReport {
  const packages = collectRepoPackageEvidence(rootDir);
  const report: RepoPackageEvidenceReport = {
    version: "1.0",
    generatedAt: new Date().toISOString(),
    rootDir,
    packageCount: packages.length,
    packages,
  };

  const outDir = dirname(outputPath);
  if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
  writeFileSync(outputPath, JSON.stringify(report, null, 2) + "\n", "utf-8");
  return report;
}

function findManifestFiles(rootDir: string): string[] {
  const found: string[] = [];

  function walk(dir: string, depth: number): void {
    if (depth > 5) return;
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name)) walk(join(dir, entry.name), depth + 1);
        continue;
      }
      if (entry.isFile() && MANIFEST_FILES.has(entry.name)) {
        found.push(join(dir, entry.name));
      }
    }
  }

  walk(rootDir, 0);
  return found.sort();
}

function parsePackageJson(path: string, rel: string): PackageVersionEvidence[] {
  const pkg = parseJson(path) as Record<string, unknown> | undefined;
  if (!pkg) return [];
  const out: PackageVersionEvidence[] = [];

  for (const section of ["dependencies", "optionalDependencies", "peerDependencies"]) {
    out.push(...dependenciesFromObject(pkg[section], rel, "package-json", false));
  }
  out.push(...dependenciesFromObject(pkg.devDependencies, rel, "package-json", true));

  if (typeof pkg.name === "string") {
    const version = typeof pkg.version === "string" ? pkg.version : undefined;
    out.push({
      name: pkg.name,
      version: normalizeVersion(version),
      versionKind: versionKind(version, "range"),
      ecosystem: "npm",
      source: "package-json",
      path: rel,
      raw: version ? `${pkg.name}@${version}` : pkg.name,
    });
  }

  return out;
}

function parsePackageLock(path: string, rel: string): PackageVersionEvidence[] {
  const lock = parseJson(path) as Record<string, unknown> | undefined;
  if (!lock) return [];
  const out: PackageVersionEvidence[] = [];
  const packages = lock.packages;

  if (packages && typeof packages === "object") {
    for (const [pkgPath, value] of Object.entries(packages as Record<string, unknown>)) {
      if (!pkgPath.includes("node_modules/") || !value || typeof value !== "object") continue;
      const name = pkgPath.slice(pkgPath.lastIndexOf("node_modules/") + "node_modules/".length);
      const version = (value as Record<string, unknown>).version;
      if (typeof version !== "string") continue;
      out.push(exact(name, version, "npm", "package-lock", rel, `${name}@${version}`));
    }
  }

  const dependencies = lock.dependencies;
  if (dependencies && typeof dependencies === "object") {
    for (const [name, value] of Object.entries(dependencies as Record<string, unknown>)) {
      const version = value && typeof value === "object" ? (value as Record<string, unknown>).version : undefined;
      if (typeof version === "string") {
        out.push(exact(name, version, "npm", "package-lock", rel, `${name}@${version}`));
      }
    }
  }

  return out;
}

function parsePnpmLock(path: string, rel: string): PackageVersionEvidence[] {
  const raw = readFileSync(path, "utf-8");
  const out: PackageVersionEvidence[] = [];
  const packageKeyRe = /^\s{2}\/?((?:@[^/\s]+\/)?[^@\s/][^@\s]*)@([0-9][^:\s(]*)(?:\([^)]*\))?:\s*$/;

  for (const line of raw.split(/\r?\n/)) {
    const match = line.match(packageKeyRe);
    if (!match) continue;
    out.push(exact(match[1], match[2], "npm", "pnpm-lock", rel, line.trim()));
  }

  return out;
}

function parseYarnLock(path: string, rel: string): PackageVersionEvidence[] {
  const lines = readFileSync(path, "utf-8").split(/\r?\n/);
  const out: PackageVersionEvidence[] = [];
  let pendingNames: string[] = [];

  for (const line of lines) {
    if (line && !line.startsWith(" ") && line.endsWith(":")) {
      pendingNames = line
        .slice(0, -1)
        .split(",")
        .map((descriptor) => descriptor.trim().replace(/^"|"$/g, ""))
        .map(nameFromYarnDescriptor)
        .filter((name): name is string => !!name);
      continue;
    }

    const version = line.match(/^\s+version\s+"([^"]+)"/)?.[1];
    if (!version || pendingNames.length === 0) continue;
    for (const name of pendingNames) {
      out.push(exact(name, version, "npm", "yarn-lock", rel, `${name}@${version}`));
    }
    pendingNames = [];
  }

  return out;
}

function parseRequirements(path: string, rel: string): PackageVersionEvidence[] {
  const out: PackageVersionEvidence[] = [];
  for (const rawLine of readFileSync(path, "utf-8").split(/\r?\n/)) {
    const line = rawLine.replace(/\s+#.*$/, "").trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    const exactMatch = line.match(/^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([A-Za-z0-9_.!+-]+)$/);
    if (exactMatch) {
      out.push(exact(exactMatch[1], exactMatch[2], "pip", "requirements", rel, line));
      continue;
    }
    const rangeMatch = line.match(/^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*([<>=!~].+)$/);
    if (rangeMatch) {
      out.push(range(rangeMatch[1], rangeMatch[2], "pip", "requirements", rel, line));
    }
  }
  return out;
}

function parsePyproject(path: string, rel: string): PackageVersionEvidence[] {
  const raw = readFileSync(path, "utf-8");
  const out: PackageVersionEvidence[] = [];

  const projectName = raw.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
  const projectVersion = raw.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
  if (projectName) {
    out.push({
      name: projectName,
      version: normalizeVersion(projectVersion),
      versionKind: versionKind(projectVersion, "range"),
      ecosystem: "pip",
      source: "pyproject",
      path: rel,
      raw: projectVersion ? `${projectName}==${projectVersion}` : projectName,
    });
  }

  const depsBlock = raw.match(/^\s*dependencies\s*=\s*\[([\s\S]*?)^\s*\]/m)?.[1];
  if (depsBlock) {
    for (const dep of depsBlock.matchAll(/"([^"]+)"/g)) {
      out.push(...parsePythonRequirement(dep[1], "pyproject", rel));
    }
  }

  const poetryDeps = raw.match(/^\[tool\.poetry\.dependencies\]\s*$([\s\S]*?)(?=^\[|\Z)/m)?.[1];
  if (poetryDeps) {
    for (const line of poetryDeps.split(/\r?\n/)) {
      const match = line.match(/^\s*([A-Za-z0-9_.-]+)\s*=\s*"([^"]+)"/);
      if (!match || match[1].toLowerCase() === "python") continue;
      out.push(range(match[1], match[2], "pip", "pyproject", rel, line.trim()));
    }
  }

  return out;
}

function parseUvLock(path: string, rel: string): PackageVersionEvidence[] {
  const raw = readFileSync(path, "utf-8");
  const out: PackageVersionEvidence[] = [];
  for (const block of raw.split(/\[\[package\]\]/g)) {
    const name = block.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
    const version = block.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
    if (name && version) out.push(exact(name, version, "pip", "uv-lock", rel, `${name}==${version}`));
  }
  return out;
}

function parseGoMod(path: string, rel: string): PackageVersionEvidence[] {
  const out: PackageVersionEvidence[] = [];
  for (const rawLine of readFileSync(path, "utf-8").split(/\r?\n/)) {
    const line = rawLine.replace(/\/\/.*$/, "").trim();
    const match = line.match(/^(?:require\s+)?([A-Za-z0-9_.~/-]+)\s+v?([0-9][A-Za-z0-9_.+-]*)/);
    if (!match || match[1] === "module") continue;
    out.push(exact(match[1], match[2], "gomod", "go-mod", rel, line));
  }
  return out;
}

function parsePomXml(path: string, rel: string): PackageVersionEvidence[] {
  const raw = readFileSync(path, "utf-8");
  const out: PackageVersionEvidence[] = [];
  for (const dep of raw.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const block = dep[1];
    const groupId = block.match(/<groupId>\s*([^<]+)\s*<\/groupId>/)?.[1]?.trim();
    const artifactId = block.match(/<artifactId>\s*([^<]+)\s*<\/artifactId>/)?.[1]?.trim();
    const version = block.match(/<version>\s*([^<]+)\s*<\/version>/)?.[1]?.trim();
    if (!groupId || !artifactId) continue;
    const name = `${groupId}:${artifactId}`;
    const kind = version && !version.includes("${") ? "exact" : "unknown";
    out.push({
      name,
      version: kind === "exact" ? normalizeVersion(version) : undefined,
      versionKind: kind,
      ecosystem: "maven",
      source: "pom-xml",
      path: rel,
      raw: version ? `${name}:${version}` : name,
    });
  }
  return out;
}

function parsePythonRequirement(
  requirement: string,
  source: "pyproject",
  rel: string,
): PackageVersionEvidence[] {
  const exactMatch = requirement.match(/^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([A-Za-z0-9_.!+-]+)$/);
  if (exactMatch) return [exact(exactMatch[1], exactMatch[2], "pip", source, rel, requirement)];
  const rangeMatch = requirement.match(/^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*([<>=!~].+)$/);
  if (rangeMatch) return [range(rangeMatch[1], rangeMatch[2], "pip", source, rel, requirement)];
  const name = requirement.match(/^([A-Za-z0-9_.-]+)/)?.[1];
  return name ? [unknown(name, "pip", source, rel, requirement)] : [];
}

function dependenciesFromObject(
  value: unknown,
  rel: string,
  source: "package-json",
  devDependency: boolean,
): PackageVersionEvidence[] {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  return Object.entries(value as Record<string, unknown>)
    .filter(([, raw]) => typeof raw === "string")
    .map(([name, raw]) => ({
      name,
      version: normalizeVersion(raw as string),
      versionKind: versionKind(raw as string, "range"),
      ecosystem: "npm" as const,
      source,
      path: rel,
      raw: `${name}@${raw}`,
      devDependency,
    }));
}

function parseJson(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf-8"));
  } catch {
    return undefined;
  }
}

function exact(
  name: string,
  version: string,
  ecosystem: PackageVersionEvidence["ecosystem"],
  source: PackageVersionEvidence["source"],
  path: string,
  raw: string,
): PackageVersionEvidence {
  return {
    name,
    version: normalizeVersion(version),
    versionKind: "exact",
    ecosystem,
    source,
    path,
    raw,
  };
}

function range(
  name: string,
  versionRange: string,
  ecosystem: PackageVersionEvidence["ecosystem"],
  source: PackageVersionEvidence["source"],
  path: string,
  raw: string,
): PackageVersionEvidence {
  return {
    name,
    version: normalizeVersion(versionRange),
    versionKind: "range",
    ecosystem,
    source,
    path,
    raw,
  };
}

function unknown(
  name: string,
  ecosystem: PackageVersionEvidence["ecosystem"],
  source: PackageVersionEvidence["source"],
  path: string,
  raw: string,
): PackageVersionEvidence {
  return { name, versionKind: "unknown", ecosystem, source, path, raw };
}

function normalizeVersion(version: string | undefined): string | undefined {
  if (!version) return undefined;
  const match = version.match(/\d{1,4}(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?/);
  return match?.[0];
}

function versionKind(
  version: string | undefined,
  fallback: PackageVersionEvidence["versionKind"],
): PackageVersionEvidence["versionKind"] {
  if (!version) return "unknown";
  return /^[v=]?\d{1,4}(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?$/.test(version.trim())
    ? "exact"
    : fallback;
}

function nameFromYarnDescriptor(descriptor: string): string | undefined {
  const withoutProtocol = descriptor.replace(/^patch:/, "");
  if (withoutProtocol.startsWith("@")) {
    const secondAt = withoutProtocol.indexOf("@", withoutProtocol.indexOf("/") + 1);
    return secondAt > 0 ? withoutProtocol.slice(0, secondAt) : withoutProtocol;
  }
  const at = withoutProtocol.indexOf("@");
  return at > 0 ? withoutProtocol.slice(0, at) : withoutProtocol;
}

function dedupePackageEvidence(evidence: PackageVersionEvidence[]): PackageVersionEvidence[] {
  const rank = { exact: 3, range: 2, unknown: 1 };
  const byKey = new Map<string, PackageVersionEvidence>();

  for (const item of evidence) {
    if (!item.name) continue;
    const key = `${item.ecosystem ?? "unknown"}:${item.name.toLowerCase()}`;
    const existing = byKey.get(key);
    if (!existing || rank[item.versionKind] > rank[existing.versionKind]) {
      byKey.set(key, item);
    }
  }

  return [...byKey.values()].sort((a, b) => a.name.localeCompare(b.name));
}
