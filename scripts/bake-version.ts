#!/usr/bin/env bun
/**
 * P2-12 [§REPRO]: Bake the current git hash into version.ts at build time.
 * Run this as part of the build pipeline to ensure scannerCommit is available
 * even in environments without .git (Docker, dist bundles).
 *
 * Usage: bun scripts/bake-version.ts
 */
import { execSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const versionFile = join(__dirname, "..", "packages", "cli", "src", "version.ts");

let gitHash = "dev";
try {
  gitHash = execSync("git rev-parse HEAD", { encoding: "utf-8" }).trim();
} catch {
  console.warn("[bake-version] git not available, keeping BUILD_GIT_HASH as 'dev'");
}

const content = readFileSync(versionFile, "utf-8");
const updated = content.replace(
  /export const BUILD_GIT_HASH = "[^"]*";/,
  `export const BUILD_GIT_HASH = "${gitHash}";`,
);

if (content !== updated) {
  writeFileSync(versionFile, updated);
  console.log(`[bake-version] Baked git hash: ${gitHash}`);
} else {
  console.log("[bake-version] BUILD_GIT_HASH pattern not found, skipping");
}
