/**
 * Single source of truth for the CLI version.
 * All files that need the version string should import this.
 */
export const CLI_VERSION = "0.1.0-alpha.1";

/**
 * P2-12 [§REPRO]: Build-time git hash fallback.
 * Runtime `git rev-parse HEAD` fails in Docker containers and dist bundles
 * without .git directories, producing scannerCommit="unknown" which makes
 * the scan non-reproducible (violates R5.1).
 *
 * This constant is updated by the build script (scripts/bake-version.ts).
 * If the build script hasn't run, falls back to "dev" (local development).
 * getScannerCommit() in scan.ts uses this as fallback when runtime git fails.
 */
export const BUILD_GIT_HASH = "dev";
