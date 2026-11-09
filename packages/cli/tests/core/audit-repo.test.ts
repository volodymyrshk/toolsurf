import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  buildAuditImageTag,
  buildDockerScanTarget,
  buildRepoAuditOutputDir,
  createAuditRepoManifest,
  inferRepoAuditName,
  resolveBuildContext,
  resolveDockerfile,
} from "../../src/core/audit-repo.js";

const TMP_DIR = join(import.meta.dir, "../.tmp-audit-repo");

describe("audit repo core", () => {
  beforeEach(() => {
    rmSync(TMP_DIR, { recursive: true, force: true });
    mkdirSync(TMP_DIR, { recursive: true });
  });

  afterEach(() => {
    rmSync(TMP_DIR, { recursive: true, force: true });
  });

  test("infers stable target names and output paths from GitHub URLs", () => {
    expect(inferRepoAuditName("https://github.com/vendor/payments-mcp.git")).toBe("payments-mcp");
    expect(buildRepoAuditOutputDir("https://github.com/vendor/payments-mcp.git", TMP_DIR)).toBe(TMP_DIR);
  });

  test("builds deterministic local image tags and stdio scan targets", () => {
    expect(buildAuditImageTag("payments_mcp", "ABCDEF1234567890")).toBe("scanner-audit-payments-mcp:abcdef123456");
    expect(buildDockerScanTarget("scanner-audit-payments:abcdef", "node dist/server.js")).toBe(
      "docker run --rm -i scanner-audit-payments:abcdef node dist/server.js",
    );
  });

  test("creates a planned manifest for a prebuilt Docker image", () => {
    const manifest = createAuditRepoManifest({
      repo: "https://github.com/vendor/fetch-mcp.git",
      outputDir: TMP_DIR,
      image: "scanner-fetch:local",
      targetCommand: "--stdio",
    });

    expect(manifest.status).toBe("planned");
    expect(manifest.docker.buildEnabled).toBe(false);
    expect(manifest.scan.target).toBe("docker run --rm -i scanner-fetch:local --stdio");
  });

  test("resolves root Dockerfile first", () => {
    writeFileSync(join(TMP_DIR, "Dockerfile"), "FROM scratch\n", "utf-8");
    mkdirSync(join(TMP_DIR, "nested"), { recursive: true });
    writeFileSync(join(TMP_DIR, "nested", "Dockerfile"), "FROM scratch\n", "utf-8");

    expect(resolveDockerfile(TMP_DIR)).toBe(join(TMP_DIR, "Dockerfile"));
  });

  test("resolves a unique nested Dockerfile and rejects ambiguous monorepos", () => {
    mkdirSync(join(TMP_DIR, "servers", "fetch"), { recursive: true });
    writeFileSync(join(TMP_DIR, "servers", "fetch", "Dockerfile"), "FROM scratch\n", "utf-8");

    expect(resolveDockerfile(TMP_DIR)).toBe(join(TMP_DIR, "servers", "fetch", "Dockerfile"));

    mkdirSync(join(TMP_DIR, "servers", "git"), { recursive: true });
    writeFileSync(join(TMP_DIR, "servers", "git", "Dockerfile"), "FROM scratch\n", "utf-8");

    expect(() => resolveDockerfile(TMP_DIR)).toThrow("Multiple Dockerfiles found");
  });

  test("resolves repo-relative build contexts", () => {
    mkdirSync(join(TMP_DIR, "servers"), { recursive: true });
    expect(resolveBuildContext(TMP_DIR, "servers")).toBe(join(TMP_DIR, "servers"));
    expect(existsSync(TMP_DIR)).toBe(true);
  });
});
