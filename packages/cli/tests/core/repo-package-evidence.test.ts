import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  collectRepoPackageEvidence,
  writeRepoPackageEvidenceReport,
} from "../../src/core/repo-package-evidence.js";

let tmpRoots: string[] = [];

function tempRepo(): string {
  const root = mkdtempSync(join(tmpdir(), "scanner-package-evidence-"));
  tmpRoots.push(root);
  return root;
}

function write(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, "utf-8");
}

afterEach(() => {
  for (const root of tmpRoots) {
    rmSync(root, { recursive: true, force: true });
  }
  tmpRoots = [];
});

describe("repo package evidence", () => {
  test("collects exact npm versions from package-lock over package.json ranges", () => {
    const root = tempRepo();
    write(join(root, "package.json"), JSON.stringify({
      name: "demo-mcp",
      version: "1.0.0",
      dependencies: {
        "n8n-mcp": "^2.47.3",
        "mcp-server-kubernetes": "^3.4.0",
        "range-only": "^1.2.3",
      },
    }));
    write(join(root, "package-lock.json"), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/n8n-mcp": { version: "2.47.3" },
        "node_modules/mcp-server-kubernetes": { version: "3.4.0" },
      },
    }));

    const evidence = collectRepoPackageEvidence(root);

    expect(evidence.find((pkg) => pkg.name === "n8n-mcp")).toMatchObject({
      version: "2.47.3",
      versionKind: "exact",
      ecosystem: "npm",
      source: "package-lock",
      path: "package-lock.json",
    });
    expect(evidence.find((pkg) => pkg.name === "mcp-server-kubernetes")).toMatchObject({
      version: "3.4.0",
      versionKind: "exact",
      source: "package-lock",
    });
    expect(evidence.find((pkg) => pkg.name === "range-only")).toMatchObject({
      version: "1.2.3",
      versionKind: "range",
      source: "package-json",
    });
  });

  test("collects Python, Go, and Maven package evidence from common manifests", () => {
    const root = tempRepo();
    write(join(root, "requirements.txt"), [
      "mcp-server-git==2026.1.13",
      "excel-mcp-server>=0.1.7",
    ].join("\n"));
    write(join(root, "uv.lock"), [
      "[[package]]",
      'name = "mcp"',
      'version = "1.22.0"',
      "",
      "[[package]]",
      'name = "mcp-server-git"',
      'version = "2026.1.13"',
    ].join("\n"));
    write(join(root, "go.mod"), [
      "module example.com/demo",
      "",
      "require (",
      "  github.com/modelcontextprotocol/go-sdk v1.4.0",
      ")",
    ].join("\n"));
    write(join(root, "pom.xml"), [
      "<project>",
      "  <dependencies>",
      "    <dependency>",
      "      <groupId>io.modelcontextprotocol.sdk</groupId>",
      "      <artifactId>mcp-core</artifactId>",
      "      <version>0.10.0</version>",
      "    </dependency>",
      "  </dependencies>",
      "</project>",
    ].join("\n"));

    const evidence = collectRepoPackageEvidence(root);

    expect(evidence.find((pkg) => pkg.name === "mcp-server-git")).toMatchObject({
      version: "2026.1.13",
      versionKind: "exact",
      ecosystem: "pip",
    });
    expect(evidence.find((pkg) => pkg.name === "github.com/modelcontextprotocol/go-sdk")).toMatchObject({
      version: "1.4.0",
      versionKind: "exact",
      ecosystem: "gomod",
      source: "go-mod",
    });
    expect(evidence.find((pkg) => pkg.name === "io.modelcontextprotocol.sdk:mcp-core")).toMatchObject({
      version: "0.10.0",
      versionKind: "exact",
      ecosystem: "maven",
      source: "pom-xml",
    });
    expect(evidence.find((pkg) => pkg.name === "excel-mcp-server")).toMatchObject({
      version: "0.1.7",
      versionKind: "range",
      source: "requirements",
    });
  });

  test("writes a dependency-evidence artifact for audit-repo manifests", () => {
    const root = tempRepo();
    const output = join(root, ".scanner", "dependency-evidence.json");
    write(join(root, "package-lock.json"), JSON.stringify({
      dependencies: {
        "n8n-mcp": { version: "2.47.3" },
      },
    }));

    const report = writeRepoPackageEvidenceReport(root, output);
    const parsed = JSON.parse(readFileSync(output, "utf-8"));

    expect(report.packageCount).toBe(1);
    expect(parsed).toMatchObject({
      version: "1.0",
      rootDir: root,
      packageCount: 1,
      packages: [{ name: "n8n-mcp", version: "2.47.3", versionKind: "exact" }],
    });
  });
});
