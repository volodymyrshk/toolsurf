import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parse } from "yaml";
import {
  findingManifestTemplate,
  loadFindingManifest,
  resolveManifestPath,
  validateFindingManifest,
} from "../../src/core/finding-manifest.js";

const TMP_DIR = join(import.meta.dir, ".tmp-finding-manifest");

afterEach(() => {
  rmSync(TMP_DIR, { recursive: true, force: true });
});

function validManifest(script = "./scripts/repro.sh") {
  return {
    finding_id: "paypal-2026-05-001",
    target: {
      vendor: "PayPal",
      repo: "paypal/mcp",
      commit_sha: "0123456789abcdef0123456789abcdef01234567",
      file: "src/tools.ts",
      line: 42,
    },
    class: {
      cwe: "CWE-285",
      owasp_llm: "LLM05 supply-chain vulnerabilities",
      our_taxonomy: "agent-tool.annotation.destructive-gap",
    },
    cvss: {
      vector: "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
      score: 8.1,
    },
    impact: "A financial action can be misclassified as read-only by downstream agents.",
    reproduction: {
      preconditions: ["Target is checked out at the tested commit"],
      steps: ["Run the reproduction script"],
      script,
      expected_output: "annotation-gap-confirmed",
    },
    patch_suggestion: "Set destructiveHint=true and require explicit user confirmation.",
    disclosure: {
      channel: "security@example.com",
      cvelist_candidate: true,
    },
  };
}

describe("finding manifest", () => {
  test("validates a complete finding.yaml manifest", () => {
    const result = validateFindingManifest(validManifest());
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  test("rejects missing required fields", () => {
    const result = validateFindingManifest({
      finding_id: "bad",
      target: { vendor: "Vendor" },
      reproduction: { steps: [], script: "" },
    });

    expect(result.valid).toBe(false);
    expect(result.errors).toContain("Missing required field: target.repo");
    expect(result.errors).toContain("Missing required field: target.commit_sha");
    expect(result.errors).toContain("Missing required field: class");
    expect(result.errors).toContain("Missing required field: impact");
  });

  test("checks script existence relative to manifest directory", () => {
    mkdirSync(join(TMP_DIR, "scripts"), { recursive: true });
    writeFileSync(join(TMP_DIR, "scripts", "repro.sh"), "#!/bin/sh\necho ok\n", "utf-8");

    const result = validateFindingManifest(validManifest(), TMP_DIR);
    expect(result.valid).toBe(true);

    const missing = validateFindingManifest(validManifest("./scripts/missing.sh"), TMP_DIR);
    expect(missing.valid).toBe(false);
    expect(missing.errors[0]).toContain("reproduction.script does not exist");
  });

  test("validates optional kill-chain proof bundle metadata", () => {
    const manifest = {
      ...validManifest(),
      kill_chain: {
        ids: ["KC-SSRF-001"],
        proof_bundle: {
          path: "/tmp/chamber/proofs/chamber-proofs.jsonl",
          proof_count: 1,
          missing_artifact_count: 0,
        },
        proof_artifacts: [
          {
            proof_id: "KC-SSRF-001-PROOF-1",
            proof_type: "outbound-http-callback",
            kind: "http-capture",
            path: "/tmp/chamber/captures/http/requests.jsonl",
            downloadable: true,
            canary: "chamber-fuzz-0-deadbeef",
          },
        ],
      },
    };

    expect(validateFindingManifest(manifest).valid).toBe(true);

    const invalid = {
      ...manifest,
      kill_chain: {
        ...manifest.kill_chain,
        proof_bundle: {
          path: "",
          proof_count: -1,
          missing_artifact_count: -1,
        },
      },
    };
    const result = validateFindingManifest(invalid);
    expect(result.valid).toBe(false);
    expect(result.errors).toContain("kill_chain.proof_bundle.path is required");
    expect(result.errors).toContain("kill_chain.proof_bundle.proof_count must be a non-negative number");
    expect(result.errors).toContain("kill_chain.proof_bundle.missing_artifact_count must be a non-negative number");
  });

  test("loads YAML from disk", () => {
    mkdirSync(join(TMP_DIR, "scripts"), { recursive: true });
    writeFileSync(join(TMP_DIR, "scripts", "repro.sh"), "#!/bin/sh\necho ok\n", "utf-8");
    const manifestPath = join(TMP_DIR, "finding.yaml");
    writeFileSync(manifestPath, findingManifestTemplate().replace("./scripts/repro-vendor-2026-05-001.sh", "./scripts/repro.sh"));

    const loaded = loadFindingManifest(manifestPath);
    expect(loaded.manifest.finding_id).toBe("vendor-2026-05-001");
    expect(loaded.baseDir).toBe(TMP_DIR);
  });

  test("resolves relative and absolute manifest paths", () => {
    expect(resolveManifestPath("/tmp/base", "./scripts/repro.sh")).toBe("/tmp/base/scripts/repro.sh");
    expect(resolveManifestPath("/tmp/base", "/var/tmp/repro.sh")).toBe("/var/tmp/repro.sh");
  });

  test("template is valid YAML and follows the schema", () => {
    const parsed = parse(findingManifestTemplate());
    const result = validateFindingManifest(parsed);
    expect(result.valid).toBe(true);
  });
});
