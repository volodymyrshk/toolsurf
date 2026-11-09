import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { parse, stringify } from "yaml";

export interface FindingManifest {
  finding_id: string;
  target: {
    vendor: string;
    repo: string;
    commit_sha: string;
    file?: string;
    line?: number;
  };
  class: {
    cwe?: string;
    owasp_llm?: string;
    our_taxonomy: string;
  };
  cvss?: {
    vector?: string;
    score?: number;
  };
  impact: string;
  reproduction: {
    preconditions?: string[];
    steps: string[];
    script: string;
    expected_output?: string;
  };
  kill_chain?: {
    ids: string[];
    proof_bundle?: {
      path: string;
      proof_count: number;
      missing_artifact_count: number;
    };
    proof_artifacts: Array<{
      proof_id: string;
      proof_type: string;
      kind: string;
      path: string;
      downloadable: boolean;
      canary?: string;
    }>;
  };
  patch_suggestion: string;
  disclosure?: {
    channel?: string;
    sent?: string | null;
    response_received?: string | null;
    response_content?: string | null;
    cvelist_candidate?: boolean;
  };
}

export interface LoadedFindingManifest {
  manifest: FindingManifest;
  manifestPath: string;
  baseDir: string;
}

export interface ManifestValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

const SHA_RE = /^[a-f0-9]{7,40}$/i;
const CVE_CWE_RE = /^CWE-\d+$/i;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every(isNonEmptyString);
}

function pushMissing(errors: string[], path: string): void {
  errors.push(`Missing required field: ${path}`);
}

export function validateFindingManifest(value: unknown, baseDir?: string): ManifestValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  if (!isRecord(value)) {
    return { valid: false, errors: ["Manifest root must be an object"], warnings };
  }

  if (!isNonEmptyString(value.finding_id)) pushMissing(errors, "finding_id");

  const target = value.target;
  if (!isRecord(target)) {
    pushMissing(errors, "target");
  } else {
    if (!isNonEmptyString(target.vendor)) pushMissing(errors, "target.vendor");
    if (!isNonEmptyString(target.repo)) pushMissing(errors, "target.repo");
    if (!isNonEmptyString(target.commit_sha)) {
      pushMissing(errors, "target.commit_sha");
    } else if (!SHA_RE.test(target.commit_sha)) {
      errors.push("target.commit_sha must be a 7-40 character git SHA");
    }
    if (target.line !== undefined && (typeof target.line !== "number" || target.line < 1)) {
      errors.push("target.line must be a positive number when present");
    }
  }

  const klass = value.class;
  if (!isRecord(klass)) {
    pushMissing(errors, "class");
  } else {
    if (!isNonEmptyString(klass.our_taxonomy)) pushMissing(errors, "class.our_taxonomy");
    if (klass.cwe !== undefined && (!isNonEmptyString(klass.cwe) || !CVE_CWE_RE.test(klass.cwe))) {
      errors.push("class.cwe must look like CWE-78 when present");
    }
  }

  const cvss = value.cvss;
  if (cvss !== undefined) {
    if (!isRecord(cvss)) {
      errors.push("cvss must be an object when present");
    } else if (cvss.score !== undefined && (typeof cvss.score !== "number" || cvss.score < 0 || cvss.score > 10)) {
      errors.push("cvss.score must be a number between 0 and 10");
    }
  }

  if (!isNonEmptyString(value.impact)) pushMissing(errors, "impact");
  if (!isNonEmptyString(value.patch_suggestion)) pushMissing(errors, "patch_suggestion");

  const reproduction = value.reproduction;
  if (!isRecord(reproduction)) {
    pushMissing(errors, "reproduction");
  } else {
    if (reproduction.preconditions !== undefined && !isStringArray(reproduction.preconditions)) {
      errors.push("reproduction.preconditions must be a string array when present");
    }
    if (!isStringArray(reproduction.steps) || reproduction.steps.length === 0) {
      errors.push("reproduction.steps must contain at least one step");
    }
    if (!isNonEmptyString(reproduction.script)) {
      pushMissing(errors, "reproduction.script");
    } else if (baseDir) {
      const scriptPath = resolveManifestPath(baseDir, reproduction.script);
      if (!existsSync(scriptPath)) {
        errors.push(`reproduction.script does not exist: ${reproduction.script}`);
      }
    }
    if (reproduction.expected_output !== undefined && !isNonEmptyString(reproduction.expected_output)) {
      errors.push("reproduction.expected_output must be non-empty when present");
    }
  }

  const killChain = value.kill_chain;
  if (killChain !== undefined) {
    if (!isRecord(killChain)) {
      errors.push("kill_chain must be an object when present");
    } else {
      if (!isStringArray(killChain.ids) || killChain.ids.length === 0) {
        errors.push("kill_chain.ids must contain at least one chain id");
      }
      const proofBundle = killChain.proof_bundle;
      if (proofBundle !== undefined) {
        if (!isRecord(proofBundle)) {
          errors.push("kill_chain.proof_bundle must be an object when present");
        } else {
          if (!isNonEmptyString(proofBundle.path)) {
            errors.push("kill_chain.proof_bundle.path is required");
          }
          if (
            typeof proofBundle.proof_count !== "number" ||
            proofBundle.proof_count < 0
          ) {
            errors.push("kill_chain.proof_bundle.proof_count must be a non-negative number");
          }
          if (
            typeof proofBundle.missing_artifact_count !== "number" ||
            proofBundle.missing_artifact_count < 0
          ) {
            errors.push("kill_chain.proof_bundle.missing_artifact_count must be a non-negative number");
          }
        }
      }
      if (!Array.isArray(killChain.proof_artifacts) || killChain.proof_artifacts.length === 0) {
        errors.push("kill_chain.proof_artifacts must contain at least one artifact");
      } else {
        for (const [index, artifact] of killChain.proof_artifacts.entries()) {
          if (!isRecord(artifact)) {
            errors.push(`kill_chain.proof_artifacts[${index}] must be an object`);
            continue;
          }
          if (!isNonEmptyString(artifact.proof_id)) {
            errors.push(`kill_chain.proof_artifacts[${index}].proof_id is required`);
          }
          if (!isNonEmptyString(artifact.proof_type)) {
            errors.push(`kill_chain.proof_artifacts[${index}].proof_type is required`);
          }
          if (!isNonEmptyString(artifact.kind)) {
            errors.push(`kill_chain.proof_artifacts[${index}].kind is required`);
          }
          if (!isNonEmptyString(artifact.path)) {
            errors.push(`kill_chain.proof_artifacts[${index}].path is required`);
          }
          if (artifact.downloadable !== true) {
            errors.push(`kill_chain.proof_artifacts[${index}].downloadable must be true`);
          }
        }
      }
    }
  }

  const disclosure = value.disclosure;
  if (disclosure !== undefined && !isRecord(disclosure)) {
    errors.push("disclosure must be an object when present");
  }

  if (isNonEmptyString(value.finding_id) && !/^[a-z0-9][a-z0-9._-]*$/i.test(value.finding_id)) {
    warnings.push("finding_id should be filesystem- and CVE-tracker-friendly");
  }
  if (isRecord(target) && isNonEmptyString(target.commit_sha) && target.commit_sha.length < 12) {
    warnings.push("target.commit_sha is short; use a full 40-character SHA for vendor disclosures when possible");
  }
  if (isRecord(reproduction) && !isNonEmptyString(reproduction.expected_output)) {
    warnings.push("reproduction.expected_output is recommended so repro-check can verify more than exit code");
  }

  return { valid: errors.length === 0, errors, warnings };
}

export function loadFindingManifest(path: string): LoadedFindingManifest {
  const manifestPath = resolve(path);
  const baseDir = dirname(manifestPath);
  const raw = readFileSync(manifestPath, "utf-8");
  const parsed = parse(raw) as unknown;
  const validation = validateFindingManifest(parsed, baseDir);

  if (!validation.valid) {
    throw new Error(validation.errors.join("\n"));
  }

  return {
    manifest: parsed as FindingManifest,
    manifestPath,
    baseDir,
  };
}

export function resolveManifestPath(baseDir: string, path: string): string {
  return isAbsolute(path) ? path : resolve(join(baseDir, path));
}

export function findingManifestTemplate(): string {
  const template: FindingManifest = {
    finding_id: "vendor-2026-05-001",
    target: {
      vendor: "Vendor Name",
      repo: "org/repo",
      commit_sha: "0123456789abcdef0123456789abcdef01234567",
      file: "src/server/tool-router.ts",
      line: 142,
    },
    class: {
      cwe: "CWE-78",
      owasp_llm: "LLM02 insecure output handling",
      our_taxonomy: "agent-tool.injection.shell",
    },
    cvss: {
      vector: "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
      score: 9.6,
    },
    impact:
      "An attacker can cause the agent tool runtime to execute arbitrary shell commands in the target environment.",
    reproduction: {
      preconditions: [
        "Target is checked out at the commit above",
        "Target is running inside the detonation chamber",
      ],
      steps: [
        "Run the reproduction script from the manifest directory",
        "Observe the expected marker in stdout or chamber logs",
      ],
      script: "./scripts/repro-vendor-2026-05-001.sh",
      expected_output: "got-shell",
    },
    patch_suggestion:
      "Replace shell string execution with execFile/spawn using an argument array and server-side allowlisting.",
    disclosure: {
      channel: "security@example.com",
      sent: null,
      response_received: null,
      response_content: null,
      cvelist_candidate: true,
    },
  };

  return stringify(template);
}
