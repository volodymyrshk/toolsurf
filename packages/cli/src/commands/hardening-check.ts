/**
 * Hardening Guard Script.
 *
 * Automated pre-flight check that verifies the instrument meets
 * research-readiness criteria. Run before publishing results or
 * cutting a release to ensure scoring integrity.
 *
 * Usage:
 *   toolsurf hardening-check
 *   toolsurf hardening-check --verbose
 *
 * Outputs: ALL PASS / BLOCKED: [reason] / CONDITIONALLY CLEARED: [notes]
 */

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import chalk from "chalk";

export interface HardeningCheckOptions {
  verbose?: boolean;
}

interface CheckResult {
  name: string;
  status: "PASS" | "FAIL" | "WARN";
  detail: string;
}

const THIS_DIR = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = join(THIS_DIR, "..", "..");
const SRC_DIR = join(PKG_ROOT, "src");
const TEST_DIR = join(PKG_ROOT, "tests");

export async function runHardeningCheck(options: HardeningCheckOptions = {}): Promise<void> {
  const results: CheckResult[] = [];

  // 1. Anchor fixtures exist
  results.push(checkAnchorFixtures());

  // 2. Calibration / scorer / dedup suites pass
  results.push(checkCalibrationSuites());

  // 3. Adversarial bypass suite passes
  results.push(checkAdversarialBypassSuite());

  // 4. TypeScript compilation passes
  results.push(checkTypeScriptCompilation());

  // 5. Full test suite passes
  results.push(checkFullTestSuite());

  // 6. finding.yaml + repro-check workflow stays covered
  results.push(checkReproWorkflowCoverage());

  // 7. TS/JS source extraction stays covered
  results.push(checkSourceExtractionCoverage());

  // 8. Multiprotocol behavior proofs stay covered
  results.push(checkMultiprotocolBehaviorCoverage());

  // 9. Built-in module catalog cannot drift from scan/list-modules
  results.push(checkModuleCatalogCoverage());

  // 10. Agent Juice Shop benchmark stays covered
  results.push(checkAgentJuiceShopCoverage());

  // 11. No Math.random() in score-bearing source
  results.push(checkNoUnseededRandom());

  // 12. All modules have test coverage
  results.push(checkModuleTestCoverage());

  // 13. All adapters have test coverage
  results.push(checkAdapterTestCoverage());

  // 14. All active modules have explicit risk mappings
  results.push(checkActiveModuleRiskMappings());

  // 15. Deduplicator has false-dedup tests
  results.push(checkDedupTests());

  // 16. Config hash in provenance
  results.push(checkConfigHashProvenance());

  // 17. Calibration status is derived, not hardcoded
  results.push(checkCalibrationNotHardcoded());

  // Print results
  console.log("\n" + chalk.bold("Instrument Hardening Check"));
  console.log("═".repeat(50));

  for (const r of results) {
    const icon =
      r.status === "PASS" ? chalk.green("✓") :
      r.status === "WARN" ? chalk.yellow("⚠") :
      chalk.red("✗");
    const statusColor =
      r.status === "PASS" ? chalk.green(r.status) :
      r.status === "WARN" ? chalk.yellow(r.status) :
      chalk.red(r.status);

    console.log(`  ${icon} ${statusColor}  ${r.name}`);
    if (options.verbose || r.status !== "PASS") {
      console.log(`         ${chalk.dim(r.detail)}`);
    }
  }

  console.log("═".repeat(50));

  const fails = results.filter((r) => r.status === "FAIL");
  const warns = results.filter((r) => r.status === "WARN");

  if (fails.length > 0) {
    console.log(chalk.red.bold(`\nBLOCKED: ${fails.length} check(s) failed`));
    for (const f of fails) {
      console.log(chalk.red(`  - ${f.name}: ${f.detail}`));
    }
    process.exitCode = 1;
  } else if (warns.length > 0) {
    console.log(chalk.yellow.bold(`\nCONDITIONALLY CLEARED: ${warns.length} warning(s)`));
    for (const w of warns) {
      console.log(chalk.yellow(`  - ${w.name}: ${w.detail}`));
    }
  } else {
    console.log(chalk.green.bold("\nALL PASS — instrument is research-ready"));
  }
}

function checkAnchorFixtures(): CheckResult {
  const anchorsDir = join(TEST_DIR, "fixtures", "anchors");
  const required = ["anchor-floor.json", "anchor-midpoint.json", "anchor-ceiling.json"];
  const missing = required.filter((f) => !existsSync(join(anchorsDir, f)));

  if (missing.length > 0) {
    return { name: "Anchor fixtures", status: "FAIL", detail: `Missing: ${missing.join(", ")}` };
  }

  // Verify anchor semantics (floor=dangerous, ceiling=clean)
  try {
    const floor = JSON.parse(readFileSync(join(anchorsDir, "anchor-floor.json"), "utf-8"));
    const ceiling = JSON.parse(readFileSync(join(anchorsDir, "anchor-ceiling.json"), "utf-8"));
    if (floor._meta?.anchor !== "BENCHMARK_FLOOR" || ceiling._meta?.anchor !== "BENCHMARK_CEILING") {
      return { name: "Anchor fixtures", status: "FAIL", detail: "Anchor labels don't match filenames" };
    }
  } catch {
    return { name: "Anchor fixtures", status: "FAIL", detail: "Failed to parse anchor JSON" };
  }

  return { name: "Anchor fixtures", status: "PASS", detail: "All 3 anchors present with correct labels" };
}

function runBunTestCheck(
  name: string,
  testFiles: string[],
  successDetail: string,
): CheckResult {
  for (const file of testFiles) {
    if (!existsSync(join(PKG_ROOT, file))) {
      return {
        name,
        status: "FAIL",
        detail: `Missing test file: ${file}`,
      };
    }
  }

  try {
    execFileSync(
      "bun",
      ["test", ...testFiles],
      {
        cwd: PKG_ROOT,
        encoding: "utf-8",
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    return { name, status: "PASS", detail: successDetail };
  } catch (err) {
    const stdout = typeof err === "object" && err && "stdout" in err ? String((err as { stdout?: string }).stdout ?? "") : "";
    const stderr = typeof err === "object" && err && "stderr" in err ? String((err as { stderr?: string }).stderr ?? "") : "";
    const tail = `${stdout}\n${stderr}`.trim().split("\n").filter(Boolean).slice(-8).join(" | ");
    return {
      name,
      status: "FAIL",
      detail: tail || "bun test failed",
    };
  }
}

function checkCalibrationSuites(): CheckResult {
  return runBunTestCheck(
    "Calibration suites",
    [
      "tests/core/calibration.test.ts",
      "tests/core/scorer.test.ts",
      "tests/core/deduplicator.test.ts",
    ],
    "Calibration, scorer, and dedup suites passed",
  );
}

function checkAdversarialBypassSuite(): CheckResult {
  return runBunTestCheck(
    "Adversarial bypass suite",
    ["tests/core/adversarial-bypass.test.ts"],
    "Adversarial D3 bypass coverage passed",
  );
}

function runBunCommandCheck(
  name: string,
  args: string[],
  successDetail: string,
): CheckResult {
  try {
    execFileSync(
      "bun",
      args,
      {
        cwd: PKG_ROOT,
        encoding: "utf-8",
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    return { name, status: "PASS", detail: successDetail };
  } catch (err) {
    const stdout = typeof err === "object" && err && "stdout" in err ? String((err as { stdout?: string }).stdout ?? "") : "";
    const stderr = typeof err === "object" && err && "stderr" in err ? String((err as { stderr?: string }).stderr ?? "") : "";
    const tail = `${stdout}\n${stderr}`.trim().split("\n").filter(Boolean).slice(-8).join(" | ");
    return {
      name,
      status: "FAIL",
      detail: tail || `bun ${args.join(" ")} failed`,
    };
  }
}

function checkTypeScriptCompilation(): CheckResult {
  return runBunCommandCheck(
    "TypeScript compilation",
    ["run", "typecheck"],
    "tsc --noEmit passed",
  );
}

function checkFullTestSuite(): CheckResult {
  const testFiles = listProjectTestFiles();
  if (testFiles.length === 0) {
    return {
      name: "Full test suite",
      status: "FAIL",
      detail: "No project test files found under tests/",
    };
  }

  return runBunCommandCheck(
    "Full test suite",
    ["test", ...testFiles],
    "All tests passed",
  );
}

function listProjectTestFiles(): string[] {
  const files: string[] = [];

  function walk(dir: string): void {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(path);
      } else if (entry.isFile() && /\.(?:test|spec)\.ts$/.test(entry.name)) {
        files.push(relative(PKG_ROOT, path));
      }
    }
  }

  walk(TEST_DIR);
  return files.sort();
}

function checkReproWorkflowCoverage(): CheckResult {
  const requiredSource = [
    "src/core/finding-manifest.ts",
    "src/commands/repro-check.ts",
  ];
  for (const file of requiredSource) {
    if (!existsSync(join(PKG_ROOT, file))) {
      return {
        name: "Reproduction workflow coverage",
        status: "FAIL",
        detail: `Missing source file: ${file}`,
      };
    }
  }

  return runBunTestCheck(
    "Reproduction workflow coverage",
    [
      "tests/core/finding-manifest.test.ts",
      "tests/commands/repro-check.test.ts",
    ],
    "finding.yaml schema and repro-check command tests passed",
  );
}

function checkSourceExtractionCoverage(): CheckResult {
  const requiredSource = [
    "src/core/source-tool-extractor.ts",
    "src/commands/scan-source.ts",
  ];
  for (const file of requiredSource) {
    if (!existsSync(join(PKG_ROOT, file))) {
      return {
        name: "Source extraction coverage",
        status: "FAIL",
        detail: `Missing source file: ${file}`,
      };
    }
  }

  return runBunTestCheck(
    "Source extraction coverage",
    [
      "tests/core/source-tool-extractor.test.ts",
      "tests/commands/scan-source.test.ts",
    ],
    "AST tool extraction and scan-source runtime diff tests passed",
  );
}

function checkMultiprotocolBehaviorCoverage(): CheckResult {
  return runBunTestCheck(
    "Multiprotocol behavior proofs",
    [
      "tests/core/regression-corpus.test.ts",
      "tests/core/multiprotocol-behavior.test.ts",
    ],
    "Regression corpus and multiprotocol behavior tests passed",
  );
}

function checkModuleCatalogCoverage(): CheckResult {
  const requiredSource = [
    "src/core/module-catalog.ts",
  ];
  for (const file of requiredSource) {
    if (!existsSync(join(PKG_ROOT, file))) {
      return {
        name: "Module catalog coverage",
        status: "FAIL",
        detail: `Missing source file: ${file}`,
      };
    }
  }

  return runBunTestCheck(
    "Module catalog coverage",
    ["tests/core/module-catalog.test.ts"],
    "Module catalog completeness and mode partition tests passed",
  );
}

function checkAgentJuiceShopCoverage(): CheckResult {
  const requiredSource = [
    "src/core/agent-juice-shop.ts",
    "src/commands/agent-juice-shop.ts",
  ];
  for (const file of requiredSource) {
    if (!existsSync(join(PKG_ROOT, file))) {
      return {
        name: "Agent Juice Shop benchmark",
        status: "FAIL",
        detail: `Missing source file: ${file}`,
      };
    }
  }

  return runBunTestCheck(
    "Agent Juice Shop benchmark",
    [
      "tests/core/agent-juice-shop.test.ts",
      "tests/commands/agent-juice-shop.test.ts",
    ],
    "Benchmark corpus, report rendering, and CLI command tests passed",
  );
}

function checkNoUnseededRandom(): CheckResult {
  const scoreBearingPaths = [
    join(SRC_DIR, "core", "scorer.ts"),
    join(SRC_DIR, "core", "confidence.ts"),
    join(SRC_DIR, "core", "deduplicator.ts"),
    join(SRC_DIR, "core", "module-runner.ts"),
  ];

  const violations: string[] = [];
  for (const filePath of scoreBearingPaths) {
    if (!existsSync(filePath)) continue;
    const content = readFileSync(filePath, "utf-8");
    if (content.includes("Math.random()")) {
      const basename = filePath.split("/").pop();
      violations.push(basename!);
    }
  }

  // Also check all modules
  const sourceDirs = [
    join(SRC_DIR, "modules"),
    join(SRC_DIR, "adapters"),
  ];
  for (const sourceDir of sourceDirs) {
    if (!existsSync(sourceDir)) continue;
    for (const file of readdirSync(sourceDir).filter((f) => f.endsWith(".ts"))) {
      const content = readFileSync(join(sourceDir, file), "utf-8");
      if (content.includes("Math.random()")) {
        violations.push(file);
      }
    }
  }

  if (violations.length > 0) {
    return {
      name: "No unseeded Math.random()",
      status: "FAIL",
      detail: `Found in: ${violations.join(", ")}. Use crypto.randomUUID() instead.`,
    };
  }

  return { name: "No unseeded Math.random()", status: "PASS", detail: "No uncontrolled randomness in score paths" };
}

function checkActiveModuleRiskMappings(): CheckResult {
  const modulesDir = join(SRC_DIR, "modules");
  const targetProfilePath = join(SRC_DIR, "core", "target-profile.ts");

  if (!existsSync(modulesDir) || !existsSync(targetProfilePath)) {
    return { name: "Active module risk mappings", status: "FAIL", detail: "Module directory or target-profile.ts missing" };
  }

  const targetProfileContent = readFileSync(targetProfilePath, "utf-8");
  if (!targetProfileContent.includes('?? "high"')) {
    return {
      name: "Active module risk mappings",
      status: "FAIL",
      detail: "Unknown module risk must default to high, not low",
    };
  }

  const missing: string[] = [];
  for (const file of readdirSync(modulesDir).filter((f) => f.endsWith(".ts"))) {
    const content = readFileSync(join(modulesDir, file), "utf-8");
    if (!content.includes('mode = "active"')) continue;

    const idMatch = content.match(/\bid\s*=\s*"([^"]+)"/);
    const moduleId = idMatch?.[1];
    if (!moduleId) {
      missing.push(`${file}:missing-id`);
      continue;
    }

    if (!targetProfileContent.includes(`"${moduleId}"`)) {
      missing.push(`${moduleId} (${file})`);
    }
  }

  if (missing.length > 0) {
    return {
      name: "Active module risk mappings",
      status: "FAIL",
      detail: `Missing explicit risk mapping for: ${missing.join(", ")}`,
    };
  }

  return { name: "Active module risk mappings", status: "PASS", detail: "Every active module has an explicit risk mapping; unknowns default high" };
}

function checkModuleTestCoverage(): CheckResult {
  const modulesDir = join(SRC_DIR, "modules");
  const testModulesDir = join(TEST_DIR, "modules");

  if (!existsSync(modulesDir) || !existsSync(testModulesDir)) {
    return { name: "Module test coverage", status: "FAIL", detail: "Module or test directory missing" };
  }

  const modules = readdirSync(modulesDir).filter((f) => f.endsWith(".ts"));
  const tests = new Set(readdirSync(testModulesDir).filter((f) => f.endsWith(".test.ts")));

  const untested: string[] = [];
  for (const mod of modules) {
    const testName = mod.replace(".ts", ".test.ts");
    if (!tests.has(testName)) {
      untested.push(mod);
    }
  }

  if (untested.length > 0) {
    return {
      name: "Module test coverage",
      status: "FAIL",
      detail: `${untested.length} module(s) without tests: ${untested.join(", ")}`,
    };
  }

  return {
    name: "Module test coverage",
    status: "PASS",
    detail: `${modules.length} modules, ${tests.size} test files`,
  };
}

function checkAdapterTestCoverage(): CheckResult {
  const adaptersDir = join(SRC_DIR, "adapters");
  const testAdaptersDir = join(TEST_DIR, "adapters");

  if (!existsSync(adaptersDir) || !existsSync(testAdaptersDir)) {
    return { name: "Adapter test coverage", status: "FAIL", detail: "Adapter or adapter test directory missing" };
  }

  const adapters = readdirSync(adaptersDir)
    .filter((f) => f.endsWith("-adapter.ts"))
    .sort();
  const tests = new Set(readdirSync(testAdaptersDir).filter((f) => f.endsWith(".test.ts")));

  const untested = adapters
    .map((adapter) => adapter.replace(".ts", ".test.ts"))
    .filter((testName) => !tests.has(testName));

  if (untested.length > 0) {
    return {
      name: "Adapter test coverage",
      status: "FAIL",
      detail: `${untested.length} adapter(s) without tests: ${untested.join(", ")}`,
    };
  }

  return {
    name: "Adapter test coverage",
    status: "PASS",
    detail: `${adapters.length} adapters, ${tests.size} adapter test files`,
  };
}

function checkDedupTests(): CheckResult {
  const dedupTestPath = join(TEST_DIR, "core", "deduplicator.test.ts");
  if (!existsSync(dedupTestPath)) {
    return { name: "Deduplicator tests", status: "FAIL", detail: "tests/core/deduplicator.test.ts missing" };
  }

  const content = readFileSync(dedupTestPath, "utf-8");
  const hasFalseDedupTests = content.includes("false") && content.includes("dedup");

  if (!hasFalseDedupTests) {
    return { name: "Deduplicator tests", status: "WARN", detail: "No explicit false-dedup test cases found" };
  }

  return { name: "Deduplicator tests", status: "PASS", detail: "Dedup tests with false-dedup cases present" };
}

function checkConfigHashProvenance(): CheckResult {
  const scanPath = join(SRC_DIR, "commands", "scan.ts");
  if (!existsSync(scanPath)) {
    return { name: "Config hash in provenance", status: "FAIL", detail: "scan.ts not found" };
  }

  const content = readFileSync(scanPath, "utf-8");
  if (!content.includes("configHash")) {
    return { name: "Config hash in provenance", status: "FAIL", detail: "No configHash found in scan.ts" };
  }

  return { name: "Config hash in provenance", status: "PASS", detail: "configHash embedded in scan output" };
}

function checkCalibrationNotHardcoded(): CheckResult {
  const scanPath = join(SRC_DIR, "commands", "scan.ts");
  if (!existsSync(scanPath)) {
    return { name: "Calibration status", status: "FAIL", detail: "scan.ts not found" };
  }

  const content = readFileSync(scanPath, "utf-8");

  // Check that calibrationStatus is NOT a hardcoded string literal
  if (/calibrationStatus:\s*"CALIBRATED"/.test(content)) {
    return {
      name: "Calibration status",
      status: "FAIL",
      detail: 'calibrationStatus is hardcoded to "CALIBRATED" — must be derived from evidence',
    };
  }

  if (
    content.includes("deriveCalibrationStatus") &&
    content.includes("JSON.parse(raw)") &&
    content.includes("calculateScore([dummy])")
  ) {
    return { name: "Calibration status", status: "PASS", detail: "Derived from parsed anchor fixtures plus scoring smoke-tests" };
  }

  return { name: "Calibration status", status: "WARN", detail: "calibrationStatus origin unclear" };
}
