import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { writeFileSync, mkdirSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";

/**
 * We test the source scanner by importing the internal analysis function.
 * Since executeScanSource is the CLI entry point, we test the pattern matching
 * through the public interface with controlled file content.
 */

const TMP_DIR = join(import.meta.dir, ".tmp-scan-source-test");
const SRC_DIR = join(TMP_DIR, "server");

beforeAll(() => {
  mkdirSync(SRC_DIR, { recursive: true });
});

afterAll(() => {
  try {
    rmSync(TMP_DIR, { recursive: true, force: true });
  } catch {}
});

function writeSource(filename: string, content: string): string {
  const path = join(SRC_DIR, filename);
  writeFileSync(path, content, "utf-8");
  return path;
}

// ── Helper: run scan-source in JSON mode and parse output ────────────────────

async function runScanSource(targetPath: string, minSeverity?: string, runtimeToolsPath?: string): Promise<any> {
  const origLog = console.log;
  const origErr = console.error;
  const origWarn = console.warn;
  const origExit = process.exitCode;
  let output = "";
  console.log = (msg: string) => { output += msg + "\n"; };
  console.error = () => {};
  console.warn = () => {};

  // Dynamic import to get fresh module
  const { executeScanSource } = await import("../../src/commands/scan-source.js");
  await executeScanSource({
    path: targetPath,
    format: "json",
    minSeverity,
    runtimeToolsPath,
  });

  console.log = origLog;
  console.error = origErr;
  console.warn = origWarn;

  const exitCode = process.exitCode;
  process.exitCode = origExit ?? 0;

  try {
    // Extract JSON from output (skip spinner output)
    const jsonStart = output.indexOf("{");
    const jsonContent = output.slice(jsonStart);
    return { report: JSON.parse(jsonContent), exitCode };
  } catch {
    return { report: null, output, exitCode };
  }
}

// ─── Detection Tests ────────────────────────────────────────────────────────

describe("scan-source — command injection detection", () => {
  test("detects exec() with string interpolation", async () => {
    writeSource("cmd-inject.ts", `
import { exec } from "child_process";

server.tool("run_command", "Execute a command", { command: z.string() }, async ({ command }) => {
  const result = exec(\`ls \${args.path}\`);
  return { content: [{ type: "text", text: result }] };
});
`);

    const { report } = await runScanSource(SRC_DIR);
    const cmdFindings = report.findings.filter((f: any) => f.id === "SRC-001" || f.id === "SRC-002");
    expect(cmdFindings.length).toBeGreaterThanOrEqual(1);
  });

  test("detects exec() usage in general", async () => {
    writeSource("exec-general.ts", `
const { exec } = require("child_process");
exec("echo hello");
`);

    const { report } = await runScanSource(SRC_DIR);
    const execFindings = report.findings.filter(
      (f: any) => f.id === "SRC-002" && f.file.includes("exec-general")
    );
    expect(execFindings.length).toBeGreaterThanOrEqual(1);
  });
});

describe("scan-source — hardcoded secrets", () => {
  test("detects hardcoded API keys", async () => {
    writeSource("secrets.ts", `
const config = {
  api_key: "my_fake_generic_key_string_that_is_long_enough", // Fake test key
  database: "postgres://localhost/mydb",
};
`);

    const { report } = await runScanSource(SRC_DIR);
    const secretFindings = report.findings.filter(
      (f: any) => f.id === "SRC-004" && f.file.includes("secrets")
    );
    expect(secretFindings.length).toBeGreaterThanOrEqual(1);
  });

  test("detects hardcoded auth tokens", async () => {
    writeSource("tokens.ts", `
const auth_token = "my_fake_generic_token_string_that_is_long_enough"; // Fake token
`);

    const { report } = await runScanSource(SRC_DIR);
    const tokenFindings = report.findings.filter(
      (f: any) => f.id === "SRC-004" && f.file.includes("tokens")
    );
    expect(tokenFindings.length).toBeGreaterThanOrEqual(1);
  });
});

describe("scan-source — SSRF / network access", () => {
  test("detects fetch() with user input as URL", async () => {
    writeSource("ssrf.ts", `
server.tool("fetch_url", "Fetch a URL", {}, async (args) => {
  const response = await fetch(args.url);
  return { text: await response.text() };
});
`);

    const { report } = await runScanSource(SRC_DIR);
    const ssrfFindings = report.findings.filter(
      (f: any) => f.id === "SRC-007" && f.file.includes("ssrf")
    );
    expect(ssrfFindings.length).toBeGreaterThanOrEqual(1);
  });
});

describe("scan-source — SQL injection", () => {
  test("detects SQL with string interpolation", async () => {
    writeSource("sqli.ts", `
async function queryUser(args: any) {
  const result = await db.query(\`SELECT * FROM users WHERE name = '\${args.name}'\`);
  return result;
}
`);

    const { report } = await runScanSource(SRC_DIR);
    const sqliFindings = report.findings.filter(
      (f: any) => f.id === "SRC-008" && f.file.includes("sqli")
    );
    expect(sqliFindings.length).toBeGreaterThanOrEqual(1);
  });
});

describe("scan-source — eval / code execution", () => {
  test("detects eval() usage", async () => {
    writeSource("eval.ts", `
function processExpression(input: string) {
  return eval(input);
}
`);

    const { report } = await runScanSource(SRC_DIR);
    const evalFindings = report.findings.filter(
      (f: any) => f.id === "SRC-010" && f.file.includes("eval")
    );
    expect(evalFindings.length).toBeGreaterThanOrEqual(1);
  });

  test("detects new Function() constructor", async () => {
    writeSource("func-constructor.ts", `
const handler = new Function("args", "return args.value * 2");
`);

    const { report } = await runScanSource(SRC_DIR);
    const funcFindings = report.findings.filter(
      (f: any) => f.id === "SRC-010" && f.file.includes("func-constructor")
    );
    expect(funcFindings.length).toBeGreaterThanOrEqual(1);
  });
});

describe("scan-source — Python detection", () => {
  test("detects os.system in Python", async () => {
    writeSource("dangerous.py", `
import os

def execute_tool(args):
    os.system(f"ls {args['path']}")
`);

    const { report } = await runScanSource(SRC_DIR);
    const pyFindings = report.findings.filter(
      (f: any) => f.id === "SRC-011" && f.file.includes("dangerous.py")
    );
    expect(pyFindings.length).toBeGreaterThanOrEqual(1);
  });

  test("detects pickle.loads in Python", async () => {
    writeSource("pickle-use.py", `
import pickle

def handle_data(raw_bytes):
    return pickle.loads(raw_bytes)
`);

    const { report } = await runScanSource(SRC_DIR);
    const pickleFindings = report.findings.filter(
      (f: any) => f.id === "SRC-012" && f.file.includes("pickle-use.py")
    );
    expect(pickleFindings.length).toBeGreaterThanOrEqual(1);
  });
});

describe("scan-source — environment exposure", () => {
  test("detects JSON.stringify(process.env)", async () => {
    writeSource("env-leak.ts", `
server.tool("env", "Get environment", {}, async () => {
  return { text: JSON.stringify(process.env) };
});
`);

    const { report } = await runScanSource(SRC_DIR);
    const envFindings = report.findings.filter(
      (f: any) => f.id === "SRC-014" && f.file.includes("env-leak")
    );
    expect(envFindings.length).toBeGreaterThanOrEqual(1);
  });
});

describe("scan-source — overly permissive paths", () => {
  test("detects root directory exposure", async () => {
    writeSource("root-path.ts", `
const allowedDir = "/";
`);

    const { report } = await runScanSource(SRC_DIR);
    const pathFindings = report.findings.filter(
      (f: any) => f.id === "SRC-013" && f.file.includes("root-path")
    );
    expect(pathFindings.length).toBeGreaterThanOrEqual(1);
  });
});

describe("scan-source — clean files", () => {
  test("reports no findings for safe code", async () => {
    // Create a clean temp dir with only a safe file
    const cleanDir = join(TMP_DIR, "clean-server");
    mkdirSync(cleanDir, { recursive: true });
    writeFileSync(
      join(cleanDir, "safe.ts"),
      `
import { Server } from "@modelcontextprotocol/sdk/server/index.js";

const server = new Server({ name: "safe-server", version: "1.0.0" });

// A simple safe utility — no tool registration, no security patterns
function greetUser(name: string): string {
  const sanitized = name.replace(/[^a-zA-Z]/g, "");
  return "Hello " + sanitized;
}
export { greetUser };
`,
      "utf-8"
    );

    const { report } = await runScanSource(cleanDir);
    expect(report.findings).toHaveLength(0);
  });
});

describe("scan-source — severity filtering", () => {
  test("filters by minimum severity", async () => {
    const filteredDir = join(TMP_DIR, "filter-server");
    mkdirSync(filteredDir, { recursive: true });
    writeFileSync(
      join(filteredDir, "mixed.ts"),
      `
eval("hello");
const allowedDir = "/";
`,
      "utf-8"
    );

    const { report: fullReport } = await runScanSource(filteredDir);
    const { report: filteredReport } = await runScanSource(filteredDir, "CRITICAL");

    // Full report should have more findings than CRITICAL-only
    expect(fullReport.findings.length).toBeGreaterThanOrEqual(filteredReport.findings.length);
    // All filtered findings should be CRITICAL
    for (const f of filteredReport.findings) {
      expect(f.severity).toBe("CRITICAL");
    }
  });
});

describe("scan-source — output format", () => {
  test("JSON output contains expected fields", async () => {
    const { report } = await runScanSource(SRC_DIR);
    expect(report.type).toBe("source-analysis");
    expect(report.timestamp).toBeDefined();
    expect(report.filesScanned).toBeGreaterThan(0);
    expect(report.rulesChecked).toBeGreaterThan(0);
    expect(typeof report.durationMs).toBe("number");
    expect(Array.isArray(report.findings)).toBe(true);
    expect(report.summary).toBeDefined();
    expect(report.summary.total).toBe(report.findings.length);
    expect(Array.isArray(report.extractedTools)).toBe(true);
  });

  test("findings contain file, line, code context", async () => {
    const { report } = await runScanSource(SRC_DIR);
    if (report.findings.length > 0) {
      const f = report.findings[0];
      expect(f.file).toBeDefined();
      expect(typeof f.line).toBe("number");
      expect(f.code).toBeDefined();
      expect(f.severity).toBeDefined();
      expect(f.title).toBeDefined();
      expect(f.remediation).toBeDefined();
    }
  });

  test("JSON output includes AST-extracted tools and source/runtime diff findings", async () => {
    const diffDir = join(TMP_DIR, "runtime-diff-server");
    mkdirSync(diffDir, { recursive: true });
    writeFileSync(
      join(diffDir, "server.ts"),
      `
server.tool(
  "source_tool",
  "Source declared tool",
  { type: "object", properties: {} },
  { annotations: { readOnlyHint: true } },
  async () => ({ ok: true })
);
`,
      "utf-8"
    );
    const runtimeToolsPath = join(diffDir, "runtime-tools.json");
    writeFileSync(
      runtimeToolsPath,
      JSON.stringify({
        tools: [
          {
            name: "source_tool",
            inputSchema: {},
            annotations: { destructiveHint: true },
          },
          {
            name: "runtime_only",
            inputSchema: {},
          },
        ],
      }),
      "utf-8"
    );

    const { report } = await runScanSource(diffDir, undefined, runtimeToolsPath);

    expect(report.extractedTools.map((tool: any) => tool.name)).toContain("source_tool");
    expect(report.runtimeDiff.missingInSource).toEqual(["runtime_only"]);
    expect(report.runtimeDiff.annotationDiffs.length).toBeGreaterThanOrEqual(1);
    expect(report.findings.map((finding: any) => finding.id)).toContain("SRC-AST-005");
    expect(report.findings.map((finding: any) => finding.id)).toContain("SRC-AST-006");
  });
});

describe("scan-source — MCP registration risk rules", () => {
  test("flags high-risk metadata-table registrations marked read-only", async () => {
    const regDir = join(TMP_DIR, "mcp-reg-server");
    mkdirSync(regDir, { recursive: true });
    writeFileSync(
      join(regDir, "server.ts"),
      `
const paymentTools = {
  capture_payment: {
    name: "capture_payment",
    description: "Capture a payment for an order",
    annotations: { readOnlyHint: true, destructiveHint: false },
    inputSchema: { type: "object", properties: { orderId: { type: "string" } } },
  },
};

const register = server["tool"].bind(server);
register(paymentTools.capture_payment, async ({ orderId }) => {
  return await payments.capture(orderId);
});
`,
      "utf-8"
    );

    const { report } = await runScanSource(regDir);
    const ids = report.findings.map((finding: any) => finding.id);

    expect(report.extractedTools.map((tool: any) => tool.name)).toContain("capture_payment");
    expect(ids).toContain("MCP-REG-002");
    expect(ids).toContain("MCP-REG-003");
  });

  test("flags high-risk this.tool registrations with missing annotations", async () => {
    const regDir = join(TMP_DIR, "mcp-reg-missing-annotations");
    mkdirSync(regDir, { recursive: true });
    writeFileSync(
      join(regDir, "server.ts"),
      `
class PaymentServer {
  register() {
    this.tool("refund_payment", "Refund a payment", { type: "object", properties: {} }, async () => {
      return { ok: true };
    });
  }
}
`,
      "utf-8"
    );

    const { report } = await runScanSource(regDir);
    expect(report.findings.map((finding: any) => finding.id)).toContain("MCP-REG-001");
  });
});

describe("scan-source — exit codes", () => {
  test("exit code 3 for CRITICAL findings", async () => {
    const critDir = join(TMP_DIR, "critical-server");
    mkdirSync(critDir, { recursive: true });
    writeFileSync(
      join(critDir, "eval-danger.ts"),
      `eval("dangerous");\n`,
      "utf-8"
    );

    const { exitCode } = await runScanSource(critDir);
    expect(exitCode).toBe(3);
  });
});
