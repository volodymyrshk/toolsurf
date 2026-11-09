import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

export interface CompetitorToolConfig {
  name: string;
  command: string;
  versionCommand?: string;
}

export interface AgentJuiceShopComparisonConfig {
  corpusDir?: string;
  tools: CompetitorToolConfig[];
}

export interface AgentJuiceShopComparisonOptions {
  configPath?: string;
  outputDir?: string;
  dryRun?: boolean;
  runId?: string;
}

export interface CompetitorTranscript {
  name: string;
  command: string;
  versionCommand?: string;
  versionOutput?: string;
  startedAt: string;
  durationMs: number;
  exitCode: number;
  stdoutFile: string;
  stderrFile: string;
  transcriptFile: string;
  dryRun: boolean;
}

export interface AgentJuiceShopComparisonManifest {
  version: "1.0";
  createdAt: string;
  runId: string;
  runDir: string;
  configPath?: string;
  corpusDir?: string;
  transcripts: CompetitorTranscript[];
}

export function comparisonConfigTemplate(): AgentJuiceShopComparisonConfig {
  return {
    corpusDir: "data/agent-juice-shop",
    tools: [
      {
        name: "mcp-scan",
        command: "mcp-scan --version && mcp-scan scan data/agent-juice-shop",
        versionCommand: "mcp-scan --version",
      },
      {
        name: "mcp-shield",
        command: "mcp-shield --help",
        versionCommand: "mcp-shield --version",
      },
    ],
  };
}

export function runAgentJuiceShopComparison(
  options: AgentJuiceShopComparisonOptions,
): AgentJuiceShopComparisonManifest {
  const config = loadComparisonConfig(options.configPath);
  const runId = options.runId ?? new Date().toISOString().replace(/[:.]/g, "-");
  const rootDir = resolve(options.outputDir ?? join("data", "agent-juice-shop", "comparisons"));
  const runDir = join(rootDir, runId);
  if (!existsSync(runDir)) mkdirSync(runDir, { recursive: true });

  const transcripts = config.tools.map((tool) =>
    runCompetitorTool(tool, runDir, options.dryRun === true)
  );

  const manifest: AgentJuiceShopComparisonManifest = {
    version: "1.0",
    createdAt: new Date().toISOString(),
    runId,
    runDir,
    configPath: options.configPath ? resolve(options.configPath) : undefined,
    corpusDir: config.corpusDir,
    transcripts,
  };

  writeFileSync(join(runDir, "comparison.manifest.json"), JSON.stringify(manifest, null, 2) + "\n", "utf-8");
  return manifest;
}

function loadComparisonConfig(configPath?: string): AgentJuiceShopComparisonConfig {
  if (!configPath) return comparisonConfigTemplate();
  if (!existsSync(configPath)) {
    const template = comparisonConfigTemplate();
    mkdirSync(dirname(configPath), { recursive: true });
    writeFileSync(configPath, JSON.stringify(template, null, 2) + "\n", "utf-8");
    return template;
  }
  const parsed = JSON.parse(readFileSync(configPath, "utf-8")) as AgentJuiceShopComparisonConfig;
  if (!Array.isArray(parsed.tools)) {
    throw new Error("Agent Juice Shop comparison config must contain a tools array");
  }
  for (const tool of parsed.tools) {
    if (!tool.name || !tool.command) {
      throw new Error("Each comparison tool must contain name and command");
    }
  }
  return parsed;
}

function runCompetitorTool(
  tool: CompetitorToolConfig,
  runDir: string,
  dryRun: boolean,
): CompetitorTranscript {
  const safeName = tool.name.replace(/[^a-zA-Z0-9_-]+/g, "_");
  const stdoutFile = join(runDir, `${safeName}.stdout.txt`);
  const stderrFile = join(runDir, `${safeName}.stderr.txt`);
  const transcriptFile = join(runDir, `${safeName}.transcript.json`);
  const startedAt = new Date().toISOString();
  const start = performance.now();

  let versionOutput: string | undefined;
  let stdout = "";
  let stderr = "";
  let exitCode = 0;

  if (dryRun) {
    stdout = `[dry-run] ${tool.command}\n`;
    if (tool.versionCommand) versionOutput = `[dry-run] ${tool.versionCommand}\n`;
  } else {
    if (tool.versionCommand) {
      const version = runShell(tool.versionCommand, runDir);
      versionOutput = version.stdout + version.stderr;
    }
    const result = runShell(tool.command, runDir);
    stdout = result.stdout;
    stderr = result.stderr;
    exitCode = result.exitCode;
  }

  writeFileSync(stdoutFile, stdout, "utf-8");
  writeFileSync(stderrFile, stderr, "utf-8");

  const transcript: CompetitorTranscript = {
    name: tool.name,
    command: tool.command,
    versionCommand: tool.versionCommand,
    versionOutput,
    startedAt,
    durationMs: Math.round(performance.now() - start),
    exitCode,
    stdoutFile,
    stderrFile,
    transcriptFile,
    dryRun,
  };
  writeFileSync(transcriptFile, JSON.stringify(transcript, null, 2) + "\n", "utf-8");
  return transcript;
}

function runShell(command: string, cwd: string): { stdout: string; stderr: string; exitCode: number } {
  try {
    const stdout = execFileSync("sh", ["-lc", command], {
      cwd,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { stdout, stderr: "", exitCode: 0 };
  } catch (err) {
    const error = err as { stdout?: Buffer | string; stderr?: Buffer | string; status?: number };
    return {
      stdout: bufferToString(error.stdout),
      stderr: bufferToString(error.stderr),
      exitCode: typeof error.status === "number" ? error.status : 1,
    };
  }
}

function bufferToString(value: Buffer | string | undefined): string {
  if (typeof value === "string") return value;
  if (Buffer.isBuffer(value)) return value.toString("utf-8");
  return "";
}
