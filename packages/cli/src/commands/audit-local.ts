import { existsSync, readFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir, platform } from "node:os";
import chalk from "chalk";
import ora from "ora";
import { executeScan } from "./scan.js";
import { printBanner } from "../core/reporter.js";

// ─── Types ───────────────────────────────────────────────────────────────────

interface McpServerEntry {
  command: string;
  args?: string[];
  env?: Record<string, string>;
}

interface DiscoveredConfig {
  source: string;
  path: string;
  servers: Record<string, McpServerEntry>;
}

export interface AuditLocalOptions {
  active: boolean;
  compliance?: string[];
  outputDir?: string;
  timeout: number;
}

// ─── Config discovery ────────────────────────────────────────────────────────

/**
 * Known MCP config file locations per platform.
 * Each entry: [human-readable source name, absolute path]
 */
function getConfigPaths(): Array<[string, string]> {
  const home = homedir();
  const os = platform();

  const paths: Array<[string, string]> = [];

  // Claude Desktop
  if (os === "darwin") {
    paths.push(["Claude Desktop", join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")]);
  } else if (os === "win32") {
    paths.push(["Claude Desktop", join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json")]);
  } else {
    paths.push(["Claude Desktop", join(home, ".config", "claude", "claude_desktop_config.json")]);
  }

  // Claude Code (project-level and global)
  paths.push(["Claude Code (global)", join(home, ".claude.json")]);

  // Cursor
  if (os === "darwin") {
    paths.push(["Cursor", join(home, ".cursor", "mcp.json")]);
  } else if (os === "win32") {
    paths.push(["Cursor", join(home, ".cursor", "mcp.json")]);
  } else {
    paths.push(["Cursor", join(home, ".cursor", "mcp.json")]);
  }

  // Windsurf (Codeium)
  if (os === "darwin") {
    paths.push(["Windsurf", join(home, ".codeium", "windsurf", "mcp_config.json")]);
  } else if (os === "win32") {
    paths.push(["Windsurf", join(home, ".codeium", "windsurf", "mcp_config.json")]);
  } else {
    paths.push(["Windsurf", join(home, ".codeium", "windsurf", "mcp_config.json")]);
  }

  // VS Code (global MCP settings)
  if (os === "darwin") {
    paths.push(["VS Code", join(home, "Library", "Application Support", "Code", "User", "settings.json")]);
  } else if (os === "win32") {
    paths.push(["VS Code", join(home, "AppData", "Roaming", "Code", "User", "settings.json")]);
  } else {
    paths.push(["VS Code", join(home, ".config", "Code", "User", "settings.json")]);
  }

  return paths;
}

/**
 * Parse an MCP config file and extract server entries.
 */
function parseConfigFile(source: string, filePath: string): DiscoveredConfig | null {
  try {
    const raw = readFileSync(filePath, "utf-8");
    const data = JSON.parse(raw);

    // Standard format: { mcpServers: { ... } }
    let servers: Record<string, McpServerEntry> | undefined = data.mcpServers;

    // VS Code format: { "mcp.servers": { ... } } or nested
    if (!servers && data["mcp.servers"]) {
      servers = data["mcp.servers"];
    }
    if (!servers && data.mcp?.servers) {
      servers = data.mcp.servers;
    }

    if (!servers || Object.keys(servers).length === 0) {
      return null;
    }

    // Filter to only stdio servers with a command
    const stdioServers: Record<string, McpServerEntry> = {};
    for (const [name, entry] of Object.entries(servers)) {
      if (entry.command) {
        stdioServers[name] = entry;
      }
    }

    if (Object.keys(stdioServers).length === 0) {
      return null;
    }

    return { source, path: filePath, servers: stdioServers };
  } catch {
    return null;
  }
}

/**
 * Discover all local MCP configs.
 */
function discoverConfigs(): DiscoveredConfig[] {
  const configs: DiscoveredConfig[] = [];

  for (const [source, filePath] of getConfigPaths()) {
    if (existsSync(filePath)) {
      const config = parseConfigFile(source, filePath);
      if (config) {
        configs.push(config);
      }
    }
  }

  return configs;
}

// ─── Command execution ──────────────────────────────────────────────────────

/**
 * Build the server command string from an MCP server entry.
 */
function buildServerCommand(entry: McpServerEntry): string {
  const parts = [entry.command, ...(entry.args ?? [])];
  return parts.map(p => (p.includes(" ") ? `"${p}"` : p)).join(" ");
}

/**
 * Execute the audit-local command.
 */
export async function executeAuditLocal(options: AuditLocalOptions): Promise<void> {
  printBanner("Local MCP Server Audit");

  // ── Step 1: Discover configs
  const spinner = ora("Discovering local MCP configurations...").start();
  const configs = discoverConfigs();

  if (configs.length === 0) {
    spinner.fail("No MCP configurations found");
    console.log();
    console.log(chalk.dim("  Searched for configs from:"));
    for (const [source, path] of getConfigPaths()) {
      console.log(chalk.dim(`    ${source}: ${path}`));
    }
    console.log();
    console.log(chalk.dim("  Make sure you have Claude Desktop, Cursor, Windsurf, or VS Code"));
    console.log(chalk.dim("  configured with MCP servers."));
    console.log();
    return;
  }

  // Count total servers
  const totalServers = configs.reduce((sum, c) => sum + Object.keys(c.servers).length, 0);
  spinner.succeed(`Found ${totalServers} server(s) across ${configs.length} config(s)`);
  console.log();

  // ── Step 2: Show discovery results
  for (const config of configs) {
    console.log(chalk.bold(`  ${config.source}`));
    console.log(chalk.dim(`  ${config.path}`));
    for (const [name, entry] of Object.entries(config.servers)) {
      console.log(`    ${chalk.cyan(name)} ${chalk.dim("→")} ${entry.command} ${(entry.args ?? []).join(" ")}`);
    }
    console.log();
  }

  console.log(chalk.dim("  ─".repeat(30)));
  console.log();

  // ── Step 3: Prepare output dir if specified
  if (options.outputDir) {
    if (!existsSync(options.outputDir)) {
      mkdirSync(options.outputDir, { recursive: true });
    }
  }

  // ── Step 4: Scan each server
  const results: Array<{ name: string; source: string; score: number | null; error?: string }> = [];
  let serverIndex = 0;

  for (const config of configs) {
    for (const [name, entry] of Object.entries(config.servers)) {
      serverIndex++;
      const serverCommand = buildServerCommand(entry);

      console.log(chalk.bold(`  [${serverIndex}/${totalServers}] Scanning: ${name}`));
      console.log(chalk.dim(`  Source: ${config.source}`));
      console.log(chalk.dim(`  Command: ${serverCommand}`));
      console.log();

      try {
        // Build output path if output dir specified
        const outputFile = options.outputDir
          ? join(options.outputDir, `${name.replace(/[^a-zA-Z0-9_-]/g, "_")}.sarif`)
          : undefined;

        await executeScan({
          server: serverCommand,
          transport: "stdio",
          format: "terminal",
          active: options.active,
          verbose: false,
          timeout: options.timeout,
          output: outputFile,
          compliance: options.compliance,
          probeTimeout: 5000,
          probeDelay: 100,
        });

        // We don't have easy access to the score here, but the report already printed
        results.push({ name, source: config.source, score: null });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error(chalk.red(`  Error scanning ${name}: ${message}`));
        console.log();
        results.push({ name, source: config.source, score: null, error: message });
      }

      // Separator between servers
      if (serverIndex < totalServers) {
        console.log();
        console.log(chalk.dim("  ═".repeat(40)));
        console.log();
      }
    }
  }

  // ── Step 5: Summary
  console.log();
  console.log(chalk.bold("  Audit Summary"));
  console.log(chalk.dim("  ─".repeat(30)));
  console.log();

  const succeeded = results.filter(r => !r.error).length;
  const failed = results.filter(r => r.error).length;

  console.log(`  ${chalk.green(`${succeeded} server(s) scanned successfully`)}`);
  if (failed > 0) {
    console.log(`  ${chalk.red(`${failed} server(s) failed`)}`);
    for (const r of results.filter(r => r.error)) {
      console.log(chalk.red(`    ${r.name}: ${r.error}`));
    }
  }

  if (options.outputDir) {
    console.log();
    console.log(chalk.dim(`  Reports saved to: ${options.outputDir}`));
  }

  console.log();
}
