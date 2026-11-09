/**
 * Interactive Wizard — guided setup when toolsurf is run with no arguments.
 *
 * Uses Node's built-in readline/promises (zero new dependencies).
 * Walks the user through server command, profile, output format, and confirms.
 */

import { createInterface } from "node:readline/promises";
import chalk from "chalk";
import { printBanner } from "./reporter.js";
import type { ProfileName } from "./profiles.js";

export interface WizardResult {
  /** MCP server command */
  server: string;
  /** Selected scan profile */
  profile: ProfileName;
  /** Output format */
  format: "terminal" | "json" | "html" | "markdown";
  /** Optional output file path */
  output?: string;
  /** Whether the user confirmed the scan */
  confirmed: boolean;
}

export async function runWizard(): Promise<WizardResult> {
  const rl = createInterface({
    input: process.stdin,
    output: process.stderr,
  });

  try {
    printBanner("Interactive Setup");

    console.error(chalk.dim("  Answer a few questions to configure your scan.\n"));

    // ── Step 1: Server command ──────────────────────────────────────────

    console.error(chalk.bold("  Step 1: MCP Server Command"));
    console.error(
      chalk.dim('  Example: npx -y @modelcontextprotocol/server-filesystem /tmp')
    );
    console.error(
      chalk.dim('  Example: node ./my-mcp-server.js')
    );
    const server = await rl.question(chalk.cyan("\n  > Server command: "));

    if (!server.trim()) {
      console.error(chalk.red("\n  Server command is required.\n"));
      return {
        server: "",
        profile: "standard",
        format: "terminal",
        confirmed: false,
      };
    }

    console.error();

    // ── Step 2: Profile selection ───────────────────────────────────────

    console.error(chalk.bold("  Step 2: Scan Profile"));
    console.error();
    console.error(
      chalk.dim("  1) ") +
        chalk.bold("quick") +
        chalk.dim("       — passive checks only, fast (~5s)")
    );
    console.error(
      chalk.dim("  2) ") +
        chalk.bold("standard") +
        chalk.dim("    — passive + active probes (~30s)")
    );
    console.error(
      chalk.dim("  3) ") +
        chalk.bold("enterprise") +
        chalk.dim("  — full suite: compliance, TUI, autofix, summary (~60s)")
    );
    const profileChoice = await rl.question(
      chalk.cyan("\n  > Profile [1/2/3] (default: 2): ")
    );
    const profileMap: Record<string, ProfileName> = {
      "1": "quick",
      "2": "standard",
      "3": "enterprise",
      quick: "quick",
      standard: "standard",
      enterprise: "enterprise",
    };
    const profile = profileMap[profileChoice.trim().toLowerCase()] ?? "standard";
    console.error(chalk.dim(`  Selected: ${profile}\n`));

    // ── Step 3: Output format ───────────────────────────────────────────

    console.error(chalk.bold("  Step 3: Output Format"));
    console.error();
    console.error(chalk.dim("  1) terminal   2) json   3) html   4) markdown"));
    const formatChoice = await rl.question(
      chalk.cyan("\n  > Format [1/2/3/4] (default: 1): ")
    );
    const formatMap: Record<string, WizardResult["format"]> = {
      "1": "terminal",
      "2": "json",
      "3": "html",
      "4": "markdown",
      terminal: "terminal",
      json: "json",
      html: "html",
      markdown: "markdown",
    };
    const format = formatMap[formatChoice.trim().toLowerCase()] ?? "terminal";
    console.error(chalk.dim(`  Selected: ${format}\n`));

    // ── Step 4: Output file (optional) ──────────────────────────────────

    const output = await rl.question(
      chalk.cyan("  > Save report to file (press Enter to skip): ")
    );

    // ── Confirmation ────────────────────────────────────────────────────

    console.error();
    console.error(chalk.bold("  Scan Configuration:"));
    console.error(`    Server:  ${chalk.white(server.trim())}`);
    console.error(`    Profile: ${chalk.white(profile)}`);
    console.error(`    Format:  ${chalk.white(format)}`);
    if (output.trim()) {
      console.error(`    Output:  ${chalk.white(output.trim())}`);
    }
    console.error();

    const confirm = await rl.question(chalk.cyan("  > Start scan? [Y/n] "));
    const confirmed = confirm.trim().toLowerCase() !== "n";

    if (!confirmed) {
      console.error(chalk.dim("\n  Scan cancelled.\n"));
    }

    return {
      server: server.trim(),
      profile,
      format,
      output: output.trim() || undefined,
      confirmed,
    };
  } finally {
    rl.close();
  }
}
