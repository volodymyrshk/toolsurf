import { existsSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import chalk from "chalk";

const CONFIG_DIR = join(homedir(), ".toolsurf");
const ACCEPTANCE_FILE = join(CONFIG_DIR, ".accepted");
const CURRENT_VERSION = "1.0"; // Bump this to re-prompt

/**
 * Check if the user has accepted the legal notice.
 * On first run, displays the notice and requires acceptance.
 * Returns true if accepted, false if declined.
 */
export async function ensureAcceptance(): Promise<boolean> {
  // Check if already accepted
  if (existsSync(ACCEPTANCE_FILE)) {
    try {
      const content = readFileSync(ACCEPTANCE_FILE, "utf-8");
      const data = JSON.parse(content);
      if (data.version === CURRENT_VERSION) {
        return true;
      }
    } catch {
      // Corrupted file, re-prompt
    }
  }

  // Display the legal notice
  console.log();
  console.log(chalk.bold.yellow("  ⚠  TOOLSURF — FIRST RUN NOTICE"));
  console.log(chalk.dim("  ─".repeat(30)));
  console.log();
  console.log(
    chalk.white(
      "  toolsurf is a security testing tool for MCP servers.\n" +
        "  You must only scan servers you own or have explicit\n" +
        "  authorization to test.\n"
    )
  );
  console.log(
    chalk.white(
      "  The --active flag makes tool calls to the target server\n" +
        "  that may have side effects. Use only in controlled\n" +
        "  environments.\n"
    )
  );
  console.log(
    chalk.dim(
      "  Full legal notice: https://github.com/toolsurf/toolsurf/blob/main/LEGAL_NOTICE\n"
    )
  );
  console.log(
    chalk.white(
      "  By continuing, you confirm you will use toolsurf\n" +
        "  only for authorized security testing.\n"
    )
  );

  // Prompt for acceptance
  const accepted = await promptAcceptance();

  if (accepted) {
    // Persist acceptance
    try {
      if (!existsSync(CONFIG_DIR)) {
        mkdirSync(CONFIG_DIR, { recursive: true });
      }
      writeFileSync(
        ACCEPTANCE_FILE,
        JSON.stringify({
          version: CURRENT_VERSION,
          acceptedAt: new Date().toISOString(),
          hostname: process.env.HOSTNAME ?? "unknown",
        }),
        "utf-8"
      );
    } catch {
      // Non-fatal if we can't persist
    }
    console.log(chalk.green("  ✓ Accepted. This prompt won't appear again.\n"));
    return true;
  }

  console.log(chalk.red("  ✗ Declined. toolsurf will not run.\n"));
  return false;
}

/**
 * Prompt for acceptance via stdin.
 * In CI environments (no TTY), auto-accept with a warning.
 */
async function promptAcceptance(): Promise<boolean> {
  // In non-interactive environments, check for env var
  if (!process.stdin.isTTY) {
    if (process.env.TOOLSURF_ACCEPT === "true") {
      return true;
    }
    console.log(
      chalk.yellow(
        "  Non-interactive environment detected.\n" +
          "  Set TOOLSURF_ACCEPT=true to accept the legal notice.\n"
      )
    );
    return false;
  }

  // Interactive prompt
  process.stdout.write(chalk.bold("  Do you accept? [y/N] "));

  return new Promise((resolve) => {
    const stdin = process.stdin;
    stdin.setEncoding("utf-8");
    stdin.resume();

    const onData = (data: string) => {
      stdin.removeListener("data", onData);
      stdin.pause();
      const answer = data.toString().trim().toLowerCase();
      resolve(answer === "y" || answer === "yes");
    };

    stdin.on("data", onData);

    // Timeout after 60 seconds
    setTimeout(() => {
      stdin.removeListener("data", onData);
      stdin.pause();
      console.log();
      resolve(false);
    }, 60_000);
  });
}

/**
 * Skip acceptance check entirely.
 * Used when --accept flag is provided on the command line.
 */
export function forceAcceptance(): void {
  const CONFIG_DIR_PATH = join(homedir(), ".toolsurf");
  if (!existsSync(CONFIG_DIR_PATH)) {
    mkdirSync(CONFIG_DIR_PATH, { recursive: true });
  }
  writeFileSync(
    join(CONFIG_DIR_PATH, ".accepted"),
    JSON.stringify({
      version: CURRENT_VERSION,
      acceptedAt: new Date().toISOString(),
      forcedViaFlag: true,
    }),
    "utf-8"
  );
}
