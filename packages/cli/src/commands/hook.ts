/**
 * Pre-commit hook installer.
 *
 * Installs a git pre-commit hook that runs toolsurf scan
 * before each commit. Fails the commit if critical findings exist.
 *
 * Usage:
 *   toolsurf hook install
 *   toolsurf hook uninstall
 */

import { writeFileSync, unlinkSync, existsSync, chmodSync } from "node:fs";
import { resolve } from "node:path";
import chalk from "chalk";

const HOOK_CONTENT = `#!/bin/sh
# toolsurf pre-commit hook
# Runs MCP server security audit before each commit.
# Install: toolsurf hook install
# Remove:  toolsurf hook uninstall

echo "[toolsurf] Running pre-commit security scan..."

# Check if .toolsurfrc.json exists with server config
if [ -f ".toolsurfrc.json" ]; then
  npx toolsurf scan --ci --accept 2>/dev/null
  EXIT_CODE=$?

  if [ $EXIT_CODE -eq 3 ]; then
    echo ""
    echo "[toolsurf] CRITICAL findings detected. Commit blocked."
    echo "[toolsurf] Run 'npx toolsurf scan' for details."
    exit 1
  fi

  if [ $EXIT_CODE -eq 2 ]; then
    echo "[toolsurf] WARNING: Security findings detected (non-blocking)."
  fi
else
  echo "[toolsurf] No .toolsurfrc.json found, skipping scan."
fi

exit 0
`;

export function executeHook(action: string): void {
  const gitDir = resolve(process.cwd(), ".git");
  if (!existsSync(gitDir)) {
    console.error(chalk.red("  Error: Not a git repository"));
    process.exitCode = 1;
    return;
  }

  const hookPath = resolve(gitDir, "hooks", "pre-commit");

  switch (action) {
    case "install": {
      if (existsSync(hookPath)) {
        console.log(
          chalk.yellow("  Pre-commit hook already exists. Overwriting...")
        );
      }
      writeFileSync(hookPath, HOOK_CONTENT, "utf-8");
      chmodSync(hookPath, 0o755);
      console.log(chalk.green("  Pre-commit hook installed successfully."));
      console.log(
        chalk.dim("  The hook will run toolsurf scan before each commit.")
      );
      break;
    }
    case "uninstall": {
      if (!existsSync(hookPath)) {
        console.log(chalk.dim("  No pre-commit hook found."));
        return;
      }
      unlinkSync(hookPath);
      console.log(chalk.green("  Pre-commit hook removed."));
      break;
    }
    default:
      console.error(
        chalk.red(`  Unknown action: ${action}. Use "install" or "uninstall".`)
      );
      process.exitCode = 1;
  }
}
