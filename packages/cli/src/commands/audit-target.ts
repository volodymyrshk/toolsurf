import chalk from "chalk";
import { createTargetAudit, type AuditTargetOptions, type TargetManifest } from "../core/target-connector.js";

export async function executeAuditTarget(options: AuditTargetOptions): Promise<TargetManifest> {
  const manifest = createTargetAudit(options);

  console.log(chalk.green(`  Target manifest: ${manifest.artifacts.manifest}`));
  console.log(chalk.dim(`  Target:          ${manifest.name}`));
  console.log(chalk.dim(`  Repo:            ${manifest.repo}`));
  if (manifest.commit) console.log(chalk.dim(`  Commit:          ${manifest.commit}`));
  console.log(chalk.dim(`  Mode:            ${manifest.executionMode}`));
  if (manifest.chamber) {
    console.log(chalk.dim(`  Chamber:         ${manifest.chamber.manifest}`));
  }
  if (!options.execute) {
    console.log(chalk.yellow("  Planned only. Pass --execute to clone/build the target."));
  }

  return manifest;
}
