import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import chalk from "chalk";
import {
  comparisonConfigTemplate,
  runAgentJuiceShopComparison,
  type AgentJuiceShopComparisonManifest,
} from "../core/agent-juice-shop-compare.js";

export interface AgentJuiceShopCompareCommandOptions {
  config?: string;
  outputDir?: string;
  dryRun?: boolean;
  init?: string | boolean;
}

export async function executeAgentJuiceShopCompare(
  options: AgentJuiceShopCompareCommandOptions,
): Promise<AgentJuiceShopComparisonManifest | void> {
  if (options.init) {
    const template = JSON.stringify(comparisonConfigTemplate(), null, 2) + "\n";
    if (typeof options.init === "string") {
      mkdirSync(dirname(options.init), { recursive: true });
      writeFileSync(options.init, template, "utf-8");
      console.log(chalk.green(`  Wrote comparison config template: ${options.init}`));
    } else {
      console.log(template);
    }
    return;
  }

  const manifest = runAgentJuiceShopComparison({
    configPath: options.config,
    outputDir: options.outputDir,
    dryRun: options.dryRun,
  });

  console.log(chalk.green(`  Comparison manifest: ${manifest.runDir}/comparison.manifest.json`));
  for (const transcript of manifest.transcripts) {
    const status = transcript.exitCode === 0 ? chalk.green("ok") : chalk.red(`exit ${transcript.exitCode}`);
    console.log(`  ${status} ${transcript.name} -> ${transcript.transcriptFile}`);
  }

  return manifest;
}
