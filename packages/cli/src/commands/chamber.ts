import chalk from "chalk";
import {
  type ChamberManifest,
  type ChamberTargetSpec,
} from "../core/detonation-chamber.js";
import { ChamberRuntime } from "../core/chamber-runtime.js";

export interface ChamberCommandOptions {
  action: "init" | "up" | "down" | "logs";
  name?: string;
  outputDir?: string;
  runDir?: string;
  runDocker?: boolean;
  targetImage?: string;
  targetBuild?: string;
  targetDockerfile?: string;
  targetCommand?: string;
  targetPorts?: string[];
  targetReadWrite?: boolean;
}

export async function executeChamber(options: ChamberCommandOptions): Promise<ChamberManifest | void> {
  if (options.action === "init" || options.action === "up") {
    if (!validateTargetOptions(options)) {
      return;
    }

    const runtime = ChamberRuntime.create({
      name: options.name,
      outputDir: options.outputDir,
      target: targetFromOptions(options),
    });
    const manifest = runtime.manifest;

    console.log(chalk.green(`  Chamber manifest: ${manifest.runDir}/chamber.manifest.json`));
    console.log(chalk.dim(`  Compose file:      ${manifest.composeFile}`));
    console.log(chalk.dim(`  Fake HTTP:         ${manifest.services.fakeHttp.url}`));
    console.log(chalk.dim(`  Fake metadata:     ${manifest.services.fakeMetadata.url}`));
    console.log(chalk.dim(`  Fake SMTP:         ${manifest.services.fakeSmtp.host}:${manifest.services.fakeSmtp.port}`));
    console.log(chalk.dim(`  Fake DNS:          ${manifest.services.fakeDns.host}:${manifest.services.fakeDns.port}`));

    if (options.action === "up" && options.runDocker !== false) {
      if (runDockerCompose(runtime, ["up", "-d"])) {
        console.log(chalk.green("  Chamber containers started"));
      }
    } else if (options.action === "up") {
      console.log(chalk.yellow("  Docker execution skipped; compose artifacts were generated only."));
    }

    return manifest;
  }

  if (!options.runDir) {
    throw new Error(`chamber ${options.action} requires --run-dir`);
  }

  const runtime = ChamberRuntime.load(options.runDir);
  const manifest = runtime.manifest;
  if (options.action === "down") {
    if (runDockerCompose(runtime, ["down", "--remove-orphans"])) {
      console.log(chalk.green("  Chamber containers stopped"));
    }
    return manifest;
  }

  runDockerCompose(runtime, ["logs", "--no-color"]);
  return manifest;
}

function targetFromOptions(options: ChamberCommandOptions): ChamberTargetSpec | undefined {
  if (!options.targetImage && !options.targetBuild && !options.targetCommand) {
    return undefined;
  }

  return {
    image: options.targetImage,
    buildContext: options.targetBuild,
    dockerfile: options.targetDockerfile,
    command: options.targetCommand,
    ports: options.targetPorts,
    readOnly: options.targetReadWrite ? false : undefined,
  };
}

function validateTargetOptions(options: ChamberCommandOptions): boolean {
  if (options.targetImage && isPlaceholderImage(options.targetImage)) {
    process.exitCode = 2;
    console.error(chalk.red(`  Refusing placeholder target image: ${options.targetImage}`));
    console.error(chalk.dim("  Build a local image first, then pass that tag:"));
    console.error(chalk.dim("    docker build -t scanner-target:local /path/to/target"));
    console.error(chalk.dim("    bun run src/index.ts chamber up --target-image scanner-target:local --target-port 127.0.0.1:3100:3100"));
    console.error(chalk.dim("  Or let the chamber build from a local repo:"));
    console.error(chalk.dim("    bun run src/index.ts chamber up --target-build /path/to/target --target-command \"node dist/server.js\" --target-port 127.0.0.1:3100:3100"));
    return false;
  }

  if (options.targetImage && options.targetBuild) {
    process.exitCode = 2;
    console.error(chalk.red("  Use either --target-image or --target-build, not both."));
    return false;
  }

  return true;
}

function isPlaceholderImage(image: string): boolean {
  return /^(?:your-org\/your-target|YOUR_IMAGE)(?::(?:latest|YOUR_TAG))?$/i.test(image);
}

function runDockerCompose(runtime: ChamberRuntime, args: string[]): boolean {
  try {
    runtime.compose(args);
    return true;
  } catch (err) {
    process.exitCode = 4;
    const message = err instanceof Error ? err.message : String(err);
    console.error(chalk.red(`  Docker compose failed: ${message}`));
    const manifest = runtime.manifest;
    console.error(chalk.dim(`  Compose file: ${manifest.composeFile}`));
    if (manifest.target?.image) {
      console.error(chalk.dim(`  Target image: ${manifest.target.image}`));
      console.error(chalk.dim("  If this is a private image, run docker login. If it is local, verify docker image ls shows the tag."));
    }
    return false;
  }
}
