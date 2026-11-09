/**
 * Configuration file support.
 *
 * Loads settings from .toolsurfrc.json in CWD or specified path.
 * CLI flags always override config file values.
 */

import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

export interface ToolSurfConfig {
  /** Default scan profile */
  profile?: "quick" | "standard" | "enterprise";
  /** Default output format */
  format?: "terminal" | "json" | "html" | "markdown";
  /** Enable active scanning by default */
  active?: boolean;
  /** Default compliance frameworks */
  compliance?: string[];
  /** Minimum severity filter */
  minSeverity?: string;
  /** Probe timeout in ms */
  probeTimeout?: number;
  /** Probe delay in ms */
  probeDelay?: number;
  /** Connection timeout in ms */
  timeout?: number;
  /** Max output tokens the deployed LLM can emit in one response. */
  llmOutputTokenLimit?: number;
  /** Modules to run (or exclude with "!module-id") */
  modules?: string[];
  /** Custom payloads file path */
  payloads?: string;
  /** Ignored finding IDs (baseline) */
  ignore?: string[];
  /** Verbose output */
  verbose?: boolean;
}

const CONFIG_FILENAMES = [
  ".toolsurfrc.json",
  ".toolsurfrc",
  "toolsurf.config.json",
];

/**
 * Load config from the nearest config file.
 * Returns empty config if no file found.
 */
export function loadConfig(explicitPath?: string): ToolSurfConfig {
  if (explicitPath) {
    return readConfigFile(explicitPath);
  }

  // Search CWD for config files
  const cwd = process.cwd();
  for (const filename of CONFIG_FILENAMES) {
    const fullPath = resolve(cwd, filename);
    if (existsSync(fullPath)) {
      return readConfigFile(fullPath);
    }
  }

  return {};
}

function readConfigFile(filePath: string): ToolSurfConfig {
  try {
    const content = readFileSync(filePath, "utf-8");
    const config = JSON.parse(content);

    // Validate known keys
    const validKeys = new Set([
      "profile",
      "format",
      "active",
      "compliance",
      "minSeverity",
      "probeTimeout",
      "probeDelay",
      "timeout",
      "llmOutputTokenLimit",
      "modules",
      "payloads",
      "ignore",
      "verbose",
    ]);

    const unknownKeys = Object.keys(config).filter((k) => !validKeys.has(k));
    if (unknownKeys.length > 0) {
      console.error(
        `[toolsurf] Warning: Unknown config keys: ${unknownKeys.join(", ")}`
      );
    }

    return config as ToolSurfConfig;
  } catch (err) {
    console.error(
      `[toolsurf] Error reading config file ${filePath}: ${
        err instanceof Error ? err.message : String(err)
      }`
    );
    return {};
  }
}

/**
 * Merge CLI options over config file values.
 * CLI flags take precedence.
 */
export function mergeConfig(
  config: ToolSurfConfig,
  cliOpts: Record<string, unknown>
): Record<string, unknown> {
  const merged: Record<string, unknown> = { ...config };

  // CLI flags override config values (only if explicitly provided)
  for (const [key, value] of Object.entries(cliOpts)) {
    if (value !== undefined) {
      merged[key] = value;
    }
  }

  return merged;
}

/**
 * Load custom payloads from a JSON file.
 * Expected format: [{ "value": "...", "label": "..." }, ...]
 */
export function loadCustomPayloads(
  filePath: string
): Array<{ value: string; label: string }> {
  try {
    const content = readFileSync(filePath, "utf-8");
    const payloads = JSON.parse(content);

    if (!Array.isArray(payloads)) {
      throw new Error("Payloads file must contain a JSON array");
    }

    return payloads.map((p: unknown, i: number) => {
      const entry = p as Record<string, unknown>;
      if (typeof entry.value !== "string") {
        throw new Error(`Payload at index ${i} missing "value" string`);
      }
      return {
        value: entry.value,
        label: typeof entry.label === "string" ? entry.label : `custom-${i}`,
      };
    });
  } catch (err) {
    console.error(
      `Error loading payloads from ${filePath}: ${
        err instanceof Error ? err.message : String(err)
      }`
    );
    return [];
  }
}

/**
 * Load ignored finding IDs from .toolsurfignore or config.
 * File format: one finding ID per line, # comments allowed.
 */
export function loadIgnoreList(configIgnore?: string[]): Set<string> {
  const ignored = new Set<string>(configIgnore ?? []);

  // Check for .toolsurfignore file
  const ignorePath = resolve(process.cwd(), ".toolsurfignore");
  if (existsSync(ignorePath)) {
    try {
      const content = readFileSync(ignorePath, "utf-8");
      for (const line of content.split("\n")) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith("#")) {
          ignored.add(trimmed);
        }
      }
    } catch {
      // ignore read errors
    }
  }

  return ignored;
}
