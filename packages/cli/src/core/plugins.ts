import { existsSync, readdirSync, statSync } from "node:fs";
import { join, resolve, extname } from "node:path";
import { homedir } from "node:os";
import type { AuditModule } from "../types/index.js";

/**
 * Plugin loading system for custom audit modules.
 *
 * Plugins are standard ES modules that default-export an AuditModule.
 * They can be loaded from:
 *   1. Explicit paths via --plugin flags
 *   2. The ~/.toolsurf/plugins/ directory (auto-discovered)
 *   3. node_modules packages matching "toolsurf-plugin-*"
 *
 * Plugin modules must export a default object implementing AuditModule:
 *
 *   export default {
 *     id: "my-custom-check",
 *     name: "My Custom Check",
 *     description: "Checks something custom",
 *     version: "1.0.0",
 *     mode: "passive",
 *     async run(context) { return []; }
 *   };
 */

/** Default plugin directory */
const PLUGIN_DIR = join(homedir(), ".toolsurf", "plugins");

/** Valid plugin file extensions */
const VALID_EXTENSIONS = new Set([".js", ".mjs", ".ts"]);

export interface PluginLoadResult {
  /** Successfully loaded modules */
  modules: AuditModule[];
  /** Errors encountered during loading */
  errors: Array<{ path: string; error: string }>;
}

/**
 * Load plugins from explicit paths and the default plugin directory.
 *
 * @param explicitPaths - Paths passed via --plugin flags
 * @param autoDiscover - Whether to scan ~/.toolsurf/plugins/ (default: true)
 */
export async function loadPlugins(
  explicitPaths: string[] = [],
  autoDiscover: boolean = true,
): Promise<PluginLoadResult> {
  const modules: AuditModule[] = [];
  const errors: Array<{ path: string; error: string }> = [];
  const seenIds = new Set<string>();

  // 1. Load explicit paths
  for (const pluginPath of explicitPaths) {
    const abs = resolve(pluginPath);
    const result = await loadSinglePlugin(abs);
    if (result.error) {
      errors.push({ path: abs, error: result.error });
    } else if (result.module) {
      if (seenIds.has(result.module.id)) {
        errors.push({ path: abs, error: `Duplicate plugin ID "${result.module.id}"` });
      } else {
        seenIds.add(result.module.id);
        modules.push(result.module);
      }
    }
  }

  // 2. Auto-discover from ~/.toolsurf/plugins/
  if (autoDiscover && existsSync(PLUGIN_DIR)) {
    const files = discoverPluginFiles(PLUGIN_DIR);
    for (const filePath of files) {
      const result = await loadSinglePlugin(filePath);
      if (result.error) {
        errors.push({ path: filePath, error: result.error });
      } else if (result.module) {
        if (seenIds.has(result.module.id)) {
          // Skip silently — explicit paths take precedence
          continue;
        }
        seenIds.add(result.module.id);
        modules.push(result.module);
      }
    }
  }

  return { modules, errors };
}

/**
 * Discover plugin files in a directory (non-recursive).
 */
function discoverPluginFiles(dir: string): string[] {
  try {
    return readdirSync(dir)
      .filter((f) => VALID_EXTENSIONS.has(extname(f)))
      .map((f) => join(dir, f))
      .filter((f) => statSync(f).isFile());
  } catch {
    return [];
  }
}

/**
 * Load a single plugin file and validate it implements AuditModule.
 */
async function loadSinglePlugin(
  filePath: string,
): Promise<{ module?: AuditModule; error?: string }> {
  if (!existsSync(filePath)) {
    return { error: `File not found: ${filePath}` };
  }

  const ext = extname(filePath);
  if (!VALID_EXTENSIONS.has(ext)) {
    return { error: `Unsupported file extension "${ext}". Use .js, .mjs, or .ts` };
  }

  try {
    // Dynamic import — works with both ESM .js and Bun's .ts support
    const imported = await import(filePath);
    const candidate = imported.default ?? imported;

    const validation = validateAuditModule(candidate);
    if (validation) {
      return { error: validation };
    }

    return { module: candidate as AuditModule };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { error: `Failed to import: ${message}` };
  }
}

/**
 * Validate that an object implements the AuditModule interface.
 * Returns an error string if invalid, or null if valid.
 */
function validateAuditModule(obj: unknown): string | null {
  if (!obj || typeof obj !== "object") {
    return "Plugin must export an object";
  }

  const mod = obj as Record<string, unknown>;

  if (typeof mod.id !== "string" || mod.id.length === 0) {
    return "Plugin must have a non-empty 'id' string";
  }

  if (typeof mod.name !== "string" || mod.name.length === 0) {
    return "Plugin must have a non-empty 'name' string";
  }

  if (typeof mod.description !== "string") {
    return "Plugin must have a 'description' string";
  }

  if (typeof mod.version !== "string") {
    return "Plugin must have a 'version' string";
  }

  if (mod.mode !== "passive" && mod.mode !== "active") {
    return "Plugin 'mode' must be 'passive' or 'active'";
  }

  if (typeof mod.run !== "function") {
    return "Plugin must have a 'run' function";
  }

  // Guard against built-in module IDs
  const RESERVED_PREFIXES = [
    "tool-permissions", "transport-security", "schema-manipulation",
    "context-extraction", "secret-leak-detection", "resource-prompt-audit",
    "ssrf-detection", "active-fuzzer", "tool-shadowing",
    "response-fingerprinting", "auth-boundary-testing", "supply-chain-analysis",
    "custom-rules",
  ];
  if (RESERVED_PREFIXES.includes(mod.id as string)) {
    return `Plugin ID "${mod.id}" conflicts with a built-in module`;
  }

  return null;
}

/**
 * Get the default plugin directory path.
 */
export function getPluginDir(): string {
  return PLUGIN_DIR;
}
