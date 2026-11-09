import { createHash } from "node:crypto";
import type { ToolInfo } from "../types/index.js";

/**
 * TOFU (Trust-on-First-Use) Schema Hashing
 *
 * Computes a deterministic SHA-256 hash of a server's complete tool schema.
 * On re-scan, comparing the current hash against the baseline detects
 * "rug pull via listChanged" attacks — where a server modifies its tool
 * definitions after initial trust has been established.
 *
 * What's included in the hash:
 *   - Tool names (sorted for determinism)
 *   - Tool descriptions
 *   - Full input schemas (JSON-serialized, keys sorted)
 *   - Tool annotations (readOnlyHint, destructiveHint, etc.)
 *
 * What's excluded:
 *   - Server info (name/version changes are expected)
 *   - Resources and prompts (separate concern)
 *   - Ordering (tools are sorted by name before hashing)
 */

/**
 * Compute per-tool hashes and a combined server schema hash.
 * Returns both the aggregate hash and per-tool hashes for granular diffing.
 */
export function computeSchemaHash(tools: ToolInfo[]): {
  /** SHA-256 hash of the entire tool schema set */
  schemaHash: string;
  /** Per-tool SHA-256 hashes, keyed by tool name */
  toolHashes: Record<string, string>;
  /** Number of tools included in the hash */
  toolCount: number;
} {
  const toolHashes: Record<string, string> = {};

  // Sort tools by name for deterministic ordering
  const sorted = [...tools].sort((a, b) => a.name.localeCompare(b.name));

  const combinedHasher = createHash("sha256");

  for (const tool of sorted) {
    // Build a canonical representation of the tool
    const canonical = JSON.stringify({
      name: tool.name,
      description: tool.description ?? "",
      inputSchema: sortObjectKeys(tool.inputSchema ?? {}),
      annotations: sortObjectKeys(tool.annotations ?? {}),
    });

    // Per-tool hash
    const toolHash = createHash("sha256").update(canonical).digest("hex");
    toolHashes[tool.name] = toolHash;

    // Feed into combined hash
    combinedHasher.update(canonical);
  }

  return {
    schemaHash: combinedHasher.digest("hex"),
    toolHashes,
    toolCount: sorted.length,
  };
}

/**
 * Compare two schema hash results and return the differences.
 */
export function diffSchemaHashes(
  baseline: { schemaHash: string; toolHashes: Record<string, string> },
  current: { schemaHash: string; toolHashes: Record<string, string> }
): {
  changed: boolean;
  addedTools: string[];
  removedTools: string[];
  modifiedTools: string[];
} {
  if (baseline.schemaHash === current.schemaHash) {
    return { changed: false, addedTools: [], removedTools: [], modifiedTools: [] };
  }

  const baselineTools = new Set(Object.keys(baseline.toolHashes));
  const currentTools = new Set(Object.keys(current.toolHashes));

  const addedTools = [...currentTools].filter((t) => !baselineTools.has(t));
  const removedTools = [...baselineTools].filter((t) => !currentTools.has(t));
  const modifiedTools = [...currentTools].filter(
    (t) => baselineTools.has(t) && baseline.toolHashes[t] !== current.toolHashes[t]
  );

  return { changed: true, addedTools, removedTools, modifiedTools };
}

/**
 * Recursively sort object keys for deterministic JSON serialization.
 */
function sortObjectKeys(obj: unknown): unknown {
  if (obj === null || obj === undefined) return obj;
  if (Array.isArray(obj)) return obj.map(sortObjectKeys);
  if (typeof obj === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(obj as Record<string, unknown>).sort()) {
      sorted[key] = sortObjectKeys((obj as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return obj;
}
