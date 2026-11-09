import chalk from "chalk";
import type { Finding, ScanReport } from "../types/index.js";

/**
 * Auto-Fix Suggestion Engine.
 *
 * Generates actionable fix suggestions for common security findings,
 * including code patches, config changes, and MCP-specific remediation.
 */

// ─── Fix suggestion structure ───────────────────────────────────────────────

export interface FixSuggestion {
  /** Finding ID this fix addresses */
  findingId: string;
  /** Short description of the fix */
  title: string;
  /** Fix category */
  category: "config" | "code" | "schema" | "architecture";
  /** Difficulty level */
  effort: "trivial" | "easy" | "moderate" | "significant";
  /** Suggested code/config patch (if applicable) */
  patch?: string;
  /** File hint (where to apply) */
  fileHint?: string;
  /** Priority (1 = fix first) */
  priority: number;
}

// ─── Fix generators keyed by finding pattern ────────────────────────────────

type FixGenerator = (finding: Finding) => FixSuggestion | null;

const FIX_GENERATORS: Array<{ pattern: RegExp; generate: FixGenerator }> = [
  // Schema constraints (TP-004)
  {
    pattern: /^TP-004/,
    generate: (f) => ({
      findingId: f.id,
      title: `Add schema constraints to "${f.toolName}"`,
      category: "schema",
      effort: "easy",
      priority: 3,
      fileHint: "tool definition file",
      patch: `// Add constraints to string parameters in "${f.toolName}"
{
  "type": "object",
  "properties": {
    "path": {
      "type": "string",
      "maxLength": 4096,
      "pattern": "^[\\\\w./\\\\-]+$",
      "description": "File path (alphanumeric, dots, slashes, hyphens only)"
    }
  },
  "required": ["path"],
  "additionalProperties": false
}`,
    }),
  },

  // Dangerous tool names (TP-003)
  {
    pattern: /^TP-003/,
    generate: (f) => ({
      findingId: f.id,
      title: "Add destructiveHint annotation",
      category: "schema",
      effort: "trivial",
      priority: 2,
      patch: `// Add safety annotations to dangerous tools
{
  "name": "${f.toolName ?? "tool_name"}",
  "annotations": {
    "destructiveHint": true,
    "readOnlyHint": false,
    "idempotentHint": false
  }
}`,
    }),
  },

  // Dynamic tool registration (TS-004)
  {
    pattern: /^TS-004/,
    generate: () => ({
      findingId: "TS-004",
      title: "Disable dynamic tool registration",
      category: "config",
      effort: "easy",
      priority: 2,
      patch: `// In your MCP server configuration, disable listChanged:
{
  "capabilities": {
    "tools": {
      "listChanged": false
    }
  }
}`,
    }),
  },

  // Schema honesty (TS-001)
  {
    pattern: /^TS-001/,
    generate: () => ({
      findingId: "TS-001",
      title: "Add runtime schema validation",
      category: "code",
      effort: "moderate",
      priority: 1,
      patch: `// Install: npm install zod
import { z } from "zod";

// Define schema matching your MCP tool's inputSchema
const toolSchema = z.object({
  path: z.string().min(1).max(4096),
});

// Validate in your tool handler
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const parsed = toolSchema.safeParse(request.params.arguments);
  if (!parsed.success) {
    throw new McpError(ErrorCode.InvalidParams, parsed.error.message);
  }
  // ... use parsed.data safely
});`,
    }),
  },

  // Undeclared params (TS-003)
  {
    pattern: /^TS-003/,
    generate: () => ({
      findingId: "TS-003",
      title: "Reject undeclared parameters",
      category: "schema",
      effort: "trivial",
      priority: 1,
      patch: `// Set additionalProperties: false in your tool schema
{
  "inputSchema": {
    "type": "object",
    "properties": { ... },
    "required": [...],
    "additionalProperties": false
  }
}`,
    }),
  },

  // Unconstrained arrays (SM-004)
  {
    pattern: /^SM-004/,
    generate: (f) => ({
      findingId: f.id,
      title: `Add array constraints to "${f.toolName}"`,
      category: "schema",
      effort: "easy",
      priority: 3,
      patch: `// Add maxItems and item type constraints
{
  "type": "array",
  "items": { "type": "string" },
  "maxItems": 100,
  "minItems": 1
}`,
    }),
  },

  // Secret leak (SL-*)
  {
    pattern: /^SL-/,
    generate: (f) => ({
      findingId: f.id,
      title: "Remove hardcoded secrets",
      category: "code",
      effort: "moderate",
      priority: 1,
      patch: `// Move secrets to environment variables
// Before (DANGEROUS):
const API_KEY = "sk-1234567890abcdef";

// After (SAFE):
const API_KEY = process.env.API_KEY;
if (!API_KEY) throw new Error("API_KEY env var required");`,
    }),
  },

  // SSRF (SSRF-*)
  {
    pattern: /^SSRF/,
    generate: (f) => ({
      findingId: f.id,
      title: "Add URL allowlist validation",
      category: "code",
      effort: "moderate",
      priority: 1,
      patch: `// Validate URLs against an allowlist before fetching
const ALLOWED_HOSTS = new Set(["api.example.com", "cdn.example.com"]);

function validateUrl(input: string): URL {
  const url = new URL(input);
  // Block internal IPs
  if (/^(127\\.|10\\.|192\\.168\\.|172\\.(1[6-9]|2|3[01])\\.)/.test(url.hostname)) {
    throw new Error("Internal addresses blocked");
  }
  if (url.protocol !== "https:") {
    throw new Error("Only HTTPS allowed");
  }
  if (!ALLOWED_HOSTS.has(url.hostname)) {
    throw new Error(\`Host \${url.hostname} not in allowlist\`);
  }
  return url;
}`,
    }),
  },

  // Unicode encoding (AF-007)
  {
    pattern: /^AF-007/,
    generate: (f) => ({
      findingId: f.id,
      title: `Normalize Unicode input in "${f.toolName}"`,
      category: "code",
      effort: "easy",
      priority: 2,
      patch: `// Normalize and sanitize Unicode input
function sanitizeInput(input: string): string {
  return input
    .normalize("NFC")                         // Canonical Unicode form
    .replace(/[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F]/g, "")  // Strip control chars
    .replace(/[\\u200B-\\u200F\\u2028-\\u202F\\uFEFF]/g, "")  // Strip zero-width/BOM
    .trim();
}`,
    }),
  },

  // Oversized input (AF-006)
  {
    pattern: /^AF-006/,
    generate: (f) => ({
      findingId: f.id,
      title: `Add input length limits to "${f.toolName}"`,
      category: "code",
      effort: "trivial",
      priority: 3,
      patch: `// Enforce max input length in your tool handler
const MAX_INPUT_LENGTH = 10_000; // 10KB

if (typeof input === "string" && input.length > MAX_INPUT_LENGTH) {
  throw new McpError(
    ErrorCode.InvalidParams,
    \`Input exceeds maximum length of \${MAX_INPUT_LENGTH} characters\`
  );
}`,
    }),
  },

  // Mutation-based (AF-009)
  {
    pattern: /^AF-009/,
    generate: () => ({
      findingId: "AF-009",
      title: "Switch from blocklist to allowlist validation",
      category: "architecture",
      effort: "significant",
      priority: 2,
      patch: `// Instead of blocking known-bad patterns (bypassable):
// ❌ if (input.includes("../")) throw Error("blocked");

// Use allowlist validation (not bypassable):
// ✅ Validate against what IS allowed
const ALLOWED_PATTERN = /^[a-zA-Z0-9_\\-./]+$/;
if (!ALLOWED_PATTERN.test(input)) {
  throw new Error("Input contains disallowed characters");
}

// For file paths, canonicalize and verify:
const resolved = path.resolve(baseDir, input);
if (!resolved.startsWith(path.resolve(baseDir))) {
  throw new Error("Path escapes allowed directory");
}`,
    }),
  },

  // Resource boundary (AB-003)
  {
    pattern: /^AB-003/,
    generate: () => ({
      findingId: "AB-003",
      title: "Implement path boundary enforcement",
      category: "code",
      effort: "moderate",
      priority: 1,
      patch: `import path from "node:path";

const ALLOWED_BASE = "/safe/directory";

function enforceBoundary(inputPath: string): string {
  const resolved = path.resolve(ALLOWED_BASE, inputPath);
  if (!resolved.startsWith(path.resolve(ALLOWED_BASE) + path.sep)) {
    throw new Error("Access denied: path outside allowed directory");
  }
  return resolved;
}`,
    }),
  },

  // Outbound data sinks (CE-001)
  {
    pattern: /^CE-001/,
    generate: () => ({
      findingId: "CE-001",
      title: "Add output filtering for sensitive data",
      category: "code",
      effort: "moderate",
      priority: 2,
      patch: `// Redact sensitive patterns before any outbound data
function redactSensitive(output: string): string {
  return output
    .replace(/(?:api[_-]?key|token|secret|password)\\s*[=:]\\s*\\S+/gi, "[REDACTED]")
    .replace(/eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+/g, "[JWT_REDACTED]")
    .replace(/(?:sk|pk)[-_](?:live|test)[-_][A-Za-z0-9]{24,}/g, "[KEY_REDACTED]");
}`,
    }),
  },
];

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Generate fix suggestions for all findings in a report.
 */
export function generateFixSuggestions(report: ScanReport): FixSuggestion[] {
  const suggestions: FixSuggestion[] = [];
  const seen = new Set<string>();

  for (const finding of report.findings) {
    for (const generator of FIX_GENERATORS) {
      if (generator.pattern.test(finding.id)) {
        const fix = generator.generate(finding);
        if (fix && !seen.has(fix.findingId)) {
          suggestions.push(fix);
          seen.add(fix.findingId);
        }
        break;
      }
    }
  }

  // Sort by priority (lower = fix first)
  suggestions.sort((a, b) => a.priority - b.priority);
  return suggestions;
}

/**
 * Output fix suggestions to terminal.
 */
export function outputFixSuggestions(suggestions: FixSuggestion[]): void {
  if (suggestions.length === 0) {
    console.log(chalk.green("\n  No auto-fix suggestions — all findings require manual review.\n"));
    return;
  }

  console.log();
  console.log(chalk.bold.cyan("  ╭─────────────────────────────────────────────────────────────╮"));
  console.log(chalk.bold.cyan("  │") + chalk.bold("  AUTO-FIX SUGGESTIONS") + chalk.dim("  — actionable patches for findings") + chalk.bold.cyan("  │"));
  console.log(chalk.bold.cyan("  ╰─────────────────────────────────────────────────────────────╯"));
  console.log();

  const effortColors: Record<string, (s: string) => string> = {
    trivial: chalk.green,
    easy: chalk.cyan,
    moderate: chalk.yellow,
    significant: chalk.red,
  };

  const categoryIcons: Record<string, string> = {
    config: "⚙",
    code: "🔧",
    schema: "📐",
    architecture: "🏗",
  };

  for (let i = 0; i < suggestions.length; i++) {
    const fix = suggestions[i];
    const effortColor = effortColors[fix.effort] ?? chalk.dim;
    const icon = categoryIcons[fix.category] ?? "•";
    const priority = fix.priority === 1 ? chalk.red("P1") : fix.priority === 2 ? chalk.yellow("P2") : chalk.dim("P3");

    console.log(
      `  ${priority} ${icon}  ${chalk.bold(fix.title)}` +
      chalk.dim(` [${fix.findingId}]`) +
      `  ${effortColor(`(${fix.effort})`)}`
    );

    if (fix.fileHint) {
      console.log(chalk.dim(`      File: ${fix.fileHint}`));
    }

    if (fix.patch) {
      const lines = fix.patch.split("\n");
      console.log(chalk.dim("      ┌─ suggested patch ─────────────────────────────"));
      for (const line of lines) {
        const highlighted = line.startsWith("//")
          ? chalk.dim(`      │ ${line}`)
          : line.startsWith("// ❌") || line.startsWith("// Before")
            ? chalk.red(`      │ ${line}`)
            : line.startsWith("// ✅") || line.startsWith("// After")
              ? chalk.green(`      │ ${line}`)
              : chalk.white(`      │ ${line}`);
        console.log(highlighted);
      }
      console.log(chalk.dim("      └──────────────────────────────────────────────"));
    }

    if (i < suggestions.length - 1) console.log();
  }

  console.log();
  console.log(chalk.dim(`  ${suggestions.length} fix suggestion(s) generated. Apply patches to your MCP server source code.`));
  console.log();
}
