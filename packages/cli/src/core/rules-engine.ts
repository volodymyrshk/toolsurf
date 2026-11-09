/**
 * Rule DSL Engine — Policy-as-Code for MCP Server Security.
 *
 * Allows organizations to define custom security rules in YAML/JSON
 * that are evaluated against server capabilities and scan results.
 * This turns toolsurf from a scanner into a governance platform.
 *
 * Rule file format (.toolsurf-rules.yml or .toolsurf-rules.json):
 *
 *   rules:
 *     - id: ORG-001
 *       name: "No shell execution tools"
 *       severity: CRITICAL
 *       match:
 *         tool_name: /exec|shell|run_command/i
 *       message: "Shell execution tools are banned by security policy"
 *
 *     - id: ORG-002
 *       name: "All tools must have descriptions"
 *       severity: HIGH
 *       match:
 *         tool_description: null
 *       message: "Every tool must have a description for audit trail"
 *
 *     - id: ORG-003
 *       name: "Max 15 tools per server"
 *       severity: MEDIUM
 *       match:
 *         tool_count: { gt: 15 }
 *       message: "Servers should expose no more than 15 tools"
 */

import { readFileSync, existsSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import chalk from "chalk";
import { Severity, type CheckResult, CheckStatus } from "../types/index.js";
import type { ServerCapabilities } from "../types/index.js";

// ─── Rule Definition Types ──────────────────────────────────────────────────

export interface RuleMatch {
  /** Match against tool name (string or /regex/flags) */
  tool_name?: string | null;
  /** Match against tool description (string, /regex/, or null for missing) */
  tool_description?: string | null;
  /** Match against resource URI patterns */
  resource_uri?: string | null;
  /** Match against prompt name patterns */
  prompt_name?: string | null;
  /** Match tool count thresholds */
  tool_count?: { gt?: number; lt?: number; eq?: number };
  /** Match resource count thresholds */
  resource_count?: { gt?: number; lt?: number; eq?: number };
  /** Match prompt count thresholds */
  prompt_count?: { gt?: number; lt?: number; eq?: number };
  /** Match against server name */
  server_name?: string | null;
  /** Match against server version */
  server_version?: string | null;
  /** Match tool parameter names */
  param_name?: string | null;
  /** Match against tool annotations */
  annotation?: {
    destructiveHint?: boolean;
    readOnlyHint?: boolean;
    openWorldHint?: boolean;
  };
  /** Match tool input schema properties */
  schema_property?: string | null;
  /** Match against capability keys */
  capability?: string | null;
}

export interface CustomRule {
  /** Unique rule identifier (e.g., "ORG-001") */
  id: string;
  /** Human-readable rule name */
  name: string;
  /** Severity when rule matches */
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  /** Match conditions */
  match: RuleMatch;
  /** Description/message when rule triggers */
  message: string;
  /** Remediation guidance */
  remediation?: string;
  /** CWE ID if applicable */
  cweId?: string;
  /** Whether to negate the match (fail when NOT matched) */
  negate?: boolean;
}

export interface RulesFile {
  rules: CustomRule[];
}

// ─── Rule File Loader ───────────────────────────────────────────────────────

/**
 * Load rules from a YAML or JSON file.
 * Supports both .yml/.yaml and .json extensions.
 * YAML is parsed as a simplified subset (no anchors/aliases needed).
 */
export function loadRules(filePath: string): CustomRule[] {
  if (!existsSync(filePath)) {
    throw new Error(`Rules file not found: ${filePath}`);
  }

  const content = readFileSync(filePath, "utf-8");
  let data: RulesFile;

  if (filePath.endsWith(".json")) {
    data = JSON.parse(content) as RulesFile;
  } else {
    data = parseYaml(content) as RulesFile;
  }

  if (!data.rules || !Array.isArray(data.rules)) {
    throw new Error('Rules file must contain a "rules" array');
  }

  // Validate each rule
  for (let i = 0; i < data.rules.length; i++) {
    const rule = data.rules[i];
    if (!rule.id) throw new Error(`Rule at index ${i} missing "id"`);
    if (!rule.name) throw new Error(`Rule at index ${i} missing "name"`);
    if (!rule.severity) throw new Error(`Rule "${rule.id}" missing "severity"`);
    if (!rule.match) throw new Error(`Rule "${rule.id}" missing "match"`);
    if (!rule.message) throw new Error(`Rule "${rule.id}" missing "message"`);

    const validSeverities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    if (!validSeverities.includes(rule.severity)) {
      throw new Error(
        `Rule "${rule.id}" has invalid severity "${rule.severity}". ` +
        `Valid: ${validSeverities.join(", ")}`
      );
    }
  }

  return data.rules;
}

// ─── Rule Evaluation Engine ─────────────────────────────────────────────────

/**
 * Evaluate custom rules against server capabilities.
 * Returns CheckResult[] compatible with the existing module system.
 */
export function evaluateRules(
  rules: CustomRule[],
  capabilities: ServerCapabilities
): CheckResult[] {
  const results: CheckResult[] = [];

  for (const rule of rules) {
    const violations = evaluateRule(rule, capabilities);

    if (violations.length > 0 && !rule.negate) {
      // Rule matched — create finding
      results.push({
        id: rule.id,
        name: rule.name,
        status: CheckStatus.FAIL,
        message: `${rule.message} (${violations.length} violation${violations.length > 1 ? "s" : ""})`,
        finding: {
          id: rule.id,
          module: "custom-rules",
          severity: Severity[rule.severity as keyof typeof Severity],
          title: rule.name,
          description: rule.message,
          evidence: { violations, ruleId: rule.id },
          remediation: rule.remediation ?? "Review and address this policy violation.",
          cweId: rule.cweId,
        },
      });
    } else if (violations.length === 0 && rule.negate) {
      // Negated rule: fail when NO match found
      results.push({
        id: rule.id,
        name: rule.name,
        status: CheckStatus.FAIL,
        message: `${rule.message} (expected match not found)`,
        finding: {
          id: rule.id,
          module: "custom-rules",
          severity: Severity[rule.severity as keyof typeof Severity],
          title: rule.name,
          description: rule.message,
          evidence: { ruleId: rule.id, negate: true },
          remediation: rule.remediation ?? "Review and address this policy violation.",
          cweId: rule.cweId,
        },
      });
    } else {
      // Rule passed
      results.push({
        id: rule.id,
        name: rule.name,
        status: CheckStatus.PASS,
        message: rule.negate ? "Expected condition met" : "No violations found",
      });
    }
  }

  return results;
}

/**
 * Evaluate a single rule against capabilities.
 * Returns list of specific violations (tool names, resource URIs, etc.)
 */
function evaluateRule(
  rule: CustomRule,
  capabilities: ServerCapabilities
): string[] {
  const violations: string[] = [];
  const match = rule.match;
  const { tools, resources, prompts, serverInfo } = capabilities;

  // ── Tool name matching ──────────────────────────────────────────────
  if (match.tool_name !== undefined) {
    if (match.tool_name === null) {
      // null means "tools with no name" — not really useful but consistent
    } else {
      const pattern = toRegex(match.tool_name);
      for (const tool of tools) {
        if (pattern.test(tool.name)) {
          violations.push(`Tool "${tool.name}" matches forbidden pattern`);
        }
      }
    }
  }

  // ── Tool description matching ───────────────────────────────────────
  if (match.tool_description !== undefined) {
    if (match.tool_description === null) {
      // null means "tools missing descriptions"
      for (const tool of tools) {
        if (!tool.description || tool.description.trim() === "") {
          violations.push(`Tool "${tool.name}" has no description`);
        }
      }
    } else {
      const pattern = toRegex(match.tool_description);
      for (const tool of tools) {
        if (tool.description && pattern.test(tool.description)) {
          violations.push(`Tool "${tool.name}" description matches pattern`);
        }
      }
    }
  }

  // ── Resource URI matching ───────────────────────────────────────────
  if (match.resource_uri !== undefined) {
    if (match.resource_uri === null) {
      // Resources with no URI — shouldn't happen but handle it
    } else {
      const pattern = toRegex(match.resource_uri);
      for (const resource of resources) {
        if (pattern.test(resource.uri)) {
          violations.push(`Resource "${resource.uri}" matches forbidden pattern`);
        }
      }
    }
  }

  // ── Prompt name matching ────────────────────────────────────────────
  if (match.prompt_name !== undefined) {
    if (match.prompt_name === null) {
      for (const prompt of prompts) {
        if (!prompt.name) {
          violations.push("Prompt found with no name");
        }
      }
    } else {
      const pattern = toRegex(match.prompt_name);
      for (const prompt of prompts) {
        if (pattern.test(prompt.name)) {
          violations.push(`Prompt "${prompt.name}" matches forbidden pattern`);
        }
      }
    }
  }

  // ── Count thresholds ────────────────────────────────────────────────
  if (match.tool_count) {
    const count = tools.length;
    if (match.tool_count.gt !== undefined && count > match.tool_count.gt) {
      violations.push(`Tool count ${count} exceeds maximum ${match.tool_count.gt}`);
    }
    if (match.tool_count.lt !== undefined && count < match.tool_count.lt) {
      violations.push(`Tool count ${count} below minimum ${match.tool_count.lt}`);
    }
    if (match.tool_count.eq !== undefined && count !== match.tool_count.eq) {
      violations.push(`Tool count ${count} does not equal ${match.tool_count.eq}`);
    }
  }

  if (match.resource_count) {
    const count = resources.length;
    if (match.resource_count.gt !== undefined && count > match.resource_count.gt) {
      violations.push(`Resource count ${count} exceeds maximum ${match.resource_count.gt}`);
    }
    if (match.resource_count.lt !== undefined && count < match.resource_count.lt) {
      violations.push(`Resource count ${count} below minimum ${match.resource_count.lt}`);
    }
  }

  if (match.prompt_count) {
    const count = prompts.length;
    if (match.prompt_count.gt !== undefined && count > match.prompt_count.gt) {
      violations.push(`Prompt count ${count} exceeds maximum ${match.prompt_count.gt}`);
    }
  }

  // ── Server name/version matching ────────────────────────────────────
  if (match.server_name !== undefined && match.server_name !== null) {
    const pattern = toRegex(match.server_name);
    if (pattern.test(serverInfo.name)) {
      violations.push(`Server name "${serverInfo.name}" matches forbidden pattern`);
    }
  }

  if (match.server_version !== undefined && match.server_version !== null) {
    const pattern = toRegex(match.server_version);
    if (pattern.test(serverInfo.version)) {
      violations.push(`Server version "${serverInfo.version}" matches pattern`);
    }
  }

  // ── Parameter name matching ─────────────────────────────────────────
  if (match.param_name !== undefined && match.param_name !== null) {
    const pattern = toRegex(match.param_name);
    for (const tool of tools) {
      const props = (tool.inputSchema?.properties ?? {}) as Record<string, unknown>;
      for (const paramName of Object.keys(props)) {
        if (pattern.test(paramName)) {
          violations.push(`Tool "${tool.name}" has forbidden param "${paramName}"`);
        }
      }
    }
  }

  // ── Annotation matching ─────────────────────────────────────────────
  if (match.annotation) {
    for (const tool of tools) {
      const ann = tool.annotations;
      if (!ann) continue;

      if (
        match.annotation.destructiveHint !== undefined &&
        ann.destructiveHint === match.annotation.destructiveHint
      ) {
        violations.push(
          `Tool "${tool.name}" has destructiveHint=${ann.destructiveHint}`
        );
      }
      if (
        match.annotation.readOnlyHint !== undefined &&
        ann.readOnlyHint === match.annotation.readOnlyHint
      ) {
        violations.push(
          `Tool "${tool.name}" has readOnlyHint=${ann.readOnlyHint}`
        );
      }
      if (
        match.annotation.openWorldHint !== undefined &&
        ann.openWorldHint === match.annotation.openWorldHint
      ) {
        violations.push(
          `Tool "${tool.name}" has openWorldHint=${ann.openWorldHint}`
        );
      }
    }
  }

  // ── Schema property matching ────────────────────────────────────────
  if (match.schema_property !== undefined && match.schema_property !== null) {
    const pattern = toRegex(match.schema_property);
    for (const tool of tools) {
      const schema = tool.inputSchema;
      const schemaStr = JSON.stringify(schema);
      if (pattern.test(schemaStr)) {
        violations.push(`Tool "${tool.name}" schema matches pattern`);
      }
    }
  }

  // ── Capability matching ─────────────────────────────────────────────
  if (match.capability !== undefined && match.capability !== null) {
    const pattern = toRegex(match.capability);
    const capKeys = Object.keys(capabilities.capabilities ?? {});
    for (const key of capKeys) {
      if (pattern.test(key)) {
        violations.push(`Server declares capability "${key}"`);
      }
    }
  }

  return violations;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Compiled regex cache — avoids re-compiling the same pattern string on every
 * rule evaluation call. Key is the raw pattern string, value is the compiled RegExp.
 * This is module-scoped and lives for the process lifetime (rules don't change mid-run).
 */
const regexCache = new Map<string, RegExp>();

/**
 * Convert a string to a RegExp. Supports /pattern/flags syntax.
 * Plain strings are matched as case-insensitive contains.
 * Results are cached so repeated evaluations of the same rule don't recompile.
 */
function toRegex(pattern: string): RegExp {
  const cached = regexCache.get(pattern);
  if (cached) return cached;

  let compiled: RegExp;
  // Check for /regex/flags format
  const regexMatch = pattern.match(/^\/(.+)\/([gimsuy]*)$/);
  if (regexMatch) {
    const source = regexMatch[1];
    // Guard against catastrophic backtracking (ReDoS):
    // Reject patterns with nested quantifiers like (a+)+, (a*)*,  (.+)+, etc.
    if (/([+*])\)?[+*{]/.test(source) || /\([^)]*[+*]\)[+*{]/.test(source)) {
      throw new Error(
        `Potentially unsafe regex pattern rejected (nested quantifiers / ReDoS risk): ${pattern}`
      );
    }
    // Limit pattern length to prevent resource exhaustion
    if (source.length > 500) {
      throw new Error(`Regex pattern too long (${source.length} chars, max 500): ${pattern.slice(0, 60)}...`);
    }
    compiled = new RegExp(source, regexMatch[2]);
  } else {
    // Plain string — exact substring match (case-insensitive)
    compiled = new RegExp(escapeRegex(pattern), "i");
  }

  regexCache.set(pattern, compiled);
  return compiled;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ─── Rule Results Output ────────────────────────────────────────────────────

/**
 * Output custom rule results to terminal.
 */
export function outputRuleResults(results: CheckResult[]): void {
  const failures = results.filter((r) => r.status === CheckStatus.FAIL);
  const passes = results.filter((r) => r.status === CheckStatus.PASS);

  if (results.length === 0) return;

  console.log();
  console.log(
    chalk.bold.cyan(
      "  ╭─────────────────────────────────────────────────────────────╮"
    )
  );
  console.log(
    chalk.bold.cyan("  │") +
    chalk.bold("  CUSTOM POLICY RULES") +
    chalk.dim(`  — ${results.length} rule(s) evaluated`) +
    " ".repeat(Math.max(0, 22 - String(results.length).length)) +
    chalk.bold.cyan("│")
  );
  console.log(
    chalk.bold.cyan(
      "  ╰─────────────────────────────────────────────────────────────╯"
    )
  );
  console.log();

  for (const result of results) {
    const icon = result.status === CheckStatus.PASS
      ? chalk.green("  PASS")
      : chalk.red("  FAIL");
    const severity = result.finding
      ? severityColor(result.finding.severity)(` ${result.finding.severity} `)
      : "";

    console.log(
      `    ${icon}  ${severity} ${chalk.bold(result.name)} ${chalk.dim(`[${result.id}]`)}`
    );

    if (result.status === CheckStatus.FAIL && result.message) {
      console.log(chalk.dim(`          ${result.message}`));
    }
  }

  console.log();
  console.log(
    chalk.dim(
      `    ${passes.length} passed, ${failures.length} failed`
    )
  );
  console.log();
}

function severityColor(severity: string): (s: string) => string {
  switch (severity) {
    case "CRITICAL": return chalk.bgRed.white;
    case "HIGH": return chalk.red;
    case "MEDIUM": return chalk.yellow;
    case "LOW": return chalk.dim;
    default: return chalk.dim;
  }
}
