import type { ToolInfo } from "../types/report.js";

// ─── Types ──────────────────────────────────────────────────────────────────────

/** Category of passive evidence detected. */
export type PeavSignalCategory =
  | "sql-error-leak"
  | "filesystem-error-leak"
  | "stack-trace-leak"
  | "reflected-input"
  | "timing-anomaly";

/** A single piece of passive evidence found in a tool's response. */
export interface PeavSignal {
  category: PeavSignalCategory;
  description: string;
  matchedPattern: string;
  /** Snippet of the response that triggered the signal (truncated). */
  excerpt: string;
}

/** PEAV result for a single tool. */
export interface PeavResult {
  toolName: string;
  hasEvidence: boolean;
  signals: PeavSignal[];
  responseTimeMs: number;
  callErrored: boolean;
  errorMessage?: string;
}

/** Full PEAV report across all tested tools. */
export interface PeavReport {
  timestamp: string;
  durationMs: number;
  results: PeavResult[];
  /** Tools that already show evidence (skip full fuzz). */
  toolsWithEvidence: string[];
  /** Tools that need full active fuzzing. */
  toolsNeedingFuzz: string[];
}

// ─── Detection patterns ─────────────────────────────────────────────────────────

interface DetectionPattern { re: RegExp; label: string }

const SQL_ERROR_PATTERNS: DetectionPattern[] = [
  { re: /sqlite3?\.OperationalError|SQLITE_ERROR/i, label: "sqlite-error" },
  { re: /You have an error in your SQL syntax/i, label: "mysql-syntax" },
  { re: /ERROR:\s+syntax error at or near/i, label: "pg-syntax" },
  { re: /\bunclosed quotation mark after the character string\b/i, label: "mssql-syntax" },
  { re: /\bORA-\d{5}\b/, label: "oracle-error" },
  { re: /near ".*": syntax error/i, label: "sqlite-near-syntax" },
];

const FS_ERROR_PATTERNS: DetectionPattern[] = [
  { re: /ENOENT.*\/(?:etc|usr|var|home|tmp|root)\//i, label: "enoent-system-path" },
  { re: /no such file or directory.*\/(?:etc|usr|var|home|tmp|root)\//i, label: "no-such-file-system-path" },
  { re: /EACCES.*permission denied/i, label: "eacces-permission" },
  { re: /EISDIR.*is a directory/i, label: "eisdir-leak" },
  { re: /Error:.*ENOENT.*["']\/[^"']+["']/i, label: "enoent-full-path" },
];

const STACK_TRACE_PATTERNS: DetectionPattern[] = [
  { re: /at Object\.<anonymous>/, label: "node-stack-trace" },
  { re: /at Module\._compile/, label: "node-module-trace" },
  { re: /at async [\w.]+\s+\(/, label: "node-async-trace" },
  { re: /Traceback \(most recent call last\)/, label: "python-traceback" },
  { re: /File ".*", line \d+, in /, label: "python-file-trace" },
  { re: /at [\w.$]+\.[\w.$]+\([\w.]+\.java:\d+\)/, label: "java-stack-trace" },
  { re: /goroutine \d+ \[running\]:/, label: "go-goroutine-trace" },
];

const TIMING_ANOMALY_THRESHOLD_MS = 3000;
const MAX_EXCERPT_LENGTH = 200;

// ─── Helpers ────────────────────────────────────────────────────────────────────

/** Extract up to 3 string-type parameter names from a tool's input schema. */
function extractStringParams(schema: Record<string, unknown>): string[] {
  const properties = schema.properties as Record<string, Record<string, unknown>> | undefined;
  if (!properties) return [];
  const params: string[] = [];
  for (const [name, def] of Object.entries(properties)) {
    if (def && def.type === "string") {
      params.push(name);
      if (params.length >= 3) break;
    }
  }
  return params;
}

/** Build a benign argument set using innocuous values. */
function buildBenignArgs(paramNames: string[]): Record<string, unknown> {
  const args: Record<string, unknown> = {};
  for (const name of paramNames) {
    args[name] = "test";
  }
  return args;
}

function buildCanaryArgs(paramNames: string[], inputValue: string): Record<string, unknown> {
  const args = buildBenignArgs(paramNames);
  const firstParam = paramNames[0];
  if (firstParam) {
    args[firstParam] = inputValue;
  }
  return args;
}

function truncate(text: string, maxLength: number = MAX_EXCERPT_LENGTH): string {
  return text.length <= maxLength ? text : text.slice(0, maxLength) + "...";
}

function stringifyResponse(response: unknown): string {
  if (typeof response === "string") return response;
  if (response === null || response === undefined) return "";
  try { return JSON.stringify(response); } catch { return String(response); }
}

// ─── Signal detection ───────────────────────────────────────────────────────────

/** Descriptions keyed by signal category. */
const CATEGORY_DESCRIPTIONS: Record<string, (label: string) => string> = {
  "sql-error-leak": (l) => `SQL error trace detected (${l}): database errors leak in normal responses, indicating unsanitized SQL construction.`,
  "filesystem-error-leak": (l) => `Filesystem error leaked (${l}): full system paths visible in response, suggesting path traversal readiness.`,
  "stack-trace-leak": (l) => `Stack trace leaked (${l}): internal code paths and file structures exposed to callers.`,
};

/**
 * Scan responseText against a pattern list, returning the first match as a signal.
 * Returns undefined if no pattern matches.
 */
function scanPatterns(
  responseText: string,
  patterns: DetectionPattern[],
  category: PeavSignalCategory,
): PeavSignal | undefined {
  for (const { re, label } of patterns) {
    const match = re.exec(responseText);
    if (match) {
      const start = Math.max(0, match.index - 40);
      return {
        category,
        description: CATEGORY_DESCRIPTIONS[category]!(label),
        matchedPattern: label,
        excerpt: truncate(responseText.slice(start, match.index + 160)),
      };
    }
  }
  return undefined;
}

/**
 * OS error wrappers that *naturally* echo the user-supplied path. These are
 * normal Node/Python/Go error templates and do not indicate missing sanitization
 * — only that the runtime built an error message containing the input. PEAV
 * must not flag these as `reflected-input`.
 */
const OS_ERROR_WRAPPERS = [
  /\bENOENT\b.*?["'`]?[^"'`\n]*["'`]?/i,
  /\bEACCES\b.*?["'`]?[^"'`\n]*["'`]?/i,
  /\bEISDIR\b.*?["'`]?[^"'`\n]*["'`]?/i,
  /\bENOTDIR\b.*?["'`]?[^"'`\n]*["'`]?/i,
  /\bEPERM\b.*?["'`]?[^"'`\n]*["'`]?/i,
  /no such file or directory/i,
  /permission denied/i,
  /is a directory/i,
];

/**
 * Returns true when the inputValue appears only inside an OS-error wrapper.
 * In that case the reflection is the runtime echoing the path the prober
 * supplied — not a sanitization defect.
 */
function reflectionIsInsideOsError(responseText: string, inputValue: string): boolean {
  if (!responseText.includes(inputValue)) return false;
  // Look at every occurrence of inputValue and check if any of them are NOT
  // inside an OS-error wrapper. If at least one is outside, the reflection is
  // genuine and should still be flagged.
  let searchFrom = 0;
  let foundOutside = false;
  while (true) {
    const idx = responseText.indexOf(inputValue, searchFrom);
    if (idx === -1) break;
    const windowStart = Math.max(0, idx - 80);
    const windowEnd = Math.min(responseText.length, idx + inputValue.length + 80);
    const window = responseText.slice(windowStart, windowEnd);
    const insideWrapper = OS_ERROR_WRAPPERS.some((re) => re.test(window));
    if (!insideWrapper) {
      foundOutside = true;
      break;
    }
    searchFrom = idx + inputValue.length;
  }
  return !foundOutside;
}

/** Analyze a response for all passive evidence categories. */
function analyzeResponse(
  responseText: string,
  inputValue: string,
  responseTimeMs: number,
): PeavSignal[] {
  const signals: PeavSignal[] = [];

  const sqlSignal = scanPatterns(responseText, SQL_ERROR_PATTERNS, "sql-error-leak");
  if (sqlSignal) signals.push(sqlSignal);

  // Filesystem-error-leak is meant to detect a server *resolving* paths the
  // agent shouldn't see (e.g. /etc/passwd). When the leaked path is the canary
  // we just supplied, this is normal Node fs error behavior — suppress it.
  const fsSignal = scanPatterns(responseText, FS_ERROR_PATTERNS, "filesystem-error-leak");
  if (fsSignal) {
    const leakedPathContainsCanary =
      typeof fsSignal.excerpt === "string" && fsSignal.excerpt.includes(inputValue);
    if (!leakedPathContainsCanary) signals.push(fsSignal);
  }

  const stackSignal = scanPatterns(responseText, STACK_TRACE_PATTERNS, "stack-trace-leak");
  if (stackSignal) signals.push(stackSignal);

  // Reflected-input only matters when the reflection lands somewhere the
  // attacker controls (HTML, downstream prompts, JSON values returned to the
  // agent). Reflections inside OS error wrappers are runtime-generated and do
  // not indicate missing sanitization.
  if (
    inputValue.length >= 4 &&
    responseText.includes(inputValue) &&
    !reflectionIsInsideOsError(responseText, inputValue)
  ) {
    signals.push({
      category: "reflected-input",
      description: "Input value reflected verbatim in output, suggesting no input sanitization or output encoding.",
      matchedPattern: "verbatim-reflection",
      excerpt: truncate(inputValue),
    });
  }

  if (responseTimeMs > TIMING_ANOMALY_THRESHOLD_MS) {
    signals.push({
      category: "timing-anomaly",
      description: `Response took ${responseTimeMs}ms (threshold: ${TIMING_ANOMALY_THRESHOLD_MS}ms), suggesting complex backend processing or potential for timing-based attacks.`,
      matchedPattern: "slow-response",
      excerpt: `${responseTimeMs}ms`,
    });
  }

  return signals;
}

// ─── Main PEAV runner ───────────────────────────────────────────────────────────

/**
 * Run Passive Evidence of Active Vulnerability (PEAV) analysis.
 *
 * Sends a single benign call per tool and inspects the response for passive
 * signals: SQL errors, filesystem leaks, stack traces, reflected input, and
 * timing anomalies. Tools that already leak evidence can skip the full fuzz
 * pass, reducing scan time and avoiding unnecessary destructive probing.
 *
 * @param callTool - Function to invoke a tool on the target server.
 * @param tools - List of tools discovered on the target.
 * @returns Full PEAV report with per-tool results and triage lists.
 */
export async function runPeav(
  callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>,
  tools: ToolInfo[],
): Promise<PeavReport> {
  const startTime = Date.now();
  const results: PeavResult[] = [];

  for (const tool of tools) {
    const stringParams = extractStringParams(tool.inputSchema);

    if (stringParams.length === 0) {
      results.push({
        toolName: tool.name,
        hasEvidence: false,
        signals: [],
        responseTimeMs: 0,
        callErrored: false,
      });
      continue;
    }

    // H-3: Use UUID-based canary instead of "test" to avoid false positive
    // reflected-input detection on servers that legitimately mention "test"
    // in status strings, error messages, or environment names.
    const inputValue = `peav_${crypto.randomUUID().slice(0, 8)}`;
    const benignArgs = buildCanaryArgs(stringParams, inputValue);
    let responseText = "";
    let responseTimeMs = 0;
    let callErrored = false;
    let errorMessage: string | undefined;

    const callStart = Date.now();
    try {
      let response = await callTool(tool.name, benignArgs);
      responseTimeMs = Date.now() - callStart;
      responseText = stringifyResponse(response);

      // P2-11: Hysteresis for timing anomaly. If the first call is slow,
      // try a second time and use max time. Analyze both responses (union of signals).
      if (responseTimeMs > TIMING_ANOMALY_THRESHOLD_MS * 0.8) {
        const firstResponseText = responseText;
        const hysStart = Date.now();
        response = await callTool(tool.name, benignArgs);
        const rt2 = Date.now() - hysStart;
        // M-5: Use max time (not average) for timing anomaly detection,
        // and union both responses so first-call evidence is not lost.
        responseTimeMs = Math.max(responseTimeMs, rt2);
        responseText = firstResponseText + "\n" + stringifyResponse(response);
      }
    } catch (err: unknown) {
      responseTimeMs = Date.now() - callStart; // BUGFIX: was erroneously using global startTime
      callErrored = true;
      const errStr = err instanceof Error ? err.message : String(err);
      errorMessage = errStr;
      responseText = errStr; // Error messages themselves can contain evidence
    }

    const signals = analyzeResponse(responseText, inputValue, responseTimeMs);
    results.push({
      toolName: tool.name,
      hasEvidence: signals.length > 0,
      signals,
      responseTimeMs,
      callErrored,
      errorMessage,
    });
  }

  const durationMs = Date.now() - startTime;
  const toolsWithEvidence = results.filter((r) => r.hasEvidence).map((r) => r.toolName);
  const toolsNeedingFuzz = results.filter((r) => !r.hasEvidence).map((r) => r.toolName);

  return {
    timestamp: new Date().toISOString(),
    durationMs,
    results,
    toolsWithEvidence,
    toolsNeedingFuzz,
  };
}

// PEAV is a pre-flight evidence pass. scan.ts passes toolsWithEvidence through
// to active modules as peavEvidenceTools so deeper fuzzing can prioritize, not
// skip, tools that already looked suspicious.
