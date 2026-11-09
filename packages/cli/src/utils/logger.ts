/**
 * Structured logger for toolsurf.
 *
 * Controlled by:
 *   --log-level <level>   CLI flag (debug | info | warn | error)
 *   LOG_LEVEL env var     Same values, CLI flag takes precedence
 *   --log-format json     Emits newline-delimited JSON for CI/structured pipelines
 *
 * All output goes to stderr so it never pollutes stdout scan reports.
 */

export type LogLevel = "debug" | "info" | "warn" | "error" | "silent";

const LEVEL_RANK: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
  silent: 4,
};

let _level: LogLevel = (process.env.LOG_LEVEL as LogLevel | undefined) ?? "warn";
let _jsonFormat = false;

/** Override the active log level at runtime (called by CLI option parser). */
export function setLogLevel(level: LogLevel): void {
  _level = level;
}

/** Switch to newline-delimited JSON output (for --log-format json). */
export function setJsonFormat(enabled: boolean): void {
  _jsonFormat = enabled;
}

function emit(level: Exclude<LogLevel, "silent">, message: string, meta?: Record<string, unknown>): void {
  if (LEVEL_RANK[level] < LEVEL_RANK[_level]) return;

  if (_jsonFormat) {
    process.stderr.write(
      JSON.stringify({ ts: new Date().toISOString(), level, message, ...meta }) + "\n"
    );
    return;
  }

  const prefix = level === "debug" ? "[DEBUG]"
    : level === "info"  ? "[INFO] "
    : level === "warn"  ? "[WARN] "
    : "[ERROR]";

  const line = meta && Object.keys(meta).length > 0
    ? `${prefix} ${message} ${JSON.stringify(meta)}`
    : `${prefix} ${message}`;

  process.stderr.write(line + "\n");
}

export const logger = {
  debug: (message: string, meta?: Record<string, unknown>) => emit("debug", message, meta),
  info:  (message: string, meta?: Record<string, unknown>) => emit("info",  message, meta),
  warn:  (message: string, meta?: Record<string, unknown>) => emit("warn",  message, meta),
  error: (message: string, meta?: Record<string, unknown>) => emit("error", message, meta),
};
