/**
 * Token-bucket rate limiter for active scan tool calls.
 *
 * Prevents accidental DoS of the target server during full-active scans.
 * The active fuzzer can generate 320+ tool calls per tool (8 payloads × strategies
 * × 5 evasion attempts). For a server with 20 tools this is 6,000+ calls per scan.
 *
 * Exposed as --max-calls-per-scan <n> CLI option. Recommended default: 500.
 */

export class RateLimitExceededError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RateLimitExceededError";
  }
}

export class ScanRateLimiter {
  private callCount = 0;

  constructor(private readonly maxCalls: number) {}

  /**
   * Record a tool call for the given module.
   * Throws RateLimitExceededError if the scan-level cap is reached.
   */
  acquire(moduleName: string): void {
    if (++this.callCount > this.maxCalls) {
      throw new RateLimitExceededError(
        `Scan rate limit of ${this.maxCalls} tool calls exceeded in module "${moduleName}". ` +
        `Increase with --max-calls-per-scan or reduce the number of active modules.`
      );
    }
  }

  /** Current call count. */
  get count(): number {
    return this.callCount;
  }

  /** Remaining calls before the cap. */
  get remaining(): number {
    return Math.max(0, this.maxCalls - this.callCount);
  }
}
