import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
  type ToolInfo,
} from "../types/index.js";

/**
 * Timing Anomaly Detector Module.
 *
 * Manual pentesters notice when responses are unusually slow or fast.
 * Timing differences reveal:
 * - Blind SQL injection (true vs false branches have different timing)
 * - Path traversal (existing file vs non-existing file)
 * - Authentication bypass (valid user vs invalid user)
 * - Resource exhaustion (unbounded operations)
 *
 * This module sends pairs of payloads and measures response times:
 * - Payload A: benign baseline
 * - Payload B: suspicious variant
 * If B is significantly slower than A, it may indicate a vulnerability.
 *
 * Finding prefixes: TAD-001 through TAD-003
 */
export class TimingAnomalyDetectorModule implements AuditModule {
  id = "timing-anomaly";
  name = "Timing Anomaly Detector";
  description =
    "Measures response time differences between benign and suspicious payloads to detect blind vulnerabilities";
  version = "1.0.0";
  mode = "active" as const;

  /** Minimum timing difference (ms) to flag as anomalous */
  private readonly TIMING_THRESHOLD_MS = 500;

  /** Ratio threshold (suspicious / benign > 2.0 = anomalous) */
  private readonly RATIO_THRESHOLD = 2.0;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];

    if (!context.callTool || !context.activeMode) {
      checks.push({
        id: "TAD-000",
        name: "Timing Anomaly Detector (Active)",
        status: CheckStatus.SKIP,
        message: "Requires --active flag and callTool access",
      });
      return checks;
    }

    const { capabilities: { tools }, callTool } = context;

    for (const tool of tools) {
      const stringParam = this.findStringParam(tool);
      if (!stringParam) continue;

      const anomalies = await this.testTimingAnomalies(tool, stringParam, callTool);

      if (anomalies.length > 0) {
        const maxSeverity = anomalies.some((a) => a.severity === Severity.CRITICAL)
          ? Severity.CRITICAL
          : anomalies.some((a) => a.severity === Severity.HIGH)
            ? Severity.HIGH
            : Severity.MEDIUM;

        checks.push({
          id: `TAD-${tool.name}`,
          name: `Timing analysis: ${tool.name}`,
          status: CheckStatus.FAIL,
          message: `${anomalies.length} timing anomaly(ies) in ${tool.name}`,
          finding: {
            id: `TAD-${tool.name}`,
            module: this.id,
            severity: maxSeverity,
            title: `Timing anomaly in "${tool.name}"`,
            description:
              `Tool "${tool.name}" showed significant response time differences between ` +
              `benign and suspicious payloads. This is a strong indicator of a blind ` +
              `vulnerability (blind SQL injection, path traversal, or authentication bypass). ` +
              `The server processes certain inputs differently, revealing internal state ` +
              `through timing side channels.`,
            evidence: {
              toolName: tool.name,
              anomalies: anomalies.map((a) => ({
                testType: a.testType,
                benignTimeMs: a.benignTime,
                suspiciousTimeMs: a.suspiciousTime,
                ratio: a.ratio.toFixed(2),
                payload: a.payload.substring(0, 100),
              })),
            },
            remediation:
              "Implement consistent response times for all inputs (use fixed-delay responses). " +
              "Use parameterized queries to prevent blind SQL injection. " +
              "Validate file paths before attempting access. " +
              "Ensure authentication checks take constant time regardless of user existence.",
            toolName: tool.name,
            cweId: "CWE-208", // Observable Timing Discrepancy
            confidence: 0.75,
          },
        });
      }
    }

    if (checks.length === 0) {
      checks.push({
        id: "TAD-000",
        name: "Timing Anomaly Detector",
        status: CheckStatus.PASS,
        message: "No timing anomalies detected",
      });
    }

    return checks;
  }

  private async testTimingAnomalies(
    tool: ToolInfo,
    paramName: string,
    callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>
  ): Promise<Array<{ testType: string; benignTime: number; suspiciousTime: number; ratio: number; payload: string; severity: Severity }>> {
    const anomalies: Array<{ testType: string; benignTime: number; suspiciousTime: number; ratio: number; payload: string; severity: Severity }> = [];

    const timingTests = [
      {
        testType: "sql-blind-tautology",
        benign: "benign_test_value",
        suspicious: "' OR '1'='1' --",
        severity: Severity.CRITICAL,
      },
      {
        testType: "sql-blind-sleep",
        benign: "benign_test_value",
        suspicious: "'; SELECT pg_sleep(2); --",
        severity: Severity.CRITICAL,
      },
      {
        testType: "path-traversal-exists",
        benign: "/tmp/nonexistent_file_12345.txt",
        suspicious: "/etc/passwd",
        severity: Severity.HIGH,
      },
      {
        testType: "auth-valid-vs-invalid",
        benign: "definitely_invalid_user_12345",
        suspicious: "admin",
        severity: Severity.HIGH,
      },
      {
        testType: "regex-redos",
        benign: "aaaa",
        suspicious: "a".repeat(1000) + "!",
        severity: Severity.MEDIUM,
      },
    ];

    for (const test of timingTests) {
      try {
        // Measure benign time (2 samples, take average)
        const benignTimes: number[] = [];
        for (let i = 0; i < 2; i++) {
          const start = performance.now();
          await callTool(tool.name, { [paramName]: test.benign });
          benignTimes.push(performance.now() - start);
          await new Promise((r) => setTimeout(r, 50));
        }
        const benignTime = (benignTimes[0] + benignTimes[1]) / 2;

        // Measure suspicious time (2 samples, take average)
        const suspiciousTimes: number[] = [];
        for (let i = 0; i < 2; i++) {
          const start = performance.now();
          await callTool(tool.name, { [paramName]: test.suspicious });
          suspiciousTimes.push(performance.now() - start);
          await new Promise((r) => setTimeout(r, 50));
        }
        const suspiciousTime = (suspiciousTimes[0] + suspiciousTimes[1]) / 2;

        const diff = suspiciousTime - benignTime;
        const ratio = benignTime > 0 ? suspiciousTime / benignTime : 0;

        if (diff > this.TIMING_THRESHOLD_MS && ratio > this.RATIO_THRESHOLD) {
          anomalies.push({
            testType: test.testType,
            benignTime,
            suspiciousTime,
            ratio,
            payload: test.suspicious,
            severity: test.severity,
          });
        }
      } catch {
        // One of the calls failed — skip this test
      }
    }

    return anomalies;
  }

  private findStringParam(tool: ToolInfo): string | null {
    const props = (tool.inputSchema as any)?.properties;
    if (!props) return null;
    for (const [key, val] of Object.entries(props)) {
      if ((val as any).type === "string") return key;
    }
    return null;
  }
}
