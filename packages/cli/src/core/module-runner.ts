import type {
  AuditModule,
  ModuleContext,
  ModuleResult,
  ServerCapabilities,
  TransportConfig,
  ChamberProbeConfig,
  Finding,
  CheckResult,
  PackageVersionEvidence,
} from "../types/index.js";
import { Severity, CheckStatus } from "../types/index.js";

export interface RunnerOptions {
  /** Server capabilities manifest */
  capabilities: ServerCapabilities;
  /** Modules to execute */
  modules: AuditModule[];
  /** Function to call MCP tools (for active modules) */
  callTool?: (name: string, args: Record<string, unknown>) => Promise<unknown>;
  /** Enable active scanning modules */
  activeMode?: boolean;
  /** Verbose logging */
  verbose?: boolean;
  /** Timeout per active probe in ms */
  probeTimeout?: number;
  /** Delay between active probes in ms */
  probeDelay?: number;
  /** Progress callback for module lifecycle (result is passed on complete/error) */
  onProgress?: (moduleId: string, status: "start" | "complete" | "error", result?: ModuleResult) => void;
  /** Granular progress callback for active module status updates */
  onDetailProgress?: (message: string) => void;
  /** Custom payloads for active fuzzing */
  customPayloads?: Array<{ value: string; label: string }>;
  /** Package/version evidence from repo manifests and lockfiles. */
  packageEvidence?: PackageVersionEvidence[];
  /** Called before each active module to reset circuit breaker state */
  onBeforeActiveModule?: () => void;
  /** Tool names with PEAV evidence — active modules should prioritize these */
  peavEvidenceTools?: Set<string>;
  /** @deprecated Use peavEvidenceTools. */
  peavSkipTools?: Set<string>;
  /** M-7: Max tools to fuzz per strategy in active-fuzzer (default: 10) */
  maxFuzzTargets?: number;
  /** Model output-token cap used to bound passive token-exhaustion estimates. */
  llmOutputTokenLimit?: number;
  /** Transport used to reach the server (passed through to ModuleContext). */
  transport?: TransportConfig;
  /** Detonation chamber endpoints/capture paths for active exploit evidence. */
  chamber?: ChamberProbeConfig;
}

/**
 * Module Runner — orchestrates the execution of audit modules.
 * Runs passive modules in parallel, active modules sequentially.
 */
export class ModuleRunner {
  /**
   * Execute all audit modules and aggregate results.
   * Passive modules run concurrently for speed.
   * Active modules run sequentially (they make tool calls that may conflict).
   */
  async run(options: RunnerOptions): Promise<ModuleResult[]> {
    const {
      capabilities,
      modules,
      callTool,
      activeMode = false,
      verbose = false,
      probeTimeout,
      probeDelay,
      onProgress,
      onDetailProgress,
      customPayloads,
      onBeforeActiveModule,
      peavEvidenceTools,
      peavSkipTools,
    } = options;

    // Split into passive and active modules
    const passiveModules = modules.filter((m) => m.mode === "passive");
    const activeModules = modules.filter((m) => m.mode === "active");

    const context: ModuleContext = {
      capabilities,
      callTool,
      activeMode,
      verbose,
      probeTimeout,
      probeDelay,
      onProgress: onDetailProgress,
      customPayloads,
      packageEvidence: options.packageEvidence,
      peavEvidenceTools: peavEvidenceTools ?? peavSkipTools,
      peavSkipTools,
      maxFuzzTargets: options.maxFuzzTargets,
      llmOutputTokenLimit: options.llmOutputTokenLimit,
      transport: options.transport,
      chamber: options.chamber,
    };

    // ── Run passive modules in parallel ──────────────────────────────────
    const passiveResults = await Promise.all(
      passiveModules.map((mod) => this.runModule(mod, context, onProgress, verbose))
    );
    // Notify completion for all passive modules (they started in parallel)
    for (const result of passiveResults) {
      onProgress?.(result.moduleId, result.error ? "error" : "complete", result);
    }

    // ── Run active modules sequentially ──────────────────────────────────
    const activeResults: ModuleResult[] = [];
    for (const mod of activeModules) {
      if (!activeMode) {
        if (verbose) {
          console.error(
            `[toolsurf:runner] Skipping active module "${mod.id}" (use --active to enable)`
          );
        }
        continue;
      }

      onBeforeActiveModule?.(); // Reset circuit breaker for each module
      onProgress?.(mod.id, "start");
      // Per-module timeout scales with tool count.
      // Active fuzzer with REST fallback fuzzes POST/PUT/path-param endpoints with
      // 6 strategies × ~8 payloads × up to 5 evasion retries × 100ms delay per probe.
      // Budget ~20s per fuzzable tool (strategies run sequentially).
      // When done, AbortSignal fires and the module exits cleanly.
      // Formula: base 60s + 20s per tool, min 120s, max 600s (10 min).
      const toolCount = capabilities.tools?.length ?? 10;
      const moduleTimeoutMs = Math.min(600_000, Math.max(120_000, 60_000 + toolCount * 20_000));
      const result = await this.runModuleWithTimeout(mod, context, moduleTimeoutMs, verbose);
      onProgress?.(mod.id, result.error ? "error" : "complete", result);
      activeResults.push(result);
    }

    return [...passiveResults, ...activeResults];
  }

  /**
   * Run a module with an overall timeout. If the module exceeds the timeout,
   * it returns an error result instead of hanging forever.
   */
  private async runModuleWithTimeout(
    mod: AuditModule,
    context: ModuleContext,
    timeoutMs: number,
    verbose: boolean = false
  ): Promise<ModuleResult> {
    const startTime = performance.now();

    // AbortController fires when the timeout expires, signalling the module
    // to stop launching new probes. Active modules check context.signal?.aborted
    // between probe iterations to avoid keeping the event loop alive after the
    // module-runner has moved on (the root cause of the GraphQL/REST hang).
    const abortController = new AbortController();
    const contextWithSignal: ModuleContext = { ...context, signal: abortController.signal };

    const modulePromise = this.runModule(mod, contextWithSignal, undefined, verbose);

    const timeoutPromise = new Promise<ModuleResult>((resolve) => {
      const timer = setTimeout(() => {
        // Fire the abort signal so in-progress probe loops exit at their next check
        abortController.abort();
        const durationMs = Math.round(performance.now() - startTime);
        if (verbose) {
          console.error(
            `[toolsurf:runner] Active module "${mod.id}" timed out after ${timeoutMs}ms — skipping`
          );
        }
        // Per INSTRUMENT-HARDENING-REPORT §CODE item #11 / G.5:
        // A timed-out module must NOT silently contribute findings=[] (which
        // looks like a clean pass). Instead, emit a synthetic [NOT ASSESSED]
        // INFO finding so callers and research outputs can distinguish
        // "module ran and found nothing" from "module never finished".
        // This applies to ALL protocols (MCP, REST, GraphQL, gRPC, etc.)
        // because module-runner is protocol-agnostic.
        const notAssessedFinding: Finding = {
          id: `NOT-ASSESSED-${mod.id}`,
          title: `[NOT ASSESSED] ${mod.name} timed out`,
          description:
            `[NOT ASSESSED] Module "${mod.id}" timed out after ${timeoutMs}ms. ` +
            `Results from this module are unavailable. This finding should NOT be ` +
            `interpreted as a clean pass — the module was unable to complete its checks. ` +
            `Re-run with a higher --timeout or investigate server responsiveness.`,
          severity: Severity.INFO,
          module: mod.id,
          confidence: 1.0,
          remediation: "Increase per-module timeout (--timeout) or investigate server responsiveness.",
          evidence: { timeoutMs, moduleId: mod.id, moduleName: mod.name },
        };
        const notAssessedCheck: CheckResult = {
          id: `NOT-ASSESSED-${mod.id}`,
          name: `[NOT ASSESSED] ${mod.name}`,
          status: CheckStatus.ERROR,
          message: `Module timed out after ${timeoutMs}ms — results unavailable`,
        };
        resolve({
          moduleId: mod.id,
          moduleName: mod.name,
          moduleVersion: mod.version,
          durationMs,
          checks: [notAssessedCheck],
          findings: [notAssessedFinding],
          error: `Module timed out after ${timeoutMs}ms`,
        });
      }, timeoutMs);
      if (typeof timer === "object" && "unref" in timer) {
        (timer as any).unref();
      }
    });

    return Promise.race([modulePromise, timeoutPromise]);
  }

  /**
   * Run a single module with error isolation.
   */
  private async runModule(
    mod: AuditModule,
    context: ModuleContext,
    onProgress?: (moduleId: string, status: "start" | "complete" | "error", result?: ModuleResult) => void,
    verbose: boolean = false
  ): Promise<ModuleResult> {
    onProgress?.(mod.id, "start");
    const startTime = performance.now();

    try {
      const checks = await mod.run(context);
      const durationMs = Math.round(performance.now() - startTime);

      // Extract findings from check results
      const findings: Finding[] = checks
        .filter((c): c is CheckResult & { finding: Finding } => !!c.finding)
        .map((c) => c.finding);

      return {
        moduleId: mod.id,
        moduleName: mod.name,
        moduleVersion: mod.version,
        durationMs,
        checks,
        findings,
      };
    } catch (err) {
      const durationMs = Math.round(performance.now() - startTime);
      const errorMessage =
        err instanceof Error ? err.message : String(err);

      if (verbose) {
        console.error(
          `[toolsurf:runner] Module "${mod.id}" crashed: ${errorMessage}`
        );
      }

      return {
        moduleId: mod.id,
        moduleName: mod.name,
        moduleVersion: mod.version,
        durationMs,
        checks: [],
        findings: [],
        error: errorMessage,
      };
    }
  }
}
