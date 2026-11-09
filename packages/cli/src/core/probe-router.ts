import { existsSync, readFileSync } from "node:fs";

/**
 * ProbeIntent router (Items 1+2 of the kill-chain architecture upgrade).
 *
 * The router is the single point at which active modules fire payloads at the
 * target. Modules construct a typed `ProbeIntent` and hand it off; the router
 * does three things in one transaction:
 *
 *   1. Refuses any payload that lacks a canary. The discriminated union
 *      below makes `canary` non-optional on every variant, so the type system
 *      rejects un-canaried intents at compile time. The runtime check exists
 *      only as a belt-and-suspenders guard against `as any` casts.
 *
 *   2. Registers `(canary → ProbeIntent)` in a per-scan registry *before*
 *      firing. The kill-chain assembler reads this registry to attribute
 *      chamber captures to the exact probe that produced them — turning what
 *      used to be post-hoc string-matching into prospective attribution.
 *
 *   3. Snapshots the chamber sensor capture-line counts before and after each
 *      `callTool()` so the router itself can return per-probe hits. Modules no
 *      longer have to count capture lines manually.
 *
 * What this is NOT:
 *
 *   - It does not own escalation. That's Item 3 (Dynamic Escalation), and
 *     belongs in a layer above the router that consumes `ProbeOutcome`s and
 *     decides which intents to fire next.
 *   - It does not build payloads. Modules still own attack payload generation;
 *     the router only attaches a canary, fires, and observes.
 *   - It does not modify the kill-chain engine. The kill-chain assembler reads
 *     the registry as a side-channel to enrich attribution; the engine itself
 *     stays in `kill-chain.ts` unchanged.
 */

// ────────────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────────────

export type ProbeSink = "http" | "metadata" | "dns" | "smtp" | "netflow";

/**
 * Where the router should watch for sensor hits attributable to a probe.
 * Modules declare this so the router can compute per-probe `hits` without
 * the module having to call `countCaptureLines()` itself.
 */
export interface ProbeExpectedSensor {
  sink: ProbeSink;
  captureFile: string;
}

/**
 * A probe whose payload is intended to land in a chamber URL/HTTP sensor.
 * Used by active-fuzzer's chamber strategy and (in the future) ssrf-detection.
 */
export interface SsrfCanaryIntent {
  kind: "ssrf-canary";
  canary: string;
  toolName: string;
  paramName: string;
  payload: string;
  /** A short label for the evasion class (`plain`, `imds-aws`, `dns-rebind`, …). */
  payloadVariant: string;
  expectedSensors: ProbeExpectedSensor[];
}

/**
 * A probe whose payload is intended to land in chamber-served HTML/MD that the
 * target then echoes back into the agent context (IPI relay class).
 */
export interface IpiCanaryIntent {
  kind: "ipi-canary";
  canary: string;
  toolName: string;
  paramName: string;
  payload: string;
  expectedSensors: ProbeExpectedSensor[];
}

/**
 * A shell-context probe (command/cmd/argv parameters). Same registration rules
 * as ssrf-canary; separate kind so the kill-chain assembler can label it
 * differently.
 */
export interface CommandInjectionCanaryIntent {
  kind: "command-injection-canary";
  canary: string;
  toolName: string;
  paramName: string;
  payload: string;
  payloadVariant: string;
  expectedSensors: ProbeExpectedSensor[];
}

/**
 * A state-mutation probe. The router fires the call but the *proof* lives
 * elsewhere — Item 5 (state oracle) snapshots the workdir before/after and
 * reads the canary back out of the diff. Included here so the router stays the
 * single firing point as Item 5 lands.
 */
export interface StateMutationIntent {
  kind: "state-mutation";
  canary: string;
  toolName: string;
  args: Record<string, unknown>;
  /** Empty array if no chamber sensors are relevant — state oracle owns proof. */
  expectedSensors: ProbeExpectedSensor[];
}

/**
 * Discriminated union — every variant has `canary: string` required.
 * There is no way to construct a ProbeIntent without one through the type
 * system. The runtime guard in `fire()` exists only to catch `as any` casts.
 */
export type ProbeIntent =
  | SsrfCanaryIntent
  | IpiCanaryIntent
  | CommandInjectionCanaryIntent
  | StateMutationIntent;

export interface ProbeSensorHit {
  sink: ProbeSink;
  captureFile: string;
  beforeCount: number;
  afterCount: number;
  delta: number;
}

export interface ProbeOutcome {
  intent: ProbeIntent;
  /** True iff the underlying callTool() resolved without throwing. */
  fired: boolean;
  /** Error message when the call threw. Captures may still have landed. */
  error?: string;
  /** Raw tool response — useful for IPI relay matching, ignored otherwise. */
  rawResult?: unknown;
  /** Per-sink before/after capture counts attributed to this probe. */
  hits: ProbeSensorHit[];
  /** Wall-clock duration of the call. */
  durationMs: number;
  /** UTC timestamp when the probe fired. */
  firedAt: string;
}

export interface RegisteredProbe {
  intent: ProbeIntent;
  registeredAt: string;
  outcome?: ProbeOutcome;
}

export type ToolCaller = (
  name: string,
  args: Record<string, unknown>,
) => Promise<unknown>;

export interface ProbeRouterOptions {
  callTool: ToolCaller;
  /**
   * Optional verbose hook for trace logging — the router itself does not call
   * console.* so test runs stay quiet. Modules set this from their context.
   */
  onTrace?: (event: ProbeRouterTraceEvent) => void;
}

export type ProbeRouterTraceEvent =
  | { kind: "register"; canary: string; intentKind: ProbeIntent["kind"] }
  | { kind: "fire-start"; canary: string; toolName: string }
  | { kind: "fire-end"; canary: string; durationMs: number; hits: number; error?: string };

// ────────────────────────────────────────────────────────────────────────────
// Router
// ────────────────────────────────────────────────────────────────────────────

export class ProbeRouter {
  private readonly callTool: ToolCaller;
  private readonly onTrace?: (event: ProbeRouterTraceEvent) => void;
  private readonly registry = new Map<string, RegisteredProbe>();

  constructor(options: ProbeRouterOptions) {
    this.callTool = options.callTool;
    this.onTrace = options.onTrace;
  }

  /**
   * Fire a probe through the router. Steps, in order:
   *   1. Validate canary present + non-empty + unique-per-router.
   *   2. Register `(canary → intent)` in the registry.
   *   3. Snapshot expected-sensor capture-line counts.
   *   4. Build args from intent and call the tool.
   *   5. Re-read sensor counts and diff to produce hits[].
   *   6. Persist the outcome on the registry entry and return it.
   *
   * The router never throws on tool errors — those are recorded in
   * `outcome.error` so callers can branch without try/catch.
   *
   * It DOES throw on canary violations (missing/empty/colliding), because
   * those are programmer errors that mean the kill-chain attribution will be
   * broken downstream.
   */
  async fire(intent: ProbeIntent): Promise<ProbeOutcome> {
    this.assertCanaryValid(intent);
    if (this.registry.has(intent.canary)) {
      throw new Error(
        `ProbeRouter: canary collision — "${intent.canary}" was already registered`,
      );
    }

    const registeredAt = new Date().toISOString();
    const entry: RegisteredProbe = { intent, registeredAt };
    this.registry.set(intent.canary, entry);
    this.onTrace?.({ kind: "register", canary: intent.canary, intentKind: intent.kind });

    const before = snapshotSensors(intent.expectedSensors);
    const start = performance.now();
    this.onTrace?.({ kind: "fire-start", canary: intent.canary, toolName: intent.toolName });

    const args = buildToolArgs(intent);
    let rawResult: unknown;
    let error: string | undefined;
    try {
      rawResult = await this.callTool(intent.toolName, args);
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    }

    const durationMs = performance.now() - start;
    const after = snapshotSensors(intent.expectedSensors);
    const hits = diffSensors(intent.expectedSensors, before, after);

    const outcome: ProbeOutcome = {
      intent,
      fired: error === undefined,
      error,
      rawResult,
      hits,
      durationMs,
      firedAt: registeredAt,
    };
    entry.outcome = outcome;

    this.onTrace?.({
      kind: "fire-end",
      canary: intent.canary,
      durationMs,
      hits: hits.length,
      error,
    });

    return outcome;
  }

  /** Look up a probe by its canary. Used by the kill-chain assembler. */
  lookupCanary(canary: string): RegisteredProbe | undefined {
    return this.registry.get(canary);
  }

  /** Snapshot of every probe registered with this router. */
  allProbes(): RegisteredProbe[] {
    return Array.from(this.registry.values());
  }

  /** Count of registered probes. Useful for module summaries. */
  registeredCount(): number {
    return this.registry.size;
  }

  /** Count of probes whose underlying tool call resolved without throwing. */
  firedCount(): number {
    let n = 0;
    for (const r of this.registry.values()) {
      if (r.outcome?.fired) n++;
    }
    return n;
  }

  /** Count of probes whose sensor hits[] is non-empty. */
  capturedCount(): number {
    let n = 0;
    for (const r of this.registry.values()) {
      if ((r.outcome?.hits.length ?? 0) > 0) n++;
    }
    return n;
  }

  // ── Guards ───────────────────────────────────────────────────────────────

  private assertCanaryValid(intent: ProbeIntent): void {
    // The discriminated union prevents a missing canary at compile time, but
    // runtime callers can still bypass the type system with `as any`. We
    // validate explicitly so kill-chain attribution can never silently break.
    const canary = (intent as { canary?: unknown }).canary;
    if (typeof canary !== "string" || canary.length === 0) {
      throw new Error(
        "ProbeRouter: ProbeIntent rejected — missing or empty canary. " +
          "Every probe must carry a unique correlation token before it reaches the protocol adapter.",
      );
    }
  }
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

/**
 * Build the `args` object passed to `callTool()` from a ProbeIntent. State-
 * mutation intents pass `args` verbatim; everything else is the canonical
 * `{ [paramName]: payload }` shape that the active-fuzzer chamber strategy
 * uses today.
 */
function buildToolArgs(intent: ProbeIntent): Record<string, unknown> {
  switch (intent.kind) {
    case "state-mutation":
      return intent.args;
    case "ssrf-canary":
    case "ipi-canary":
    case "command-injection-canary":
      return { [intent.paramName]: intent.payload };
  }
}

interface SensorCount {
  sink: ProbeSink;
  captureFile: string;
  count: number;
}

function snapshotSensors(sensors: ProbeExpectedSensor[]): SensorCount[] {
  const out: SensorCount[] = [];
  for (const s of sensors) {
    out.push({ sink: s.sink, captureFile: s.captureFile, count: countLines(s.captureFile) });
  }
  return out;
}

function diffSensors(
  sensors: ProbeExpectedSensor[],
  before: SensorCount[],
  after: SensorCount[],
): ProbeSensorHit[] {
  const hits: ProbeSensorHit[] = [];
  for (let i = 0; i < sensors.length; i++) {
    const b = before[i]?.count ?? 0;
    const a = after[i]?.count ?? 0;
    if (a > b) {
      hits.push({
        sink: sensors[i].sink,
        captureFile: sensors[i].captureFile,
        beforeCount: b,
        afterCount: a,
        delta: a - b,
      });
    }
  }
  return hits;
}

function countLines(path: string | undefined): number {
  if (!path || !existsSync(path)) return 0;
  const raw = readFileSync(path, "utf-8").trim();
  return raw === "" ? 0 : raw.split("\n").length;
}

// ────────────────────────────────────────────────────────────────────────────
// Convenience helpers for modules
// ────────────────────────────────────────────────────────────────────────────

/**
 * Build the standard expected-sensor list for chamber-backed network probes.
 * Modules can call this from their ChamberProbeConfig instead of hand-rolling
 * the tuple every time. Empty/missing capture files are filtered out — a
 * sensor that doesn't exist on this chamber should not appear in `hits`.
 */
export function chamberNetworkSensors(chamber: {
  captures?: {
    http?: string;
    metadata?: string;
    dns?: string;
    smtp?: string;
    netflow?: string;
  };
}): ProbeExpectedSensor[] {
  const out: ProbeExpectedSensor[] = [];
  const captures = chamber.captures ?? {};
  if (captures.http) out.push({ sink: "http", captureFile: captures.http });
  if (captures.metadata) out.push({ sink: "metadata", captureFile: captures.metadata });
  if (captures.dns) out.push({ sink: "dns", captureFile: captures.dns });
  if (captures.smtp) out.push({ sink: "smtp", captureFile: captures.smtp });
  if (captures.netflow) out.push({ sink: "netflow", captureFile: captures.netflow });
  return out;
}

/**
 * Build a unique canary string of the form `<prefix>-<base36-counter>-<hex8>`.
 * Modules pass their own counter; the random suffix prevents collisions across
 * concurrent scans that share a chamber.
 */
export function makeCanary(prefix: string, counter: number, randomHex8: string): string {
  return `${prefix}-${counter.toString(36)}-${randomHex8}`;
}
