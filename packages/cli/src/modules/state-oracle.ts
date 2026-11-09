import { join } from "node:path";
import { randomUUID } from "node:crypto";
import {
  CheckStatus,
  Severity,
  type AuditModule,
  type CheckResult,
  type ModuleContext,
  type ToolInfo,
} from "../types/index.js";
import {
  ProbeRouter,
  makeCanary,
  type StateMutationIntent,
} from "../core/probe-router.js";
import {
  diffSnapshots,
  findCanariesInDelta,
  takeSnapshot,
  writeDeltaArtifact,
  type StateDelta,
} from "../core/state-oracle.js";

/**
 * State Oracle audit module (Item 5 of the kill-chain architecture upgrade).
 *
 * Runs only when the chamber was provisioned with a host workdir
 * (`chamber.workdir`). The wiring chain is:
 *
 *   1. Caller passes `workdir: { enabled: true }` to ChamberRuntime.create.
 *   2. detonation-chamber.ts mints `<runDir>/workdir/` on the host.
 *   3. applyChamberToConnectParams adds `-v <hostPath>:<containerPath>` and
 *      `-e SCANNER_CHAMBER_WORKDIR=<containerPath>` to the target's
 *      `docker run`.
 *   4. This module:
 *        a) Snapshots the host workdir (baseline).
 *        b) Fires `state-mutation` ProbeIntents through the router for tools
 *           whose schema looks like a write-pair (`path` + `content`-style
 *           params). Each payload is canary-laced in both the path AND the
 *           content so canary search succeeds regardless of what the tool
 *           strips.
 *        c) Snapshots again, diffs, searches for canaries.
 *        d) When canary-bearing changes are present, persists the delta as a
 *           JSON artifact and emits a `CHAMBER-FS-001` finding pointing at
 *           it. The kill-chain assembler in kill-chain.ts already turns that
 *           into a `state-delta` proof artifact.
 *
 * No findings are emitted on a clean diff — silence is the right signal when
 * no state-mutation succeeded. The chamber panel still surfaces the run via
 * the chamber-evidence module's normal capture rollup.
 */

const PATH_PARAM_RE = /^(path|file|file_path|filepath|filename|target_path|destination|dest|out_path)$/i;
const CONTENT_PARAM_RE = /^(content|body|text|data|payload|value|message)$/i;
const STATE_VERB_RE = /\b(write|create|save|store|append|update|put|patch|edit)\b/i;

interface WritePairCandidate {
  tool: ToolInfo;
  pathParam: string;
  contentParam: string;
}

export class StateOracleModule implements AuditModule {
  id = "state-oracle";
  name = "State Oracle (filesystem diff)";
  description =
    "Snapshots the chamber workdir before/after active probing and emits a CHAMBER-FS finding when a probe canary lands on disk";
  version = "1.0.0";
  // Runs as "active" so it executes alongside other probes and BEFORE the
  // chamber-evidence synthesizer (ordering is preserved by module-catalog.ts).
  mode = "active" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const chamber = context.chamber;
    const workdir = chamber?.workdir;

    if (!chamber || !workdir) {
      checks.push({
        id: "STATE-ORACLE-001",
        name: "State oracle baseline",
        status: CheckStatus.SKIP,
        message:
          "Chamber workdir not provisioned — state-oracle is opt-in. Re-run with --state-oracle to enable.",
      });
      return checks;
    }
    if (!context.callTool) {
      checks.push({
        id: "STATE-ORACLE-001",
        name: "State oracle baseline",
        status: CheckStatus.SKIP,
        message: "Active mode required for state-oracle probing.",
      });
      return checks;
    }

    const tools = context.capabilities.tools ?? [];
    const candidates = findWritePairCandidates(tools);
    if (candidates.length === 0) {
      checks.push({
        id: "STATE-ORACLE-001",
        name: "State oracle baseline",
        status: CheckStatus.PASS,
        message:
          "No write-pair tools found — state-oracle has no probe surface for this target.",
      });
      return checks;
    }

    // Baseline. We snapshot immediately before firing so that mutations from
    // other modules that may have already written through `containerPath` are
    // out of scope. (They run sequentially; this module is ordered before
    // chamber-evidence but after the other write-class modules — anything
    // they wrote is already on the floor by the time we baseline.)
    const baseline = takeSnapshot(workdir.hostPath);

    const router = new ProbeRouter({
      callTool: context.callTool,
      onTrace: context.verbose
        ? (e) => {
            if (e.kind === "fire-end" && e.error) {
              console.error(
                `[toolsurf:state-oracle] probe error canary=${e.canary} ${e.error}`,
              );
            }
          }
        : undefined,
    });

    let canaryCounter = 0;
    const firedCanaries: string[] = [];

    for (const c of candidates) {
      if (context.probeDelay && context.probeDelay > 0) {
        await new Promise((r) => setTimeout(r, context.probeDelay));
      }

      const canary = makeCanary(
        "chamber-state",
        canaryCounter++,
        randomUUID().replace(/-/g, "").slice(0, 8),
      );
      firedCanaries.push(canary);

      // Embed the canary in BOTH the path AND the content so canary search
      // succeeds regardless of which one the tool keeps. The path is rooted
      // under the container-side mount so the host can see the resulting
      // file.
      const intent: StateMutationIntent = {
        kind: "state-mutation",
        canary,
        toolName: c.tool.name,
        args: {
          [c.pathParam]: `${workdir.containerPath}/${canary}.txt`,
          [c.contentParam]:
            `state-oracle canary: ${canary}\n` +
            "If this file is on disk inside the chamber workdir, the target executed a state mutation.\n",
        },
        // The router's expectedSensors are network-only; state-oracle
        // verifies through filesystem diff, not capture lines.
        expectedSensors: [],
      };

      await router.fire(intent);
    }

    const after = takeSnapshot(workdir.hostPath);
    const delta = diffSnapshots(baseline, after);
    const hits = findCanariesInDelta(delta, firedCanaries);

    if (hits.length === 0) {
      checks.push({
        id: "STATE-ORACLE-001",
        name: "State oracle diff",
        status: CheckStatus.PASS,
        message: `Probed ${candidates.length} write-pair tool(s); workdir delta did not contain any probe canary.`,
      });
      return checks;
    }

    const artifactDir = join(chamber.runDir ?? workdir.hostPath, "captures", "state");
    const oracleId = `state-oracle-${randomUUID().slice(0, 8)}`;
    const artifactPath = writeDeltaArtifact(artifactDir, delta, oracleId);

    // Emit a single CHAMBER-FS-001 — the kill-chain assembler reads `fsDiffFile`
    // off this finding's evidence to attach a `state-delta` proof artifact.
    const affectedTools = Array.from(new Set(hits.map((h) => toolForChange(h.change.path, candidates))));
    const fsDiffFile = artifactPath;

    checks.push({
      id: "CHAMBER-FS-001",
      name: "Chamber state oracle proof",
      status: CheckStatus.FAIL,
      message:
        `${hits.length} canary-bearing change(s) observed in chamber workdir from ${affectedTools.length} tool(s)`,
      finding: {
        id: "CHAMBER-FS-001",
        module: this.id,
        severity: Severity.CRITICAL,
        title: "Tool wrote attacker-canaried content into chamber workdir (state-corruption proof)",
        description:
          `The state oracle planted ${firedCanaries.length} canary-laced write probes through tool input ` +
          "schemas. After probing, the chamber workdir contained file changes whose paths or contents " +
          `included the canary token, proving the target executed the mutation. ` +
          "This is a downloadable proof artifact suitable for vendor disclosure.",
        evidence: {
          oracleId,
          fsDiffFile,
          stateDiffFile: fsDiffFile,
          firedCanaries,
          hits: hits.map((h) => ({
            canary: h.canary,
            kind: h.change.kind,
            path: h.change.path,
            matchedIn: h.matchedIn,
          })),
          summary: summarizeDelta(delta),
          verifiedBy: "state-oracle",
        },
        remediation:
          "Constrain write paths to a strict allowlist; reject paths containing user-controlled tokens; " +
          "require explicit user confirmation for write/create/delete operations.",
        cweId: "CWE-22",
        confidence: 0.99,
        affectedTools,
        affectedCount: affectedTools.length,
        toolName: affectedTools[0],
      },
    });

    return checks;
  }
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

function findWritePairCandidates(tools: ToolInfo[]): WritePairCandidate[] {
  const out: WritePairCandidate[] = [];
  for (const tool of tools) {
    const props = (tool.inputSchema as Record<string, unknown> | undefined)
      ?.properties as Record<string, unknown> | undefined;
    if (!props) continue;

    let pathParam: string | undefined;
    let contentParam: string | undefined;
    for (const [name, schema] of Object.entries(props)) {
      const s = schema as Record<string, unknown> | undefined;
      if (!s || s.type !== "string") continue;
      if (!pathParam && PATH_PARAM_RE.test(name)) pathParam = name;
      else if (!contentParam && CONTENT_PARAM_RE.test(name)) contentParam = name;
    }

    if (pathParam && contentParam) {
      out.push({ tool, pathParam, contentParam });
      continue;
    }

    // Description-fallback: a tool whose name OR description contains a state
    // verb but only has a path param — try to fire with a single-arg call
    // using the canary path; the tool may default the body internally.
    if (
      pathParam &&
      !contentParam &&
      (STATE_VERB_RE.test(tool.name) || STATE_VERB_RE.test(tool.description ?? ""))
    ) {
      out.push({ tool, pathParam, contentParam: pathParam });
    }
  }
  return out;
}

function toolForChange(changedPath: string, candidates: WritePairCandidate[]): string {
  // If the canary in the path follows our convention (`chamber-state-N-…`),
  // any candidate could have produced it — without per-canary tool tracking
  // (router knows, but we don't thread it through here for v1) we surface
  // the union of candidates. Good enough for v1.
  if (candidates.length === 1) return candidates[0].tool.name;
  // Take the first whose tool name appears in the changed path, else first.
  for (const c of candidates) {
    if (changedPath.toLowerCase().includes(c.tool.name.toLowerCase())) return c.tool.name;
  }
  return candidates[0].tool.name;
}

function summarizeDelta(delta: StateDelta): {
  added: number;
  modified: number;
  deleted: number;
} {
  let added = 0;
  let modified = 0;
  let deleted = 0;
  for (const c of delta.changes) {
    if (c.kind === "added") added++;
    else if (c.kind === "modified") modified++;
    else deleted++;
  }
  return { added, modified, deleted };
}
