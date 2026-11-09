import { existsSync, readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import {
  CheckStatus,
  Severity,
  type AuditModule,
  type CheckResult,
  type ModuleContext,
  type ToolInfo,
} from "../types/index.js";
import { runAdversarialAgent, type AgentRunResult } from "../core/adversarial-agent.js";

/**
 * Adversarial Agent Audit Module (Item 6 v1).
 *
 * Drives the deterministic IPI harness during active scanning:
 *
 *   1. Identifies a URL-accepting tool the target exposes.
 *   2. Plants a chamber URL into that tool, simulating "agent fetches
 *      external context".
 *   3. The harness parses the chamber's hostile-mode response, extracts the
 *      embedded `__IPI_DIRECTIVE__:tool:args` line, and calls the named
 *      tool — same `callTool` channel a compromised agent would use.
 *   4. After the second-order call lands, this module reads the chamber
 *      capture file to confirm the second call hit a chamber sensor.
 *      That's the cognitive-IPI proof the kill-chain assembler labels
 *      `agent-triggered-callback`.
 *
 * Module is gated on chamber presence + active mode; otherwise SKIP. A
 * target with no URL-accepting tools also results in SKIP — it has no
 * fetch surface for the harness to seed.
 */

const URL_PARAM_RE = /^(url|uri|endpoint|href|link|src|webhook|callback|fetch_url|request_url|webhook_url|callback_url|redirect_url|target_url|notification_url|push_url|agent_url|peer_url)$/i;

export class AdversarialAgentModule implements AuditModule {
  id = "adversarial-agent";
  name = "Adversarial Agent (deterministic IPI fixture)";
  description =
    "Simulates an LLM agent following an injected directive in chamber content; emits CHAMBER-IPI-AGENT-001 when the second-order tool call lands a chamber capture";
  version = "1.0.0";
  mode = "active" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const chamber = context.chamber;

    if (!chamber || !context.callTool) {
      checks.push({
        id: "ADV-AGENT-001",
        name: "Adversarial agent fixture",
        status: CheckStatus.SKIP,
        message: "Adversarial agent fixture requires --active and a chamber.",
      });
      return checks;
    }

    const seedTool = pickFetchSeed(context.capabilities.tools ?? []);
    if (!seedTool) {
      checks.push({
        id: "ADV-AGENT-001",
        name: "Adversarial agent fixture",
        status: CheckStatus.SKIP,
        message: "No URL-accepting tool available — fixture has no fetch surface.",
      });
      return checks;
    }

    // Snapshot the http capture file before firing so we can attribute the
    // second-order callback to the harness's run.
    const httpCapture = chamber.captures?.http;
    const linesBefore = countCaptureLines(httpCapture);

    const runId = randomUUID().slice(0, 8);
    const seedUrl = `${chamber.fakeHttpUrl}/ipi-agent-seed/${runId}`;

    let result: AgentRunResult;
    try {
      result = await runAdversarialAgent({
        userPrompt:
          "User: please summarize the content at the linked URL for me.",
        initialFetch: {
          toolName: seedTool.toolName,
          paramName: seedTool.paramName,
          url: seedUrl,
        },
        callTool: context.callTool,
      });
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      checks.push({
        id: "ADV-AGENT-001",
        name: "Adversarial agent fixture",
        status: CheckStatus.WARN,
        message: `Harness threw before completing: ${detail}`,
      });
      return checks;
    }

    if (!result.ipiCompleted) {
      // Harness halted early — surface why. Each failure mode is
      // diagnostic, not a finding: it tells operators where the IPI vector
      // got cut off (no directive parsed, malformed JSON, second-order
      // tool call failed, …).
      const reason = result.failure?.reason ?? "unknown";
      checks.push({
        id: "ADV-AGENT-001",
        name: "Adversarial agent fixture",
        status: reason === "no-directive-present" ? CheckStatus.PASS : CheckStatus.WARN,
        message:
          reason === "no-directive-present"
            ? "Chamber response did not contain an IPI directive — agent had nothing to follow."
            : `Harness halted at ${result.finalState}: ${reason}` +
              (result.failure?.detail ? ` (${result.failure.detail})` : ""),
      });
      return checks;
    }

    // Look for a chamber-side callback attributable to the second-order
    // call. The directive's URL embeds the same runId so we can match.
    const linesAfter = countCaptureLines(httpCapture);
    const captureGrowth = linesAfter - linesBefore;

    if (captureGrowth <= 0) {
      // Harness completed but the second-order call did not produce a
      // chamber capture. This is "behavioral signal without sensor proof"
      // — partial chain.
      checks.push({
        id: "ADV-AGENT-001",
        name: "Adversarial agent fixture",
        status: CheckStatus.WARN,
        message:
          `Harness executed second-order tool '${result.directive?.tool ?? "?"}' but ` +
          "no chamber capture growth was observed — partial IPI signal.",
        finding: {
          id: "CHAMBER-IPI-AGENT-PARTIAL",
          module: this.id,
          severity: Severity.MEDIUM,
          title: "Adversarial agent executed an injected directive but second-order action was not chamber-observable",
          description:
            "The deterministic IPI harness fetched poisoned chamber content, parsed an injected directive, and " +
            "successfully called the named downstream tool. However, the chamber sensors did not record a capture " +
            "attributable to that second-order call. This is partial cognitive-IPI signal: the agent could be steered, " +
            "but the second-order action did not reach a sensor we monitor.",
          evidence: {
            transcript: result.transcript,
            directive: result.directive,
            observedCanary: result.observedCanary,
            seedUrl,
            runId,
          },
          remediation:
            "Treat tool descriptions and external content with equal distrust; sandbox tools that ingest user-pointed URLs.",
          confidence: 0.75,
          toolName: result.directive?.tool ?? seedTool.toolName,
        },
      });
      return checks;
    }

    // Full IPI chain: poisoned content fetched, directive parsed, second-
    // order tool call fired, chamber sensor recorded a follow-up callback.
    checks.push({
      id: "ADV-AGENT-001",
      name: "Adversarial agent fixture",
      status: CheckStatus.FAIL,
      message:
        `IPI chain completed end-to-end: agent followed directive '${result.directive?.tool ?? "?"}' ` +
        `and chamber recorded ${captureGrowth} second-order capture(s).`,
      finding: {
        id: "CHAMBER-IPI-AGENT-001",
        module: this.id,
        severity: Severity.CRITICAL,
        title: "Cognitive IPI chain proven: agent followed injected directive and second-order action reached chamber",
        description:
          "The deterministic adversarial-agent fixture simulated an LLM agent receiving a user prompt, fetching " +
          "external context (the detonation chamber's hostile-mode response), parsing an injected directive of the " +
          `form __IPI_DIRECTIVE__:<tool>:<json-args>, and calling the named tool. Crucially, the second-order tool ` +
          `call produced ${captureGrowth} new chamber capture(s) — sensor-bound proof that an attacker can steer ` +
          "the target into observable secondary actions purely by controlling the content it fetches.",
        evidence: {
          transcript: result.transcript,
          directive: result.directive,
          observedCanary: result.observedCanary,
          seedUrl,
          runId,
          chamberCapturesAfterSecondOrder: captureGrowth,
          captureFile: httpCapture,
          verifiedBy: "chamber-ipi-action",
        },
        remediation:
          "Reject tool-call requests whose arguments derive from external content fetched within the same agent " +
          "turn; require explicit user confirmation for any tool call whose arguments came from a previous tool's output.",
        cweId: "CWE-94",
        confidence: 0.99,
        toolName: result.directive?.tool ?? seedTool.toolName,
      },
    });

    return checks;
  }
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

interface FetchSeed {
  toolName: string;
  paramName: string;
}

function pickFetchSeed(tools: ToolInfo[]): FetchSeed | undefined {
  for (const tool of tools) {
    const props = (tool.inputSchema as Record<string, unknown> | undefined)
      ?.properties as Record<string, unknown> | undefined;
    if (!props) continue;
    for (const [paramName, schema] of Object.entries(props)) {
      const s = schema as Record<string, unknown> | undefined;
      if (!s || s.type !== "string") continue;
      if (URL_PARAM_RE.test(paramName)) {
        return { toolName: tool.name, paramName };
      }
    }
  }
  return undefined;
}

function countCaptureLines(captureFile: string | undefined): number {
  if (!captureFile || !existsSync(captureFile)) return 0;
  const raw = readFileSync(captureFile, "utf-8").trim();
  return raw === "" ? 0 : raw.split("\n").length;
}
