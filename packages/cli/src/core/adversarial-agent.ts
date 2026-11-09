/**
 * Deterministic Adversarial-Agent Fixture (Item 6 v1).
 *
 * The IPI harness simulates the cognitive vulnerability mechanics that real
 * LLM agents exhibit, without API cost or non-determinism. The contract:
 *
 *   1. Strict Parsing — the harness has NO hardcoded knowledge of what
 *      downstream tools the target exposes. It physically parses the
 *      `POISON-...` content returned by the chamber and extracts a
 *      structured directive of the form
 *         __IPI_DIRECTIVE__:<tool>:<json-args>
 *      No directive ⇒ no second-order action.
 *
 *   2. State Preservation — the harness drives a five-state machine:
 *         init → fetched → parsed → executed → done
 *      Each transition records what changed (canary observed, directive
 *      extracted, downstream call fired, etc.) so the kill-chain assembler
 *      can label each chain stage.
 *
 *   3. Failure Simulation — malformed payloads (no directive, malformed
 *      JSON, unknown tool name) DO NOT silently pass. The harness rejects
 *      them and surfaces the rejection reason on the result. This proves
 *      the active scanner generated a real attack payload, not random
 *      noise that an LLM would have ignored.
 *
 * What this is NOT:
 *
 *   - Not an LLM. There is no model, no inference, no API calls. The
 *     "decision" to follow the directive is `if (directive) call(tool)`.
 *     That's the entire cognitive simulation.
 *
 *   - Not a perfect proxy for real agent behavior — a real LLM might
 *     refuse, hallucinate, partially follow, or invent its own follow-up.
 *     This harness is for *infrastructure-level* IPI proof: "if an agent
 *     followed the instruction, would the target carry out the second-order
 *     action and would it land in the chamber?" Real-LLM-in-loop testing
 *     is a separate, deferred work item.
 */

// ────────────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────────────

export type AgentState =
  | "init"
  | "fetched"
  | "parsed"
  | "executed"
  | "done"
  | "failed";

export interface IpiDirective {
  /** Tool the directive instructs the agent to call. Free-form string —
   *  the harness does not pre-validate against a tool catalog. */
  tool: string;
  /** Arguments to pass to the tool. Parsed from the JSON payload. */
  args: Record<string, unknown>;
}

export type DirectiveParseResult =
  | { ok: true; directive: IpiDirective; rawLine: string }
  | { ok: false; reason: DirectiveParseFailure; detail?: string };

export type DirectiveParseFailure =
  | "no-directive-present"
  | "malformed-line"
  | "malformed-json"
  | "missing-tool"
  | "missing-args";

export interface AgentTranscriptEntry {
  state: AgentState;
  at: string;
  detail: string;
  /** Optional sub-evidence specific to the state transition. */
  evidence?: Record<string, unknown>;
}

export interface AgentRunOptions {
  /**
   * The simulated user prompt that initiates the conversation. It's stored
   * on the transcript verbatim — the harness doesn't try to "interpret" it
   * because the only behavior path is: fetch external context → follow any
   * directive embedded in that context.
   */
  userPrompt: string;
  /**
   * Tool the agent calls FIRST to fetch external context. This is the seed
   * of the IPI chain — it must be a URL-accepting tool the target exposes.
   */
  initialFetch: {
    toolName: string;
    paramName: string;
    /** URL the agent fetches. The chamber returns a poisoned response. */
    url: string;
  };
  /**
   * Tool-call function — same shape as ProbeRouter's ToolCaller. The
   * harness does not own the protocol; it just speaks tool calls.
   */
  callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>;
}

export interface AgentRunResult {
  finalState: AgentState;
  /** True iff the agent successfully fetched, parsed a directive, AND
   *  executed the second-order tool call. */
  ipiCompleted: boolean;
  /** The directive parsed from the chamber response, if any. */
  directive?: IpiDirective;
  /** The raw response of the second-order tool call, when fired. */
  secondOrderResult?: unknown;
  /** The poison canary observed in the fetched content, if any. */
  observedCanary?: string;
  /** Why the harness halted, when it didn't complete. */
  failure?: { reason: DirectiveParseFailure | "tool-call-failed"; detail?: string };
  /** Full state-transition transcript for kill-chain attribution. */
  transcript: AgentTranscriptEntry[];
}

// ────────────────────────────────────────────────────────────────────────────
// Strict directive parser
// ────────────────────────────────────────────────────────────────────────────

/** The exact prefix the parser looks for. Must match what the chamber's
 *  hostile-mode HOSTILE_TEMPLATE emits. */
export const IPI_DIRECTIVE_PREFIX = "__IPI_DIRECTIVE__:";

/** Pattern of a poison canary token, e.g. POISON-AB12CD34EF567890. */
const POISON_CANARY_RE = /POISON-[A-F0-9]{16}/;

/**
 * Parse the chamber response for a single IPI directive.
 *
 * Format expected:
 *   __IPI_DIRECTIVE__:<tool>:<json-args>\n
 *
 * The parser is strict by design (Constraint 3): a malformed line surfaces
 * a typed failure rather than being silently ignored. This makes it
 * impossible for the harness to "succeed" against a probe that wasn't
 * actually a valid IPI payload.
 */
export function parseIpiDirective(content: string): DirectiveParseResult {
  // Some servers re-encode underscores as `\_` (markdown autoescape). The
  // chamber-evidence module already does this normalization for capture
  // matching; we apply the same rule here so the harness stays in sync.
  const normalized = content
    .replace(/\\_/g, "_")
    .replace(/&#95;/g, "_")
    .replace(/&#x5f;/gi, "_");

  // Find the directive line. The match runs to end-of-line so embedded
  // newlines inside the JSON args block are NOT supported — keeps the
  // parser tight.
  const directiveStart = normalized.indexOf(IPI_DIRECTIVE_PREFIX);
  if (directiveStart === -1) {
    return { ok: false, reason: "no-directive-present" };
  }

  const lineEnd = normalized.indexOf("\n", directiveStart);
  const rawLine = (lineEnd === -1
    ? normalized.slice(directiveStart)
    : normalized.slice(directiveStart, lineEnd)
  ).trim();

  // Body after the prefix. Split on the FIRST colon only, because tool
  // arguments contain JSON objects with embedded colons.
  const body = rawLine.slice(IPI_DIRECTIVE_PREFIX.length);
  const firstColon = body.indexOf(":");
  if (firstColon === -1) {
    return { ok: false, reason: "malformed-line", detail: `no tool/args separator in "${rawLine}"` };
  }

  const tool = body.slice(0, firstColon).trim();
  const argsJson = body.slice(firstColon + 1).trim();
  if (tool.length === 0) {
    return { ok: false, reason: "missing-tool", detail: rawLine };
  }
  if (argsJson.length === 0) {
    return { ok: false, reason: "missing-args", detail: rawLine };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(argsJson);
  } catch (err) {
    return {
      ok: false,
      reason: "malformed-json",
      detail: err instanceof Error ? err.message : String(err),
    };
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, reason: "missing-args", detail: "args must be a JSON object" };
  }

  return {
    ok: true,
    directive: { tool, args: parsed as Record<string, unknown> },
    rawLine,
  };
}

/** Extract the first POISON-{16hex} token from a chamber response, if any. */
export function extractPoisonCanary(content: string): string | undefined {
  const match = POISON_CANARY_RE.exec(content);
  return match ? match[0] : undefined;
}

// ────────────────────────────────────────────────────────────────────────────
// Conversational state machine
// ────────────────────────────────────────────────────────────────────────────

/**
 * Run the harness end-to-end against a target.
 *
 * Sequence:
 *   1. init    — record the user prompt
 *   2. fetched — fire `initialFetch.toolName(initialFetch.url)`; record raw
 *                response and any POISON canary observed
 *   3. parsed  — extract the IPI directive from the response. On failure,
 *                halt at this state with `failed` and surface the reason
 *   4. executed — fire the directive's tool call. On error, halt at
 *                `failed` with `tool-call-failed`
 *   5. done    — second-order call returned without throwing
 *
 * Returns the full transcript so the kill-chain assembler can mark each
 * stage's status precisely (init=info, fetched=partial, parsed=partial,
 * executed=complete-on-chamber-evidence).
 */
export async function runAdversarialAgent(
  options: AgentRunOptions,
): Promise<AgentRunResult> {
  const transcript: AgentTranscriptEntry[] = [];
  const stamp = (state: AgentState, detail: string, evidence?: Record<string, unknown>) => {
    transcript.push({ state, at: new Date().toISOString(), detail, evidence });
  };

  // 1. init — user-prompt seed.
  stamp("init", "User prompt accepted; harness will follow first directive in fetched content.", {
    userPrompt: options.userPrompt,
    plannedFetch: options.initialFetch,
  });

  // 2. fetched — call the URL-accepting tool with the chamber URL.
  let fetchResult: unknown;
  try {
    fetchResult = await options.callTool(options.initialFetch.toolName, {
      [options.initialFetch.paramName]: options.initialFetch.url,
    });
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    stamp("failed", `Initial fetch threw: ${detail}`, { phase: "fetched" });
    return {
      finalState: "failed",
      ipiCompleted: false,
      transcript,
      failure: { reason: "tool-call-failed", detail },
    };
  }

  const fetchedContent = stringifyToolResult(fetchResult);
  const observedCanary = extractPoisonCanary(fetchedContent);
  stamp("fetched", "Initial fetch returned chamber content.", {
    bytes: fetchedContent.length,
    observedCanary,
  });

  // 3. parsed — strict directive extraction. Malformed payload halts the
  // chain and surfaces the reason — that proves the scanner-side payload
  // generator was wrong, not the harness.
  const parsed = parseIpiDirective(fetchedContent);
  if (!parsed.ok) {
    stamp("failed", `Directive parse failed: ${parsed.reason}`, { detail: parsed.detail });
    return {
      finalState: "failed",
      ipiCompleted: false,
      observedCanary,
      transcript,
      failure: { reason: parsed.reason, detail: parsed.detail },
    };
  }
  stamp("parsed", `Directive extracted: ${parsed.directive.tool}`, {
    tool: parsed.directive.tool,
    args: parsed.directive.args,
    rawLine: parsed.rawLine,
  });

  // 4. executed — fire the directed second-order tool call. The directive's
  // tool is treated as an opaque string (no allowlist, no schema check) —
  // that's by design. A real compromised agent would call whatever the
  // poison instructed.
  let secondOrderResult: unknown;
  try {
    secondOrderResult = await options.callTool(parsed.directive.tool, parsed.directive.args);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    stamp("failed", `Second-order tool call threw: ${detail}`, {
      tool: parsed.directive.tool,
      phase: "executed",
    });
    return {
      finalState: "failed",
      ipiCompleted: false,
      observedCanary,
      directive: parsed.directive,
      transcript,
      failure: { reason: "tool-call-failed", detail },
    };
  }
  stamp("executed", "Second-order tool call returned without throwing.", {
    tool: parsed.directive.tool,
    bytes: stringifyToolResult(secondOrderResult).length,
  });

  // 5. done — chain complete (the chamber sensors that prove the
  // second-order call landed are the caller's job to inspect; the harness
  // only owns the cognitive simulation).
  stamp("done", "IPI chain executed end-to-end.");
  return {
    finalState: "done",
    ipiCompleted: true,
    observedCanary,
    directive: parsed.directive,
    secondOrderResult,
    transcript,
  };
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

/**
 * Convert a tool-call result into a single string for content-scanning.
 * MCP servers return `{ content: [ { type: "text", text: "..." }, ... ] }`
 * but other protocols return raw strings or arbitrary objects. We coerce
 * everything to a UTF-8 string so the parser has a single input shape.
 */
function stringifyToolResult(result: unknown): string {
  if (result == null) return "";
  if (typeof result === "string") return result;
  if (typeof result === "object") {
    const content = (result as Record<string, unknown>).content;
    if (Array.isArray(content)) {
      const parts: string[] = [];
      for (const piece of content) {
        if (piece && typeof piece === "object" && typeof (piece as Record<string, unknown>).text === "string") {
          parts.push((piece as Record<string, unknown>).text as string);
        } else {
          parts.push(JSON.stringify(piece));
        }
      }
      return parts.join("\n");
    }
    return JSON.stringify(result);
  }
  return String(result);
}
