import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
  type ToolInfo,
  type Finding,
} from "../types/index.js";

/**
 * Agentic Loop Trap Detection Module.
 *
 * Detects tool patterns that could trap an LLM agent in infinite or
 * exponentially expensive tool-calling loops. This is a novel attack
 * vector unique to autonomous AI agents (2025+).
 *
 * Attack patterns:
 * 1. Self-referential tools — a tool's output schema or description
 *    instructs the agent to call the same tool again with modified params
 * 2. Circular tool chains — tool A says "now call tool B", tool B says
 *    "now call tool A"
 * 3. State machine traps — tools with "status" or "state" parameters
 *    that create polling loops
 * 4. Pagination without termination — tools that always return a
 *    next_cursor, even on the last page
 * 5. Fork bombs — tools that instruct the agent to call multiple other
 *    tools simultaneously, each of which does the same
 *
 * Finding prefixes: LT-001 through LT-006
 */
export class AgenticLoopTrapModule implements AuditModule {
  id = "agentic-loop-trap";
  name = "Agentic Loop Trap Detection";
  description =
    "Detects tool patterns that could trap AI agents in infinite or expensive loops";
  version = "1.0.0";
  mode = "passive" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const { tools } = context.capabilities;
    const checks: CheckResult[] = [];

    checks.push(this.checkSelfReferentialDescriptions(tools));
    checks.push(this.checkPollingTraps(tools));
    checks.push(this.checkCircularChains(tools));
    checks.push(this.checkForkBombs(tools));
    checks.push(this.checkIndirectRecursion(tools));
    checks.push(this.checkStronglyConnectedComponents(tools));

    return checks;
  }

  /**
   * LT-001: Tool descriptions that instruct the LLM to call the tool again.
   * This is a prompt injection in the tool definition itself.
   */
  private checkSelfReferentialDescriptions(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];

    const LOOP_PATTERNS = [
      { pattern: /call\s+(this|the\s+same)\s+(tool|function)\s+again/i, description: "explicit self-call instruction" },
      { pattern: /repeat\s+(this|the)\s+(call|invocation|request)/i, description: "repeat instruction" },
      { pattern: /must\s+be\s+called\s+(repeatedly|multiple\s+times|in\s+a\s+loop)/i, description: "mandatory repetition" },
      { pattern: /continue\s+calling\s+until/i, description: "unbounded loop condition" },
      { pattern: /poll\s+(this|until|for)\b/i, description: "polling instruction" },
      { pattern: /keep\s+(calling|retrying|polling|running)\s+until/i, description: "unbounded retry loop" },
      { pattern: /always\s+(retry|call\s+again|repeat)\s+(on|if|when)\s+(error|failure|timeout)/i, description: "retry-on-error loop" },
      { pattern: /if\s+(?:the\s+)?result\s+is\s+(?:not\s+)?(?:ready|complete|done|finished).*call\s+again/i, description: "completion polling loop" },
    ];

    for (const tool of tools) {
      const desc = tool.description ?? "";
      const paramDescs = this.getAllParamDescriptions(tool);
      const allText = [desc, ...paramDescs].join(" ");

      for (const { pattern, description } of LOOP_PATTERNS) {
        if (pattern.test(allText)) {
          findings.push({
            id: `LT-001-${tool.name}`,
            module: this.id,
            severity: Severity.HIGH,
            title: `Loop trap in "${tool.name}": ${description}`,
            description:
              `Tool "${tool.name}" contains language instructing the LLM to call it repeatedly: ` +
              `"${allText.match(pattern)?.[0]}". An LLM agent following these instructions will ` +
              `enter an unbounded loop, consuming tokens and API credits with each iteration. ` +
              `This can be intentional (malicious billing attack) or accidental (poorly written ` +
              `tool description).`,
            evidence: {
              toolName: tool.name,
              matchedPattern: description,
              matchedText: allText.match(pattern)?.[0],
              fullDescription: desc.substring(0, 300),
            },
            remediation:
              "Remove loop instructions from tool descriptions. If polling is genuinely needed, " +
              "implement it server-side with webhooks or long-polling, not via LLM tool-calling loops. " +
              "Add a max_retries parameter if retry behavior is intentional.",
            toolName: tool.name,
            cweId: "CWE-835", // Loop with Unreachable Exit Condition
          });
          break;
        }
      }
    }

    return {
      id: "LT-001",
      name: "Self-referential loop instructions",
      status: findings.length > 0 ? CheckStatus.FAIL : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} tool(s) contain loop trap instructions`
        : "No self-referential loop patterns detected",
      finding: findings[0],
    };
  }

  /**
   * LT-002: Tools with state/status parameters that suggest polling patterns.
   * E.g., check_status(job_id) → "pending" → agent calls again → "pending" → ...
   */
  private checkPollingTraps(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];

    const POLLING_NAME_PATTERNS = [
      /^(?:check|get|poll)[_-]?(?:status|state|progress|result|completion|job|task)/i,
      /^(?:wait|await)[_-]?(?:for|until)?[_-]?(?:completion|result|ready|done)/i,
      /^(?:monitor|watch|observe)[_-]?/i,
    ];

    for (const tool of tools) {
      const isPolling = POLLING_NAME_PATTERNS.some((p) => p.test(tool.name));
      if (!isPolling) continue;

      const params = Object.keys((tool.inputSchema?.properties ?? {}) as Record<string, unknown>);
      const hasMaxRetries = params.some((p) =>
        /^(max_?retries|max_?attempts|max_?polls|timeout|max_?wait|ttl)$/i.test(p)
      );

      if (!hasMaxRetries) {
        findings.push({
          id: `LT-002-${tool.name}`,
          module: this.id,
          severity: Severity.MEDIUM,
          title: `Polling trap: "${tool.name}" has no retry/timeout limit`,
          description:
            `Tool "${tool.name}" appears to be a status-checking/polling tool but has no ` +
            `max_retries, timeout, or max_wait parameter. An LLM agent will poll this tool ` +
            `indefinitely until the status changes. If the underlying job never completes ` +
            `(or the server is malicious), the agent enters an infinite loop.`,
          evidence: {
            toolName: tool.name,
            parameters: params,
            hasMaxRetries,
            description: tool.description,
          },
          remediation:
            "Add a max_retries or timeout parameter to polling tools. Document the expected " +
            "polling interval and termination conditions in the tool description. " +
            "Better yet, implement server-side push notifications instead of client polling.",
          toolName: tool.name,
          cweId: "CWE-835",
        });
      }
    }

    return {
      id: "LT-002",
      name: "Polling traps (no termination)",
      status: findings.length > 0 ? CheckStatus.WARN : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} polling tool(s) lack termination parameters`
        : "All polling tools have proper termination controls",
      finding: findings[0],
    };
  }

  /**
   * LT-003: Circular tool references — tool descriptions that reference each other.
   * "After calling this tool, call tool_b" + "After calling this tool, call tool_a"
   */
  private checkCircularChains(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];

    // Build a reference graph: tool -> set of tools it references
    const graph = new Map<string, Set<string>>();
    const toolNames = new Set(tools.map((t) => t.name));

    for (const tool of tools) {
      const desc = (tool.description ?? "").toLowerCase();
      const paramDescs = this.getAllParamDescriptions(tool);
      const allText = [desc, ...paramDescs].join(" ").toLowerCase();

      const refs = new Set<string>();
      for (const otherName of toolNames) {
        if (otherName === tool.name) continue;
        // Check if the description mentions the other tool by name
        if (allText.includes(otherName.toLowerCase())) {
          refs.add(otherName);
        }
      }

      if (refs.size > 0) {
        graph.set(tool.name, refs);
      }
    }

    // Detect cycles using DFS
    const visited = new Set<string>();
    const inStack = new Set<string>();

    const findCycle = (node: string, path: string[]): string[] | null => {
      if (inStack.has(node)) {
        const cycleStart = path.indexOf(node);
        return path.slice(cycleStart);
      }
      if (visited.has(node)) return null;

      visited.add(node);
      inStack.add(node);
      path.push(node);

      const neighbors = graph.get(node);
      if (neighbors) {
        for (const neighbor of neighbors) {
          const cycle = findCycle(neighbor, [...path]);
          if (cycle) return cycle;
        }
      }

      inStack.delete(node);
      return null;
    };

    const reportedCycles = new Set<string>();

    for (const toolName of graph.keys()) {
      visited.clear();
      inStack.clear();
      const cycle = findCycle(toolName, []);
      if (cycle) {
        const cycleKey = [...cycle].sort().join(",");
        if (reportedCycles.has(cycleKey)) continue;
        reportedCycles.add(cycleKey);

        findings.push({
          id: `LT-003-${cycle[0]}`,
          module: this.id,
          severity: Severity.HIGH,
          title: `Circular tool chain: ${cycle.join(" → ")} → ${cycle[0]}`,
          description:
            `Tools form a circular reference chain: ${cycle.join(" → ")} → ${cycle[0]}. ` +
            `If an LLM agent follows the instructions in each tool's description, it will ` +
            `loop infinitely between these tools, consuming tokens and API credits. ` +
            `This can be weaponized as a billing attack against agent operators.`,
          evidence: {
            cycle,
            cycleLength: cycle.length,
            toolDescriptions: Object.fromEntries(
              cycle.map((name) => [name, tools.find((t) => t.name === name)?.description ?? ""])
            ),
          },
          remediation:
            "Remove circular references from tool descriptions. If tools must reference each " +
            "other, document the expected call sequence with a clear termination condition.",
          toolName: cycle.join("→"),
          cweId: "CWE-835",
        });
      }
    }

    return {
      id: "LT-003",
      name: "Circular tool chain detection",
      status: findings.length > 0 ? CheckStatus.FAIL : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} circular tool chain(s) detected`
        : "No circular tool chains found",
      finding: findings[0],
    };
  }

  /**
   * LT-004: Fork bomb patterns — tools that instruct calling multiple tools.
   * "Call tool_a, tool_b, and tool_c simultaneously" creates exponential branching.
   */
  private checkForkBombs(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];
    const toolNames = new Set(tools.map((t) => t.name));

    for (const tool of tools) {
      const desc = (tool.description ?? "").toLowerCase();
      const referencedTools: string[] = [];

      for (const name of toolNames) {
        if (name === tool.name) continue;
        if (desc.includes(name.toLowerCase())) {
          referencedTools.push(name);
        }
      }

      // Flag tools that reference 3+ other tools in their description
      if (referencedTools.length >= 3) {
        findings.push({
          id: `LT-004-${tool.name}`,
          module: this.id,
          severity: Severity.MEDIUM,
          title: `Fork bomb risk: "${tool.name}" references ${referencedTools.length} other tools`,
          description:
            `Tool "${tool.name}" references ${referencedTools.length} other tools in its ` +
            `description: ${referencedTools.join(", ")}. If the LLM interprets this as an ` +
            `instruction to call all referenced tools, and those tools reference others, ` +
            `the number of tool calls grows exponentially. This is an agentic fork bomb.`,
          evidence: {
            toolName: tool.name,
            referencedTools,
            referenceCount: referencedTools.length,
            description: tool.description?.substring(0, 300),
          },
          remediation:
            "Limit tool descriptions to describing the tool itself. Avoid instructing the LLM " +
            "to call other tools in the description. Use a separate orchestration layer if " +
            "tools need to be composed.",
          toolName: tool.name,
          cweId: "CWE-674", // Uncontrolled Recursion
        });
      }
    }

    return {
      id: "LT-004",
      name: "Fork bomb risk (multi-tool fan-out)",
      status: findings.length > 0 ? CheckStatus.WARN : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} tool(s) reference 3+ other tools (fork bomb risk)`
        : "No fork bomb patterns detected",
      finding: findings[0],
    };
  }

  /**
   * LT-005: Indirect recursion — 3+ tool cycle detected in the call graph.
   *
   * LT-003 detects direct 2-node cycles found by simple DFS. LT-005 explicitly
   * targets multi-hop cycles (A → B → C → A) that are harder to spot by inspection
   * and more likely to be introduced unintentionally.
   *
   * Uses the same DFS-based call graph built from description text references,
   * but reports only cycles of length ≥ 3 as LT-005 (to complement LT-003).
   */
  private checkIndirectRecursion(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];
    const graph = this.buildCallGraph(tools);

    const visited = new Set<string>();
    const inStack = new Set<string>();

    const findCycle = (node: string, path: string[]): string[] | null => {
      if (inStack.has(node)) {
        const cycleStart = path.indexOf(node);
        return path.slice(cycleStart);
      }
      if (visited.has(node)) return null;

      visited.add(node);
      inStack.add(node);
      path.push(node);

      for (const neighbor of (graph.get(node) ?? new Set())) {
        const cycle = findCycle(neighbor, [...path]);
        if (cycle) return cycle;
      }

      inStack.delete(node);
      return null;
    };

    const reportedCycles = new Set<string>();

    for (const toolName of graph.keys()) {
      visited.clear();
      inStack.clear();
      const cycle = findCycle(toolName, []);
      if (!cycle || cycle.length < 3) continue; // LT-003 already handles length-2 cycles

      const cycleKey = [...cycle].sort().join(",");
      if (reportedCycles.has(cycleKey)) continue;
      reportedCycles.add(cycleKey);

      findings.push({
        id: `LT-005-${cycle[0]}`,
        module: this.id,
        severity: Severity.HIGH,
        title: `Indirect recursion cycle (${cycle.length} tools): ${cycle.join(" → ")} → ${cycle[0]}`,
        description:
          `A ${cycle.length}-tool indirect recursion cycle was detected in the call graph: ` +
          `${cycle.join(" → ")} → ${cycle[0]}. ` +
          `Unlike direct loops (tool A calls A), indirect recursion cycles are harder to spot ` +
          `during review and are more likely to be triggered accidentally by an LLM agent ` +
          `following each tool's description instructions in sequence. ` +
          `Once entered, the agent will loop through all ${cycle.length} tools indefinitely, ` +
          `consuming tokens and API credits with each complete cycle.`,
        evidence: {
          cycle,
          cycleLength: cycle.length,
          fullCyclePath: [...cycle, cycle[0]].join(" → "),
          toolDescriptions: Object.fromEntries(
            cycle.map((name) => [name, tools.find((t) => t.name === name)?.description?.substring(0, 150) ?? ""])
          ),
        },
        remediation:
          "Remove circular cross-references from tool descriptions. " +
          "If tools genuinely need to reference each other, document a clear termination condition. " +
          "Add a max_iterations parameter to the entry-point tool.",
        toolName: cycle.join("→"),
        cweId: "CWE-835",
      });
    }

    return {
      id: "LT-005",
      name: "Indirect recursion cycle detection (3+ tools)",
      status: findings.length > 0 ? CheckStatus.FAIL : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} indirect recursion cycle(s) detected (≥3 tools)`
        : "No indirect recursion cycles detected",
      finding: findings[0],
    };
  }

  /**
   * LT-006: Strongly connected components (SCC) of 3+ tools.
   *
   * Uses Tarjan's SCC algorithm on the description-based call graph.
   * An SCC of size ≥ 3 means every tool in the component can reach every
   * other — any entry point into the component creates a potential infinite loop.
   * This is more comprehensive than cycle detection: it finds clusters of tools
   * that are mutually entangled regardless of entry order.
   */
  private checkStronglyConnectedComponents(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];
    const graph = this.buildCallGraph(tools);
    const toolNames = tools.map((t) => t.name);

    // Tarjan's SCC
    const index = new Map<string, number>();
    const lowlink = new Map<string, number>();
    const onStack = new Map<string, boolean>();
    const stack: string[] = [];
    let nextIndex = 0;
    const sccs: string[][] = [];

    const strongConnect = (v: string): void => {
      index.set(v, nextIndex);
      lowlink.set(v, nextIndex);
      nextIndex++;
      stack.push(v);
      onStack.set(v, true);

      for (const w of (graph.get(v) ?? new Set())) {
        if (!index.has(w)) {
          strongConnect(w);
          lowlink.set(v, Math.min(lowlink.get(v)!, lowlink.get(w)!));
        } else if (onStack.get(w)) {
          lowlink.set(v, Math.min(lowlink.get(v)!, index.get(w)!));
        }
      }

      if (lowlink.get(v) === index.get(v)) {
        const scc: string[] = [];
        let w: string;
        do {
          w = stack.pop()!;
          onStack.set(w, false);
          scc.push(w);
        } while (w !== v);
        sccs.push(scc);
      }
    };

    for (const name of toolNames) {
      if (!index.has(name) && graph.has(name)) {
        strongConnect(name);
      }
    }

    for (const scc of sccs) {
      if (scc.length < 3) continue; // trivial SCCs (single node) or simple pairs

      findings.push({
        id: `LT-006-${[...scc].sort()[0]}`,
        module: this.id,
        severity: Severity.HIGH,
        title: `Mutually entangled tool cluster (SCC of ${scc.length}): ${scc.join(", ")}`,
        description:
          `Tarjan's SCC algorithm found a strongly connected component of ${scc.length} tools: ` +
          `${scc.join(", ")}. ` +
          `Every tool in this cluster can reach every other tool via the description-based call graph. ` +
          `An LLM agent entering the cluster from any of the ${scc.length} entry points can be ` +
          `trapped in an infinite loop. This pattern is especially dangerous because it is invisible ` +
          `from a single tool's description — the loop only emerges when the full graph is analysed.`,
        evidence: {
          scc,
          sccSize: scc.length,
          internalEdges: [...scc].map((v) => ({
            from: v,
            to: [...(graph.get(v) ?? new Set())].filter((w) => scc.includes(w)),
          })).filter((e) => e.to.length > 0),
        },
        remediation:
          "Audit the descriptions of all tools in this cluster and remove circular cross-references. " +
          "Restructure the tool set to have a clear directed acyclic data flow. " +
          "If some tools must reference others, ensure there is always a clear exit path " +
          "with an explicit termination condition.",
        toolName: scc.join(", "),
        cweId: "CWE-835",
      });
    }

    return {
      id: "LT-006",
      name: "Strongly connected tool clusters (Tarjan SCC)",
      status: findings.length > 0 ? CheckStatus.FAIL : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} strongly connected component(s) of ≥3 tools detected`
        : "No strongly connected tool clusters found",
      finding: findings[0],
    };
  }

  /**
   * Build a directed call graph from tool descriptions.
   * Edge A → B exists if A's description text contains B's name.
   */
  private buildCallGraph(tools: ToolInfo[]): Map<string, Set<string>> {
    const graph = new Map<string, Set<string>>();
    const toolNames = new Set(tools.map((t) => t.name));

    for (const tool of tools) {
      const desc = (tool.description ?? "").toLowerCase();
      const paramDescs = this.getAllParamDescriptions(tool);
      const allText = [desc, ...paramDescs].join(" ").toLowerCase();

      const refs = new Set<string>();
      for (const otherName of toolNames) {
        if (otherName === tool.name) continue;
        if (allText.includes(otherName.toLowerCase())) {
          refs.add(otherName);
        }
      }

      if (refs.size > 0) {
        graph.set(tool.name, refs);
      }
    }

    return graph;
  }

  /**
   * Extract all parameter descriptions from a tool's schema.
   */
  private getAllParamDescriptions(tool: ToolInfo): string[] {
    const descriptions: string[] = [];
    const properties = (tool.inputSchema?.properties ?? {}) as Record<string, Record<string, unknown>>;

    for (const prop of Object.values(properties)) {
      if (typeof prop.description === "string") {
        descriptions.push(prop.description);
      }
    }

    return descriptions;
  }
}
