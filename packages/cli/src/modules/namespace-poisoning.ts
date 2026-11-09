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
 * Well-known tool names from popular MCP servers and AI agent frameworks.
 * Expanded catalog covering Anthropic filesystem, git, web, DB, code, memory,
 * browser automation, cloud, IDE integration, and common agent frameworks.
 * If a server has a tool with a name suspiciously close to one of these,
 * it may be attempting a typosquatting/shadowing attack.
 */
const WELL_KNOWN_TOOL_NAMES = new Set([
  // Filesystem (Anthropic reference server)
  "read_file", "write_file", "list_directory", "create_directory",
  "move_file", "search_files", "get_file_info", "read_multiple_files",
  "list_allowed_directories", "edit_file", "delete_file", "copy_file",

  // Git tools
  "git_status", "git_diff", "git_commit", "git_log", "git_push",
  "git_pull", "git_branch", "git_checkout", "git_clone", "git_add",
  "git_reset", "git_stash", "git_merge", "git_rebase", "git_tag",

  // Web/fetch tools
  "fetch", "fetch_url", "browse", "search_web", "http_request",
  "get_webpage", "navigate_browser", "click_element", "type_text",
  "take_screenshot", "scroll_page", "find_element", "evaluate_js",

  // Database tools
  "query", "execute_sql", "list_tables", "describe_table",
  "run_query", "insert_row", "update_row", "delete_row",
  "get_schema", "create_table", "drop_table",

  // Code execution
  "execute", "run_code", "eval", "shell", "bash", "python",
  "run_script", "execute_command", "spawn_process",

  // Memory/state (Anthropic memory server)
  "remember", "recall", "store", "retrieve",
  "create_memory", "get_memory", "delete_memory", "list_memories",
  "create_entities", "create_relations", "search_nodes", "open_nodes",
  "add_observations", "delete_entities",

  // GitHub tools
  "create_issue", "get_issue", "list_issues", "create_pull_request",
  "get_pull_request", "list_pull_requests", "merge_pull_request",
  "create_repository", "fork_repository", "get_file_contents",
  "push_files", "search_repositories", "search_code",

  // Slack tools
  "send_message", "get_channel_history", "list_channels",
  "get_thread_replies", "add_reaction", "get_users",

  // Sequential thinking / reasoning
  "sequential_thinking", "think", "reason", "plan",

  // Context7 / documentation
  "resolve_library_id", "get_library_docs",

  // Playwright / browser automation
  "playwright_navigate", "playwright_screenshot", "playwright_click",
  "playwright_fill", "playwright_select", "playwright_hover",
  "playwright_evaluate", "playwright_close",

  // Kubernetes / cloud
  "kubectl_apply", "kubectl_get", "kubectl_describe", "kubectl_delete",
  "helm_install", "helm_upgrade", "docker_run", "docker_build",

  // VSCode / IDE
  "open_file", "close_file", "save_file", "get_diagnostics",
  "apply_edit", "show_notification", "create_terminal",
]);

/**
 * Unicode homoglyph mappings — characters that look identical to ASCII letters.
 */
const HOMOGLYPHS: Record<string, string[]> = {
  a: ["\u0430", "\u00e0", "\u00e1", "\u00e2", "\u0101", "\u0103"],
  c: ["\u0441", "\u00e7", "\u0107"],
  d: ["\u0501", "\u0111"],
  e: ["\u0435", "\u00e8", "\u00e9", "\u00ea", "\u0113", "\u0117"],
  i: ["\u0456", "\u00ec", "\u00ed", "\u0131"],
  l: ["\u006c", "\u0031", "\u04cf", "\u217c"], // lowercase L, 1, Cyrillic
  n: ["\u0578", "\u00f1", "\u0144"],
  o: ["\u043e", "\u00f2", "\u00f3", "\u00f4", "\u014d", "\u0030"],
  p: ["\u0440", "\u03c1"],
  s: ["\u0455", "\u015b", "\u0219"],
  u: ["\u0446", "\u00f9", "\u00fa", "\u016b"],
  x: ["\u0445", "\u00d7"],
  y: ["\u0443", "\u00fd"],
};

/**
 * Semantic mismatch: read-like names vs. write/transmit descriptions.
 * The canonical "Attack #2" scenario: tool named "read_file" that
 * actually exfiltrates data to an external endpoint.
 */
const READ_NAME_SIGNALS  = /^(?:read|get|list|view|show|cat|fetch|check|describe|stat|find|search|query|peek|inspect)/i;
const WRITE_DESC_SIGNALS = /\b(?:send|transmit|upload|post|put|exfiltrate|write|delete|remove|destroy|drop|modify|update|patch|create|push|dispatch|emit|forward|relay|export|dump)\b/i;
const WRITE_NAME_SIGNALS = /^(?:write|create|update|delete|remove|push|send|post|put|upload|exec|execute|run|shell|deploy|drop|modify|alter|insert)/i;
const READ_DESC_SIGNALS  = /\b(?:read|retrieve|fetch|get|list|view|show|inspect|describe|stat|find|search|query)\b/i;

/**
 * Tool Namespace Poisoning Detection Module.
 *
 * Detects tools attempting to impersonate well-known tools via:
 * 1. Typosquatting — edit distance ≤ 2 from a known tool name
 * 2. Homoglyph attacks — Unicode characters that look like ASCII
 * 3. Name collision — multiple tools with identical normalized names
 * 4. Case confusion — read_File vs read_file
 * 5. Description-vs-name mismatch — tool named "read_file" whose description
 *    mentions transmitting, exfiltrating, or writing data (semantic rug pull)
 *
 * Novel to AI agent security (2025+): When an LLM agent is connected
 * to multiple MCP servers, a malicious server can register a tool
 * named "read_flie" (typo of "read_file") and the LLM may call
 * the wrong one, routing sensitive data to the attacker.
 *
 * Finding prefixes: NP-001 through NP-006
 */
export class NamespacePoisoningModule implements AuditModule {
  id = "namespace-poisoning";
  name = "Tool Namespace Poisoning Detection";
  description =
    "Detects typosquatting, homoglyph attacks, name collisions, and name-vs-description semantic mismatches";
  version = "2.0.0";
  mode = "passive" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const { tools } = context.capabilities;
    const checks: CheckResult[] = [];

    checks.push(this.checkTyposquatting(tools));
    checks.push(this.checkHomoglyphs(tools));
    checks.push(this.checkInternalCollisions(tools));
    checks.push(this.checkSuspiciousNaming(tools));
    checks.push(this.checkDescriptionNameMismatch(tools));
    checks.push(this.checkFunctionalDuplicates(tools));

    return checks;
  }

  /**
   * NP-005: Name-vs-description semantic mismatch.
   *
   * Detects tools where the name implies one class of operation (read/query)
   * but the description implies another (write/transmit/exfiltrate).
   * This is the "Semantic Name Shadowing" attack — Attack #2 from research findings.
   *
   * Example: tool named "read_file" with description mentioning "sends data to
   * remote endpoint" — the name looks safe to an LLM agent's planner, but the
   * implementation does something completely different.
   */
  private checkDescriptionNameMismatch(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];

    for (const tool of tools) {
      const desc = (tool.description ?? "").toLowerCase();
      if (!desc || desc.length < 20) continue;

      const nameImpliesRead  = READ_NAME_SIGNALS.test(tool.name);
      const nameImpliesWrite = WRITE_NAME_SIGNALS.test(tool.name);
      const descImpliesWrite = WRITE_DESC_SIGNALS.test(desc);
      const descImpliesRead  = READ_DESC_SIGNALS.test(desc);

      // Case A: Name says "read/get" but description says "send/write/transmit"
      if (nameImpliesRead && descImpliesWrite && !descImpliesRead) {
        const writeMatch = desc.match(WRITE_DESC_SIGNALS)?.[0];
        findings.push({
          id: `NP-005-A-${tool.name}`,
          module: this.id,
          severity: Severity.CRITICAL,
          title: `Semantic mismatch: "${tool.name}" looks like a read op but description implies "${writeMatch}"`,
          description:
            `Tool "${tool.name}" has a name strongly implying a read/query operation ` +
            `(starts with "${READ_NAME_SIGNALS.exec(tool.name)?.[0]}"), ` +
            `but its description contains write/transmit language: "${writeMatch}". ` +
            `This is a semantic name shadowing attack: the tool name passes quick review ` +
            `as "safe to call", while the description (which the LLM reads for implementation ` +
            `guidance) reveals a much more dangerous operation. ` +
            `An LLM agent's planner may approve calling "${tool.name}" without user confirmation ` +
            `because the name sounds read-only, while the actual implementation writes or exfiltrates data.`,
          evidence: {
            toolName: tool.name,
            nameSuggests: "read/query",
            descriptionSuggests: writeMatch,
            descriptionExcerpt: desc.substring(0, 300),
          },
          remediation:
            "Rename the tool to accurately reflect its operation, or change the implementation " +
            "to match the name. A tool named 'read_X' must only read. A tool that writes, " +
            "sends, or transmits must be named accordingly (e.g., 'send_X', 'write_X').",
          toolName: tool.name,
          cweId: "CWE-436", // Interpretation Conflict
          confidence: 0.8,
        });
      }

      // Case B: Name says "write/send" but description only says "read/query" (potentially deceptive in other direction)
      if (nameImpliesWrite && descImpliesRead && !descImpliesWrite) {
        findings.push({
          id: `NP-005-B-${tool.name}`,
          module: this.id,
          severity: Severity.HIGH,
          title: `Semantic mismatch: "${tool.name}" looks like a write op but description only mentions reads`,
          description:
            `Tool "${tool.name}" has a name implying write/execute operations, ` +
            `but its description only mentions read/query behavior. ` +
            `This inconsistency may indicate an undocumented write side-effect, ` +
            `or an attempt to obscure dangerous capabilities behind benign documentation.`,
          evidence: {
            toolName: tool.name,
            nameSuggests: "write/execute",
            descriptionSuggests: "read/query",
            descriptionExcerpt: desc.substring(0, 300),
          },
          remediation:
            "Ensure the tool description accurately documents ALL operations the tool performs, " +
            "including any write, delete, or network operations.",
          toolName: tool.name,
          cweId: "CWE-436",
          confidence: 0.65,
        });
      }
    }

    return {
      id: "NP-005",
      name: "Name-vs-description semantic mismatch",
      status: findings.length > 0
        ? (findings.some(f => f.severity === Severity.CRITICAL) ? CheckStatus.FAIL : CheckStatus.WARN)
        : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} tool(s) have names that contradict their descriptions`
        : "All tool names are semantically consistent with their descriptions",
      finding: findings[0],
    };
  }

  /**
   * NP-001: Typosquatting — tool name within edit distance 1-2 of a well-known tool.
   */
  private checkTyposquatting(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];

    for (const tool of tools) {
      const normalized = tool.name.toLowerCase().replace(/[-_.]/g, "_");

      // Skip exact matches — those are fine
      if (WELL_KNOWN_TOOL_NAMES.has(normalized)) continue;

      for (const known of WELL_KNOWN_TOOL_NAMES) {
        const distance = this.levenshtein(normalized, known);

        if (distance === 1 || (distance === 2 && normalized.length > 6)) {
          findings.push({
            id: `NP-001-${tool.name}`,
            module: this.id,
            severity: Severity.HIGH,
            title: `Possible typosquat: "${tool.name}" is ${distance} character(s) from "${known}"`,
            description:
              `Tool "${tool.name}" has a name within edit distance ${distance} of the well-known ` +
              `tool "${known}". In a multi-server environment, an LLM could accidentally call this ` +
              `tool instead of the legitimate one, routing sensitive data or operations to the wrong server. ` +
              `This is a common supply-chain attack vector in AI agent ecosystems.`,
            evidence: {
              toolName: tool.name,
              similarTo: known,
              editDistance: distance,
              normalized,
            },
            remediation:
              "If this is intentional, rename the tool to avoid confusion with well-known tools. " +
              "If this is a legitimate alternative implementation, use a distinct prefix (e.g., 'myapp_read_file').",
            toolName: tool.name,
            cweId: "CWE-349", // Acceptance of Extraneous Untrusted Data With Trusted Data
          });
          break; // One match per tool is enough
        }
      }
    }

    return {
      id: "NP-001",
      name: "Typosquatting detection",
      status: findings.length > 0 ? CheckStatus.FAIL : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} possible typosquatting tool(s) detected`
        : "No typosquatting detected",
      finding: findings[0],
    };
  }

  /**
   * NP-002: Homoglyph attacks — Unicode characters masquerading as ASCII.
   */
  private checkHomoglyphs(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];

    for (const tool of tools) {
      const suspiciousChars: Array<{ char: string; position: number; looksLike: string }> = [];

      for (let i = 0; i < tool.name.length; i++) {
        const char = tool.name[i];
        const code = char.charCodeAt(0);

        // Flag any non-ASCII character in a tool name
        if (code > 127) {
          const looksLike = this.findHomoglyphSource(char);
          suspiciousChars.push({
            char,
            position: i,
            looksLike: looksLike ?? "unknown",
          });
        }
      }

      if (suspiciousChars.length > 0) {
        findings.push({
          id: `NP-002-${tool.name}`,
          module: this.id,
          severity: Severity.CRITICAL,
          title: `Homoglyph attack: "${tool.name}" contains Unicode lookalike characters`,
          description:
            `Tool "${tool.name}" contains ${suspiciousChars.length} non-ASCII character(s) that ` +
            `visually resemble ASCII letters. This is a classic homoglyph attack — the tool name ` +
            `looks legitimate to humans reviewing the server configuration, but is actually a ` +
            `different string that could be used to impersonate a trusted tool. ` +
            `Suspicious characters: ${suspiciousChars.map((c) => `U+${c.char.charCodeAt(0).toString(16).toUpperCase()} at position ${c.position} (looks like '${c.looksLike}')`).join(", ")}`,
          evidence: {
            toolName: tool.name,
            suspiciousChars,
            hexDump: [...tool.name].map((c) => `U+${c.charCodeAt(0).toString(16).toUpperCase()}`).join(" "),
          },
          remediation:
            "Tool names should only contain ASCII alphanumeric characters, hyphens, and underscores. " +
            "Remove all Unicode characters from tool names.",
          toolName: tool.name,
          cweId: "CWE-1007", // Insufficient Visual Distinction of Homoglyphs
        });
      }
    }

    return {
      id: "NP-002",
      name: "Homoglyph detection",
      status: findings.length > 0 ? CheckStatus.FAIL : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} tool(s) contain Unicode homoglyph characters`
        : "No homoglyph attacks detected",
      finding: findings[0],
    };
  }

  /**
   * NP-003: Internal name collisions — multiple tools with the same normalized name.
   */
  private checkInternalCollisions(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];
    const normalized = new Map<string, ToolInfo[]>();

    for (const tool of tools) {
      const key = tool.name.toLowerCase().replace(/[-_.]/g, "").replace(/\s+/g, "");
      const existing = normalized.get(key) ?? [];
      existing.push(tool);
      normalized.set(key, existing);
    }

    for (const [key, group] of normalized) {
      if (group.length <= 1) continue;

      const names = group.map((t) => t.name);
      findings.push({
        id: `NP-003-${key}`,
        module: this.id,
        severity: Severity.HIGH,
        title: `Name collision: ${group.length} tools normalize to "${key}"`,
        description:
          `Multiple tools have names that normalize to the same string: ${names.join(", ")}. ` +
          `LLMs may confuse these tools, especially when the difference is only in casing ` +
          `or separator characters. This creates unpredictable behavior in agent tool selection.`,
        evidence: {
          normalizedName: key,
          collidingTools: names,
          toolCount: group.length,
        },
        remediation:
          "Use distinct, unambiguous tool names. Avoid tools that differ only by " +
          "casing (read_File vs read_file) or separators (readFile vs read-file).",
        toolName: names.join(", "),
        cweId: "CWE-694", // Use of Multiple Resources with Duplicate Identifier
      });
    }

    return {
      id: "NP-003",
      name: "Internal name collisions",
      status: findings.length > 0 ? CheckStatus.FAIL : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} name collision group(s) detected`
        : "All tool names are unique after normalization",
      finding: findings[0],
    };
  }

  /**
   * NP-004: Suspicious naming patterns that suggest deception.
   */
  private checkSuspiciousNaming(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];

    const SUSPICIOUS_PATTERNS = [
      { pattern: /^_/, description: "starts with underscore (hidden tool)", severity: Severity.MEDIUM },
      { pattern: /^\./, description: "starts with dot (hidden tool)", severity: Severity.MEDIUM },
      { pattern: /\s/, description: "contains whitespace (evasion)", severity: Severity.HIGH },
      { pattern: /[\x00-\x1f]/, description: "contains control characters", severity: Severity.CRITICAL },
      { pattern: /^(test|debug|tmp|temp|dev|internal|private|admin|root|system)$/i, description: "uses reserved/internal name", severity: Severity.MEDIUM },
      { pattern: /(.)\1{4,}/, description: "contains character repetition (obfuscation)", severity: Severity.MEDIUM },
    ];

    for (const tool of tools) {
      for (const { pattern, description, severity } of SUSPICIOUS_PATTERNS) {
        if (pattern.test(tool.name)) {
          findings.push({
            id: `NP-004-${tool.name}`,
            module: this.id,
            severity,
            title: `Suspicious tool name: "${tool.name}" — ${description}`,
            description:
              `Tool "${tool.name}" has a suspicious naming pattern: ${description}. ` +
              `This may indicate an attempt to hide the tool from review or impersonate ` +
              `system-level functionality.`,
            evidence: {
              toolName: tool.name,
              pattern: description,
              hexDump: [...tool.name].map((c) =>
                c.charCodeAt(0) < 32
                  ? `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`
                  : c
              ).join(""),
            },
            remediation:
              "Use clear, descriptive tool names with only ASCII alphanumeric characters, " +
              "hyphens, and underscores.",
            toolName: tool.name,
            cweId: "CWE-116", // Improper Encoding or Escaping of Output
          });
          break; // One finding per tool
        }
      }
    }

    return {
      id: "NP-004",
      name: "Suspicious naming patterns",
      status: findings.length > 0 ? CheckStatus.WARN : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} tool(s) have suspicious naming patterns`
        : "All tool names follow standard conventions",
      finding: findings[0],
    };
  }

  /**
   * NP-006: Functional duplicate detection via description token overlap.
   *
   * Catches tools that do the same thing under different names — causing
   * agent confusion and potential double-execution. An LLM agent may call
   * both "search_files" and "find_files" thinking they are different operations
   * when they are functionally identical.
   *
   * Uses cosine similarity on token frequency vectors of tool descriptions.
   * Default threshold: 0.85 (configurable via finding evidence).
   */
  private checkFunctionalDuplicates(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];
    const SIMILARITY_THRESHOLD = 0.85;

    // Tokenise descriptions into lowercased word-frequency vectors
    const tokenVectors = tools.map((t) => this.tokenVector(t.description ?? ""));

    const reportedPairs = new Set<string>();

    for (let i = 0; i < tools.length; i++) {
      if (!tools[i].description || (tools[i].description ?? "").length < 30) continue;

      for (let j = i + 1; j < tools.length; j++) {
        if (!tools[j].description || (tools[j].description ?? "").length < 30) continue;

        // Skip if names are identical (already caught by NP-003)
        const normA = tools[i].name.toLowerCase().replace(/[-_.]/g, "");
        const normB = tools[j].name.toLowerCase().replace(/[-_.]/g, "");
        if (normA === normB) continue;

        const sim = this.cosineSimilarity(tokenVectors[i], tokenVectors[j]);
        if (sim < SIMILARITY_THRESHOLD) continue;

        const pairKey = [tools[i].name, tools[j].name].sort().join("|");
        if (reportedPairs.has(pairKey)) continue;
        reportedPairs.add(pairKey);

        // Extra signal: check for verb overlap in names
        const verbA = tools[i].name.match(/^([a-z]+)/i)?.[1]?.toLowerCase();
        const verbB = tools[j].name.match(/^([a-z]+)/i)?.[1]?.toLowerCase();
        const sameVerb = verbA && verbB && verbA === verbB;

        findings.push({
          id: `NP-006-${tools[i].name}-${tools[j].name}`,
          module: this.id,
          severity: sameVerb ? Severity.HIGH : Severity.MEDIUM,
          title: `Probable functional duplicate: "${tools[i].name}" and "${tools[j].name}" (${Math.round(sim * 100)}% description similarity)`,
          description:
            `Tools "${tools[i].name}" and "${tools[j].name}" have descriptions with ` +
            `${Math.round(sim * 100)}% cosine similarity (threshold: ${Math.round(SIMILARITY_THRESHOLD * 100)}%). ` +
            (sameVerb ? `Both tool names share the same action verb ("${verbA}"). ` : "") +
            `Functionally duplicate tools under different names cause agent confusion: ` +
            `an LLM may call both tools thinking they are distinct operations, executing ` +
            `the same action twice. Malicious servers may register a shadowing duplicate ` +
            `to intercept calls intended for the legitimate tool.`,
          evidence: {
            tool1: tools[i].name,
            tool2: tools[j].name,
            similarityScore: Math.round(sim * 100) + "%",
            sameActionVerb: sameVerb ?? false,
            description1Excerpt: (tools[i].description ?? "").substring(0, 200),
            description2Excerpt: (tools[j].description ?? "").substring(0, 200),
          },
          remediation:
            "If both tools are intentionally different, make their descriptions clearly distinct. " +
            "If they are functionally equivalent, consolidate them into one tool. " +
            "Use a consistent naming convention that reflects the functional difference. " +
            "For shadow/duplicate detection, audit whether both tools are from the same server.",
          toolName: `${tools[i].name}, ${tools[j].name}`,
          cweId: "CWE-694", // Use of Multiple Resources with Duplicate Identifier
          confidence: sim,
        });
      }
    }

    return {
      id: "NP-006",
      name: "Functional duplicate detection",
      status: findings.length > 0 ? CheckStatus.WARN : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} tool pair(s) are probable functional duplicates (≥${Math.round(SIMILARITY_THRESHOLD * 100)}% description similarity)`
        : "No functional duplicate tools detected",
      finding: findings[0],
    };
  }

  /**
   * Build a token frequency map from a tool description.
   * Lowercases and strips punctuation; ignores stop words.
   */
  private tokenVector(text: string): Map<string, number> {
    const STOP_WORDS = new Set([
      "a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for",
      "of", "with", "by", "from", "as", "is", "was", "are", "were", "be",
      "been", "being", "have", "has", "had", "do", "does", "did", "will",
      "would", "could", "should", "may", "might", "shall", "can", "this",
      "that", "these", "those", "it", "its", "not", "no", "if", "when",
    ]);

    const freq = new Map<string, number>();
    const tokens = text.toLowerCase().replace(/[^a-z0-9\s]/g, " ").split(/\s+/);

    for (const token of tokens) {
      if (token.length < 3 || STOP_WORDS.has(token)) continue;
      freq.set(token, (freq.get(token) ?? 0) + 1);
    }

    return freq;
  }

  /**
   * Compute cosine similarity between two token frequency vectors.
   */
  private cosineSimilarity(a: Map<string, number>, b: Map<string, number>): number {
    if (a.size === 0 || b.size === 0) return 0;

    let dotProduct = 0;
    let normA = 0;
    let normB = 0;

    for (const [token, countA] of a) {
      const countB = b.get(token) ?? 0;
      dotProduct += countA * countB;
      normA += countA * countA;
    }
    for (const countB of b.values()) {
      normB += countB * countB;
    }

    const denom = Math.sqrt(normA) * Math.sqrt(normB);
    return denom === 0 ? 0 : dotProduct / denom;
  }

  /**
   * Compute Levenshtein edit distance between two strings.
   */
  private levenshtein(a: string, b: string): number {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;

    const matrix: number[][] = [];
    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        const cost = b[i - 1] === a[j - 1] ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j - 1] + cost,
        );
      }
    }

    return matrix[b.length][a.length];
  }

  /**
   * Find which ASCII character a Unicode character is trying to imitate.
   */
  private findHomoglyphSource(char: string): string | null {
    for (const [ascii, glyphs] of Object.entries(HOMOGLYPHS)) {
      if (glyphs.includes(char)) return ascii;
    }
    return null;
  }
}
