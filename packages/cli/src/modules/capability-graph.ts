import {
  CheckStatus,
  Severity,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
} from "../types/index.js";

type CapabilityCategory =
  | "file-read"
  | "file-write"
  | "network-fetch"
  | "command-execution"
  | "database-query"
  | "system-config"
  | "user-interaction"
  // Domain-specific buckets — kept distinct from generic file-read/file-write
  // so reports can express "this is a git server, not a generic FS server".
  | "git-read"
  | "git-write"
  | "branch-control"
  | "history-read"
  | "graph-read"
  | "graph-write"
  | "unknown";

/**
 * Token-based capability classification. Tool names are split on
 * `_`, `-`, `/`, `.`, and camelCase boundaries, then each token is checked
 * against the keyword sets below. Description text is intentionally NOT
 * searched: filesystem tool descriptions almost always contain
 * "directory" / "list" / "read" and would falsely collapse every tool into
 * "file-read".
 *
 * A tool may match multiple categories — `read_and_post` is both file-read
 * and network-fetch.
 */
const CAPABILITY_KEYWORDS: Record<Exclude<CapabilityCategory, "unknown">, ReadonlySet<string>> = {
  "file-write": new Set([
    "write", "put", "post", "update", "delete", "remove", "rm", "mkdir",
    "touch", "append", "create", "edit", "move", "rename", "chmod", "chown",
    "save", "add",
  ]),
  "file-read": new Set([
    "read", "cat", "ls", "dir", "tree", "stat", "head", "tail", "grep",
    "search", "list", "find", "get", "open", "show", "view", "info",
  ]),
  "network-fetch": new Set([
    "fetch", "http", "https", "curl", "wget", "graphql", "request",
    "webhook", "download", "api",
  ]),
  "command-execution": new Set([
    "run", "exec", "execute", "cmd", "shell", "bash", "sh", "process",
    "spawn", "eval",
  ]),
  "database-query": new Set([
    "sql", "query", "select", "insert", "mongo", "postgres", "mysql",
    "sqlite", "redis", "kv",
  ]),
  "system-config": new Set([
    "config", "settings", "env", "envvar", "restart", "kill", "start",
    "stop", "systemctl", "service",
  ]),
  "user-interaction": new Set([
    "ask", "prompt", "notify", "confirm", "elicit", "sample", "message",
  ]),

  // Domain: git ─────────────────────────────────────────────────────────────
  // Read tokens that — when combined with a `git` prefix — describe state
  // inspection rather than mutation: status, diff, log, show, blame, ls-files.
  "git-read": new Set([
    "status", "diff", "log", "show", "blame", "describe",
  ]),
  "git-write": new Set([
    // Tokens common to git mutation tools. Composition with `git` prefix is
    // required (see classifyDomain below) so `add` here doesn't hijack
    // `add_observations` from the memory server.
    "commit", "stage", "push", "pull", "merge", "rebase", "cherrypick",
    "reset", "revert", "stash", "checkout", "tag", "fetch",
  ]),
  "branch-control": new Set([
    "branch", "checkout", "switch",
  ]),
  "history-read": new Set([
    "log", "history", "blame", "reflog",
  ]),

  // Domain: knowledge graph (e.g. memory MCP) ─────────────────────────────
  "graph-read": new Set([
    "graph", "nodes", "node", "relations", "relation", "observations",
  ]),
  "graph-write": new Set([
    "entity", "entities", "relation", "relations", "observation",
    "observations",
  ]),
};

/**
 * Domain classification.
 *
 * Keywords like `add`, `branch`, or `relation` are too generic to use bare —
 * `add` could be `git add` (write), `add_observations` (graph-write), or
 * `add_user` (file-write somewhere else). We resolve this by gating
 * domain-specific categories on a domain *prefix* (`git_`, `graph_`/`node_`/
 * `entity_`/`observation_`) appearing somewhere in the name.
 */
function isGitTool(tokens: string[]): boolean {
  return tokens.some((t) => t === "git");
}
function isGraphTool(tokens: string[]): boolean {
  // Memory MCP exposes tool names like `create_entities`, `add_observations`,
  // `read_graph`, `search_nodes` — any of these tokens flag it as graph-domain.
  const graphSignals = new Set([
    "graph", "nodes", "node", "entity", "entities", "relation",
    "relations", "observation", "observations",
  ]);
  return tokens.some((t) => graphSignals.has(t));
}

function tokenize(name: string): string[] {
  // Split on _ - / . and at camelCase boundaries; lowercase each token.
  return name
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .split(/[_\-/.\s]+/)
    .filter(Boolean)
    .map((t) => t.toLowerCase());
}

const HIGH_RISK_CATEGORIES: ReadonlySet<CapabilityCategory> = new Set([
  "command-execution",
  "file-write",
  "network-fetch",
  "database-query",
  "git-write",
  "graph-write",
  "branch-control",
]);

/**
 * Categories whose keywords ONLY apply when a domain prefix is present.
 * Without this gate, `add` from `add_observations` would be misclassified
 * as generic file-write.
 */
const DOMAIN_GATED_CATEGORIES: Partial<Record<CapabilityCategory, (tokens: string[]) => boolean>> = {
  "git-read": isGitTool,
  "git-write": isGitTool,
  "branch-control": isGitTool,
  "history-read": isGitTool,
  "graph-read": isGraphTool,
  "graph-write": isGraphTool,
};

/**
 * Tool Capability Graph Module.
 *
 * Groups tools by operational capability (multi-label, name-only). Produces a
 * structural map auditors and downstream modules use to reason about blast
 * radius. The module is intentionally cheap and conservative — it should
 * agree with `dangerous-capability` on whether high-risk surfaces exist.
 */
export class ToolCapabilityGraphModule implements AuditModule {
  id = "capability-graph";
  name = "Tool Capability Graph";
  description = "Builds a semantic graph of tool capabilities for risk profiling and visualization";
  version = "1.1.0";
  mode = "passive" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const { tools } = context.capabilities;

    if (tools.length === 0) {
      checks.push({
        id: "TCG-001",
        name: "Tool Capability Graph",
        status: CheckStatus.PASS,
        message: "No tools to build a capability graph",
      });
      return checks;
    }

    const categorizedTools: Record<CapabilityCategory, string[]> = {
      "file-read": [],
      "file-write": [],
      "network-fetch": [],
      "command-execution": [],
      "database-query": [],
      "system-config": [],
      "user-interaction": [],
      "git-read": [],
      "git-write": [],
      "branch-control": [],
      "history-read": [],
      "graph-read": [],
      "graph-write": [],
      "unknown": [],
    };

    // Multi-label categorization via tokenized name matching. A tool may
    // belong to several categories (e.g. `read_and_post` → file-read +
    // network-fetch). Domain-gated categories (git-*, graph-*) only apply
    // when the corresponding domain prefix is detected on the tool name.
    for (const tool of tools) {
      const tokens = tokenize(tool.name);
      const isGit = isGitTool(tokens);
      const isGraph = isGraphTool(tokens);
      let matched = false;

      for (const [category, keywords] of Object.entries(CAPABILITY_KEYWORDS)) {
        const cat = category as CapabilityCategory;
        const gate = DOMAIN_GATED_CATEGORIES[cat];
        if (gate && !gate(tokens)) continue;
        if (tokens.some((t) => keywords.has(t))) {
          categorizedTools[cat].push(tool.name);
          matched = true;
        }
      }

      // Suppress generic file-read/file-write classifications when a
      // domain bucket already absorbed the tool — `git_add` is git-write,
      // not file-write; `add_observations` is graph-write, not file-write.
      if (isGit) {
        categorizedTools["file-read"] = categorizedTools["file-read"].filter((n) => n !== tool.name);
        categorizedTools["file-write"] = categorizedTools["file-write"].filter((n) => n !== tool.name);
      }
      if (isGraph) {
        categorizedTools["file-read"] = categorizedTools["file-read"].filter((n) => n !== tool.name);
        categorizedTools["file-write"] = categorizedTools["file-write"].filter((n) => n !== tool.name);
      }

      if (!matched) {
        categorizedTools["unknown"].push(tool.name);
      }
    }

    const activeCategories = Object.entries(categorizedTools)
      .filter(([, t]) => t.length > 0)
      .reduce(
        (acc, [cat, t]) => {
          acc[cat] = t;
          return acc;
        },
        {} as Record<string, string[]>,
      );

    const highRiskCategories = (Object.keys(activeCategories) as CapabilityCategory[]).filter((c) =>
      HIGH_RISK_CATEGORIES.has(c),
    );

    checks.push({
      id: "TCG-001",
      name: "Capability Graph Built",
      status: CheckStatus.PASS,
      message: `Graph built across ${Object.keys(activeCategories).length} capability axes`,
      finding: {
        id: "TCG-001",
        module: this.id,
        severity: Severity.INFO,
        title: "Server Capability Map",
        description:
          `The server exposes tools across ${Object.keys(activeCategories).length} capability areas. ` +
          (highRiskCategories.length > 0
            ? `It exposes high-risk capabilities: ${highRiskCategories.join(", ")}.`
            : "No inherently high-risk capabilities detected."),
        evidence: {
          totalTools: tools.length,
          graphNodes: activeCategories,
          highRiskCategories,
        },
        remediation: "Review the capability graph to ensure no unintended high-risk abilities are exposed to the AI agent.",
        cweId: "CWE-200",
      },
    });

    return checks;
  }
}
