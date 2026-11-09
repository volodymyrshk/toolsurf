import type { Finding } from "../types/finding.js";

/**
 * Deduplication result — primary findings shown to the user,
 * supporting findings available in the full report.
 */
export interface DeduplicationResult {
  /** Primary findings — one per unique issue, with affectedCount/affectedTools set */
  primary: Finding[];
  /** Supporting findings — collapsed duplicates, kept for full report detail */
  supporting: Finding[];
  /** Stats about what was collapsed */
  stats: {
    totalBefore: number;
    totalAfter: number;
    groupsCollapsed: number;
  };
}

/**
 * Extract a deduplication group key from a finding.
 *
 * Findings are grouped when they represent the same root cause
 * applied across multiple tools. The key is derived from the
 * finding ID prefix (e.g., "TP-005", "AF-007") which encodes
 * the check type, ignoring the per-tool suffix.
 *
 * Examples:
 *   "TP-005-read_file"  → "TP-005"
 *   "AF-007-list_dir"   → "AF-007"
 *   "TS-004"            → "TS-004" (standalone, no tool suffix)
 */
function extractGroupKey(finding: Finding): string {
  // Finding IDs follow the pattern: PREFIX-NNN or PREFIX-NNN-toolName
  // Extract the PREFIX-NNN part as the group key
  const match = finding.id.match(/^([A-Z]+-\d+)/);
  return match ? match[1] : finding.id;
}

/**
 * Severity rank for sorting (higher = more severe).
 */
const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

/**
 * Cross-module dedup: detect findings from different modules that flag
 * the same tool for overlapping root causes. For example:
 *   - TP-005 "unconstrained params" on tool X  +  AF-007 "unicode bypass" on tool X
 *     → same root cause: lack of input validation
 *   - DC-001 "arbitrary SQL" on tool X  +  AF-003 "SQL injection" on tool X
 *     → same root cause: unconstrained SQL input
 *
 * When overlap is detected, the lower-severity finding is demoted to supporting.
 */
const CROSS_MODULE_OVERLAP: Array<[string, string]> = [
  // Same tool: passive "unconstrained" + active "injection confirmed" → keep the active one
  ["TP-005", "AF-001"],  // unconstrained params + command injection
  ["TP-005", "AF-002"],  // unconstrained params + path traversal
  ["TP-005", "AF-003"],  // unconstrained params + SQL injection
  ["TP-005", "AF-004"],  // unconstrained params + XSS
  ["TP-005", "AF-007"],  // unconstrained params + unicode bypass
  // Passive SQL detection + active SQL injection confirmation
  ["DC-001", "AF-003"],  // arbitrary SQL + active SQL injection
  // Schema manipulation + active fuzzer findings
  ["SM-004", "AF-001"],  // suspicious schema + command injection
  ["SM-004", "AF-002"],  // suspicious schema + path traversal
];

function isAnnotationOnlySupplyChainFinding(finding: Finding): boolean {
  if (extractGroupKey(finding) !== "SC-003") return false;
  const issues = finding.evidence?.issues;
  return Array.isArray(issues) &&
    issues.length === 1 &&
    typeof issues[0] === "string" &&
    issues[0].startsWith("No tool annotations declared");
}

/**
 * Deduplicate findings by grouping identical root causes.
 *
 * Two dedup passes:
 * 1. **Same-check grouping:** Multiple tools triggering the same check
 *    (e.g., 8 tools all fail "TP-005") → collapse into one primary.
 * 2. **Cross-module overlap:** Different modules flagging the same tool
 *    for overlapping root causes → keep the higher-confidence finding.
 *
 * The primary finding is the highest-severity instance. If tied,
 * the highest-confidence instance wins. Supporting findings are
 * retained for detailed drill-down in full reports.
 */
export function deduplicateFindings(findings: Finding[]): DeduplicationResult {
  if (findings.length === 0) {
    return { primary: [], supporting: [], stats: { totalBefore: 0, totalAfter: 0, groupsCollapsed: 0 } };
  }

  // P2-13 [§REPRO]: Sort findings deterministically before deduplication.
  // Promise.all() passive module execution produces non-deterministic finding order.
  // While LSE aggregation is order-independent (sum of exp is commutative), the
  // dedup step keeps the FIRST occurrence when merging — different runs could
  // retain different instances. Sorting by (module, id, toolName) ensures the
  // same primary finding is selected regardless of execution order.
  const sortedFindings = [...findings].sort((a, b) => {
    const modCmp = (a.module ?? "").localeCompare(b.module ?? "");
    if (modCmp !== 0) return modCmp;
    const idCmp = a.id.localeCompare(b.id);
    if (idCmp !== 0) return idCmp;
    return (a.toolName ?? "").localeCompare(b.toolName ?? "");
  });

  // P1-06 [§CODE §ARCH]: Group key now includes moduleId to prevent cross-module
  // false deduplication. Two different modules detecting the same finding ID on
  // the same tool represent INDEPENDENT evidence and must not be merged.
  // Key: (findingIdPrefix, moduleId) instead of just (findingIdPrefix).
  const groups = new Map<string, Finding[]>();
  for (const finding of sortedFindings) {
    const idPrefix = extractGroupKey(finding);
    const key = `${idPrefix}::${finding.module ?? "unknown"}`;
    finding.dedupGroup = idPrefix; // preserve original group label for display

    const group = groups.get(key);
    if (group) {
      group.push(finding);
    } else {
      groups.set(key, [finding]);
    }
  }

  const primary: Finding[] = [];
  const supporting: Finding[] = [];
  let groupsCollapsed = 0;

  for (const [_key, group] of groups) {
    if (group.length === 1) {
      // Standalone finding — no dedup needed
      primary.push(group[0]);
      continue;
    }

    // Multiple findings with same root cause — collapse
    groupsCollapsed++;

    // Sort: highest severity first, then highest confidence
    group.sort((a, b) => {
      const sevDiff = (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
      if (sevDiff !== 0) return sevDiff;
      return (b.confidence ?? 0.5) - (a.confidence ?? 0.5);
    });

    const lead = group[0];
    const affectedTools = group
      .map((f) => f.toolName)
      .filter((t): t is string => !!t);

    // Unique tool names
    const uniqueTools = [...new Set(affectedTools)];

    // Create the primary finding with aggregated metadata
    const primaryFinding: Finding = {
      ...lead,
      affectedCount: group.length,
      affectedTools: uniqueTools.length > 0 ? uniqueTools : undefined,
      // Rewrite the title to reflect the systemic nature
      title: uniqueTools.length > 1
        ? `${lead.title.replace(/ in tool ".*"$/, "").replace(/ ".*"$/, "")} (${uniqueTools.length} tools affected)`
        : lead.title,
    };

    primary.push(primaryFinding);
    supporting.push(...group.slice(1));
  }

  // ── Pass 2: Cross-module overlap dedup ────────────────────────────────────
  // For findings targeting the same tool, if two modules flag overlapping
  // root causes, demote the lower-severity/confidence one to supporting.
  const demoted = new Set<Finding>();

  for (const [prefixA, prefixB] of CROSS_MODULE_OVERLAP) {
    const findingsA = primary.filter((f) => extractGroupKey(f) === prefixA && !demoted.has(f));
    const findingsB = primary.filter((f) => extractGroupKey(f) === prefixB && !demoted.has(f));

    for (const fA of findingsA) {
      for (const fB of findingsB) {
        // Only dedup if they target the same tool
        if (!fA.toolName || !fB.toolName) continue;

        // Check tool overlap: either same tool, or one affects the other's tools
        const toolsA = new Set([fA.toolName, ...(fA.affectedTools ?? [])]);
        const toolsB = new Set([fB.toolName, ...(fB.affectedTools ?? [])]);
        const hasOverlap = [...toolsA].some((t) => toolsB.has(t));

        if (!hasOverlap) continue;

        // Demote the lower-confidence finding (active probes > passive heuristics)
        const confA = fA.confidence ?? 0.5;
        const confB = fB.confidence ?? 0.5;
        const sevA = SEVERITY_RANK[fA.severity] ?? 0;
        const sevB = SEVERITY_RANK[fB.severity] ?? 0;

        // Keep the one with higher confidence; if tied, keep higher severity
        if (confA < confB || (confA === confB && sevA < sevB)) {
          demoted.add(fA);
        } else {
          demoted.add(fB);
        }
      }
    }
  }

  const tp006 = primary.find((f) => extractGroupKey(f) === "TP-006" && !demoted.has(f));
  if (tp006) {
    for (const finding of primary) {
      if (!demoted.has(finding) && isAnnotationOnlySupplyChainFinding(finding)) {
        demoted.add(finding);
      }
    }
  }

  if (demoted.size > 0) {
    groupsCollapsed += demoted.size;
    for (const f of demoted) {
      const idx = primary.indexOf(f);
      if (idx >= 0) primary.splice(idx, 1);
      supporting.push(f);
    }
  }

  // Sort primary findings: highest severity first
  primary.sort((a, b) => {
    const sevDiff = (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
    if (sevDiff !== 0) return sevDiff;
    return (b.confidence ?? 0.5) - (a.confidence ?? 0.5);
  });

  return {
    primary,
    supporting,
    stats: {
      totalBefore: findings.length,
      totalAfter: primary.length,
      groupsCollapsed,
    },
  };
}
