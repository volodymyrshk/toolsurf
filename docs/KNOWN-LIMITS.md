# Known Limitations — ToolSurf

> Version: v0.1.0-alpha.1 / Formula v4.0
> Last updated: 2026-04-01
> Source: Security Audit Report (§ADV, §MEAS)

This document formally declares the measurement boundaries and detection gaps
of the ToolSurf scanner. All items listed here are intentional scope
exclusions or fundamental measurement constraints. They MUST be cited in
any research paper's Limitations section that uses ToolSurf output.

---

## 1. Supply Chain Analysis Constraints (P2-16)

The `supply-chain-analysis` module provides **static metadata analysis only**.
It CANNOT verify:

- **Author identity**: Package author fields are self-declared and unverified.
  A malicious actor can impersonate a trusted author.
- **Transitive dependencies**: Only direct dependencies of the scanned server
  are analyzed. Transitive dependency chains (dep-of-dep) are not resolved.
- **Staged rollouts / dormant takeover**: The module cannot detect a package
  that was clean at publication but later compromised via maintainer takeover
  or staged malicious update.
- **Binary/native addon inspection**: Native Node.js addons (.node files) and
  compiled binaries are opaque to the scanner.

**Impact on research**: Supply chain risk scores reflect metadata quality only.
A server with "clean" supply chain findings may still be compromised at the
transitive dependency level. Papers should note: *"Supply chain analysis is
limited to direct dependency metadata; transitive and staged-rollout risks
are out of scope."*

---

## 2. Unassessed Vulnerability Classes (P3-17)

The following 13 vulnerability classes are **not covered** by the current
scanner. They represent real attack vectors in agentic AI deployments but
require capabilities beyond static schema analysis and single-session probing:

| # | Class | Why Not Covered |
|---|-------|-----------------|
| 1 | Multi-agent consensus manipulation | Requires multi-agent orchestration environment |
| 2 | Prompt cache poisoning | Requires persistent cache state across sessions |
| 3 | Context window saturation DoS | Requires measuring token consumption over time |
| 4 | Cross-framework syntax confusion | Requires running the same tool across multiple frameworks |
| 5 | Sandbox escape | Requires runtime execution environment introspection |
| 6 | Intra-session state carryover | Requires multi-turn stateful session testing |
| 7 | Timing channel exploitation | Requires high-precision timing measurements |
| 8 | Tool discovery denial | Requires testing tool listing enumeration failures |
| 9 | Semantic tool collision | Requires NLP-level semantic similarity analysis |
| 10 | Inference cost explosion | Requires measuring LLM token/compute consumption |
| 11 | Recursive tool invocation without depth limit | Requires deep call-chain monitoring |
| 12 | Post-processing hook injection | Requires framework-specific hook introspection |
| 13 | Framework-specific behavior differences | Requires testing across Claude/GPT/Gemini/etc. |

**Impact on research**: Scanner scores reflect **schema-level and single-session
probe risks only**. The absence of findings in these classes does NOT indicate
safety. Papers should include this table in their limitations section.

---

## 3. Sandbox/Honeypot Indistinguishability (P1-08)

The scanner **cannot distinguish** a sandboxed/honeypot server from a production
server. A honeypot with 30 dangerous-looking tools that return static mock
responses will receive high-risk scores identical to a real production server
with the same tool schemas.

**Mitigation**: Use `--context sandboxed` flag to embed a disclaimer in output.
All targets in research datasets must be independently verified as non-sandboxed
production servers.

---

## 4. Annotation Trust Boundary (P1-07)

MCP tool annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`,
`openWorldHint`) are **self-declared by the server**. An adversary controlling
the server can set any annotation to any value. The scanner uses annotations
as input signals but treats them as untrusted:

- Annotation-only rug-pull findings (low confidence) contribute max 0.15 to
  the trustViolation axis per finding.
- Behaviour-confirmed rug-pull findings (high confidence, Bayesian-boosted)
  contribute up to 0.50.

---

## 5. Static Analysis Ceiling (ADV BYPASS PERFECT SCORE)

A server with a single, well-constrained, safe tool (e.g., `fetch_weather`
with enum-restricted parameters) will score ~95-100 on umriScalar. The scanner
**cannot detect**:

- Zero-day vulnerabilities in the server's runtime libraries
- Timing side-channel attacks
- Supply chain compromises in transitive dependencies

This is a fundamental limitation of static schema analysis. The scanner's
domain is **tool interface risk**, not **runtime security posture**.

---

## 6. Scale Type Constraints

All scores produced by the scanner are **ORDINAL** (see scorer.ts scale type
declarations). Valid operations:

- Rank comparisons (Server A is riskier than Server B)
- Medians, percentiles, quartiles
- Non-parametric statistical tests (Mann-Whitney U, Kruskal-Wallis)

Invalid operations (require interval/ratio scale justification):

- Arithmetic means of scores
- Score differences (Delta CRS)
- Percentages ("Server A is 30% riskier")
