# ToolSurf Architecture Map

> ToolSurf v0.1.0-alpha.1 · 39 modules (23 passive, 16 active) · UMRI v4.0

## 1. System Overview

```
                         CLI Entry (index.ts)
                              │
                   ┌──────────┼──────────┐
                   │          │          │
                scan       scan-all   audit-local
                   │          │          │
                   └──────────┼──────────┘
                              │
                    ┌─────────▼─────────┐
                    │  Protocol Adapter  │
                    │  (adapters/)       │
                    └─────────┬─────────┘
                              │ ServerCapabilities
                    ┌─────────▼─────────┐
                    │  Module Runner     │
                    │  (module-runner)   │
                    └─────────┬─────────┘
                              │ ModuleResult[]
              ┌───────────────┼───────────────┐
              │               │               │
        ┌─────▼─────┐  ┌─────▼─────┐  ┌──────▼──────┐
        │ Confidence │  │ Dedup     │  │ Compliance  │
        │ (assign)   │  │ (dedup)   │  │ (enrich)    │
        └─────┬─────┘  └─────┬─────┘  └──────┬──────┘
              └───────────────┼───────────────┘
                              │ Finding[]
                    ┌─────────▼─────────┐
                    │  Scorer            │
                    │  (UMRI v4.0)       │
                    └─────────┬─────────┘
                              │ RiskProfile + Score
                    ┌─────────▼─────────┐
                    │  Reporter          │
                    │  (JSON/SARIF/TUI)  │
                    └───────────────────┘
```

## 2. Entry Surfaces

| Entry | File | Description |
|-------|------|-------------|
| CLI | `src/index.ts` | Commander-based CLI with 10 subcommands |
| Library | `src/commands/scan.ts:executeScan()` | Programmatic API for scan orchestration |
| Mock Server | `src/commands/mock.ts` | Standalone MCP shadow proxy |

## 3. Adapter Layer (`src/adapters/`)

Adapters normalize different protocol servers into a common `ServerCapabilities` shape.

| Adapter | Protocol | Status |
|---------|----------|--------|
| `mcp-adapter.ts` | MCP (stdio/SSE/Streamable HTTP) | Production |
| `rest-adapter.ts` | REST/OpenAPI | Production |
| `openai-adapter.ts` | OpenAI function-calling | Production |
| `langchain-adapter.ts` | LangChain tools | Production |
| `graphql-adapter.ts` | GraphQL | Production |
| `grpc-adapter.ts` | gRPC | Production |

**Boundary contract:**
- **Input:** Protocol-specific connection config (command string, URL, etc.)
- **Output:** `ServerCapabilities` (tools, resources, prompts, serverInfo)
- **Failure:** Throws with protocol-specific error. Caller handles retry/fallback.

## 4. Module System (`src/modules/`)

Built-in audit modules, each implementing the `AuditModule` interface.

**Interface contract:**
```typescript
interface AuditModule {
  id: string;          // unique identifier
  name: string;        // human-readable
  mode: "passive" | "active";
  run(context: ModuleContext): Promise<CheckResult[]>;
}
```

**Pre-conditions:** `context.capabilities` is fully populated. For active modules, `context.callTool` is available.
**Post-conditions:** Returns `CheckResult[]`. Each result has `id`, `status` (PASS/WARN/FAIL/SKIP), optional `finding`.
**Failure mode:** Module-level timeout (default 30s). On timeout, returns partial results + SKIP status.

### Module Registry

| # | Module ID | Mode |
|---|-----------|------|
| 1 | `tool-permissions` | passive |
| 2 | `transport-security` | passive |
| 3 | `schema-manipulation` | passive |
| 4 | `context-extraction` | passive |
| 5 | `secret-leak-detection` | passive |
| 6 | `resource-prompt-audit` | passive |
| 7 | `supply-chain-analysis` | passive |
| 8 | `current-vulnerability-intel` | passive |
| 9 | `rug-pull-detection` | passive |
| 10 | `exfiltration-chain` | passive |
| 11 | `namespace-poisoning` | passive |
| 12 | `token-exhaustion` | passive |
| 13 | `agentic-loop-trap` | passive |
| 14 | `output-injection` | active |
| 15 | `capability-graph` | passive |
| 16 | `dangerous-capability` | passive |
| 17 | `description-injection` | passive |
| 18 | `semantic-injection` | passive |
| 19 | `ipi-susceptibility` | passive |
| 20 | `handshake-fuzzer` | passive |
| 21 | `mcp-apps-audit` | passive |
| 22 | `discovery-scanner` | passive |
| 23 | `eu-ai-act` | passive |
| 24 | `agent-output-trust` | passive |
| 25 | `context-aware-fuzzer` | active |
| 26 | `output-injection-detector` | active |
| 27 | `timing-anomaly` | active |
| 28 | `session-state-leakage` | active |
| 29 | `ssrf-detection` | active |
| 30 | `active-fuzzer` | active |
| 31 | `tool-shadowing` | active |
| 32 | `response-fingerprinting` | active |
| 33 | `auth-boundary-testing` | active |
| 34 | `chained-exploit` | active |
| 35 | `annotation-verifier` | active |
| 36 | `session-isolation` | active |
| 37 | `state-oracle` | active |
| 38 | `adversarial-agent` | active |
| 39 | `chamber-evidence` | active |

## 5. Aggregation Pipeline (`src/core/`)

The scoring pipeline processes module results through 4 stages:

```
ModuleResult[] ──► confidence.ts ──► deduplicator.ts ──► scorer.ts ──► RiskProfile
                    (assign)         (merge dupes)       (UMRI v4.0)
```

### 5.1 Confidence Assignment (`confidence.ts`)
- **Pre:** Raw `ModuleResult[]` with findings
- **Post:** Each finding gets a `confidence` score [0,1]
- **Failure:** Defaults to confidence=0.5 on error

### 5.2 Deduplication (`deduplicator.ts`)
- **Pre:** All findings from all modules (may contain duplicates)
- **Post:** Deduplicated `Finding[]` — merges findings with same CWE + similar evidence
- **Failure:** Returns original findings unmodified
- **Invariant:** Must never merge findings with different root causes (false-dedup tested)

### 5.3 Scoring (`scorer.ts`)
- **Pre:** Deduplicated findings
- **Post:** `securityScore` (0-100, penalty-deduction), `RiskProfile` (5-axis UMRI v4.0)
- **Formula:** `CRS = 1 - prod(1 - w_i * phi(A_i))`, `phi(x) = x(1+x)`
- **Formula version:** `SCORING_FORMULA_VERSION = "v4.0"`
- **SSVC mapping:** CRS thresholds → Track/Track*/Attend/Act
- **Calibration:** ECE and Brier score functions available for validation

### 5.4 UMRI v4.0 Risk Axes

| Axis | Weight | Source | Scale |
|------|--------|--------|-------|
| Exposure (SE) | 0.15 | Transport, schema openness | [0,1] continuous |
| Exploit Chain (EC) | 0.25 | Finding chains, severity density | [0,1] continuous |
| Severity Density (VD) | 0.20 | Weighted finding count | [0,1] continuous |
| Capability Risk (CR) | 0.25 | Dangerous tool capabilities | [0,1] continuous |
| Trust Violation (TV) | 0.15 | Rug-pull, annotation lies | [0,1] continuous |

### 5.5 Missing-Data Policy
- Module timeout → SKIP status, no findings emitted, no score impact
- Missing capabilities field → axis defaults to 0 (safe assumption)
- Active mode disabled → active modules not run, no SKIP inflation

## 6. Compliance Layer (`src/compliance/`, `src/data/`)

Dual-path enrichment:
1. **CWE-based** (traditional): Finding CWE → NIST, SOC2, ASVS, HIPAA, PCI-DSS, ISO 27001, FedRAMP, GDPR
2. **Prefix-based** (agentic): Finding ID prefix → OWASP LLM v2.0, ASI10, AST10, MITRE ATLAS v5.4.0

## 7. Output Formats (`src/core/reporter.ts`, `sarif.ts`, `research-reporter.ts`)

| Format | File | Use Case |
|--------|------|----------|
| Terminal TUI | `reporter.ts` + `tui-dashboard.ts` | Interactive scanning |
| JSON | `reporter.ts` | Machine-readable full report |
| SARIF | `sarif.ts` | IDE/CI integration |
| Markdown | `reporter.ts` | Documentation |
| Research JSON | `research-reporter.ts` | Academic dataset (slim/full) |

## 8. Calibration Infrastructure

| Component | File | Purpose |
|-----------|------|---------|
| Anchor fixtures | `tests/fixtures/anchors/` | Score scale validation (floor/midpoint/ceiling) |
| Adversarial fixtures | `tests/fixtures/anchors/adversarial-*` | Scoring manipulation resistance |
| Calibration tests | `tests/core/calibration.test.ts` | CI-enforced anchor validation |
| Guard script | `src/commands/hardening-check.ts` | Pre-flight research-readiness check |
| ECE/Brier | `src/core/scorer.ts` | Probabilistic calibration metrics |

## 9. Dependency Graph

```
index.ts
  └─► commands/scan.ts
        ├─► adapters/registry.ts ──► adapters/*-adapter.ts
        ├─► core/module-runner.ts ──► modules/*.ts
        ├─► core/confidence.ts
        ├─► core/deduplicator.ts
        ├─► core/scorer.ts
        ├─► core/tofu-hash.ts
        ├─► core/peav.ts
        ├─► compliance/compliance-enricher.ts ──► data/compliance-mappings.ts
        ├─► core/reporter.ts ──► core/tui-dashboard.ts
        ├─► core/sarif.ts
        └─► core/research-reporter.ts
```
