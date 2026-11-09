# Contributing to ToolSurf

Thanks for taking a look. ToolSurf is an open-source security audit tool for AI agent tool interfaces, and contributions of all kinds are welcome: modules, protocol adapters, detection tuning, docs, and bug reports.

## Getting started

```bash
git clone https://github.com/volodymyrshk/toolsurf.git
cd toolsurf
bun install

# Run the CLI from source
bun run dev -- scan -s "npx -y @modelcontextprotocol/server-filesystem /tmp" --profile quick

# Test, typecheck, build
bun run test
bun run typecheck
bun run build
```

Requires Bun 1.1+ and Node.js 20+.

## Project structure

```
packages/cli/
  src/
    index.ts                  # CLI entry point (Commander)
    commands/
      scan.ts                 # Main scan orchestration
      scan-all.ts             # Registry-based fleet scans
      audit-local.ts          # Local IDE config discovery
      audit-repo.ts           # Repo → image → chamber → full-active scan
      scan-source.ts          # Static analysis of server source
      diff.ts                 # Report comparison
      badge.ts                # SVG score badges
      hook.ts                 # Git pre-commit hook
    adapters/                 # MCP, REST, GraphQL, gRPC, A2A, OpenAI, LangChain
    core/
      module-catalog.ts       # Single source of truth for module registration
      module-runner.ts        # Parallel passive, sequential active execution
      scorer.ts               # UMRI v4.0 risk scoring
      confidence.ts           # Evidence and confidence assignment
      reporter.ts             # Terminal, JSON, HTML, Markdown output
      sarif.ts                # SARIF v2.1.0 output
      profiles.ts             # quick / standard / enterprise presets
      target-profile.ts       # passive-only / safe-active / full-active modes
    modules/                  # 39 audit modules
    compliance/               # Framework enrichment
    data/                     # CWE and control mappings
    types/                    # Shared TypeScript interfaces
  tests/                      # Mirrors src/
```

## Adding an audit module

Every module implements the `AuditModule` interface:

```typescript
import {
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
} from "../types/index.js";

export class MyModule implements AuditModule {
  id = "my-module";
  name = "My Check";
  description = "Detects a specific class of tool-interface risk";
  version = "1.0.0";
  mode = "passive" as const; // or "active"

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const { tools, resources, prompts } = context.capabilities;

    // Analysis goes here.

    checks.push({
      id: "MY-001",
      name: "Check name",
      status: CheckStatus.PASS, // PASS | WARN | FAIL | SKIP
      message: "What was checked and what was found",
      // Attach a Finding for WARN / FAIL results:
      // finding: { id, module, severity, title, description, evidence, remediation },
    });

    return checks;
  }
}
```

Steps:

1. Add the module in `packages/cli/src/modules/your-module.ts`.
2. Register it in `packages/cli/src/core/module-catalog.ts` — this is the only registry.
3. Add tests in `packages/cli/tests/modules/your-module.test.ts`.
4. Add CWE and CVSS mappings in `packages/cli/src/core/sarif.ts` if you introduce new CWEs.
5. Update `README.md` if the module list or counts change.

Guidelines:

- **Passive modules** analyze `context.capabilities` only. They never call tools.
- **Active modules** use `context.callTool()`. Guard for its absence and return `SKIP` checks when the target cannot be probed.
- Respect scan-mode gating. Active modules must not run against a `passive-only` target.
- Finding IDs follow `XX-NNN` (for example `TP-001`, `AF-003`).
- Every finding needs a remediation. Include `cweId` where one applies.
- Do not add a module that only greps for a string a regex can already catch without new value.

## Adding compliance mappings

Mappings live in `packages/cli/src/data/compliance-mappings.ts`. Extend `CWE_COMPLIANCE_MAP` with the framework, control ID, title, and requirement text. Then update `cweToScore()` in `packages/cli/src/core/sarif.ts` if the CWE is new.

## Adding a protocol adapter

Adapters normalize a protocol into `ServerCapabilities` (tools, resources, prompts, server info). Implement the adapter contract in `packages/cli/src/adapters/`, register it in the adapter registry, and add a fixture-backed test. Every adapter must support passive discovery; active probing should degrade gracefully when a protocol cannot make arbitrary calls.

## Running tests

```bash
cd packages/cli

bun test                                              # everything
bun test tests/modules/active-fuzzer.test.ts          # one file
bun test --grep "tool-permissions"                    # by name
```

The suite currently runs **930 tests across 93 files**.

## Pull requests

- Keep a PR to one feature or fix.
- Add tests for new modules and behavior changes.
- Run `bun run test`, `bun run typecheck`, and `bun run build`.
- Do not include secrets, tokens, customer data, or research corpora.
- Keep active modules opt-in and scan-mode aware.
- Update public docs when flags, profiles, or module counts change.

## Reporting security issues

Do not open a public issue for a vulnerability in ToolSurf itself. Use [SECURITY.md](SECURITY.md).
