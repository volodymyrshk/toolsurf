# Agent Juice Shop Benchmark

Agent Juice Shop is the scanner-owned benchmark corpus for agent tool security. It is meant to be a startup asset: a reproducible way to show what the scanner catches, where it is weak, and how it compares to adjacent tools without making unsupported market claims.

Run it from the CLI:

```bash
bun run packages/cli/src/index.ts agent-juice-shop --format markdown --output agent-juice-shop-report.md --fail-on-miss
```

The command emits a machine-readable or Markdown report with:

- Scenario pass/fail status.
- Expected finding prefixes and detected finding prefixes.
- Protocol coverage.
- A documentation-based competitor matrix.
- Source URLs for competitor claims.

## Current Corpus

| Scenario | Protocols | Core signal |
| --- | --- | --- |
| MCP metadata/runtime annotation drift | MCP | Read-only/destructive metadata trust breaks, arbitrary SQL, token exposure |
| REST/OpenAPI schema vs runtime enforcement gap | REST/OpenAPI | Contract/runtime mismatch and user-controlled callback surfaces |
| GraphQL resolver contract gap | GraphQL | Resolver exfiltration and mutation behavior hidden behind introspection |
| gRPC reflection command surface | gRPC | Command-like RPC methods exposed through protobuf/reflection |
| A2A Agent Card delegation abuse | A2A | Delegation, callback URLs, and secondary credential prompts |
| OpenAI/LangChain natural-language injection | OpenAI Functions, LangChain tools | Prompt/tool-description injection and hidden credential forwarding |
| Cross-protocol exfiltration chain | A2A, MCP, REST | Agent delegation to MCP filesystem read followed by REST exfiltration |
| Source/runtime drift | TS/JS, MCP | Source-declared tools diverge from runtime tools/list |

## Comparison Rules

The competitor matrix is intentionally cautious. Snyk Agent Scan, MCPShield, Microsoft Agent Governance Toolkit, and Invariant MCP-Scan are represented from public documentation only unless a pinned execution transcript is attached.

Do not publish claims like "better than X" from the matrix alone. A publishable comparison needs:

- Exact tool name, version, commit, install command, and date.
- Exact Agent Juice Shop corpus version.
- Full command transcript for every scanner.
- Raw outputs committed as artifacts.
- A mapping from each scanner's finding taxonomy to benchmark signals.
- A false-positive and false-negative review by scenario.

## Why This Is Strategically Useful

This benchmark pushes the scanner into a differentiated lane:

- It is multiprotocol, not MCP-only.
- It includes cross-protocol chains, not isolated tool checks only.
- It ties TS/JS source extraction to runtime discovery.
- It produces reproducible pass/fail signals that can become CI gates.
- It creates a neutral artifact for research, demos, and sales conversations.

The next startup-grade step is to run third-party tools against the same corpus with pinned versions and add the resulting transcripts under `data/agent-juice-shop/`.
