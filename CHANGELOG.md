# Changelog

All notable changes to ToolSurf are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.1] — 2026-11-09

First public release.

### Added

- **Unified audit engine** for seven protocols: MCP (stdio and streamable
  HTTP), REST/OpenAPI, GraphQL, gRPC, A2A, OpenAI function calling, and
  LangChain tools.
- **39 audit modules** — 23 passive schema and configuration analyzers plus 16
  active probes, including fuzzing, SSRF, tool shadowing, auth boundaries,
  session isolation, state oracles, and a deterministic indirect-prompt-
  injection harness.
- **Scan profiles** — `quick` (passive only), `standard` (passive + active),
  and `enterprise` (full suite with compliance mapping, TUI, autofix, and an
  executive summary).
- **Scan modes** — `passive-only`, `safe-active`, and `full-active`, with
  enforcement that filters modules by risk.
- **Scoring and evidence fusion** — multi-axis risk profile and Bayesian
  confidence updates from active probes.
- **Reporting** — terminal, JSON, HTML, Markdown, SARIF, research JSON,
  SVG score badges, and report diffing.
- **Policy as code** — YAML/JSON rule DSL for custom findings.
- **CI/CD integration** — `--fail-below` score gates, a composite GitHub
  Action, SARIF upload, Docker image, and a git pre-commit hook.
- **Fleet scanning** — registry-based multi-target audits.
- **Compliance mapping** — NIST, SOC 2, OWASP ASVS, HIPAA, PCI DSS,
  ISO 27001, and FedRAMP.
- **Agent Juice Shop** — a deterministic, multi-protocol regression benchmark.

### Security

- Active modules are opt-in and gated by scan mode. `full-active` requires
  explicit authorization and should only be run against targets you own or
  have written permission to test.

[Unreleased]: https://github.com/volodymyrshk/toolsurf/compare/v0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/volodymyrshk/toolsurf/releases/tag/v0.1.0-alpha.1
