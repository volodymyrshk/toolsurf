# ToolSurf

Security audits for AI agents and tool interfaces. ToolSurf scans MCP servers, REST/OpenAPI, GraphQL, gRPC, A2A agents, OpenAI function calls and LangChain tools with one engine and 39 audit modules, then reports findings with severity, CWE and fix suggestions.

## Quick start

```bash
# Passive scan of an MCP server (no tool calls)
npx toolsurf scan -s "npx -y @modelcontextprotocol/server-filesystem /tmp" --profile quick

# Install globally
npm i -g toolsurf
toolsurf --help
```

Scan profiles: `quick` (passive only), `standard` (adds safe active probes), `enterprise` (all modules). Active modules make real tool calls, so run them against disposable test environments only.

## Authorized use only

Only scan systems you own or have explicit written permission to test. See `LEGAL_NOTICE` in this package.

## Documentation

Architecture, all modules, CI usage and the GitHub Action: **https://github.com/volodymyrshk/toolsurf**

Apache-2.0. Built by [Volodymyr Shkarban](https://github.com/volodymyrshk), with contributions from Oleksandr Leontiev.
