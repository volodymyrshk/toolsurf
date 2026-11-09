# ToolSurf

Security audits for AI agents and tool interfaces.

```bash
npx toolsurf scan -s "npx -y @modelcontextprotocol/server-filesystem /tmp" --profile quick
```

39 audit modules across MCP, REST/OpenAPI, GraphQL, gRPC, A2A, OpenAI function calling, and LangChain tools. Passive schema analysis by default; 16 active probes behind an explicit profile.

Full documentation, architecture, and examples:

**https://github.com/volodymyrshk/toolsurf**

Apache-2.0. Built by [Volodymyr Shkarban](https://github.com/volodymyrshk), with contributions from Oleksandr Leontiev.
