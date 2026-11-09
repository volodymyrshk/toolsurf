import { describe, test, expect } from "bun:test";
import { createAdapter, getSupportedProtocols, isProtocolType } from "../../src/adapters/registry.js";
import { McpAdapter } from "../../src/adapters/mcp-adapter.js";
import { OpenAiAdapter } from "../../src/adapters/openai-adapter.js";
import { LangChainAdapter } from "../../src/adapters/langchain-adapter.js";
import { RestApiAdapter } from "../../src/adapters/rest-adapter.js";
import { GraphQlAdapter } from "../../src/adapters/graphql-adapter.js";
import { GrpcAdapter } from "../../src/adapters/grpc-adapter.js";
import { A2aAdapter } from "../../src/adapters/a2a-adapter.js";

describe("Adapter Registry", () => {
  test("createAdapter returns McpAdapter for 'mcp'", () => {
    const adapter = createAdapter("mcp");
    expect(adapter).toBeInstanceOf(McpAdapter);
    expect(adapter.protocol).toBe("mcp");
    expect(adapter.displayName).toBe("MCP (Model Context Protocol)");
  });

  test("createAdapter defaults to 'mcp' when no protocol specified", () => {
    const adapter = createAdapter();
    expect(adapter).toBeInstanceOf(McpAdapter);
  });

  test("createAdapter returns correct adapter for each protocol", () => {
    expect(createAdapter("openai-functions")).toBeInstanceOf(OpenAiAdapter);
    expect(createAdapter("langchain-tools")).toBeInstanceOf(LangChainAdapter);
    expect(createAdapter("rest-api")).toBeInstanceOf(RestApiAdapter);
    expect(createAdapter("graphql")).toBeInstanceOf(GraphQlAdapter);
    expect(createAdapter("grpc")).toBeInstanceOf(GrpcAdapter);
    expect(createAdapter("a2a")).toBeInstanceOf(A2aAdapter);
  });

  test("each adapter has correct protocol and displayName", () => {
    const cases: Array<[string, string]> = [
      ["openai-functions", "OpenAI Function Calling"],
      ["langchain-tools", "LangChain Tools"],
      ["rest-api", "REST API (OpenAPI/Swagger)"],
      ["graphql", "GraphQL"],
      ["grpc", "gRPC"],
      ["a2a", "Agent-to-Agent (A2A)"],
    ];
    for (const [protocol, displayName] of cases) {
      const adapter = createAdapter(protocol as any);
      expect(adapter.protocol).toBe(protocol);
      expect(adapter.displayName).toBe(displayName);
    }
  });

  test("createAdapter throws for unknown protocol", () => {
    expect(() => createAdapter("unknown-protocol" as any)).toThrow("Unknown protocol");
  });

  test("getSupportedProtocols returns all protocol types", () => {
    const protocols = getSupportedProtocols();
    expect(protocols).toContain("mcp");
    expect(protocols).toContain("openai-functions");
    expect(protocols).toContain("langchain-tools");
    expect(protocols).toContain("rest-api");
    expect(protocols).toContain("graphql");
    expect(protocols).toContain("grpc");
    expect(protocols).toContain("a2a");
    expect(protocols.length).toBe(7);
  });

  test("isProtocolType validates known protocols", () => {
    expect(isProtocolType("mcp")).toBe(true);
    expect(isProtocolType("openai-functions")).toBe(true);
    expect(isProtocolType("langchain-tools")).toBe(true);
    expect(isProtocolType("rest-api")).toBe(true);
    expect(isProtocolType("graphql")).toBe(true);
    expect(isProtocolType("grpc")).toBe(true);
    expect(isProtocolType("a2a")).toBe(true);
  });

  test("isProtocolType rejects unknown strings", () => {
    expect(isProtocolType("http")).toBe(false);
    expect(isProtocolType("")).toBe(false);
    expect(isProtocolType("websocket")).toBe(false);
    expect(isProtocolType("mcp-v2")).toBe(false);
  });
});
