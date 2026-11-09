import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { A2aAdapter } from "../../src/adapters/a2a-adapter.js";

const TMP_DIR = join(import.meta.dir, ".tmp-a2a-adapter");
const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
  rmSync(TMP_DIR, { recursive: true, force: true });
});

function writeAgentCard(name: string, card: Record<string, unknown>): string {
  mkdirSync(TMP_DIR, { recursive: true });
  const path = join(TMP_DIR, name);
  writeFileSync(path, JSON.stringify(card), "utf-8");
  return path;
}

describe("A2A Adapter", () => {
  test("has correct protocol metadata", () => {
    const adapter = new A2aAdapter();
    expect(adapter.protocol).toBe("a2a");
    expect(adapter.displayName).toBe("Agent-to-Agent (A2A)");
  });

  test("parses Agent Card skills from file", async () => {
    const specFile = writeAgentCard("agent-card.json", {
      name: "payments-agent",
      version: "1.2.3",
      capabilities: {
        streaming: true,
        pushNotifications: false,
        stateTransitionHistory: true,
        extendedAgentCard: true,
      },
      securitySchemes: {
        bearerAuth: {
          httpAuthSecurityScheme: {
            scheme: "Bearer",
            bearerFormat: "JWT",
          },
        },
      },
      security: [{ bearerAuth: ["payments:write"] }],
      signatures: [{ protected: "header", signature: "signature" }],
      authentication: {
        schemes: ["legacyApiKey"],
      },
      skills: [
        {
          id: "create_refund",
          description: "Create a refund for an order",
          inputSchema: {
            type: "object",
            properties: {
              orderId: { type: "string" },
              amount: { type: "number" },
            },
            required: ["orderId"],
          },
        },
      ],
    });

    const adapter = new A2aAdapter();
    const caps = await adapter.connect({ params: { specFile } });

    expect(caps.protocol).toBe("a2a");
    expect(caps.serverInfo.name).toBe("payments-agent");
    expect(caps.serverInfo.version).toBe("1.2.3");
    expect(caps.capabilities.streaming).toBe(true);
    expect(caps.capabilities.stateTransitionHistory).toBe(true);
    expect(caps.capabilities.extendedAgentCard).toBe(true);
    expect(caps.capabilities.securitySchemes).toEqual({
      bearerAuth: {
        httpAuthSecurityScheme: {
          scheme: "Bearer",
          bearerFormat: "JWT",
        },
      },
    });
    expect(caps.capabilities.security).toEqual([{ bearerAuth: ["payments:write"] }]);
    expect(caps.capabilities.authenticationSchemes).toEqual(["bearerAuth", "legacyApiKey"]);
    expect(caps.capabilities.signedAgentCard).toBe(true);
    expect(caps.tools).toHaveLength(1);
    expect(caps.tools[0].name).toBe("create_refund");
    expect(caps.tools[0].sourceProtocol).toBe("a2a");
    expect(caps.tools[0].nativeType).toBe("skill");
    expect(caps.tools[0].httpMethod).toBe("JSON-RPC");
  });

  test("infers input schema from JSON examples", async () => {
    const specFile = writeAgentCard("examples-card.json", {
      name: "research-agent",
      skills: [
        {
          id: "summarize",
          examples: ['{"query":"agent security","limit":3}'],
        },
      ],
    });

    const adapter = new A2aAdapter();
    const caps = await adapter.connect({ params: { specFile } });
    const properties = caps.tools[0].inputSchema.properties as Record<string, { type: string }>;

    expect(properties.query.type).toBe("string");
    expect(properties.limit.type).toBe("number");
  });

  test("throws on missing URL and spec file", async () => {
    const adapter = new A2aAdapter();
    await expect(adapter.connect({ params: {} })).rejects.toThrow("requires a server URL or Agent Card file");
  });

  test("uses deterministic JSON-RPC request ids for active invocation", async () => {
    const sentBodies: Array<Record<string, unknown>> = [];
    globalThis.fetch = async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/.well-known/agent.json")) {
        return new Response(JSON.stringify({
          name: "live-agent",
          skills: [{ id: "summarize", inputSchema: { type: "object", properties: { input: { type: "string" } } } }],
        }), { status: 200 });
      }

      if (url.endsWith("/tasks/send")) {
        sentBodies.push(JSON.parse(String(init?.body)));
        return new Response(JSON.stringify({ result: { ok: true } }), { status: 200 });
      }

      return new Response("not found", { status: 404 });
    };

    const adapter = new A2aAdapter();
    await adapter.connect({ params: { url: "https://agent.example/rpc" } });
    await adapter.invoke("summarize", { input: "first" });
    await adapter.invoke("summarize", { input: "second" });

    expect(sentBodies).toHaveLength(2);
    expect(sentBodies[0].id).toBe(1);
    expect((sentBodies[0].params as Record<string, unknown>).id).toBe("audit-1");
    expect(sentBodies[1].id).toBe(2);
    expect((sentBodies[1].params as Record<string, unknown>).id).toBe("audit-2");
  });

  test("uses card-declared JSON-RPC interface for current Agent Card URLs", async () => {
    const seenUrls: string[] = [];
    const sentBodies: Array<Record<string, unknown>> = [];
    globalThis.fetch = async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      seenUrls.push(url);

      if (url === "https://cards.example/.well-known/agent-card.json") {
        return new Response(JSON.stringify({
          protocolVersion: "1.0",
          name: "current-agent",
          version: "2026.06",
          supportedInterfaces: [
            {
              url: "https://rpc.example/a2a",
              protocolBinding: "JSONRPC",
              protocolVersion: "1.0",
            },
          ],
          skills: [
            {
              id: "summarize",
              inputSchema: { type: "object", properties: { input: { type: "string" } } },
            },
          ],
        }), { status: 200 });
      }

      if (url === "https://rpc.example/a2a") {
        sentBodies.push(JSON.parse(String(init?.body)));
        return new Response(JSON.stringify({ result: { ok: true } }), { status: 200 });
      }

      return new Response("not found", { status: 404 });
    };

    const adapter = new A2aAdapter();
    const caps = await adapter.connect({
      params: { url: "https://cards.example/.well-known/agent-card.json" },
    });
    const result = await adapter.invoke("summarize", { input: "agent security" });

    expect(seenUrls[0]).toBe("https://cards.example/.well-known/agent-card.json");
    expect(caps.protocolVersion).toBe("A2A 1.0");
    expect(caps.capabilities.serviceUrl).toBe("https://rpc.example/a2a");
    expect(sentBodies).toHaveLength(1);
    expect(sentBodies[0].method).toBe("SendMessage");
    expect((sentBodies[0].params as any).metadata.skillId).toBe("summarize");
    expect(result).toEqual({ ok: true });
  });
});
