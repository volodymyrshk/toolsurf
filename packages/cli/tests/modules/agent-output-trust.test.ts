import { describe, test, expect } from "bun:test";
import { AgentOutputTrustModule } from "../../src/modules/agent-output-trust.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ModuleContext, ToolInfo, ServerCapabilities } from "../../src/types/index.js";

function makeContext(tools: ToolInfo[]): ModuleContext {
  return {
    capabilities: {
      serverInfo: { name: "test", version: "1.0" },
      protocolVersion: "2025-11-05",
      capabilities: {},
      tools,
      resources: [],
      prompts: [],
    },
    activeMode: false,
    verbose: false,
  };
}

describe("Agent Output Trust Module", () => {
  const mod = new AgentOutputTrustModule();

  test("module metadata", () => {
    expect(mod.id).toBe("agent-output-trust");
    expect(mod.mode).toBe("passive");
  });

  // ── AOT-001: Relay / forwarding patterns ───────────────────────────

  test("AOT-001: detects 'trusted_by' relay pattern", async () => {
    const results = await mod.run(makeContext([
      {
        name: "relay_tool",
        description: "This tool is trusted_by the downstream orchestrator and relays all responses automatically.",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const aot001 = results.find((r) => r.id === "AOT-001");
    expect(aot001?.status).toBe(CheckStatus.WARN);
    expect(aot001?.finding?.title).toContain("relay_tool");
    expect(aot001?.finding?.severity).toBe(Severity.HIGH);
  });

  test("AOT-001: detects 'relay to' pattern", async () => {
    const results = await mod.run(makeContext([
      {
        name: "data_relay",
        description: "Fetches external data and relays to the processing pipeline for further analysis.",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const aot001 = results.find((r) => r.id === "AOT-001");
    expect(aot001?.status).toBe(CheckStatus.WARN);
    expect(aot001?.finding?.title).toContain("data_relay");
  });

  test("AOT-001: detects 'forward to' pattern", async () => {
    const results = await mod.run(makeContext([
      {
        name: "forwarder",
        description: "Reads messages from the queue and forwards to the output handler for delivery.",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const aot001 = results.find((r) => r.id === "AOT-001");
    expect(aot001?.status).toBe(CheckStatus.WARN);
    expect(aot001?.finding?.title).toContain("forwarder");
  });

  test("AOT-001: detects 'pass to another agent' pattern", async () => {
    const results = await mod.run(makeContext([
      {
        name: "agent_bridge",
        description: "Collects data from external sources and passes to another agent for decision-making.",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const aot001 = results.find((r) => r.id === "AOT-001");
    expect(aot001?.status).toBe(CheckStatus.WARN);
    expect(aot001?.finding?.title).toContain("agent_bridge");
  });

  test("AOT-001: detects 'send to agent' pattern", async () => {
    const results = await mod.run(makeContext([
      {
        name: "dispatcher",
        description: "Processes incoming requests and sends to another agent for final verification.",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const aot001 = results.find((r) => r.id === "AOT-001");
    expect(aot001?.status).toBe(CheckStatus.WARN);
  });

  test("AOT-001: detects 'downstream agent' pattern", async () => {
    const results = await mod.run(makeContext([
      {
        name: "upstream_tool",
        description: "Fetches data and sends it to the downstream agent for processing and storage.",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const aot001 = results.find((r) => r.id === "AOT-001");
    expect(aot001?.status).toBe(CheckStatus.WARN);
    expect(aot001?.finding?.title).toContain("downstream");
  });

  test("AOT-001: detects 'pipes output' pattern", async () => {
    const results = await mod.run(makeContext([
      {
        name: "pipe_tool",
        description: "Retrieves the latest metrics and pipes output to the reporting subsystem.",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const aot001 = results.find((r) => r.id === "AOT-001");
    expect(aot001?.status).toBe(CheckStatus.WARN);
  });

  test("AOT-001: detects 'output is passed to' pattern", async () => {
    const results = await mod.run(makeContext([
      {
        name: "analyzer",
        description: "Analyzes the incoming payload. The output is passed to the next stage of the pipeline.",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const aot001 = results.find((r) => r.id === "AOT-001");
    expect(aot001?.status).toBe(CheckStatus.WARN);
  });

  test("AOT-001: passes for clean description without relay language", async () => {
    const results = await mod.run(makeContext([
      {
        name: "search_files",
        description: "Search for files matching a given pattern in the workspace directory.",
        inputSchema: {
          type: "object",
          properties: { query: { type: "string" } },
        },
      },
    ]));

    const aot001 = results.find((r) => r.id === "AOT-001");
    expect(aot001?.status).toBe(CheckStatus.PASS);
  });

  // ── AOT-002: Schema-matched output->input trust chain ──────────────

  test("AOT-002: detects high schema overlap between tools", async () => {
    const results = await mod.run(makeContext([
      {
        name: "fetch_user",
        description: "Fetch user data from the external API and return it.",
        inputSchema: { type: "object", properties: { userId: { type: "string" } } },
        outputSchema: {
          type: "object",
          properties: {
            name: { type: "string" },
            email: { type: "string" },
            role: { type: "string" },
          },
        },
      } as ToolInfo & { outputSchema: Record<string, unknown> },
      {
        name: "store_user",
        description: "Store user data in the internal database.",
        inputSchema: {
          type: "object",
          properties: {
            name: { type: "string" },
            email: { type: "string" },
            role: { type: "string" },
          },
        },
      },
    ]));

    const aot002 = results.find((r) => r.id === "AOT-002");
    expect(aot002?.status).toBe(CheckStatus.WARN);
    expect(aot002?.finding?.title).toContain("fetch_user");
    expect(aot002?.finding?.title).toContain("store_user");
    expect(aot002?.finding?.severity).toBe(Severity.MEDIUM);
  });

  test("AOT-002: detects overlap with extra fields (>=70% match)", async () => {
    const results = await mod.run(makeContext([
      {
        name: "scrape_page",
        description: "Scrape a web page and extract structured data.",
        inputSchema: { type: "object", properties: { url: { type: "string" } } },
        outputSchema: {
          type: "object",
          properties: {
            title: { type: "string" },
            body: { type: "string" },
            author: { type: "string" },
          },
        },
      } as ToolInfo & { outputSchema: Record<string, unknown> },
      {
        name: "index_content",
        description: "Index content into the search engine.",
        inputSchema: {
          type: "object",
          properties: {
            title: { type: "string" },
            body: { type: "string" },
            author: { type: "string" },
            indexId: { type: "string" },
          },
        },
      },
    ]));

    const aot002 = results.find((r) => r.id === "AOT-002");
    expect(aot002?.status).toBe(CheckStatus.WARN);
    expect(aot002?.finding?.title).toContain("schema overlap");
  });

  test("AOT-002: passes when schemas do not overlap", async () => {
    const results = await mod.run(makeContext([
      {
        name: "get_weather",
        description: "Get weather data for a location.",
        inputSchema: { type: "object", properties: { city: { type: "string" } } },
        outputSchema: {
          type: "object",
          properties: {
            temperature: { type: "number" },
            humidity: { type: "number" },
            windSpeed: { type: "number" },
          },
        },
      } as ToolInfo & { outputSchema: Record<string, unknown> },
      {
        name: "send_email",
        description: "Send an email to a recipient.",
        inputSchema: {
          type: "object",
          properties: {
            to: { type: "string" },
            subject: { type: "string" },
            body: { type: "string" },
          },
        },
      },
    ]));

    const aot002 = results.find((r) => r.id === "AOT-002");
    expect(aot002?.status).toBe(CheckStatus.PASS);
  });

  test("AOT-002: passes when output schema has only 1 field", async () => {
    const results = await mod.run(makeContext([
      {
        name: "get_id",
        description: "Returns a single identifier for a resource.",
        inputSchema: { type: "object", properties: {} },
        outputSchema: {
          type: "object",
          properties: {
            id: { type: "string" },
          },
        },
      } as ToolInfo & { outputSchema: Record<string, unknown> },
      {
        name: "delete_item",
        description: "Delete an item by its identifier.",
        inputSchema: {
          type: "object",
          properties: {
            id: { type: "string" },
          },
        },
      },
    ]));

    const aot002 = results.find((r) => r.id === "AOT-002");
    expect(aot002?.status).toBe(CheckStatus.PASS);
  });

  test("AOT-002: passes when tool has no outputSchema", async () => {
    const results = await mod.run(makeContext([
      {
        name: "list_items",
        description: "List all items in the store.",
        inputSchema: {
          type: "object",
          properties: { page: { type: "number" } },
        },
      },
      {
        name: "process_items",
        description: "Process items by page.",
        inputSchema: {
          type: "object",
          properties: { page: { type: "number" } },
        },
      },
    ]));

    const aot002 = results.find((r) => r.id === "AOT-002");
    expect(aot002?.status).toBe(CheckStatus.PASS);
  });

  // ── AOT-003: Trust escalation via output forwarding ────────────────

  test("AOT-003: detects forwarding to database write", async () => {
    const results = await mod.run(makeContext([
      {
        name: "ingest_data",
        description: "Fetches data from external sources. The output is then passed to the write layer which will insert into the database.",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const aot003 = results.find((r) => r.id === "AOT-003");
    expect(aot003?.status).toBe(CheckStatus.FAIL);
    expect(aot003?.finding?.severity).toBe(Severity.CRITICAL);
    expect(aot003?.finding?.title).toContain("database write");
  });

  test("AOT-003: detects forwarding to file write", async () => {
    const results = await mod.run(makeContext([
      {
        name: "template_renderer",
        description: "Renders templates from user input. The result is then forwarded to the save layer which will write the file to disk on the filesystem.",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const aot003 = results.find((r) => r.id === "AOT-003");
    expect(aot003?.status).toBe(CheckStatus.FAIL);
    expect(aot003?.finding?.title).toContain("file write");
  });

  test("AOT-003: detects forwarding to command execution", async () => {
    const results = await mod.run(makeContext([
      {
        name: "code_compiler",
        description: "Compiles code snippets. The output passed to the runtime which will execute the compiled script.",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const aot003 = results.find((r) => r.id === "AOT-003");
    expect(aot003?.status).toBe(CheckStatus.FAIL);
    expect(aot003?.finding?.title).toContain("command execution");
  });

  test("AOT-003: detects forwarding to external API call", async () => {
    const results = await mod.run(makeContext([
      {
        name: "api_bridge",
        description: "Normalizes input from various sources. The result sent to the dispatcher which will call the external api endpoint.",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const aot003 = results.find((r) => r.id === "AOT-003");
    expect(aot003?.status).toBe(CheckStatus.FAIL);
    expect(aot003?.finding?.title).toContain("external API call");
  });

  test("AOT-003: detects forwarding to email dispatch", async () => {
    const results = await mod.run(makeContext([
      {
        name: "notification_builder",
        description: "Builds notification templates from event data. The output is then sent to the mailer which will dispatch email to the recipient list.",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const aot003 = results.find((r) => r.id === "AOT-003");
    expect(aot003?.status).toBe(CheckStatus.FAIL);
    expect(aot003?.finding?.title).toContain("dispatch");
  });

  test("AOT-003: passes for clean description without escalation", async () => {
    const results = await mod.run(makeContext([
      {
        name: "format_json",
        description: "Formats a JSON payload according to the specified schema and returns the result.",
        inputSchema: {
          type: "object",
          properties: { data: { type: "string" } },
        },
      },
    ]));

    const aot003 = results.find((r) => r.id === "AOT-003");
    expect(aot003?.status).toBe(CheckStatus.PASS);
  });

  test("AOT-003: passes for privileged operation without forwarding context", async () => {
    const results = await mod.run(makeContext([
      {
        name: "db_writer",
        description: "Accepts validated records and inserts them into the database directly.",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const aot003 = results.find((r) => r.id === "AOT-003");
    expect(aot003?.status).toBe(CheckStatus.PASS);
  });

  // ── Edge cases ─────────────────────────────────────────────────────

  test("all checks pass with empty tools array", async () => {
    const results = await mod.run(makeContext([]));

    expect(results).toHaveLength(3);
    expect(results.every((r) => r.status === CheckStatus.PASS)).toBe(true);
  });

  test("AOT-001: skips tools with no description", async () => {
    const results = await mod.run(makeContext([
      {
        name: "no_desc_tool",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const aot001 = results.find((r) => r.id === "AOT-001");
    expect(aot001?.status).toBe(CheckStatus.PASS);
  });

  test("AOT-001: skips tools with short descriptions (<20 chars)", async () => {
    const results = await mod.run(makeContext([
      {
        name: "short_desc",
        description: "Relays output.",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const aot001 = results.find((r) => r.id === "AOT-001");
    expect(aot001?.status).toBe(CheckStatus.PASS);
  });

  test("AOT-003: skips tools with short descriptions (<30 chars)", async () => {
    const results = await mod.run(makeContext([
      {
        name: "short_escalation",
        description: "Output passed to db.",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    const aot003 = results.find((r) => r.id === "AOT-003");
    expect(aot003?.status).toBe(CheckStatus.PASS);
  });

  test("returns exactly 3 check results", async () => {
    const results = await mod.run(makeContext([
      {
        name: "basic_tool",
        description: "A simple tool that does basic data transformation.",
        inputSchema: { type: "object", properties: {} },
      },
    ]));

    expect(results).toHaveLength(3);
    expect(results.map((r) => r.id)).toEqual(["AOT-001", "AOT-002", "AOT-003"]);
  });
});
