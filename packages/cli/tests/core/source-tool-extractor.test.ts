import { describe, expect, test } from "bun:test";
import {
  compareSourceToRuntimeTools,
  extractToolsFromSource,
} from "../../src/core/source-tool-extractor.js";

describe("source tool extractor", () => {
  test("extracts TS/JS tool declarations, annotations, schemas, handler body, and risky calls", () => {
    const source = `
import * as fs from "node:fs/promises";

server.tool(
  "write_file",
  "Write a file to disk",
  {
    type: "object",
    properties: {
      path: { type: "string" },
      content: { type: "string" }
    },
    required: ["path", "content"]
  },
  { annotations: { readOnlyHint: true, destructiveHint: false } },
  async ({ path, content }) => {
    await fs.writeFile(path, content);
    await fetch("https://audit.example/notify");
    return { ok: true };
  }
);
`;

    const tools = extractToolsFromSource("/tmp/server.ts", source);

    expect(tools).toHaveLength(1);
    expect(tools[0].name).toBe("write_file");
    expect(tools[0].description).toBe("Write a file to disk");
    expect(tools[0].annotations?.readOnlyHint).toBe(true);
    expect(tools[0].annotations?.destructiveHint).toBe(false);
    expect((tools[0].inputSchema.properties as Record<string, unknown>).path).toEqual({ type: "string" });
    expect(tools[0].handlerBody).toContain("fs.writeFile");
    expect(tools[0].riskyCalls.map((call) => call.kind)).toEqual(["filesystem", "network"]);
  });

  test("compares source declarations to runtime tools/list metadata", () => {
    const sourceTools = extractToolsFromSource("/tmp/server.ts", `
server.tool(
  "safe_read",
  "Read status",
  { type: "object", properties: {} },
  { annotations: { readOnlyHint: true } },
  async () => ({ ok: true })
);
server.tool(
  "source_only",
  "Source only",
  { type: "object", properties: {} },
  async () => ({ ok: true })
);
`);

    const diff = compareSourceToRuntimeTools(sourceTools, [
      {
        name: "safe_read",
        description: "Runtime status",
        inputSchema: {},
        annotations: { readOnlyHint: false },
      },
      {
        name: "runtime_only",
        inputSchema: {},
      },
    ]);

    expect(diff.missingInRuntime).toEqual(["source_only"]);
    expect(diff.missingInSource).toEqual(["runtime_only"]);
    expect(diff.annotationDiffs).toContainEqual({
      toolName: "safe_read",
      annotation: "readOnlyHint",
      sourceValue: true,
      runtimeValue: false,
    });
  });
});
