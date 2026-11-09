/**
 * Mock Server Command — Standalone MCP Shadow Proxy HTTP Server.
 *
 * Exposes McpShadowProxy as a REST API for safe active scanning
 * without a live MCP backend.
 *
 * Usage:
 *   toolsurf mock --schema capabilities.json
 *   toolsurf mock --schema capabilities.json --port 3200
 *   toolsurf mock --schema capabilities.json --format json
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { McpShadowProxy } from "../shadow/mcp-shadow-proxy.js";
import type { ServerCapabilities } from "../types/report.js";

export interface MockOptions {
  /** Path to a JSON file containing ServerCapabilities (tool schemas) */
  schema: string;
  /** Port to listen on (default: 3100) */
  port?: number;
  /** Output format for call log (default: "terminal") */
  format?: "json" | "terminal";
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((res, rej) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => res(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", rej);
  });
}

function sendJson(res: ServerResponse, status: number, data: unknown): void {
  const body = JSON.stringify(data, null, 2);
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) });
  res.end(body);
}

function loadCapabilities(schemaPath: string): ServerCapabilities {
  const absPath = resolve(process.cwd(), schemaPath);
  let raw: string;
  try { raw = readFileSync(absPath, "utf-8"); } catch (err) {
    throw new Error(`Failed to read schema file "${absPath}": ${err instanceof Error ? err.message : err}`);
  }
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new Error(`Schema file is not valid JSON: ${absPath}`); }

  const data = parsed as Record<string, unknown>;
  if (!Array.isArray(data.tools)) {
    throw new Error(`Schema file must contain a "tools" array. Got keys: ${Object.keys(data).join(", ")}`);
  }
  return {
    serverInfo: (data.serverInfo as ServerCapabilities["serverInfo"]) ?? { name: "shadow-mock", version: "0.0.0" },
    protocolVersion: (data.protocolVersion as string) ?? "2025-03-26",
    capabilities: (data.capabilities as Record<string, unknown>) ?? {},
    tools: data.tools as ServerCapabilities["tools"],
    resources: (data.resources as ServerCapabilities["resources"]) ?? [],
    prompts: (data.prompts as ServerCapabilities["prompts"]) ?? [],
  };
}

const ROUTES_HELP = {
  "POST /tools/call": "Call a tool via the shadow proxy",
  "GET /stats": "Get proxy call statistics",
  "GET /log": "Get full call log",
};

export async function executeMock(options: MockOptions): Promise<void> {
  const port = options.port ?? 3100;
  const format = options.format ?? "terminal";
  const capabilities = loadCapabilities(options.schema);
  const proxy = new McpShadowProxy(capabilities);

  const server = createServer(async (req, res) => {
    const url = req.url ?? "/";
    const method = req.method ?? "GET";
    try {
      if (method === "POST" && url === "/tools/call") {
        const body = await readBody(req);
        const payload = JSON.parse(body) as { name?: string; arguments?: Record<string, unknown> };
        if (!payload.name || typeof payload.name !== "string") {
          sendJson(res, 400, { error: "Missing required field: name (string)" });
          return;
        }
        const args = payload.arguments ?? {};
        const result = await proxy.callTool(payload.name, args);
        if (format === "terminal") {
          process.stdout.write(`  [${proxy.getStats().totalCalls}] ${payload.name} (${Object.keys(args).length} args)\n`);
        }
        sendJson(res, 200, { result });
        return;
      }
      if (method === "GET" && url === "/stats") { sendJson(res, 200, proxy.getStats()); return; }
      if (method === "GET" && url === "/log")   { sendJson(res, 200, proxy.getCallLog()); return; }
      sendJson(res, 404, { error: "Not found", routes: ROUTES_HELP });
    } catch (err) {
      sendJson(res, 500, { error: err instanceof Error ? err.message : String(err) });
    }
  });

  return new Promise<void>((done, reject) => {
    server.on("error", (err: NodeJS.ErrnoException) => {
      reject(err.code === "EADDRINUSE" ? new Error(`Port ${port} is already in use`) : err);
    });
    server.listen(port, () => {
      const name = capabilities.serverInfo.name;
      console.log(`\n  Shadow Proxy Server`);
      console.log(`  ───────────────────────────────────────`);
      console.log(`  Server:  ${name}  |  Tools: ${capabilities.tools.length}  |  http://localhost:${port}`);
      console.log(`  Routes:  POST /tools/call  |  GET /stats  |  GET /log\n`);

      const shutdown = () => {
        console.log(`\n  Shutting down shadow proxy...`);
        if (format === "terminal") {
          const s = proxy.getStats();
          console.log(`  Total calls: ${s.totalCalls}`);
          for (const [tool, count] of Object.entries(s.callsByTool)) {
            console.log(`    ${tool}: ${count}`);
          }
        }
        server.close(() => done());
      };
      process.on("SIGINT", shutdown);
      process.on("SIGTERM", shutdown);
    });
  });
}
