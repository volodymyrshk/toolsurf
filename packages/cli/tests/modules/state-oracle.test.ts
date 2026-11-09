import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { StateOracleModule } from "../../src/modules/state-oracle.js";
import { CheckStatus, Severity, type ModuleContext, type ToolInfo } from "../../src/types/index.js";

const TMP_DIRS: string[] = [];
const CONTAINER_WORKDIR = "/scanner-state";

const writeFileTool: ToolInfo = {
  name: "write_file",
  description: "Write content to a file path",
  inputSchema: {
    type: "object",
    properties: {
      path: { type: "string" },
      content: { type: "string" },
    },
  },
};

const readOnlyTool: ToolInfo = {
  name: "read_file",
  description: "Read a file path",
  inputSchema: {
    type: "object",
    properties: {
      path: { type: "string" },
    },
  },
};

function freshWorkdir(): string {
  const dir = mkdtempSync(join(tmpdir(), "scanner-state-oracle-module-"));
  TMP_DIRS.push(dir);
  return dir;
}

function makeContext(
  tools: ToolInfo[],
  callTool?: ModuleContext["callTool"],
  hostWorkdir = freshWorkdir(),
): ModuleContext {
  return {
    capabilities: {
      serverInfo: { name: "test-server", version: "1.0.0" },
      protocolVersion: "2025-11-05",
      capabilities: {},
      tools,
      resources: [],
      prompts: [],
    },
    activeMode: !!callTool,
    callTool,
    verbose: false,
    probeDelay: 0,
    chamber: {
      runDir: hostWorkdir,
      fakeHttpUrl: "http://172.30.0.10:8080",
      fakeMetadataUrl: "http://172.30.0.12",
      fakeDnsHost: "172.30.0.53",
      captures: {},
      workdir: {
        hostPath: hostWorkdir,
        containerPath: CONTAINER_WORKDIR,
      },
    },
  };
}

afterEach(() => {
  for (const dir of TMP_DIRS.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("StateOracleModule", () => {
  const module = new StateOracleModule();

  test("module metadata is correct", () => {
    expect(module.id).toBe("state-oracle");
    expect(module.mode).toBe("active");
    expect(module.version).toBe("1.0.0");
  });

  test("skips when chamber workdir is not provisioned", async () => {
    const results = await module.run({
      ...makeContext([writeFileTool], async () => ({ ok: true })),
      chamber: undefined,
    });

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe(CheckStatus.SKIP);
    expect(results[0].message).toContain("workdir not provisioned");
  });

  test("passes when no write-pair tools are available", async () => {
    const results = await module.run(makeContext([readOnlyTool], async () => ({ ok: true })));

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe(CheckStatus.PASS);
    expect(results[0].message).toContain("No write-pair tools");
  });

  test("passes when write probe does not mutate the chamber workdir", async () => {
    const results = await module.run(makeContext([writeFileTool], async () => ({ ignored: true })));

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe(CheckStatus.PASS);
    expect(results[0].message).toContain("did not contain any probe canary");
  });

  test("emits CHAMBER-FS-001 when a canary-laced write lands on disk", async () => {
    const hostWorkdir = freshWorkdir();
    const callTool = async (_name: string, args: Record<string, unknown>) => {
      const targetPath = String(args.path ?? "");
      const content = String(args.content ?? "");
      const hostPath = targetPath.replace(CONTAINER_WORKDIR, hostWorkdir);
      mkdirSync(dirname(hostPath), { recursive: true });
      writeFileSync(hostPath, content, "utf-8");
      return { ok: true, path: targetPath };
    };

    const results = await module.run(makeContext([writeFileTool], callTool, hostWorkdir));
    const finding = results[0].finding!;
    const evidence = finding.evidence as Record<string, unknown>;
    const fsDiffFile = String(evidence.fsDiffFile);

    expect(results).toHaveLength(1);
    expect(results[0].status).toBe(CheckStatus.FAIL);
    expect(finding.id).toBe("CHAMBER-FS-001");
    expect(finding.severity).toBe(Severity.CRITICAL);
    expect(evidence.verifiedBy).toBe("state-oracle");
    expect(existsSync(fsDiffFile)).toBe(true);

    const artifact = JSON.parse(readFileSync(fsDiffFile, "utf-8"));
    expect(artifact.version).toBe(1);
    expect(artifact.delta.changes.length).toBeGreaterThan(0);
    expect(JSON.stringify(artifact)).toContain("chamber-state");
  });
});
