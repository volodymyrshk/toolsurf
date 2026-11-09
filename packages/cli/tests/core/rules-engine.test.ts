import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { writeFileSync, unlinkSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import {
  loadRules,
  evaluateRules,
  outputRuleResults,
  type CustomRule,
  type RulesFile,
} from "../../src/core/rules-engine.js";
import { CheckStatus, Severity } from "../../src/types/index.js";
import type { ServerCapabilities } from "../../src/types/index.js";

// ─── Test Fixtures ──────────────────────────────────────────────────────────

const TMP_DIR = join(import.meta.dir, ".tmp-rules-test");

function makeCaps(overrides: Partial<ServerCapabilities> = {}): ServerCapabilities {
  return {
    serverInfo: { name: "test-server", version: "1.0.0" },
    protocolVersion: "2024-11-05",
    capabilities: {},
    tools: [],
    resources: [],
    prompts: [],
    ...overrides,
  };
}

function writeRulesJson(filename: string, data: RulesFile): string {
  const path = join(TMP_DIR, filename);
  writeFileSync(path, JSON.stringify(data, null, 2), "utf-8");
  return path;
}

function writeRulesYaml(filename: string, content: string): string {
  const path = join(TMP_DIR, filename);
  writeFileSync(path, content, "utf-8");
  return path;
}

beforeAll(() => {
  if (!existsSync(TMP_DIR)) {
    mkdirSync(TMP_DIR, { recursive: true });
  }
});

afterAll(() => {
  // Clean up temp files
  try {
    const { readdirSync, rmSync } = require("node:fs");
    rmSync(TMP_DIR, { recursive: true, force: true });
  } catch {}
});

// ─── loadRules() ────────────────────────────────────────────────────────────

describe("loadRules()", () => {
  test("loads valid JSON rules file", () => {
    const path = writeRulesJson("valid.json", {
      rules: [
        {
          id: "TEST-001",
          name: "No exec tools",
          severity: "CRITICAL",
          match: { tool_name: "/exec|shell/i" },
          message: "Shell tools banned",
        },
      ],
    });

    const rules = loadRules(path);
    expect(rules).toHaveLength(1);
    expect(rules[0].id).toBe("TEST-001");
    expect(rules[0].severity).toBe("CRITICAL");
  });

  test("loads YAML-format rules file", () => {
    const path = writeRulesYaml(
      "valid.yml",
      `rules:
  - id: YAML-001
    name: "No shell tools"
    severity: HIGH
    message: "Shell tools are forbidden"
    match:
      tool_name: /exec|shell/i
`
    );

    const rules = loadRules(path);
    expect(rules).toHaveLength(1);
    expect(rules[0].id).toBe("YAML-001");
    expect(rules[0].name).toBe("No shell tools");
  });

  test("loads multiple rules from one file", () => {
    const path = writeRulesJson("multi.json", {
      rules: [
        {
          id: "M-001",
          name: "Rule 1",
          severity: "HIGH",
          match: { tool_name: "exec" },
          message: "msg1",
        },
        {
          id: "M-002",
          name: "Rule 2",
          severity: "LOW",
          match: { tool_count: { gt: 10 } },
          message: "msg2",
        },
        {
          id: "M-003",
          name: "Rule 3",
          severity: "MEDIUM",
          match: { resource_uri: "/secret/" },
          message: "msg3",
        },
      ],
    });

    const rules = loadRules(path);
    expect(rules).toHaveLength(3);
  });

  test("throws on missing file", () => {
    expect(() => loadRules("/nonexistent/rules.json")).toThrow("Rules file not found");
  });

  test("throws on invalid JSON", () => {
    const path = writeRulesYaml("bad.json", "{ invalid json }}}");
    // .json extension triggers JSON.parse
    const jsonPath = join(TMP_DIR, "bad-json.json");
    writeFileSync(jsonPath, "{ not valid json }", "utf-8");
    expect(() => loadRules(jsonPath)).toThrow();
  });

  test("throws when rules array is missing", () => {
    const path = join(TMP_DIR, "norules.json");
    writeFileSync(path, JSON.stringify({ notRules: [] }), "utf-8");
    expect(() => loadRules(path)).toThrow('must contain a "rules" array');
  });

  test("throws on rule missing id", () => {
    const path = writeRulesJson("no-id.json", {
      rules: [
        { name: "test", severity: "HIGH", match: {}, message: "msg" } as any,
      ],
    });
    expect(() => loadRules(path)).toThrow('missing "id"');
  });

  test("throws on rule missing name", () => {
    const path = writeRulesJson("no-name.json", {
      rules: [
        { id: "X-1", severity: "HIGH", match: {}, message: "msg" } as any,
      ],
    });
    expect(() => loadRules(path)).toThrow('missing "name"');
  });

  test("throws on rule missing severity", () => {
    const path = writeRulesJson("no-sev.json", {
      rules: [
        { id: "X-1", name: "test", match: {}, message: "msg" } as any,
      ],
    });
    expect(() => loadRules(path)).toThrow('missing "severity"');
  });

  test("throws on invalid severity value", () => {
    const path = writeRulesJson("bad-sev.json", {
      rules: [
        {
          id: "X-1",
          name: "test",
          severity: "ULTRA" as any,
          match: {},
          message: "msg",
        },
      ],
    });
    expect(() => loadRules(path)).toThrow("invalid severity");
  });

  test("throws on rule missing match", () => {
    const path = writeRulesJson("no-match.json", {
      rules: [
        { id: "X-1", name: "test", severity: "HIGH", message: "msg" } as any,
      ],
    });
    expect(() => loadRules(path)).toThrow('missing "match"');
  });

  test("throws on rule missing message", () => {
    const path = writeRulesJson("no-msg.json", {
      rules: [
        { id: "X-1", name: "test", severity: "HIGH", match: {} } as any,
      ],
    });
    expect(() => loadRules(path)).toThrow('missing "message"');
  });

  test("preserves optional fields (remediation, cweId, negate)", () => {
    const path = writeRulesJson("optional.json", {
      rules: [
        {
          id: "OPT-001",
          name: "Full rule",
          severity: "HIGH",
          match: { tool_name: "exec" },
          message: "Ban exec",
          remediation: "Remove exec tools",
          cweId: "CWE-78",
          negate: true,
        },
      ],
    });

    const rules = loadRules(path);
    expect(rules[0].remediation).toBe("Remove exec tools");
    expect(rules[0].cweId).toBe("CWE-78");
    expect(rules[0].negate).toBe(true);
  });
});

// ─── evaluateRules() ─ Tool Name Matching ───────────────────────────────────

describe("evaluateRules() — tool_name", () => {
  test("matches tool name with regex pattern", () => {
    const rules: CustomRule[] = [
      {
        id: "TN-001",
        name: "No exec tools",
        severity: "CRITICAL",
        match: { tool_name: "/exec|shell|run_command/i" },
        message: "Shell execution tools banned",
      },
    ];

    const caps = makeCaps({
      tools: [
        { name: "execute_command", inputSchema: {} },
        { name: "read_file", inputSchema: {} },
        { name: "shell_exec", inputSchema: {} },
      ],
    });

    const results = evaluateRules(rules, caps);
    expect(results).toHaveLength(1);
    expect(results[0].status).toBe(CheckStatus.FAIL);
    expect(results[0].message).toContain("2 violation");
  });

  test("passes when no tools match", () => {
    const rules: CustomRule[] = [
      {
        id: "TN-002",
        name: "No exec tools",
        severity: "HIGH",
        match: { tool_name: "/exec|shell/i" },
        message: "No shell tools",
      },
    ];

    const caps = makeCaps({
      tools: [
        { name: "read_file", inputSchema: {} },
        { name: "list_dir", inputSchema: {} },
      ],
    });

    const results = evaluateRules(rules, caps);
    expect(results[0].status).toBe(CheckStatus.PASS);
    expect(results[0].finding).toBeUndefined();
  });

  test("matches with plain string (case-insensitive)", () => {
    const rules: CustomRule[] = [
      {
        id: "TN-003",
        name: "No sudo",
        severity: "CRITICAL",
        match: { tool_name: "sudo" },
        message: "sudo forbidden",
      },
    ];

    const caps = makeCaps({
      tools: [{ name: "run_sudo_command", inputSchema: {} }],
    });

    const results = evaluateRules(rules, caps);
    expect(results[0].status).toBe(CheckStatus.FAIL);
  });
});

// ─── evaluateRules() — tool_description ─────────────────────────────────────

describe("evaluateRules() — tool_description", () => {
  test("detects tools with missing descriptions (null match)", () => {
    const rules: CustomRule[] = [
      {
        id: "TD-001",
        name: "All tools must have descriptions",
        severity: "HIGH",
        match: { tool_description: null },
        message: "Missing tool description",
      },
    ];

    const caps = makeCaps({
      tools: [
        { name: "tool_a", description: "Does stuff", inputSchema: {} },
        { name: "tool_b", inputSchema: {} }, // no description
        { name: "tool_c", description: "", inputSchema: {} }, // empty
      ],
    });

    const results = evaluateRules(rules, caps);
    expect(results[0].status).toBe(CheckStatus.FAIL);
    expect(results[0].message).toContain("2 violation");
  });

  test("matches tool description with regex", () => {
    const rules: CustomRule[] = [
      {
        id: "TD-002",
        name: "No dangerous descriptions",
        severity: "MEDIUM",
        match: { tool_description: "/delete|destroy|drop/i" },
        message: "Dangerous tool description",
      },
    ];

    const caps = makeCaps({
      tools: [
        { name: "cleanup", description: "Delete all temporary files", inputSchema: {} },
        { name: "read", description: "Read a file", inputSchema: {} },
      ],
    });

    const results = evaluateRules(rules, caps);
    expect(results[0].status).toBe(CheckStatus.FAIL);
    expect(results[0].message).toContain("1 violation");
  });
});

// ─── evaluateRules() — Count Thresholds ─────────────────────────────────────

describe("evaluateRules() — count thresholds", () => {
  test("tool_count gt threshold", () => {
    const rules: CustomRule[] = [
      {
        id: "TC-001",
        name: "Max 3 tools",
        severity: "MEDIUM",
        match: { tool_count: { gt: 3 } },
        message: "Too many tools",
      },
    ];

    const caps = makeCaps({
      tools: [
        { name: "a", inputSchema: {} },
        { name: "b", inputSchema: {} },
        { name: "c", inputSchema: {} },
        { name: "d", inputSchema: {} },
      ],
    });

    const results = evaluateRules(rules, caps);
    expect(results[0].status).toBe(CheckStatus.FAIL);
    expect(results[0].message).toContain("violation");
  });

  test("tool_count passes when under limit", () => {
    const rules: CustomRule[] = [
      {
        id: "TC-002",
        name: "Max 10 tools",
        severity: "LOW",
        match: { tool_count: { gt: 10 } },
        message: "Too many tools",
      },
    ];

    const caps = makeCaps({
      tools: [{ name: "a", inputSchema: {} }, { name: "b", inputSchema: {} }],
    });

    const results = evaluateRules(rules, caps);
    expect(results[0].status).toBe(CheckStatus.PASS);
  });

  test("tool_count lt threshold", () => {
    const rules: CustomRule[] = [
      {
        id: "TC-003",
        name: "Min 2 tools",
        severity: "LOW",
        match: { tool_count: { lt: 2 } },
        message: "Not enough tools",
      },
    ];

    const caps = makeCaps({ tools: [{ name: "a", inputSchema: {} }] });

    const results = evaluateRules(rules, caps);
    expect(results[0].status).toBe(CheckStatus.FAIL);
  });

  test("resource_count gt threshold", () => {
    const rules: CustomRule[] = [
      {
        id: "RC-001",
        name: "Max 5 resources",
        severity: "LOW",
        match: { resource_count: { gt: 5 } },
        message: "Too many resources",
      },
    ];

    const caps = makeCaps({
      resources: Array.from({ length: 8 }, (_, i) => ({
        uri: `file:///res${i}`,
        name: `res${i}`,
      })),
    });

    const results = evaluateRules(rules, caps);
    expect(results[0].status).toBe(CheckStatus.FAIL);
  });

  test("prompt_count gt threshold", () => {
    const rules: CustomRule[] = [
      {
        id: "PC-001",
        name: "Max 3 prompts",
        severity: "LOW",
        match: { prompt_count: { gt: 3 } },
        message: "Too many prompts",
      },
    ];

    const caps = makeCaps({
      prompts: Array.from({ length: 5 }, (_, i) => ({ name: `prompt${i}` })),
    });

    const results = evaluateRules(rules, caps);
    expect(results[0].status).toBe(CheckStatus.FAIL);
  });
});

// ─── evaluateRules() — Resource URI ─────────────────────────────────────────

describe("evaluateRules() — resource_uri", () => {
  test("matches resource URI with regex", () => {
    const rules: CustomRule[] = [
      {
        id: "RU-001",
        name: "No secret resources",
        severity: "CRITICAL",
        match: { resource_uri: "/secret|password|credential/i" },
        message: "Secret resource exposed",
      },
    ];

    const caps = makeCaps({
      resources: [
        { uri: "file:///config/settings.json", name: "settings" },
        { uri: "file:///secrets/api-keys.json", name: "api-keys" },
      ],
    });

    const results = evaluateRules(rules, caps);
    expect(results[0].status).toBe(CheckStatus.FAIL);
  });
});

// ─── evaluateRules() — Server Name/Version ──────────────────────────────────

describe("evaluateRules() — server matching", () => {
  test("matches server name", () => {
    const rules: CustomRule[] = [
      {
        id: "SN-001",
        name: "Block test servers",
        severity: "HIGH",
        match: { server_name: "/test|dev|staging/i" },
        message: "Non-production server detected",
      },
    ];

    const caps = makeCaps({
      serverInfo: { name: "dev-filesystem-server", version: "2.0.0" },
    });

    const results = evaluateRules(rules, caps);
    expect(results[0].status).toBe(CheckStatus.FAIL);
  });

  test("matches server version", () => {
    const rules: CustomRule[] = [
      {
        id: "SV-001",
        name: "Block old versions",
        severity: "MEDIUM",
        match: { server_version: "/^0\\./i" },
        message: "Pre-1.0 server version",
      },
    ];

    const caps = makeCaps({
      serverInfo: { name: "my-server", version: "0.5.3" },
    });

    const results = evaluateRules(rules, caps);
    expect(results[0].status).toBe(CheckStatus.FAIL);
  });
});

// ─── evaluateRules() — Parameter Name ───────────────────────────────────────

describe("evaluateRules() — param_name", () => {
  test("matches forbidden parameter names", () => {
    const rules: CustomRule[] = [
      {
        id: "PN-001",
        name: "No password params",
        severity: "HIGH",
        match: { param_name: "/password|secret|token/i" },
        message: "Tool accepts sensitive param",
      },
    ];

    const caps = makeCaps({
      tools: [
        {
          name: "login",
          inputSchema: {
            type: "object",
            properties: {
              username: { type: "string" },
              password: { type: "string" },
            },
          },
        },
      ],
    });

    const results = evaluateRules(rules, caps);
    expect(results[0].status).toBe(CheckStatus.FAIL);
    expect(results[0].message).toContain("1 violation");
  });
});

// ─── evaluateRules() — Annotations ──────────────────────────────────────────

describe("evaluateRules() — annotation matching", () => {
  test("matches destructive annotation", () => {
    const rules: CustomRule[] = [
      {
        id: "AN-001",
        name: "No destructive tools",
        severity: "HIGH",
        match: { annotation: { destructiveHint: true } },
        message: "Destructive tool found",
      },
    ];

    const caps = makeCaps({
      tools: [
        {
          name: "delete_file",
          inputSchema: {},
          annotations: { destructiveHint: true },
        },
        {
          name: "read_file",
          inputSchema: {},
          annotations: { readOnlyHint: true },
        },
      ],
    });

    const results = evaluateRules(rules, caps);
    expect(results[0].status).toBe(CheckStatus.FAIL);
    expect(results[0].message).toContain("1 violation");
  });
});

// ─── evaluateRules() — Negate Logic ─────────────────────────────────────────

describe("evaluateRules() — negate", () => {
  test("fails when expected match NOT found (negate=true)", () => {
    const rules: CustomRule[] = [
      {
        id: "NEG-001",
        name: "Must have read_file tool",
        severity: "HIGH",
        match: { tool_name: "read_file" },
        message: "Server must expose read_file",
        negate: true,
      },
    ];

    // No read_file tool → negate means FAIL
    const caps = makeCaps({
      tools: [{ name: "write_file", inputSchema: {} }],
    });

    const results = evaluateRules(rules, caps);
    expect(results[0].status).toBe(CheckStatus.FAIL);
    expect(results[0].message).toContain("expected match not found");
  });

  test("passes when negated match IS found", () => {
    const rules: CustomRule[] = [
      {
        id: "NEG-002",
        name: "Must have read_file",
        severity: "HIGH",
        match: { tool_name: "read_file" },
        message: "Must have read_file",
        negate: true,
      },
    ];

    const caps = makeCaps({
      tools: [{ name: "read_file", inputSchema: {} }],
    });

    const results = evaluateRules(rules, caps);
    expect(results[0].status).toBe(CheckStatus.PASS);
    expect(results[0].message).toBe("Expected condition met");
  });
});

// ─── evaluateRules() — Finding Structure ────────────────────────────────────

describe("evaluateRules() — finding structure", () => {
  test("creates proper finding with all fields", () => {
    const rules: CustomRule[] = [
      {
        id: "FS-001",
        name: "No exec",
        severity: "CRITICAL",
        match: { tool_name: "exec" },
        message: "Exec forbidden",
        remediation: "Remove exec tool",
        cweId: "CWE-78",
      },
    ];

    const caps = makeCaps({
      tools: [{ name: "exec_command", inputSchema: {} }],
    });

    const results = evaluateRules(rules, caps);
    const finding = results[0].finding!;

    expect(finding.id).toBe("FS-001");
    expect(finding.module).toBe("custom-rules");
    expect(finding.severity).toBe(Severity.CRITICAL);
    expect(finding.title).toBe("No exec");
    expect(finding.description).toBe("Exec forbidden");
    expect(finding.remediation).toBe("Remove exec tool");
    expect(finding.cweId).toBe("CWE-78");
    expect(finding.evidence).toHaveProperty("violations");
    expect(finding.evidence).toHaveProperty("ruleId", "FS-001");
  });

  test("severity maps correctly for all levels", () => {
    const severities: Array<[CustomRule["severity"], Severity]> = [
      ["CRITICAL", Severity.CRITICAL],
      ["HIGH", Severity.HIGH],
      ["MEDIUM", Severity.MEDIUM],
      ["LOW", Severity.LOW],
      ["INFO", Severity.INFO],
    ];

    for (const [input, expected] of severities) {
      const rules: CustomRule[] = [
        {
          id: `SEV-${input}`,
          name: `Sev ${input}`,
          severity: input,
          match: { tool_name: "trigger" },
          message: "test",
        },
      ];

      const caps = makeCaps({
        tools: [{ name: "trigger_tool", inputSchema: {} }],
      });

      const results = evaluateRules(rules, caps);
      expect(results[0].finding!.severity).toBe(expected);
    }
  });
});

// ─── evaluateRules() — Multiple Rules ───────────────────────────────────────

describe("evaluateRules() — multiple rules", () => {
  test("evaluates all rules independently", () => {
    const rules: CustomRule[] = [
      {
        id: "MR-001",
        name: "No exec",
        severity: "CRITICAL",
        match: { tool_name: "/exec/i" },
        message: "exec banned",
      },
      {
        id: "MR-002",
        name: "Max 5 tools",
        severity: "MEDIUM",
        match: { tool_count: { gt: 5 } },
        message: "Too many tools",
      },
      {
        id: "MR-003",
        name: "No secret resources",
        severity: "HIGH",
        match: { resource_uri: "/secret/i" },
        message: "secrets exposed",
      },
    ];

    const caps = makeCaps({
      tools: [
        { name: "read_file", inputSchema: {} },
        { name: "write_file", inputSchema: {} },
      ],
      resources: [{ uri: "file:///data/public.json", name: "public" }],
    });

    const results = evaluateRules(rules, caps);
    expect(results).toHaveLength(3);
    expect(results[0].status).toBe(CheckStatus.PASS); // no exec tools
    expect(results[1].status).toBe(CheckStatus.PASS); // under 5 tools
    expect(results[2].status).toBe(CheckStatus.PASS); // no secret resources
  });

  test("mix of passing and failing rules", () => {
    const rules: CustomRule[] = [
      {
        id: "MX-001",
        name: "No exec",
        severity: "CRITICAL",
        match: { tool_name: "/exec/i" },
        message: "exec banned",
      },
      {
        id: "MX-002",
        name: "Max 2 tools",
        severity: "MEDIUM",
        match: { tool_count: { gt: 2 } },
        message: "Too many tools",
      },
    ];

    const caps = makeCaps({
      tools: [
        { name: "read_file", inputSchema: {} },
        { name: "write_file", inputSchema: {} },
        { name: "list_dir", inputSchema: {} },
      ],
    });

    const results = evaluateRules(rules, caps);
    expect(results[0].status).toBe(CheckStatus.PASS);  // no exec
    expect(results[1].status).toBe(CheckStatus.FAIL);  // 3 > 2
  });
});

// ─── evaluateRules() — Edge Cases ───────────────────────────────────────────

describe("evaluateRules() — edge cases", () => {
  test("empty rules array returns empty results", () => {
    const results = evaluateRules([], makeCaps());
    expect(results).toHaveLength(0);
  });

  test("empty capabilities with tool_name rule passes", () => {
    const rules: CustomRule[] = [
      {
        id: "EC-001",
        name: "No exec",
        severity: "HIGH",
        match: { tool_name: "/exec/i" },
        message: "test",
      },
    ];

    const results = evaluateRules(rules, makeCaps());
    expect(results[0].status).toBe(CheckStatus.PASS);
  });

  test("prompt_name matching works", () => {
    const rules: CustomRule[] = [
      {
        id: "PM-001",
        name: "No admin prompts",
        severity: "HIGH",
        match: { prompt_name: "/admin|root/i" },
        message: "Admin prompts banned",
      },
    ];

    const caps = makeCaps({
      prompts: [
        { name: "admin_setup" },
        { name: "user_greeting" },
      ],
    });

    const results = evaluateRules(rules, caps);
    expect(results[0].status).toBe(CheckStatus.FAIL);
    expect(results[0].message).toContain("1 violation");
  });

  test("schema_property matching works", () => {
    const rules: CustomRule[] = [
      {
        id: "SP-001",
        name: "No anyOf schemas",
        severity: "LOW",
        match: { schema_property: "anyOf" },
        message: "anyOf schemas found",
      },
    ];

    const caps = makeCaps({
      tools: [
        {
          name: "complex_tool",
          inputSchema: {
            type: "object",
            properties: {
              input: { anyOf: [{ type: "string" }, { type: "number" }] },
            },
          },
        },
      ],
    });

    const results = evaluateRules(rules, caps);
    expect(results[0].status).toBe(CheckStatus.FAIL);
  });

  test("capability matching works", () => {
    const rules: CustomRule[] = [
      {
        id: "CAP-001",
        name: "Check sampling capability",
        severity: "MEDIUM",
        match: { capability: "sampling" },
        message: "Sampling capability detected",
      },
    ];

    const caps = makeCaps({
      capabilities: { tools: {}, sampling: {}, resources: {} },
    });

    const results = evaluateRules(rules, caps);
    expect(results[0].status).toBe(CheckStatus.FAIL);
  });
});

// ─── outputRuleResults() ────────────────────────────────────────────────────

describe("outputRuleResults()", () => {
  test("outputs without error for mixed results", () => {
    const results = [
      {
        id: "OUT-001",
        name: "Rule 1",
        status: CheckStatus.PASS,
        message: "No violations",
      },
      {
        id: "OUT-002",
        name: "Rule 2",
        status: CheckStatus.FAIL,
        message: "2 violations found",
        finding: {
          id: "OUT-002",
          module: "custom-rules",
          severity: Severity.HIGH,
          title: "Rule 2",
          description: "Bad stuff",
          evidence: {},
          remediation: "Fix it",
        },
      },
    ];

    // Should not throw
    const origLog = console.log;
    const logs: string[] = [];
    console.log = (msg: string) => logs.push(msg);
    outputRuleResults(results);
    console.log = origLog;

    const output = logs.join("\n");
    expect(output).toContain("CUSTOM POLICY RULES");
    expect(output).toContain("1 passed, 1 failed");
  });

  test("handles empty results gracefully", () => {
    const origLog = console.log;
    const logs: string[] = [];
    console.log = (msg: string) => logs.push(msg);
    outputRuleResults([]);
    console.log = origLog;

    expect(logs).toHaveLength(0);
  });
});

// ─── YAML Parsing Edge Cases ────────────────────────────────────────────────

describe("YAML parsing", () => {
  test("parses inline count objects", () => {
    const path = writeRulesYaml(
      "inline-count.yml",
      `rules:
  - id: YP-001
    name: "Max tools"
    severity: MEDIUM
    message: "Too many tools"
    match:
      tool_count: { gt: 10 }
`
    );

    const rules = loadRules(path);
    expect(rules).toHaveLength(1);
    expect(rules[0].match.tool_count).toEqual({ gt: 10 });
  });

  test("parses multi-line count objects", () => {
    const path = writeRulesYaml(
      "multiline-count.yml",
      `rules:
  - id: YP-002
    name: "Tool range"
    severity: LOW
    message: "Tool count out of range"
    match:
      tool_count:
        gt: 20
        lt: 2
`
    );

    const rules = loadRules(path);
    expect(rules[0].match.tool_count).toEqual({ gt: 20, lt: 2 });
  });

  test("strips YAML comments", () => {
    const path = writeRulesYaml(
      "comments.yml",
      `# Top-level comment
rules:
  - id: YP-003 # inline comment
    name: "Test rule"
    severity: HIGH
    message: "Test message"
    match:
      tool_name: exec # forbidden tool
`
    );

    const rules = loadRules(path);
    expect(rules).toHaveLength(1);
    expect(rules[0].id).toBe("YP-003");
  });

  test("handles quoted values", () => {
    const path = writeRulesYaml(
      "quoted.yml",
      `rules:
  - id: YP-004
    name: "A 'complex' rule"
    severity: HIGH
    message: "Ban: dangerous tools"
    match:
      tool_name: "exec"
`
    );

    const rules = loadRules(path);
    expect(rules[0].name).toBe("A 'complex' rule");
    expect(rules[0].message).toBe("Ban: dangerous tools");
  });

  test("parses negate field", () => {
    const path = writeRulesYaml(
      "negate.yml",
      `rules:
  - id: YP-005
    name: "Must have logging"
    severity: HIGH
    message: "No logging tool found"
    negate: true
    match:
      tool_name: /log|audit/i
`
    );

    const rules = loadRules(path);
    expect(rules[0].negate).toBe(true);
  });

  test("parses annotation block", () => {
    const path = writeRulesYaml(
      "annotations.yml",
      `rules:
  - id: YP-006
    name: "No destructive"
    severity: CRITICAL
    message: "Destructive tools banned"
    match:
      annotation:
        destructiveHint: true
`
    );

    const rules = loadRules(path);
    expect(rules[0].match.annotation).toEqual({ destructiveHint: true });
  });

  test("falls back to JSON for YAML-named files with JSON content", () => {
    const path = writeRulesYaml(
      "json-as-yaml.yml",
      JSON.stringify({
        rules: [
          {
            id: "JY-001",
            name: "JSON in YAML",
            severity: "LOW",
            match: { tool_name: "test" },
            message: "test msg",
          },
        ],
      })
    );

    const rules = loadRules(path);
    expect(rules).toHaveLength(1);
    expect(rules[0].id).toBe("JY-001");
  });
});
