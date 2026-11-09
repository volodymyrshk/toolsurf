import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
  type ToolInfo,
  type Finding,
} from "../types/index.js";

type JsonSchema = Record<string, unknown>;

function schemaString(schema: JsonSchema | undefined, key: string): string {
  const value = schema?.[key];
  return typeof value === "string" ? value : "";
}

function schemaNumber(schema: JsonSchema | undefined, key: string): number | undefined {
  const value = schema?.[key];
  return typeof value === "number" ? value : undefined;
}

function schemaProperties(tool: ToolInfo): Record<string, JsonSchema> {
  return (tool.inputSchema?.properties ?? {}) as Record<string, JsonSchema>;
}

/**
 * Dangerous Capability Awareness Module (DC-001 through DC-005)
 *
 * Detects tools that grant fundamentally dangerous capabilities regardless
 * of other security controls. A tool that accepts arbitrary SQL, shell
 * commands, or code is inherently high-risk — the attack surface is the
 * tool's entire input space.
 *
 * This module addresses a critical gap: pattern-matching modules detect
 * specific payloads, but they miss the INHERENT danger of tools that
 * accept arbitrary execution input by design. A "query" tool on a postgres
 * server isn't accidentally dangerous — it's designed to run any SQL.
 *
 * All findings from this module should have HIGH confidence because the
 * detection is based on structural proof (parameter types + server context),
 * not heuristic pattern matching.
 */
export class DangerousCapabilityModule implements AuditModule {
  id = "dangerous-capability";
  name = "Dangerous Capability Awareness";
  description =
    "Detects tools that accept arbitrary code, SQL, commands, or unrestricted file operations";
  version = "1.0.0";
  mode = "passive" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const { tools } = context.capabilities;
    const serverName = context.capabilities.serverInfo?.name?.toLowerCase() ?? "";
    const checks: CheckResult[] = [];

    checks.push(this.checkArbitrarySql(tools, serverName));
    checks.push(this.checkArbitraryCodeExec(tools));
    checks.push(this.checkArbitraryShellCommand(tools));
    checks.push(this.checkUnrestrictedFileAccess(tools));
    checks.push(this.checkPathTraversalSusceptibility(tools));

    return checks;
  }

  /**
   * DC-001: Tool accepts arbitrary SQL queries.
   *
   * A tool with a "sql" or "query" parameter on a database server can
   * execute ANY SQL: SELECT (data theft), DROP/DELETE (destruction),
   * INSERT (corruption), GRANT (privilege escalation).
   */
  private checkArbitrarySql(tools: ToolInfo[], serverName: string): CheckResult {
    const findings: Finding[] = [];

    // Server context hints — increases confidence
    const isDbServer = /(?:postgres|mysql|sqlite|mariadb|mongo|redis|database|db|sql)/i.test(serverName);

    for (const tool of tools) {
      const params = Object.keys(
        (tool.inputSchema?.properties ?? {}) as Record<string, unknown>
      );
      const paramSchemas = schemaProperties(tool);
      const desc = (tool.description ?? "").toLowerCase();
      const name = tool.name.toLowerCase();

      // Check for SQL-accepting parameters
      const sqlParams = params.filter((p) =>
        /^(sql|query|statement|expression|command|raw_query|raw_sql)$/i.test(p)
      );

      // Also check if param description mentions SQL — require strong SQL-specific
      // keywords to avoid false positives on generic "query" / "search" parameters.
      // "query" alone is too broad (matches every search tool); require either:
      //   (a) explicit SQL keywords (sql, select, insert, update, delete, create table, drop, where, join), OR
      //   (b) "query" combined with database context in the tool name/description
      const sqlDescParams = params.filter((p) => {
        const schema = paramSchemas[p];
        const pDesc = schemaString(schema, "description").toLowerCase();
        const hasExplicitSqlKeyword = /\b(?:sql|select\s|insert\s|update\s+set|delete\s+from|create\s+table|drop\s|alter\s|where\s|join\s|group\s+by|order\s+by)\b/.test(pDesc);
        const hasQueryWithDbContext = /\bquery\b/.test(pDesc) && isDbServer;
        return (hasExplicitSqlKeyword || hasQueryWithDbContext) &&
               (schema?.type === "string" || !schema?.enum);
      });

      const allSqlParams = [...new Set([...sqlParams, ...sqlDescParams])];

      // Check tool name/description for database context — require compound signals,
      // not just "query" alone (which matches search/API query tools)
      const isDbTool = /(?:sql|database|db)[_\-\s]?(?:query|execute|run)?/i.test(name) ||
                       /(?:execute|run|perform)\s+(?:sql|quer|statement)/i.test(desc) ||
                       /\b(?:sql|database|table|schema|migration|resultset)\b/i.test(desc) ||
                       (/\bquer/i.test(name) && /\b(?:sql|database|db|table|row|column)\b/i.test(desc));

      if (allSqlParams.length > 0 && (isDbTool || isDbServer)) {
        // Check if there are any constraints (enum, pattern, maxLength < 200)
        const isUnconstrained = allSqlParams.some((p) => {
          const schema = paramSchemas[p];
          const maxLength = schemaNumber(schema, "maxLength");
          return !schema?.enum && !schema?.pattern &&
                 (!maxLength || maxLength > 200);
        });

        if (isUnconstrained) {
          // Confidence: higher when we have DB server context + SQL param names,
          // lower when relying only on description matching
          const hasDirectSqlParam = sqlParams.length > 0;
          const confidence = (isDbServer && hasDirectSqlParam) ? 0.95
            : (isDbServer || hasDirectSqlParam) ? 0.85
            : 0.65; // description-only match without server context

          findings.push({
            id: `DC-001-${tool.name}`,
            module: this.id,
            severity: Severity.CRITICAL,
            confidence,
            title: `Arbitrary SQL execution: "${tool.name}" accepts unconstrained SQL input`,
            description:
              `Tool "${tool.name}" accepts arbitrary SQL via parameter(s): ${allSqlParams.join(", ")}. ` +
              `This allows ANY SQL operation including: data exfiltration (SELECT), ` +
              `data destruction (DROP TABLE, DELETE), data corruption (INSERT, UPDATE), ` +
              `and privilege escalation (GRANT, CREATE ROLE). ` +
              (isDbServer
                ? `Server name "${serverName}" confirms this is a database server. `
                : "") +
              `No input validation, allowlisting, or query constraints are present in the schema.`,
            evidence: {
              toolName: tool.name,
              sqlParameters: allSqlParams,
              parameterSchemas: allSqlParams.map((p) => ({ name: p, schema: paramSchemas[p] })),
              isDbServer,
              serverName,
            },
            remediation:
              "Options: (1) Restrict to read-only queries (SELECT only) via a query parser/allowlist. " +
              "(2) Use parameterized queries with a fixed set of allowed query templates. " +
              "(3) Add schema constraints: enum of allowed operations, pattern regex for safe queries. " +
              "(4) Implement a database proxy that blocks destructive operations (DROP, DELETE, GRANT, ALTER).",
            toolName: tool.name,
            cweId: "CWE-89", // SQL Injection
          });
        }
      }
    }

    return {
      id: "DC-001",
      name: "Arbitrary SQL execution",
      status: findings.length > 0 ? CheckStatus.FAIL : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} tool(s) accept unconstrained SQL input`
        : "No arbitrary SQL execution detected",
      finding: findings[0],
    };
  }

  /**
   * DC-002: Tool accepts arbitrary code for execution.
   *
   * Tools with eval/exec/code parameters that run arbitrary code in any
   * language (Python, JS, shell, etc.) are inherently CRITICAL.
   */
  private checkArbitraryCodeExec(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];

    for (const tool of tools) {
      const params = Object.keys(
        (tool.inputSchema?.properties ?? {}) as Record<string, unknown>
      );
      const desc = (tool.description ?? "").toLowerCase();
      const name = tool.name.toLowerCase();

      // Code execution parameters
      const codeParams = params.filter((p) =>
        /^(code|script|expression|eval|source|program|snippet|function_body|lambda|exec)$/i.test(p)
      );

      // Code execution tool names
      const isCodeExecTool = /(?:eval|exec|execute|run|interpret|compile|repl)[_-]?(?:code|script|expression|js|python|program)?/i.test(name) ||
                             /(?:code|script)[_-]?(?:exec|execute|run|eval)/i.test(name);

      // Description signals
      const hasCodeExecDesc = /\b(?:execut|evaluat|run|interpret|compil)\w*\s+(?:code|script|expression|program|javascript|python|ruby)/i.test(desc) ||
                              /\b(?:arbitrary|any|custom)\s+(?:code|script|expression)/i.test(desc);

      if ((codeParams.length > 0 && (isCodeExecTool || hasCodeExecDesc)) ||
          (isCodeExecTool && hasCodeExecDesc)) {
        const execParams = codeParams.length > 0 ? codeParams : params.filter((p) =>
          /code|script|expr|source|program/i.test(p)
        );

        findings.push({
          id: `DC-002-${tool.name}`,
          module: this.id,
          severity: Severity.CRITICAL,
          confidence: 0.9,
          title: `Arbitrary code execution: "${tool.name}" runs user-supplied code`,
          description:
            `Tool "${tool.name}" accepts and executes arbitrary code` +
            (execParams.length > 0 ? ` via parameter(s): ${execParams.join(", ")}` : "") +
            `. This grants full code execution capability: file system access, network requests, ` +
            `process spawning, and anything the runtime allows. A single prompt injection can ` +
            `leverage this tool to compromise the entire system.`,
          evidence: {
            toolName: tool.name,
            codeParameters: execParams,
            description: desc.slice(0, 300),
          },
          remediation:
            "Options: (1) Remove the tool entirely — arbitrary code execution is rarely necessary. " +
            "(2) Replace with specific-purpose tools that perform defined operations. " +
            "(3) Sandbox the execution environment (container, WASM, restricted runtime). " +
            "(4) Implement an allowlist of permitted operations/functions.",
          toolName: tool.name,
          cweId: "CWE-94", // Improper Control of Generation of Code
        });
      }
    }

    return {
      id: "DC-002",
      name: "Arbitrary code execution",
      status: findings.length > 0 ? CheckStatus.FAIL : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} tool(s) execute arbitrary code`
        : "No arbitrary code execution detected",
      finding: findings[0],
    };
  }

  /**
   * DC-003: Tool accepts arbitrary shell/OS commands.
   */
  private checkArbitraryShellCommand(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];

    for (const tool of tools) {
      const params = Object.keys(
        (tool.inputSchema?.properties ?? {}) as Record<string, unknown>
      );
      const desc = (tool.description ?? "").toLowerCase();
      const name = tool.name.toLowerCase();

      // Shell command parameters
      const shellParams = params.filter((p) =>
        /^(command|cmd|shell|bash|sh|args|arguments|cli|terminal)$/i.test(p)
      );

      // Shell command tool names
      const isShellTool = /(?:shell|bash|terminal|command|cmd|exec|subprocess|spawn|system)/i.test(name);

      // Description signals
      const hasShellDesc = /\b(?:shell|bash|terminal|command[- ]line|os command|system command|subprocess)/i.test(desc) ||
                           /\b(?:run|exec)\w*\s+(?:command|shell|bash|terminal)/i.test(desc);

      if (shellParams.length > 0 && (isShellTool || hasShellDesc)) {
        findings.push({
          id: `DC-003-${tool.name}`,
          module: this.id,
          severity: Severity.CRITICAL,
          confidence: 0.9,
          title: `Arbitrary shell execution: "${tool.name}" runs OS commands`,
          description:
            `Tool "${tool.name}" accepts arbitrary shell commands via parameter(s): ${shellParams.join(", ")}. ` +
            `This grants full system access: file manipulation, network operations, process control, ` +
            `credential theft, lateral movement, and persistent backdoor installation.`,
          evidence: {
            toolName: tool.name,
            shellParameters: shellParams,
            description: desc.slice(0, 300),
          },
          remediation:
            "Options: (1) Replace with specific-purpose tools that perform defined operations. " +
            "(2) Implement strict command allowlisting (only permit specific commands). " +
            "(3) Use a restricted shell with no network/filesystem access. " +
            "(4) Add argument validation and sanitization.",
          toolName: tool.name,
          cweId: "CWE-78", // OS Command Injection
        });
      }
    }

    return {
      id: "DC-003",
      name: "Arbitrary shell/OS command execution",
      status: findings.length > 0 ? CheckStatus.FAIL : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} tool(s) execute arbitrary shell commands`
        : "No arbitrary shell command execution detected",
      finding: findings[0],
    };
  }

  /**
   * DC-004: Unrestricted file system access — tools that can read/write
   * any path without allowlisting.
   */
  private checkUnrestrictedFileAccess(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];

    // Look for file read/write tools with unconstrained path parameters
    const fileTools = tools.filter((t) => {
      const name = t.name.toLowerCase();
      return /(?:read|write|get|put|create|delete|list|cat|open|save|upload|download)[_-]?(?:file|dir|path|folder|content)/i.test(name) ||
             /^(?:cat|ls|mkdir|rm|cp|mv|touch|find|glob|tree)$/i.test(name);
    });

    for (const tool of fileTools) {
      const params = Object.keys(
        (tool.inputSchema?.properties ?? {}) as Record<string, unknown>
      );
      const paramSchemas = schemaProperties(tool);

      // Path parameters without constraints
      const pathParams = params.filter((p) => {
        const pName = p.toLowerCase();
        const schema = paramSchemas[p];
        const isPathParam = /(?:path|file|dir|folder|destination|source|src|dst|filename|filepath)/.test(pName);
        const maxLength = schemaNumber(schema, "maxLength");
        const isUnconstrained = !schema?.enum && !schema?.pattern &&
                                (!maxLength || maxLength > 200);
        return isPathParam && isUnconstrained && schema?.type === "string";
      });

      if (pathParams.length > 0) {
        // Check if the tool description mentions restrictions
        const desc = (tool.description ?? "").toLowerCase();
        const hasRestriction = /\b(?:restrict|limit|allow|sandbox|jail|whitelist|allowlist|permitted|only)\b/.test(desc);

        // Determine if it's a write tool (more dangerous)
        const isWrite = /(?:write|create|delete|remove|modify|update|append|put|save|upload|move|rename|mkdir|touch|rm)/i.test(tool.name);

        findings.push({
          id: `DC-004-${tool.name}`,
          module: this.id,
          severity: isWrite ? Severity.HIGH : Severity.MEDIUM,
          confidence: hasRestriction ? 0.5 : 0.8, // Lower if description claims restrictions
          title: `Unrestricted file ${isWrite ? "write" : "read"}: "${tool.name}" accepts arbitrary paths`,
          description:
            `Tool "${tool.name}" accepts file paths via parameter(s): ${pathParams.join(", ")} ` +
            `with no schema-level path restrictions (no enum, no pattern constraint). ` +
            (isWrite
              ? `Write access to arbitrary paths enables: overwriting config files, planting backdoors, ` +
                `corrupting data, and denial of service.`
              : `Read access to arbitrary paths enables: reading credentials, SSH keys, ` +
                `environment files, database configs, and sensitive application data.`) +
            (hasRestriction
              ? ` Note: description mentions restrictions, but these are enforced at runtime, not schema level.`
              : ""),
          evidence: {
            toolName: tool.name,
            pathParameters: pathParams,
            isWriteTool: isWrite,
            hasDescriptionRestriction: hasRestriction,
          },
          remediation:
            "Options: (1) Add 'pattern' constraint to limit paths to a safe directory. " +
            "(2) Use 'enum' to restrict to specific allowed paths. " +
            "(3) Implement server-side path validation with chroot/jail. " +
            "(4) Add readOnlyHint/destructiveHint annotations for LLM framework awareness.",
          toolName: tool.name,
          cweId: isWrite ? "CWE-73" : "CWE-22", // File path injection / Path traversal
        });
      }
    }

    // Deduplicate — just report count
    const primary = findings[0];
    if (primary && findings.length > 1) {
      primary.affectedCount = findings.length;
      primary.affectedTools = findings.map((f) => f.toolName!);
    }

    return {
      id: "DC-004",
      name: "Unrestricted file system access",
      status: findings.length > 0 ? CheckStatus.FAIL : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} tool(s) accept arbitrary file paths without schema constraints`
        : "File access tools have appropriate constraints",
      finding: primary,
    };
  }

  /**
   * DC-005: Path traversal susceptibility — tools with path/file parameters
   * that lack schema-level protection against directory traversal.
   *
   * Unlike DC-004 which catches completely unconstrained file access,
   * DC-005 specifically flags tools where:
   *   - Path params exist but have no 'pattern' regex constraint
   *   - No 'enum' restricting to safe paths
   *   - Description doesn't mention sandboxing/chroot/allowlist
   *   - The tool operates on file/directory/path concepts
   *
   * This catches CVE-2025-53110 (filesystem path traversal) type attacks
   * where `../../../etc/passwd` or `%2e%2e%2f` bypasses intended restrictions.
   *
   * Research ref: OWASP MCP Top 10 — path traversal via tool parameters.
   */
  private checkPathTraversalSusceptibility(tools: ToolInfo[]): CheckResult {
    const findings: Finding[] = [];

    for (const tool of tools) {
      const paramSchemas = schemaProperties(tool);
      const name = tool.name.toLowerCase();
      const desc = (tool.description ?? "").toLowerCase();

      // Only check tools that deal with file/path concepts
      const isFileTool =
        /(?:file|path|dir|directory|folder|read|write|copy|move|delete|rename|cat|ls|stat|chmod)/i.test(name) ||
        /(?:file|path|directory|folder|document|read|write|create|delete)\b/i.test(desc);

      if (!isFileTool) continue;

      // Find path-like parameters
      const pathParams: string[] = [];
      const vulnerableParams: Array<{ name: string; reasons: string[] }> = [];

      for (const [paramName, schema] of Object.entries(paramSchemas)) {
        const isPathParam =
          /^(path|file|filepath|file_path|filename|directory|dir|folder|source|destination|target|src|dst|from|to|location)$/i.test(paramName) ||
          /(?:path|file|directory|folder)/i.test(schemaString(schema, "description"));

        if (!isPathParam || schema?.type !== "string") continue;
        pathParams.push(paramName);

        const reasons: string[] = [];

        // Check for lack of schema-level traversal protection
        if (!schema.pattern) {
          reasons.push("no regex pattern constraint");
        } else {
          // Check if the pattern actually prevents traversal
          const pattern = String(schema.pattern);
          if (!pattern.includes("\\.\\.") && !pattern.includes("[^/]") && !pattern.includes("[^\\\\/]")) {
            reasons.push("pattern does not block '../' sequences");
          }
        }

        if (!schema.enum) {
          reasons.push("no enum allowlist");
        }

        // Check for path length — very short maxLength might be protective
        const maxLength = schemaNumber(schema, "maxLength");
        if (maxLength && maxLength < 50) {
          // Short paths are less exploitable — reduce concern
          continue;
        }

        // Check if description mentions any sandboxing
        const paramDesc = schemaString(schema, "description").toLowerCase();
        const hasSandboxMention =
          /(?:sandbox|chroot|jail|restrict|allowlist|whitelist|safe|validated|within)/i.test(paramDesc) ||
          /(?:sandbox|chroot|jail|restrict|allowlist|whitelist|safe|within)/i.test(desc);

        if (hasSandboxMention) {
          // Tool claims to have protection — lower severity but still note
          if (reasons.length > 0) {
            reasons.push("claims sandboxing in description but no schema enforcement");
          } else {
            continue; // Schema-protected + description claims protection = OK
          }
        }

        if (reasons.length > 0) {
          vulnerableParams.push({ name: paramName, reasons });
        }
      }

      if (vulnerableParams.length === 0) continue;

      findings.push({
        id: `DC-005-${tool.name}`,
        module: this.id,
        severity: Severity.HIGH,
        confidence: 0.75,
        title: `Path traversal susceptibility: "${tool.name}" accepts paths without traversal protection`,
        description:
          `Tool "${tool.name}" has ${vulnerableParams.length} path parameter(s) without ` +
          `schema-level protection against directory traversal attacks. An attacker (or an ` +
          `LLM manipulated via prompt injection) can supply paths like "../../../etc/passwd" ` +
          `or "%2e%2e%2fetc%2fpasswd" to escape intended directory boundaries. ` +
          `Vulnerable parameters: ${vulnerableParams.map(p => `"${p.name}" (${p.reasons.join(", ")})`).join("; ")}. ` +
          `See: CVE-2025-53110 (MCP filesystem path traversal).`,
        evidence: {
          toolName: tool.name,
          vulnerableParams: vulnerableParams,
          totalPathParams: pathParams.length,
          traversalPayloadExamples: [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//etc/passwd",
            "/tmp/../etc/shadow",
          ],
        },
        remediation:
          "Options: (1) Add a 'pattern' regex to the schema that rejects '..' sequences: " +
          "e.g. \"pattern\": \"^[a-zA-Z0-9_/.-]+$\" with explicit '..' rejection. " +
          "(2) Server-side: resolve paths with realpath() and verify they stay within allowed root. " +
          "(3) Use 'enum' to restrict to specific known-safe paths. " +
          "(4) Implement chroot/jail to prevent filesystem escape regardless of input.",
        toolName: tool.name,
        cweId: "CWE-22", // Path Traversal
      });
    }

    return {
      id: "DC-005",
      name: "Path traversal susceptibility",
      status: findings.length > 0 ? CheckStatus.FAIL : CheckStatus.PASS,
      message: findings.length > 0
        ? `${findings.length} tool(s) accept file paths without traversal protection`
        : "File tools have adequate path traversal protection",
      finding: findings[0],
    };
  }
}
