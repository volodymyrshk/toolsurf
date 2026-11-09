import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
} from "../types/index.js";

/**
 * Supply Chain Analysis Module (Passive).
 *
 * Analyzes the MCP server's supply chain risks:
 * 1. Package name typosquatting indicators
 * 2. Suspicious server metadata (version, name patterns)
 * 3. Excessive capability requests relative to tool count
 * 4. Known malicious package name patterns
 * 5. Server version freshness and consistency
 *
 * PASSIVE MODULE: analyzes metadata only, no tool calls.
 *
 * CWE-1357: Reliance on Insufficiently Trustworthy Component
 *
 * SC-007 and SC-008 are active checks gated behind context.activeMode.
 * They call the npm registry API to check maintainer history and version timing.
 * Configuration: --supply-chain-depth <n> (default: 2, used for transitive deps).
 */
export class SupplyChainAnalysisModule implements AuditModule {
  id = "supply-chain-analysis";
  name = "Supply Chain Analysis";
  description =
    "Analyzes server metadata and naming for supply-chain risk indicators";
  version = "2.0.0";
  mode = "passive" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];
    const { capabilities } = context;

    // Check 1: Package name typosquatting
    checks.push(this.checkTyposquatting(capabilities.serverInfo.name));

    // Check 2: Suspicious server metadata
    checks.push(this.checkSuspiciousMetadata(
      capabilities.serverInfo.name,
      capabilities.serverInfo.version
    ));

    // Check 3: Capability sprawl — excessive capabilities vs tool count
    checks.push(this.checkCapabilitySprawl(capabilities));

    // Check 4: Version anomalies
    checks.push(this.checkVersionAnomalies(capabilities.serverInfo.version));

    // Check 5: Tool count anomalies
    checks.push(this.checkToolCountAnomalies(capabilities));

    // Check 6: npm lifecycle hook risk indicators
    checks.push(this.checkLifecycleHooks(capabilities));

    // Check 7 & 8: Active-only npm registry checks (maintainer change + version timing)
    if (context.activeMode) {
      const serverName = capabilities.serverInfo.name;
      const serverVersion = capabilities.serverInfo.version;
      checks.push(await this.checkMaintainerChanges(serverName, context.signal));
      checks.push(await this.checkVersionTimingAnomaly(serverName, serverVersion, context.signal));
    }

    return checks;
  }

  /**
   * Check for typosquatting indicators in the server/package name.
   * Looks for common typosquatting patterns used in npm attacks.
   */
  private checkTyposquatting(serverName: string): CheckResult {
    const name = serverName.toLowerCase();
    const indicators: string[] = [];

    // Known popular MCP package prefixes
    const popularPrefixes = [
      "modelcontextprotocol",
      "mcp-server",
      "mcp-tool",
      "anthropic",
      "claude",
    ];

    // Check for near-miss typos of popular packages
    for (const prefix of popularPrefixes) {
      if (name === prefix) continue; // Exact match is fine
      const distance = this.levenshteinDistance(name, prefix);
      if (distance > 0 && distance <= 2) {
        indicators.push(`Name "${serverName}" is ${distance} edit(s) from "${prefix}"`);
      }

      // Check for homoglyph substitution (0 for o, 1 for l, etc.)
      const homoglyphVersion = prefix
        .replace(/o/g, "0")
        .replace(/l/g, "1")
        .replace(/i/g, "1");
      if (name === homoglyphVersion && name !== prefix) {
        indicators.push(`Name "${serverName}" uses homoglyph substitution of "${prefix}"`);
      }
    }

    // Check for suspicious naming patterns
    if (name.includes("--")) {
      indicators.push("Double-dash in package name (npm scoping confusion)");
    }
    if (/^@[^/]+\//.test(name) === false && name.includes("official")) {
      indicators.push("Claims 'official' but not scoped to an org");
    }
    if (/\d{4,}/.test(name)) {
      indicators.push("Contains suspiciously long numeric suffix");
    }
    if (name.endsWith("-dev") || name.endsWith("-test") || name.endsWith("-debug")) {
      indicators.push(`Suspicious suffix: "${name.split("-").pop()}"`);
    }

    if (indicators.length === 0) {
      return {
        id: "SC-001",
        name: "Package name typosquatting check",
        status: CheckStatus.PASS,
        message: `Server name "${serverName}" shows no typosquatting indicators`,
      };
    }

    return {
      id: "SC-001",
      name: "Package name typosquatting check",
      status: CheckStatus.WARN,
      message: `${indicators.length} typosquatting indicator(s) found`,
      finding: {
        id: "SC-001",
        module: this.id,
        severity: Severity.HIGH,
        title: "Possible typosquatting in server package name",
        description:
          `Server "${serverName}" exhibits naming patterns commonly associated with ` +
          "typosquatting attacks in package registries. This could indicate a malicious " +
          "package impersonating a legitimate MCP server.",
        evidence: { serverName, indicators },
        remediation:
          "Verify the server package name against the official registry. " +
          "Check the package publisher and download count. " +
          "Compare with the canonical package name for the intended server. " +
          "Use lockfiles and hash verification to pin dependencies.",
        cweId: "CWE-1357",
      },
    };
  }

  /**
   * Check server metadata for suspicious patterns.
   */
  private checkSuspiciousMetadata(serverName: string, version: string): CheckResult {
    const issues: string[] = [];

    // Empty or placeholder name
    if (!serverName || serverName === "unknown" || serverName === "test") {
      issues.push("Server name is empty or placeholder-like");
    }

    // Empty or placeholder version
    if (!version || version === "0.0.0" || version === "unknown") {
      issues.push("Server version is empty or placeholder-like");
    }

    // Suspiciously generic description in name
    if (/^(server|tool|api|service)$/i.test(serverName)) {
      issues.push("Server name is suspiciously generic");
    }

    // Check for dev/staging indicators in production
    const devIndicators = ["localhost", "staging", "beta", "alpha", "canary", "nightly"];
    for (const indicator of devIndicators) {
      if (serverName.toLowerCase().includes(indicator)) {
        issues.push(`Server name contains dev/staging indicator: "${indicator}"`);
      }
    }

    if (issues.length === 0) {
      return {
        id: "SC-002",
        name: "Server metadata analysis",
        status: CheckStatus.PASS,
        message: "Server metadata appears legitimate",
      };
    }

    return {
      id: "SC-002",
      name: "Server metadata analysis",
      status: CheckStatus.WARN,
      message: `${issues.length} metadata issue(s) found`,
      finding: {
        id: "SC-002",
        module: this.id,
        severity: Severity.LOW,
        title: "Suspicious server metadata",
        description:
          `Server "${serverName}" v${version} has metadata patterns that may indicate ` +
          "an incomplete, staging, or potentially malicious server deployment.",
        evidence: { serverName, version, issues },
        remediation:
          "Ensure the server has proper identification metadata. " +
          "Use semantic versioning and meaningful server names. " +
          "Remove dev/staging indicators from production deployments.",
        cweId: "CWE-1357",
      },
    };
  }

  /**
   * Check for capability sprawl — servers requesting more capabilities
   * than their tool count justifies.
   */
  private checkCapabilitySprawl(capabilities: ModuleContext["capabilities"]): CheckResult {
    const toolCount = capabilities.tools.length;
    const resourceCount = capabilities.resources.length;
    const promptCount = capabilities.prompts.length;
    const totalSurface = toolCount + resourceCount + promptCount;
    const issues: string[] = [];

    // Large number of tools with no resources/prompts (potential kitchen-sink)
    if (toolCount > 20 && resourceCount === 0 && promptCount === 0) {
      issues.push(
        `${toolCount} tools with zero resources/prompts — potential over-permissioned server`
      );
    }

    // Tools with destructive annotations relative to total
    const destructiveTools = capabilities.tools.filter(
      (t) => t.annotations?.destructiveHint === true
    );
    if (destructiveTools.length > toolCount * 0.5 && toolCount > 3) {
      issues.push(
        `${destructiveTools.length}/${toolCount} tools marked destructive — high-risk server`
      );
    }

    // No annotations at all (lack of safety metadata)
    const annotatedTools = capabilities.tools.filter(
      (t) => t.annotations && Object.keys(t.annotations).length > 0
    );
    if (annotatedTools.length === 0 && toolCount > 0) {
      issues.push(
        `No tool annotations declared — server provides no safety metadata`
      );
    }

    // Attack surface assessment
    if (totalSurface > 50) {
      issues.push(
        `Large attack surface: ${totalSurface} total capabilities (${toolCount} tools, ${resourceCount} resources, ${promptCount} prompts)`
      );
    }

    const annotationOnlyConcern =
      issues.length === 1 &&
      issues[0].startsWith("No tool annotations declared");

    if (issues.length === 0) {
      return {
        id: "SC-003",
        name: "Capability sprawl analysis",
        status: CheckStatus.PASS,
        message: `Attack surface: ${toolCount} tools, ${resourceCount} resources, ${promptCount} prompts`,
      };
    }

    if (annotationOnlyConcern) {
      return {
        id: "SC-003",
        name: "Capability sprawl analysis",
        status: CheckStatus.PASS,
        message:
          `Attack surface: ${toolCount} tools, ${resourceCount} resources, ${promptCount} prompts; ` +
          "annotation-only concern is covered by TP-006",
      };
    }

    return {
      id: "SC-003",
      name: "Capability sprawl analysis",
      status: CheckStatus.WARN,
      message: `${issues.length} capability concern(s) found`,
      finding: {
        id: "SC-003",
        module: this.id,
        severity: Severity.MEDIUM,
        title: "Excessive or poorly annotated capability surface",
        description:
          "The server's capability surface raises concerns about over-permissioning " +
          "or inadequate safety metadata. " +
          issues.join(". ") + ".",
        evidence: {
          toolCount,
          resourceCount,
          promptCount,
          destructiveToolCount: destructiveTools.length,
          annotatedToolCount: annotatedTools.length,
          issues,
        },
        remediation:
          "Apply the principle of least privilege — only expose necessary tools. " +
          "Add safety annotations (readOnlyHint, destructiveHint) to all tools. " +
          "Split large tool sets into focused server packages. " +
          "Document the security posture of each tool.",
        cweId: "CWE-250",
      },
    };
  }

  /**
   * Check version string for anomalies.
   */
  private checkVersionAnomalies(version: string): CheckResult {
    const issues: string[] = [];

    // Not semver
    if (!/^\d+\.\d+\.\d+/.test(version)) {
      issues.push(`Version "${version}" is not semantic versioning`);
    }

    // Very old major version 0.0.x
    if (/^0\.0\.\d+$/.test(version)) {
      issues.push("Pre-release version (0.0.x) — may be unstable or experimental");
    }

    // Suspiciously high version
    const parts = version.split(".");
    if (parts.length >= 1 && parseInt(parts[0], 10) > 100) {
      issues.push(`Suspiciously high major version: ${parts[0]}`);
    }

    if (issues.length === 0) {
      return {
        id: "SC-004",
        name: "Version integrity check",
        status: CheckStatus.PASS,
        message: `Version "${version}" follows expected conventions`,
      };
    }

    return {
      id: "SC-004",
      name: "Version integrity check",
      status: CheckStatus.WARN,
      message: issues[0],
    };
  }

  /**
   * Check for tool count anomalies (zero tools, suspiciously high counts).
   */
  private checkToolCountAnomalies(
    capabilities: ModuleContext["capabilities"]
  ): CheckResult {
    const toolCount = capabilities.tools.length;

    if (toolCount === 0) {
      return {
        id: "SC-005",
        name: "Tool count analysis",
        status: CheckStatus.WARN,
        message: "Server exposes zero tools — may be misconfigured",
        finding: {
          id: "SC-005",
          module: this.id,
          severity: Severity.LOW,
          title: "Server exposes no tools",
          description:
            "The MCP server advertises zero tools. This may indicate a misconfigured " +
            "server, a server in initialization state, or a server that only provides " +
            "resources/prompts without tool functionality.",
          evidence: { toolCount: 0 },
          remediation:
            "Verify the server is properly configured and initialized. " +
            "Ensure the server's tool registration is working correctly.",
          cweId: "CWE-1357",
        },
      };
    }

    return {
      id: "SC-005",
      name: "Tool count analysis",
      status: CheckStatus.PASS,
      message: `Server exposes ${toolCount} tool(s)`,
    };
  }

  /**
   * Check for npm lifecycle hook abuse indicators.
   * Dangerous preinstall/postinstall scripts are a primary supply chain vector.
   * Reference: Shai-Hulud npm worm (Nov 2025), TeamPCP LiteLLM (Mar 2026).
   */
  private checkLifecycleHooks(capabilities: ModuleContext["capabilities"]): CheckResult {
    const indicators: string[] = [];
    const transportStr = JSON.stringify(capabilities).toLowerCase();

    // Check for npx auto-install (already in transport-security, reinforce here)
    if (transportStr.includes("npx -y") || transportStr.includes("npx --yes")) {
      indicators.push("Uses 'npx -y' (auto-install without confirmation) — bypasses manual review");
    }

    // Check for install-time code execution patterns
    const dangerousPatterns = [
      { pattern: "preinstall", desc: "preinstall hook detected — code runs before package is installed" },
      { pattern: "postinstall", desc: "postinstall hook detected — code runs after installation" },
      { pattern: "prepare", desc: "'prepare' lifecycle script detected" },
      { pattern: "install && ", desc: "Chained install command — potential for hidden execution" },
    ];

    for (const { pattern, desc } of dangerousPatterns) {
      if (transportStr.includes(pattern)) {
        indicators.push(desc);
      }
    }

    // Check for obfuscation indicators in server metadata
    const obfuscationPatterns = [
      { pattern: /eval\s*\(/, desc: "eval() usage detected in configuration" },
      { pattern: /buffer\.from\s*\([^)]+,\s*['"]base64['"]/, desc: "Base64 decoding detected — potential obfuscation" },
      { pattern: /\\x[0-9a-f]{2}/i, desc: "Hex-escaped strings detected — potential obfuscation" },
      { pattern: /child_process/, desc: "child_process reference in metadata — potential command execution" },
    ];

    for (const { pattern, desc } of obfuscationPatterns) {
      if (pattern.test(transportStr)) {
        indicators.push(desc);
      }
    }

    if (indicators.length === 0) {
      return {
        id: "SC-006",
        name: "Lifecycle hook risk analysis",
        status: CheckStatus.PASS,
        message: "No dangerous lifecycle hook patterns detected",
      };
    }

    return {
      id: "SC-006",
      name: "Lifecycle hook risk analysis",
      status: CheckStatus.WARN,
      message: `${indicators.length} lifecycle hook risk indicator(s) found`,
      finding: {
        id: "SC-006",
        module: this.id,
        severity: indicators.some((i) => i.includes("preinstall") || i.includes("eval"))
          ? Severity.HIGH
          : Severity.MEDIUM,
        title: "Supply chain risk via lifecycle hooks or obfuscated code",
        description:
          "The server configuration exhibits patterns associated with supply chain attacks " +
          "via npm/pip lifecycle hooks or code obfuscation. These techniques are used by " +
          "malicious packages to execute arbitrary code during installation. " +
          "Reference: Shai-Hulud npm worm (Nov 2025), TeamPCP LiteLLM compromise (Mar 2026).",
        evidence: { indicators },
        remediation:
          "1) Audit package.json scripts section for preinstall/postinstall hooks. " +
          "2) Never use 'npx -y' with untrusted packages. " +
          "3) Pin exact package versions and verify checksums. " +
          "4) Use npm audit / pip-audit before installation. " +
          "5) Review all obfuscated code before deployment.",
        cweId: "CWE-506",
      },
    };
  }

  /**
   * SC-007: Recent maintainer change on the npm package (active mode only).
   *
   * Queries the npm registry API for the package's maintainer list over time.
   * A change in the maintainers set within the last 90 days is a supply-chain
   * risk indicator — it may indicate a compromised or sold package.
   */
  private async checkMaintainerChanges(
    packageName: string,
    signal?: AbortSignal
  ): Promise<CheckResult> {
    // Skip packages that are clearly not npm packages
    if (!packageName || packageName.length < 2 || /^\d+\.\d+\.\d+$/.test(packageName)) {
      return {
        id: "SC-007",
        name: "Maintainer change detection (npm)",
        status: CheckStatus.PASS,
        message: "Skipped — server name does not appear to be an npm package",
      };
    }

    try {
      const encodedName = encodeURIComponent(packageName);
      const localSignal = AbortSignal.timeout(10_000);
      const combinedSignal = signal
        ? AbortSignal.any([signal, localSignal])
        : localSignal;

      const res = await fetch(`https://registry.npmjs.org/${encodedName}`, {
        headers: { Accept: "application/json" },
        signal: combinedSignal,
      });

      if (!res.ok) {
        if (res.status === 404) {
          return {
            id: "SC-007",
            name: "Maintainer change detection (npm)",
            status: CheckStatus.PASS,
            message: `Package "${packageName}" not found on npm registry`,
          };
        }
        throw new Error(`npm registry returned ${res.status}`);
      }

      const data = await res.json() as Record<string, unknown>;
      const times = data.time as Record<string, string> | undefined;
      if (!times) {
        return {
          id: "SC-007",
          name: "Maintainer change detection (npm)",
          status: CheckStatus.PASS,
          message: `No version timing data available for "${packageName}"`,
        };
      }

      // Look at versions published in the last 90 days
      const ninetyDaysAgo = Date.now() - 90 * 24 * 60 * 60 * 1000;
      const recentVersions = Object.entries(times)
        .filter(([v]) => !["created", "modified"].includes(v))
        .filter(([, ts]) => new Date(ts).getTime() > ninetyDaysAgo)
        .map(([v, ts]) => ({ version: v, published: ts }));

      // Check maintainers on the most recent version
      const versions = data.versions as Record<string, { maintainers?: Array<{ name: string }> }> | undefined;
      const allVersionKeys = Object.keys(versions ?? {});
      const latestVersion = allVersionKeys[allVersionKeys.length - 1];
      const currentMaintainers = (versions?.[latestVersion]?.maintainers ?? []).map((m) => m.name);

      // Compare to oldest available version maintainers
      const oldestVersion = allVersionKeys[0];
      const originalMaintainers = (versions?.[oldestVersion]?.maintainers ?? []).map((m) => m.name);

      const newMaintainers = currentMaintainers.filter((m) => !originalMaintainers.includes(m));
      const droppedMaintainers = originalMaintainers.filter((m) => !currentMaintainers.includes(m));

      const hasMaintainerChange = (newMaintainers.length > 0 || droppedMaintainers.length > 0) && recentVersions.length > 0;

      if (!hasMaintainerChange) {
        return {
          id: "SC-007",
          name: "Maintainer change detection (npm)",
          status: CheckStatus.PASS,
          message: `No recent maintainer changes detected for "${packageName}"`,
        };
      }

      return {
        id: "SC-007",
        name: "Maintainer change detection (npm)",
        status: CheckStatus.WARN,
        message: `Maintainer change detected for "${packageName}" — ${newMaintainers.length} new, ${droppedMaintainers.length} dropped`,
        finding: {
          id: "SC-007",
          module: this.id,
          severity: Severity.HIGH,
          title: `Supply chain risk: maintainer set changed for "${packageName}"`,
          description:
            `The npm package "${packageName}" has had maintainer changes and was published ` +
            `${recentVersions.length} time(s) in the last 90 days. ` +
            (newMaintainers.length > 0 ? `New maintainers: ${newMaintainers.join(", ")}. ` : "") +
            (droppedMaintainers.length > 0 ? `Dropped maintainers: ${droppedMaintainers.join(", ")}. ` : "") +
            `Maintainer set changes on active packages are a primary supply chain attack vector — ` +
            `a new maintainer may introduce malicious code in a subsequent release ` +
            `(ref: PyPI/npm account takeover attacks, 2025).`,
          evidence: {
            packageName,
            newMaintainers,
            droppedMaintainers,
            recentVersionsPublished: recentVersions.length,
            recentVersions: recentVersions.slice(0, 5),
          },
          remediation:
            "1) Verify the new maintainer's identity and track record on npm. " +
            "2) Review the full diff of any version published after the maintainer change. " +
            "3) Pin to a specific known-good version hash in your lockfile. " +
            "4) Enable npm audit signatures verification (npm config set audit-level=moderate).",
          cweId: "CWE-1357",
        },
      };
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        return {
          id: "SC-007",
          name: "Maintainer change detection (npm)",
          status: CheckStatus.PASS,
          message: "Skipped — npm registry check timed out",
        };
      }
      return {
        id: "SC-007",
        name: "Maintainer change detection (npm)",
        status: CheckStatus.PASS,
        message: `Skipped — npm registry check failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  /**
   * SC-008: Version timing anomaly — new version published within 24h of scan (active mode only).
   *
   * A package version published very recently (within 24 hours) relative to when this scan
   * is being run may indicate a staged rollout attack or a just-compromised package.
   * "Timing attacks" in supply chains exploit the window between a malicious publish
   * and security scanner detection.
   */
  private async checkVersionTimingAnomaly(
    packageName: string,
    currentVersion: string,
    signal?: AbortSignal
  ): Promise<CheckResult> {
    if (!packageName || packageName.length < 2 || !currentVersion || currentVersion === "0.0.0") {
      return {
        id: "SC-008",
        name: "Version timing anomaly (npm)",
        status: CheckStatus.PASS,
        message: "Skipped — insufficient package metadata",
      };
    }

    try {
      const encodedName = encodeURIComponent(packageName);
      const localSignal = AbortSignal.timeout(10_000);
      const combinedSignal = signal
        ? AbortSignal.any([signal, localSignal])
        : localSignal;

      const res = await fetch(`https://registry.npmjs.org/${encodedName}/${encodeURIComponent(currentVersion)}`, {
        headers: { Accept: "application/json" },
        signal: combinedSignal,
      });

      if (!res.ok) {
        return {
          id: "SC-008",
          name: "Version timing anomaly (npm)",
          status: CheckStatus.PASS,
          message: `Version "${currentVersion}" of "${packageName}" not found on npm registry`,
        };
      }

      const versionData = await res.json() as Record<string, unknown>;
      const publishedAt = versionData._time as string | undefined
        ?? (versionData.dist as Record<string, unknown> | undefined)?._time as string | undefined;

      if (!publishedAt) {
        return {
          id: "SC-008",
          name: "Version timing anomaly (npm)",
          status: CheckStatus.PASS,
          message: `No publish timestamp for "${packageName}@${currentVersion}"`,
        };
      }

      const publishedMs = new Date(publishedAt).getTime();
      const nowMs = Date.now();
      const ageHours = (nowMs - publishedMs) / (1000 * 60 * 60);

      if (ageHours > 24) {
        return {
          id: "SC-008",
          name: "Version timing anomaly (npm)",
          status: CheckStatus.PASS,
          message: `Version "${packageName}@${currentVersion}" is ${Math.floor(ageHours)} hours old — no timing anomaly`,
        };
      }

      const ageMins = Math.round(ageHours * 60);

      return {
        id: "SC-008",
        name: "Version timing anomaly (npm)",
        status: CheckStatus.WARN,
        message: `"${packageName}@${currentVersion}" was published only ${ageMins} minutes ago — possible staged rollout`,
        finding: {
          id: "SC-008",
          module: this.id,
          severity: Severity.HIGH,
          title: `Version timing anomaly: "${packageName}@${currentVersion}" published ${ageMins} minutes ago`,
          description:
            `The version of "${packageName}" currently running (${currentVersion}) was published ` +
            `only ${ageMins} minutes ago (at ${publishedAt}). ` +
            `Very recently published package versions are a supply-chain red flag: ` +
            `they may be part of a "staged rollout" attack where a malicious version is ` +
            `published and immediately deployed before security scanners or human reviewers ` +
            `can react. The MCP server you are scanning may be running a version that was ` +
            `compromised within the last 24 hours.`,
          evidence: {
            packageName,
            version: currentVersion,
            publishedAt,
            ageMinutes: ageMins,
            scanTime: new Date(nowMs).toISOString(),
          },
          remediation:
            "1) Do not use packages published within the last 24 hours in production. " +
            "2) Review the full changelog and diff for this version before deploying. " +
            "3) Check the npm package page for any security advisories. " +
            "4) If possible, pin to a version that has been stable for at least 7 days.",
          cweId: "CWE-1357",
        },
      };
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        return {
          id: "SC-008",
          name: "Version timing anomaly (npm)",
          status: CheckStatus.PASS,
          message: "Skipped — npm registry check timed out",
        };
      }
      return {
        id: "SC-008",
        name: "Version timing anomaly (npm)",
        status: CheckStatus.PASS,
        message: `Skipped — npm registry check failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  /**
   * Calculate Levenshtein distance between two strings.
   */
  private levenshteinDistance(a: string, b: string): number {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;

    const matrix: number[][] = [];

    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        const cost = a[j - 1] === b[i - 1] ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j - 1] + cost
        );
      }
    }

    return matrix[b.length][a.length];
  }
}
