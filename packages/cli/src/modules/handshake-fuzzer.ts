import {
  Severity,
  CheckStatus,
  type AuditModule,
  type ModuleContext,
  type CheckResult,
} from "../types/index.js";

/**
 * Handshake Fuzzer Module (HF-001 through HF-005)
 *
 * Analyzes MCP connection handshake parameters for exploitable patterns.
 * Motivated by CVE-2025-6514 which demonstrated that the MCP handshake
 * itself (authorization_endpoint, redirect_uri, OAuth initialization params)
 * can be weaponized before any tool call occurs.
 *
 * Attack surface: The MCP initialization exchange exposes server identity,
 * protocol version, OAuth endpoints, and capability declarations. A malicious
 * server can embed injection payloads, open-redirect URLs, or deceptive
 * metadata in these fields to exploit vulnerable clients during connection
 * establishment — before any user-visible tool interaction takes place.
 *
 * All checks are PASSIVE: they analyze the already-negotiated handshake
 * metadata without making additional tool calls.
 *
 * CWE-20: Improper Input Validation (handshake parameters)
 */
export class HandshakeFuzzerModule implements AuditModule {
  id = "handshake-fuzzer";
  name = "Handshake Fuzzer";
  description =
    "Analyzes MCP handshake parameters for OAuth injection, redirect manipulation, protocol spoofing, and capability abuse";
  version = "1.0.0";
  mode = "passive" as const;

  async run(context: ModuleContext): Promise<CheckResult[]> {
    const checks: CheckResult[] = [];

    // HF-001: OAuth endpoint injection
    checks.push(this.checkOAuthEndpointInjection(context));

    // HF-002: Redirect URI manipulation
    checks.push(this.checkRedirectUriManipulation(context));

    // HF-003: Protocol version spoofing
    checks.push(this.checkProtocolVersionSpoofing(context));

    // HF-004: Initialization parameter injection
    checks.push(this.checkInitParamInjection(context));

    // HF-005: Capability enumeration abuse
    checks.push(this.checkCapabilityEnumerationAbuse(context));

    return checks;
  }

  /**
   * HF-001: OAuth endpoint injection.
   *
   * Analyze server capabilities for OAuth/authorization_endpoint fields.
   * Check if URLs contain injectable patterns, open redirect potential,
   * or command injection via malformed URLs.
   *
   * CVE-2025-6514: Malicious servers can supply crafted authorization_endpoint
   * values that exploit clients performing automatic OAuth flows.
   */
  private checkOAuthEndpointInjection(context: ModuleContext): CheckResult {
    const caps = context.capabilities.capabilities;
    const oauthUrls = this.extractOAuthEndpoints(caps);

    if (oauthUrls.length === 0) {
      return {
        id: "HF-001",
        name: "OAuth endpoint injection",
        status: CheckStatus.PASS,
        message: "No OAuth/authorization endpoints found in server capabilities",
      };
    }

    const injectionFindings: Array<{
      url: string;
      field: string;
      issues: string[];
    }> = [];

    for (const { url, field } of oauthUrls) {
      const issues: string[] = [];

      // Check for non-HTTPS schemes (phishing / downgrade)
      if (!/^https:\/\//i.test(url)) {
        issues.push("non-HTTPS scheme — vulnerable to credential interception");
      }

      // Check for IP addresses instead of hostnames (bypass domain validation)
      if (/^https?:\/\/(\d{1,3}\.){3}\d{1,3}/i.test(url)) {
        issues.push("IP address used instead of hostname — may bypass domain allowlists");
      }

      // Check for embedded credentials in URL
      if (/@/.test(url.split("?")[0])) {
        issues.push("URL contains embedded credentials (user@host pattern)");
      }

      // Check for localhost/internal addresses (SSRF via OAuth redirect)
      if (/^https?:\/\/(localhost|127\.|0\.0\.0\.0|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|\[::1\])/i.test(url)) {
        issues.push("points to internal/loopback address — potential SSRF vector");
      }

      // Check for command injection patterns in URL
      if (/[;|`$(){}]/.test(url) || /\$\{/.test(url)) {
        issues.push("URL contains shell metacharacters — potential command injection");
      }

      // Check for data: or javascript: URI schemes
      if (/^(data|javascript|vbscript):/i.test(url)) {
        issues.push("dangerous URI scheme detected — potential code execution");
      }

      // Check for URL-encoded traversal or null bytes
      if (/%00|%0[aAdD]/.test(url)) {
        issues.push("URL contains null bytes or CRLF — potential header injection");
      }

      // Check for overly long URLs (buffer overflow / DoS potential)
      if (url.length > 2048) {
        issues.push("URL exceeds 2048 characters — potential buffer overflow target");
      }

      if (issues.length > 0) {
        injectionFindings.push({ url: url.substring(0, 200), field, issues });
      }
    }

    if (injectionFindings.length === 0) {
      return {
        id: "HF-001",
        name: "OAuth endpoint injection",
        status: CheckStatus.PASS,
        message: `${oauthUrls.length} OAuth endpoint(s) analyzed — no injection patterns detected`,
      };
    }

    return {
      id: "HF-001",
      name: "OAuth endpoint injection",
      status: CheckStatus.FAIL,
      message: `${injectionFindings.length} OAuth endpoint(s) contain injectable patterns`,
      finding: {
        id: "HF-001",
        module: this.id,
        severity: Severity.HIGH,
        title: "OAuth endpoint injection vectors in handshake",
        description:
          `${injectionFindings.length} OAuth/authorization endpoint(s) in the server's capability ` +
          `declaration contain patterns exploitable during client-side OAuth flows. ` +
          `A malicious server can supply crafted authorization_endpoint values to: ` +
          `(1) redirect users to phishing pages, (2) steal OAuth tokens via open redirect, ` +
          `(3) execute commands if the client processes URLs unsafely. ` +
          `Ref: CVE-2025-6514.`,
        evidence: {
          endpoints: injectionFindings,
          totalEndpoints: oauthUrls.length,
        },
        remediation:
          "Clients MUST validate OAuth endpoint URLs before use: " +
          "(1) enforce HTTPS scheme only, (2) reject IP-based endpoints, " +
          "(3) validate against a domain allowlist, (4) strip shell metacharacters, " +
          "(5) reject data:/javascript: URI schemes. " +
          "Never pass server-supplied URLs to system commands without sanitization.",
        cweId: "CWE-601",
        confidence: 0.85,
      },
    };
  }

  /**
   * HF-002: Redirect URI manipulation.
   *
   * Check for redirect_uri parameters in server capabilities that could
   * be exploited for open redirect or OAuth token theft.
   */
  private checkRedirectUriManipulation(context: ModuleContext): CheckResult {
    const caps = context.capabilities.capabilities;
    const redirectUris = this.extractRedirectUris(caps);

    if (redirectUris.length === 0) {
      return {
        id: "HF-002",
        name: "Redirect URI manipulation",
        status: CheckStatus.PASS,
        message: "No redirect_uri parameters found in server capabilities",
      };
    }

    const manipulationFindings: Array<{
      uri: string;
      field: string;
      issues: string[];
    }> = [];

    for (const { uri, field } of redirectUris) {
      const issues: string[] = [];

      // Check for wildcard or overly permissive patterns
      if (/[*]/.test(uri)) {
        issues.push("wildcard pattern in redirect URI — allows arbitrary redirect targets");
      }

      // Check for path traversal in redirect URI
      if (/\.\.\/|\.\.\\/.test(uri)) {
        issues.push("path traversal in redirect URI — can escape intended redirect scope");
      }

      // Check for open redirect via parameter injection
      if (/[?&](url|redirect|next|return|goto|target|dest|continue|redir)=/i.test(uri)) {
        issues.push("redirect URI contains nested redirect parameter — open redirect chain");
      }

      // Check for fragment-based token theft (#access_token pattern)
      if (/#/.test(uri) && /token|code|auth/i.test(uri)) {
        issues.push("fragment contains token reference — potential token theft via referrer");
      }

      // Check for non-HTTPS redirect (token transmitted in clear)
      if (/^http:\/\//i.test(uri)) {
        issues.push("HTTP redirect URI — OAuth tokens transmitted without encryption");
      }

      // Check for localhost/custom-scheme redirects (mobile app hijack)
      if (/^(?!https?:\/\/)/i.test(uri) && !/^urn:/i.test(uri)) {
        issues.push("custom URI scheme — potential app hijack if scheme is claimable");
      }

      if (issues.length > 0) {
        manipulationFindings.push({ uri: uri.substring(0, 200), field, issues });
      }
    }

    if (manipulationFindings.length === 0) {
      return {
        id: "HF-002",
        name: "Redirect URI manipulation",
        status: CheckStatus.PASS,
        message: `${redirectUris.length} redirect URI(s) analyzed — no manipulation vectors detected`,
      };
    }

    return {
      id: "HF-002",
      name: "Redirect URI manipulation",
      status: CheckStatus.FAIL,
      message: `${manipulationFindings.length} redirect URI(s) are exploitable`,
      finding: {
        id: "HF-002",
        module: this.id,
        severity: Severity.HIGH,
        title: "Redirect URI manipulation vectors in handshake",
        description:
          `${manipulationFindings.length} redirect_uri value(s) in the server's handshake ` +
          `contain patterns that enable token theft or open redirect attacks. ` +
          `An attacker controlling the server can manipulate redirect_uri to intercept ` +
          `OAuth authorization codes or access tokens during the authentication flow.`,
        evidence: {
          redirectUris: manipulationFindings,
          totalUris: redirectUris.length,
        },
        remediation:
          "Clients MUST perform strict redirect_uri validation: " +
          "(1) exact-match against pre-registered URIs, (2) reject wildcard patterns, " +
          "(3) enforce HTTPS for all redirect endpoints, (4) reject URIs containing " +
          "nested redirect parameters, (5) validate URI scheme against an allowlist.",
        cweId: "CWE-601",
        confidence: 0.80,
      },
    };
  }

  /**
   * HF-003: Protocol version spoofing.
   *
   * Analyze the protocol version negotiated during handshake for
   * non-standard, deprecated, or suspicious values that could indicate
   * a spoofed or downgraded connection.
   */
  private checkProtocolVersionSpoofing(context: ModuleContext): CheckResult {
    const version = context.capabilities.protocolVersion;
    const protocol = context.capabilities.protocol ?? "mcp";
    const knownVersions = protocol === "a2a"
      ? ["A2A 0.2", "A2A 0.2.0", "A2A 0.2.1", "A2A 0.2.5", "A2A 0.3", "A2A 0.3.0", "A2A 1.0", "A2A 1.0.0"]
      : ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-05"];
    const versionPattern = protocol === "a2a" ? /^A2A \d+(?:\.\d+){1,2}$/ : /^\d{4}-\d{2}-\d{2}$/;
    const expectedFormat = protocol === "a2a" ? "A2A semantic version format" : "YYYY-MM-DD date format";
    const issues: string[] = [];

    // Check for missing or empty version
    if (!version || version.trim() === "") {
      issues.push("empty or missing protocol version — server identity unverifiable");
    } else {
      // Check for non-standard version format.
      if (!versionPattern.test(version)) {
        issues.push(`non-standard version format "${version}" — expected ${expectedFormat}`);
      }

      // Check for unknown versions
      if (protocol !== "a2a" && !knownVersions.includes(version) && versionPattern.test(version)) {
        // Valid format but unknown — could be future version or custom fork
        const versionDate = new Date(version);
        const now = new Date();
        if (versionDate > now) {
          issues.push(`future-dated protocol version "${version}" — possible spoofing`);
        }
      } else if (protocol === "a2a" && !knownVersions.includes(version) && versionPattern.test(version)) {
        issues.push(`unrecognized A2A protocol version "${version}" — verify client compatibility`);
      }

      // Check for injection payloads in version string
      if (/[<>"';&|`${}()[\]]/.test(version)) {
        issues.push("version string contains injection metacharacters");
      }

      // Check for suspiciously long version strings (overflow attempt)
      if (version.length > 20) {
        issues.push("version string exceeds expected length — potential overflow payload");
      }
    }

    if (issues.length === 0) {
      return {
        id: "HF-003",
        name: "Protocol version spoofing",
        status: CheckStatus.PASS,
        message: `Protocol version "${version}" is valid and recognized`,
      };
    }

    // Determine severity: injection metacharacters are more dangerous than unknown versions
    const hasInjection = issues.some((i) => i.includes("metacharacter") || i.includes("overflow"));
    const severity = hasInjection ? Severity.HIGH : Severity.MEDIUM;

    return {
      id: "HF-003",
      name: "Protocol version spoofing",
      status: hasInjection ? CheckStatus.FAIL : CheckStatus.WARN,
      message: `Protocol version "${version}" has ${issues.length} issue(s)`,
      finding: {
        id: "HF-003",
        module: this.id,
        severity,
        title: "Suspicious protocol version in handshake",
        description:
          `The server's negotiated protocol version "${version}" ` +
          `exhibits ${issues.length} anomaly/anomalies: ${issues.join("; ")}. ` +
          `A malicious server may spoof protocol versions to: ` +
          `(1) force clients into deprecated code paths with known vulnerabilities, ` +
          `(2) inject payloads via version strings rendered in logs or UIs, ` +
          `(3) bypass version-based security checks.`,
        evidence: {
          version,
          knownVersions,
          issues,
        },
        remediation:
          "Clients MUST validate protocol version format and value: " +
          `(1) reject versions not matching ${expectedFormat}, ` +
          "(2) maintain an allowlist of known protocol versions, " +
          "(3) sanitize version strings before logging or display, " +
          (protocol === "a2a"
            ? "(4) reject versions outside the A2A client compatibility matrix."
            : "(4) reject connections with future-dated versions."),
        cweId: "CWE-20",
        confidence: hasInjection ? 0.90 : 0.60,
      },
    };
  }

  /**
   * HF-004: Initialization parameter injection.
   *
   * Examine server info fields (name, version) for injection payloads
   * that could exploit vulnerable clients rendering this metadata in
   * logs, UIs, or downstream systems.
   */
  private checkInitParamInjection(context: ModuleContext): CheckResult {
    const { serverInfo } = context.capabilities;
    const fieldsToCheck: Array<{ field: string; value: string }> = [
      { field: "serverInfo.name", value: serverInfo.name ?? "" },
      { field: "serverInfo.version", value: serverInfo.version ?? "" },
    ];

    const injectionFindings: Array<{
      field: string;
      value: string;
      issues: string[];
    }> = [];

    for (const { field, value } of fieldsToCheck) {
      if (!value) continue;
      const issues: string[] = [];

      // Check for HTML/XSS injection (rendered in client UIs)
      if (/<script|<img|<svg|<iframe|onerror|onload|javascript:/i.test(value)) {
        issues.push("HTML/XSS payload — exploits clients rendering server name in UI");
      }

      // Check for ANSI escape sequences (terminal injection)
      // eslint-disable-next-line no-control-regex
      if (/\x1b\[|\x1b\]|\x07|\x0e|\x0f/.test(value)) {
        issues.push("ANSI escape sequences — terminal injection for log viewers");
      }

      // Check for template injection patterns (Jinja, Handlebars, etc.)
      if (/\{\{.*\}\}|\$\{.*\}|<%.*%>/.test(value)) {
        issues.push("template injection pattern — exploits server-side template rendering");
      }

      // Check for SQL injection patterns
      if (/('|"|;)\s*(OR|AND|UNION|SELECT|DROP|INSERT|DELETE|UPDATE)\b/i.test(value)) {
        issues.push("SQL injection pattern — exploits clients storing metadata in databases");
      }

      // Check for LDAP injection
      if (/[)(|*\\]/.test(value) && /[=&]/.test(value)) {
        issues.push("LDAP injection characters — exploits directory-based client lookups");
      }

      // Check for path traversal in server name
      if (/\.\.[\\/]/.test(value)) {
        issues.push("path traversal in server identity — exploits file-based logging");
      }

      // Check for null bytes
      if (/\x00|%00/.test(value)) {
        issues.push("null byte — truncation attack on string-based validation");
      }

      // Check for excessively long values (buffer overflow / DoS)
      if (value.length > 256) {
        issues.push("value exceeds 256 chars — potential buffer overflow or log flooding");
      }

      if (issues.length > 0) {
        injectionFindings.push({ field, value: value.substring(0, 200), issues });
      }
    }

    if (injectionFindings.length === 0) {
      return {
        id: "HF-004",
        name: "Initialization parameter injection",
        status: CheckStatus.PASS,
        message: `Server identity fields are clean (name="${serverInfo.name}", version="${serverInfo.version}")`,
      };
    }

    return {
      id: "HF-004",
      name: "Initialization parameter injection",
      status: CheckStatus.FAIL,
      message: `${injectionFindings.length} server identity field(s) contain injection payloads`,
      finding: {
        id: "HF-004",
        module: this.id,
        severity: Severity.HIGH,
        title: "Injection payloads in server initialization parameters",
        description:
          `Server identity fields contain content that may exploit vulnerable clients. ` +
          `MCP clients commonly render serverInfo.name in UIs, log it to files, or store ` +
          `it in databases. A malicious server can embed XSS, template injection, SQL injection, ` +
          `or terminal escape sequences in these fields to attack the client-side. ` +
          `Findings: ${injectionFindings.map((f) => `${f.field}: ${f.issues.join(", ")}`).join("; ")}.`,
        evidence: {
          fields: injectionFindings,
          serverName: (serverInfo.name ?? "").substring(0, 200),
          serverVersion: (serverInfo.version ?? "").substring(0, 200),
        },
        remediation:
          "Clients MUST sanitize all server-supplied identity fields: " +
          "(1) HTML-encode before rendering in UIs, (2) strip ANSI escape codes before logging, " +
          "(3) use parameterized queries when storing metadata, " +
          "(4) enforce maximum length limits on identity fields, " +
          "(5) reject values containing null bytes or control characters.",
        cweId: "CWE-79",
        confidence: 0.90,
      },
    };
  }

  /**
   * HF-005: Capability enumeration abuse.
   *
   * Check if declared capabilities expose excessive server internals,
   * debug information, or configuration details that aid reconnaissance.
   */
  private checkCapabilityEnumerationAbuse(context: ModuleContext): CheckResult {
    const caps = context.capabilities.capabilities;
    const issues: string[] = [];
    const evidence: Record<string, unknown> = {};

    // Serialize capabilities for deep inspection
    const capsStr = JSON.stringify(caps).toLowerCase();

    // Check for debug/development flags left enabled
    const debugPatterns = [
      "debug", "verbose", "trace", "dev_mode", "development",
      "test_mode", "staging", "profiling", "inspect",
    ];
    const foundDebug = debugPatterns.filter((p) => capsStr.includes(p));
    if (foundDebug.length > 0) {
      issues.push(`debug/development flags detected: ${foundDebug.join(", ")}`);
      evidence.debugFlags = foundDebug;
    }

    // Check for internal infrastructure exposure
    const infraPatterns = [
      /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\b/, // IP:port
      /(?:redis|postgres|mysql|mongo|rabbit|kafka|elastic):\/\//i, // service URIs
      /\b(?:aws_|gcp_|azure_)[\w]+/i, // cloud identifiers
      /arn:aws:[\w:/-]+/i, // AWS ARNs
    ];
    const foundInfra: string[] = [];
    for (const pattern of infraPatterns) {
      const match = capsStr.match(pattern);
      if (match) foundInfra.push(match[0]);
    }
    if (foundInfra.length > 0) {
      issues.push(`internal infrastructure references: ${foundInfra.join(", ")}`);
      evidence.infrastructureLeaks = foundInfra;
    }

    // Check for sensitive configuration keys
    const sensitiveKeys = this.findSensitiveKeys(caps);
    if (sensitiveKeys.length > 0) {
      issues.push(`sensitive configuration keys exposed: ${sensitiveKeys.join(", ")}`);
      evidence.sensitiveKeys = sensitiveKeys;
    }

    // Check for excessive capability depth (information overload)
    const depth = this.measureObjectDepth(caps);
    if (depth > 5) {
      issues.push(`capability tree depth ${depth} — unusually detailed internal structure`);
      evidence.capabilityDepth = depth;
    }

    // Check for version/build info leaks beyond standard serverInfo
    const versionLeaks = capsStr.match(/(?:build|commit|hash|sha|rev|branch|tag)["\s:=]+["']?[a-f0-9]{7,40}/gi);
    if (versionLeaks && versionLeaks.length > 0) {
      issues.push("build/commit hashes in capabilities — aids targeted exploit selection");
      evidence.versionLeaks = versionLeaks.slice(0, 5);
    }

    if (issues.length === 0) {
      return {
        id: "HF-005",
        name: "Capability enumeration abuse",
        status: CheckStatus.PASS,
        message: "Server capabilities do not expose excessive internals",
      };
    }

    const severity = foundInfra.length > 0 || sensitiveKeys.length > 0
      ? Severity.MEDIUM
      : Severity.LOW;

    return {
      id: "HF-005",
      name: "Capability enumeration abuse",
      status: CheckStatus.WARN,
      message: `${issues.length} information exposure issue(s) in server capabilities`,
      finding: {
        id: "HF-005",
        module: this.id,
        severity,
        title: "Server capabilities expose excessive internal details",
        description:
          `The server's capability declaration contains ${issues.length} category/categories ` +
          `of information leakage that aid attacker reconnaissance: ${issues.join("; ")}. ` +
          `Excessive capability disclosure allows attackers to map internal infrastructure, ` +
          `identify software versions for known CVE exploitation, and discover debug ` +
          `endpoints that bypass production security controls.`,
        evidence: {
          ...evidence,
          issueCount: issues.length,
          issues,
        },
        remediation:
          "Strip non-essential information from capability declarations: " +
          "(1) remove debug/development flags in production, " +
          "(2) avoid exposing internal IP addresses, service URIs, or cloud resource identifiers, " +
          "(3) do not include build hashes or version details beyond the standard serverInfo fields, " +
          "(4) minimize capability tree depth to only what clients need for operation.",
        cweId: "CWE-200",
        confidence: 0.70,
      },
    };
  }

  // ── Utility methods ────────────────────────────────────────────────────

  /**
   * Recursively extract OAuth-related endpoint URLs from capabilities.
   */
  private extractOAuthEndpoints(
    obj: unknown,
    path = "",
  ): Array<{ url: string; field: string }> {
    const results: Array<{ url: string; field: string }> = [];
    if (!obj || typeof obj !== "object") return results;

    const oauthKeys = /^(authorization_endpoint|token_endpoint|auth_url|oauth_url|issuer|jwks_uri|userinfo_endpoint|revocation_endpoint|introspection_endpoint)$/i;

    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      const currentPath = path ? `${path}.${key}` : key;

      if (oauthKeys.test(key) && typeof value === "string") {
        results.push({ url: value, field: currentPath });
      } else if (typeof value === "object" && value !== null) {
        results.push(...this.extractOAuthEndpoints(value, currentPath));
      }
    }

    return results;
  }

  /**
   * Recursively extract redirect_uri values from capabilities.
   */
  private extractRedirectUris(
    obj: unknown,
    path = "",
  ): Array<{ uri: string; field: string }> {
    const results: Array<{ uri: string; field: string }> = [];
    if (!obj || typeof obj !== "object") return results;

    const redirectKeys = /^(redirect_uri|redirect_url|callback_url|callback_uri|return_url|return_uri|redirect_uris|post_logout_redirect_uri)$/i;

    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      const currentPath = path ? `${path}.${key}` : key;

      if (redirectKeys.test(key)) {
        if (typeof value === "string") {
          results.push({ uri: value, field: currentPath });
        } else if (Array.isArray(value)) {
          for (const item of value) {
            if (typeof item === "string") {
              results.push({ uri: item, field: `${currentPath}[]` });
            }
          }
        }
      } else if (typeof value === "object" && value !== null) {
        results.push(...this.extractRedirectUris(value, currentPath));
      }
    }

    return results;
  }

  /**
   * Find keys in the capability object that suggest sensitive configuration.
   */
  private findSensitiveKeys(obj: unknown, path = ""): string[] {
    const results: string[] = [];
    if (!obj || typeof obj !== "object") return results;

    const sensitivePattern = /^(api_key|secret|password|token|credential|private_key|access_key|connection_string|dsn|database_url)$/i;

    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      const currentPath = path ? `${path}.${key}` : key;

      if (sensitivePattern.test(key)) {
        results.push(currentPath);
      }
      if (typeof value === "object" && value !== null) {
        results.push(...this.findSensitiveKeys(value, currentPath));
      }
    }

    return results;
  }

  /**
   * Measure the maximum nesting depth of an object.
   */
  private measureObjectDepth(obj: unknown, current = 0): number {
    if (!obj || typeof obj !== "object") return current;
    let maxDepth = current;
    for (const value of Object.values(obj as Record<string, unknown>)) {
      if (typeof value === "object" && value !== null) {
        maxDepth = Math.max(maxDepth, this.measureObjectDepth(value, current + 1));
      }
    }
    return maxDepth;
  }
}
