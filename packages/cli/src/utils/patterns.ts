/**
 * Shared regex patterns used across multiple audit modules.
 */

// URL/URI related parameters often vulnerable to SSRF
// Also includes component-based URL params (host, scheme, port) used to construct URLs
export const URL_PARAM_PATTERNS = /^(url|uri|endpoint|href|link|src|webhook|callback|redirect|target|destination|fetch_url|request_url|webhook_url|callback_url|redirect_url|target_url|notification_url|push_url|agent_url|peer_url|host|hostname|scheme|domain|server)$/i;

// Parameters that often take raw input, susceptible to injection
export const INJECTION_PARAM_PATTERNS = /^(query|sql|statement|expression|command|cmd|exec|shell|script|code)$/i;

/**
 * Dangerous parameter name patterns in tool input schemas.
 * Shared between tool-permissions (passive analysis) and active-fuzzer (active probing).
 */
export const DANGEROUS_PARAM_PATTERNS = [
  { pattern: /^(command|cmd|exec|shell|script|code)$/i, risk: "command-injection" },
  { pattern: /^(path|file|filepath|filename|dir|directory)$/i, risk: "path-traversal" },
  { pattern: /^(url|uri|endpoint|href|link|src|webhook|callback|webhook_url|callback_url|redirect_url|target_url|notification_url|push_url|agent_url|peer_url)$/i, risk: "ssrf" },
  { pattern: /^(query|sql|statement|expression)$/i, risk: "injection" },
  { pattern: /^(html|template|body|content|markup)$/i, risk: "xss" },
];
