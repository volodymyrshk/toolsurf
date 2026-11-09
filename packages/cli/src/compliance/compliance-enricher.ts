import type { Finding, ComplianceControl } from "../types/index.js";
import { CWE_COMPLIANCE_MAP, FINDING_COMPLIANCE_MAP } from "../data/compliance-mappings.js";

/**
 * Target data classification declared by the operator. Used to gate which
 * compliance frameworks are mapped onto findings — a sandboxed test target
 * holding no PHI/PAN/PII should not have HIPAA/PCI-DSS/GDPR controls
 * attached. Reviewers discount the entire compliance section when these
 * appear without justification.
 */
export type DataClassification = "none" | "pii" | "phi" | "pci" | "secrets" | "all";

/**
 * Frameworks that always apply regardless of declared data class — these
 * are general security or AI-governance frameworks, not data-protection
 * statutes.
 */
const GENERAL_FRAMEWORKS = new Set<string>([
  "NIST SP 800-171",
  "SOC 2 TSC",
  "OWASP ASVS",
  "ISO 27001:2022",
  "FedRAMP",
  "OWASP LLM Top 10 v2.0",
  "OWASP Agentic ASI10",
  "OWASP Agentic Skills AST10",
  "MITRE ATLAS v5.4.0",
  "NIST AI RMF",
  "EU AI Act",
]);

/**
 * Returns true when `framework` should appear on findings given the declared
 * data classification. The data-protection statutes (HIPAA, PCI-DSS, GDPR)
 * are gated; general security and AI frameworks always pass.
 */
function isFrameworkRelevant(framework: string, dataClass: DataClassification): boolean {
  if (dataClass === "all") return true;
  if (GENERAL_FRAMEWORKS.has(framework)) return true;
  switch (framework) {
    case "HIPAA":
      return dataClass === "phi";
    case "PCI-DSS v4.0":
      return dataClass === "pci";
    case "GDPR":
      return dataClass === "pii";
    default:
      // Unknown frameworks default to allowed; better to surface than silently drop.
      return true;
  }
}

/**
 * Summary of compliance framework coverage from a scan.
 */
export interface ComplianceSummary {
  /** NIST SP 800-171 controls hit */
  nist: Record<string, number>;
  /** SOC 2 TSC controls hit */
  soc2: Record<string, number>;
  /** OWASP ASVS controls hit */
  asvs: Record<string, number>;
  /** HIPAA Security Rule controls hit */
  hipaa: Record<string, number>;
  /** PCI-DSS v4.0 controls hit */
  pciDss: Record<string, number>;
  /** ISO 27001:2022 controls hit */
  iso27001: Record<string, number>;
  /** FedRAMP (NIST 800-53) controls hit */
  fedramp: Record<string, number>;
  /** GDPR articles hit */
  gdpr: Record<string, number>;
  /** OWASP LLM Top 10 v2.0 categories hit */
  owaspLlm: Record<string, number>;
  /** OWASP Agentic ASI10 categories hit */
  owaspAsi: Record<string, number>;
  /** OWASP Agentic Skills AST10 categories hit */
  owaspAst: Record<string, number>;
  /** MITRE ATLAS v5.4.0 techniques hit */
  mitreAtlas: Record<string, number>;
  /** NIST AI RMF (AI 800-1) functions hit */
  nistAiRmf: Record<string, number>;
  /** EU AI Act articles hit */
  euAiAct: Record<string, number>;
  /** Total findings with compliance mappings */
  mappedFindings: number;
  /** Total findings without compliance mappings */
  unmappedFindings: number;
}

/**
 * Enrich a list of findings with compliance framework references.
 * Attaches `complianceControls` directly to each Finding.
 *
 * Uses two mapping routes:
 *   Route 1: CWE-based mapping for traditional frameworks (NIST, SOC2, ASVS, etc.)
 *   Route 2: Finding ID prefix mapping for AI/Agentic frameworks (OWASP LLM, ASI10, AST10, MITRE ATLAS)
 */
export function enrichFindings(
  findings: Finding[],
  dataClass: DataClassification = "none",
): Finding[] {
  return findings.map((finding) => {
    const controls: ComplianceControl[] = [];

    // Route 1: CWE-based mapping (traditional frameworks)
    if (finding.cweId) {
      const cweControls = CWE_COMPLIANCE_MAP[finding.cweId];
      if (cweControls) {
        controls.push(...cweControls);
      }
    }

    // Route 2: Finding ID prefix mapping (AI/Agentic frameworks)
    const prefix = finding.id.replace(/-\d.*$/, "").replace(/-[a-z].*$/i, "");
    const prefixControls = FINDING_COMPLIANCE_MAP[prefix];
    if (prefixControls) {
      controls.push(...prefixControls.map((pc) => ({
        framework: pc.framework,
        controlId: pc.categoryId,
        controlTitle: pc.categoryTitle,
        requirement: pc.relevance,
      })));
    }

    // Filter by declared data classification — drops HIPAA/PCI/GDPR when
    // the target hasn't claimed PHI/PAN/PII data.
    const filtered = controls.filter((c) => isFrameworkRelevant(c.framework, dataClass));
    if (filtered.length === 0) return finding;

    return {
      ...finding,
      complianceControls: filtered,
    };
  });
}

/**
 * Generate a compliance summary from enriched findings.
 */
export function generateComplianceSummary(findings: Finding[]): ComplianceSummary {
  const nist: Record<string, number> = {};
  const soc2: Record<string, number> = {};
  const asvs: Record<string, number> = {};
  const hipaa: Record<string, number> = {};
  const pciDss: Record<string, number> = {};
  const iso27001: Record<string, number> = {};
  const fedramp: Record<string, number> = {};
  const gdpr: Record<string, number> = {};
  const owaspLlm: Record<string, number> = {};
  const owaspAsi: Record<string, number> = {};
  const owaspAst: Record<string, number> = {};
  const mitreAtlas: Record<string, number> = {};
  const nistAiRmf: Record<string, number> = {};
  const euAiAct: Record<string, number> = {};
  let mappedFindings = 0;
  let unmappedFindings = 0;

  for (const finding of findings) {
    if (finding.complianceControls && finding.complianceControls.length > 0) {
      mappedFindings++;
      for (const control of finding.complianceControls) {
        switch (control.framework) {
          case "NIST SP 800-171":
            nist[control.controlId] = (nist[control.controlId] ?? 0) + 1;
            break;
          case "SOC 2 TSC":
            soc2[control.controlId] = (soc2[control.controlId] ?? 0) + 1;
            break;
          case "OWASP ASVS":
            asvs[control.controlId] = (asvs[control.controlId] ?? 0) + 1;
            break;
          case "HIPAA":
            hipaa[control.controlId] = (hipaa[control.controlId] ?? 0) + 1;
            break;
          case "PCI-DSS v4.0":
            pciDss[control.controlId] = (pciDss[control.controlId] ?? 0) + 1;
            break;
          case "ISO 27001:2022":
            iso27001[control.controlId] = (iso27001[control.controlId] ?? 0) + 1;
            break;
          case "FedRAMP":
            fedramp[control.controlId] = (fedramp[control.controlId] ?? 0) + 1;
            break;
          case "GDPR":
            gdpr[control.controlId] = (gdpr[control.controlId] ?? 0) + 1;
            break;
          case "OWASP LLM Top 10 v2.0":
            owaspLlm[control.controlId] = (owaspLlm[control.controlId] ?? 0) + 1;
            break;
          case "OWASP Agentic ASI10":
            owaspAsi[control.controlId] = (owaspAsi[control.controlId] ?? 0) + 1;
            break;
          case "OWASP Agentic Skills AST10":
            owaspAst[control.controlId] = (owaspAst[control.controlId] ?? 0) + 1;
            break;
          case "MITRE ATLAS v5.4.0":
            mitreAtlas[control.controlId] = (mitreAtlas[control.controlId] ?? 0) + 1;
            break;
          case "NIST AI RMF":
            nistAiRmf[control.controlId] = (nistAiRmf[control.controlId] ?? 0) + 1;
            break;
          case "EU AI Act":
            euAiAct[control.controlId] = (euAiAct[control.controlId] ?? 0) + 1;
            break;
        }
      }
    } else {
      unmappedFindings++;
    }
  }

  return { nist, soc2, asvs, hipaa, pciDss, iso27001, fedramp, gdpr, owaspLlm, owaspAsi, owaspAst, mitreAtlas, nistAiRmf, euAiAct, mappedFindings, unmappedFindings };
}
