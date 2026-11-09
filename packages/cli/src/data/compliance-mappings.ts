import type { ComplianceControl } from "../types/index.js";

/**
 * Compliance framework mappings from CWE IDs.
 *
 * Maps security findings to eight regulatory/industry frameworks:
 *   - NIST SP 800-171 (CMMC Level 2 alignment)
 *   - SOC 2 Trust Services Criteria (TSC)
 *   - OWASP ASVS v4.0 (Application Security Verification Standard)
 *   - HIPAA Security Rule (45 CFR Part 164)
 *   - PCI-DSS v4.0 (Payment Card Industry Data Security Standard)
 *   - ISO 27001:2022 (Information Security Management)
 *   - FedRAMP (based on NIST SP 800-53)
 *   - GDPR (General Data Protection Regulation)
 */

export const CWE_COMPLIANCE_MAP: Record<string, ComplianceControl[]> = {
  "CWE-78": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.13.1",
      controlTitle: "Boundary Protection",
      requirement: "Monitor, control, and protect communications at system boundaries",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.1",
      controlTitle: "Logical and Physical Access Controls",
      requirement: "Implement logical access security to protect against unauthorized access",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V5.3.8",
      controlTitle: "Output Encoding",
      requirement: "Verify that OS command injection defenses are in place",
    },
    {
      framework: "HIPAA",
      controlId: "164.312(a)(1)",
      controlTitle: "Access Control",
      requirement: "Implement technical policies and procedures for systems that maintain ePHI to allow access only to authorized persons",
    },
    {
      framework: "PCI-DSS v4.0",
      controlId: "6.2.4",
      controlTitle: "Software Engineering Techniques",
      requirement: "Prevent common software attacks including injection flaws",
    },
    {
      framework: "ISO 27001:2022",
      controlId: "A.8.28",
      controlTitle: "Secure Coding",
      requirement: "Secure coding principles shall be applied to software development",
    },
    {
      framework: "FedRAMP",
      controlId: "SI-10",
      controlTitle: "Information Input Validation",
      requirement: "Check the validity of information inputs to the system",
    },
    {
      framework: "GDPR",
      controlId: "Art. 32",
      controlTitle: "Security of Processing",
      requirement: "Implement appropriate technical measures to ensure a level of security appropriate to the risk",
    },
  ],
  "CWE-89": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.13.1",
      controlTitle: "Boundary Protection",
      requirement: "Monitor, control, and protect communications at system boundaries",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.1",
      controlTitle: "Logical and Physical Access Controls",
      requirement: "Implement logical access security to protect against unauthorized access",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V5.3.4",
      controlTitle: "Output Encoding",
      requirement: "Verify use of parameterized queries to prevent SQL injection",
    },
    {
      framework: "HIPAA",
      controlId: "164.312(a)(1)",
      controlTitle: "Access Control",
      requirement: "Implement technical policies and procedures for systems that maintain ePHI to allow access only to authorized persons",
    },
    {
      framework: "PCI-DSS v4.0",
      controlId: "6.2.4",
      controlTitle: "Software Engineering Techniques",
      requirement: "Prevent common software attacks including injection flaws",
    },
    {
      framework: "ISO 27001:2022",
      controlId: "A.8.28",
      controlTitle: "Secure Coding",
      requirement: "Secure coding principles shall be applied to software development",
    },
    {
      framework: "FedRAMP",
      controlId: "SI-10",
      controlTitle: "Information Input Validation",
      requirement: "Check the validity of information inputs to the system",
    },
    {
      framework: "GDPR",
      controlId: "Art. 32",
      controlTitle: "Security of Processing",
      requirement: "Implement appropriate technical measures to ensure a level of security appropriate to the risk",
    },
  ],
  "CWE-94": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.13.1",
      controlTitle: "Boundary Protection",
      requirement: "Monitor, control, and protect communications at system boundaries",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.1",
      controlTitle: "Logical and Physical Access Controls",
      requirement: "Implement logical access security to protect against unauthorized access",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V5.2.4",
      controlTitle: "Sanitization and Sandboxing",
      requirement: "Verify that code injection defenses are in place for server-side templates and dynamic code execution",
    },
    {
      framework: "HIPAA",
      controlId: "164.312(a)(1)",
      controlTitle: "Access Control",
      requirement: "Implement technical policies and procedures for systems that maintain ePHI to allow access only to authorized persons",
    },
    {
      framework: "PCI-DSS v4.0",
      controlId: "6.2.4",
      controlTitle: "Software Engineering Techniques",
      requirement: "Prevent common software attacks including injection flaws",
    },
    {
      framework: "ISO 27001:2022",
      controlId: "A.8.28",
      controlTitle: "Secure Coding",
      requirement: "Secure coding principles shall be applied to software development",
    },
    {
      framework: "FedRAMP",
      controlId: "SI-10",
      controlTitle: "Information Input Validation",
      requirement: "Check the validity of information inputs to the system",
    },
    {
      framework: "GDPR",
      controlId: "Art. 32",
      controlTitle: "Security of Processing",
      requirement: "Implement appropriate technical measures to ensure a level of security appropriate to the risk",
    },
  ],
  "CWE-74": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.13.1",
      controlTitle: "Boundary Protection",
      requirement: "Monitor, control, and protect communications at system boundaries",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.1",
      controlTitle: "Logical and Physical Access Controls",
      requirement: "Implement logical access security to protect against unauthorized access",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V5.2.1",
      controlTitle: "Sanitization and Sandboxing",
      requirement: "Verify that all untrusted input is sanitized using a safe allow-list approach",
    },
    {
      framework: "HIPAA",
      controlId: "164.312(a)(1)",
      controlTitle: "Access Control",
      requirement: "Implement technical policies and procedures for systems that maintain ePHI to allow access only to authorized persons",
    },
    {
      framework: "PCI-DSS v4.0",
      controlId: "6.2.4",
      controlTitle: "Software Engineering Techniques",
      requirement: "Prevent common software attacks including injection flaws",
    },
    {
      framework: "ISO 27001:2022",
      controlId: "A.8.28",
      controlTitle: "Secure Coding",
      requirement: "Secure coding principles shall be applied to software development",
    },
    {
      framework: "FedRAMP",
      controlId: "SI-10",
      controlTitle: "Information Input Validation",
      requirement: "Check the validity of information inputs to the system",
    },
    {
      framework: "GDPR",
      controlId: "Art. 32",
      controlTitle: "Security of Processing",
      requirement: "Implement appropriate technical measures to ensure a level of security appropriate to the risk",
    },
  ],
  "CWE-918": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.13.6",
      controlTitle: "Network Communication by Exception",
      requirement: "Deny network communications traffic by default and allow by exception",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.6",
      controlTitle: "System Boundary Protections",
      requirement: "Restrict access to system boundaries and implement controls against threats",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V12.6.1",
      controlTitle: "SSRF Protection",
      requirement: "Verify that the web or application server is configured with an allowlist of resources to which the server can send requests or load data",
    },
    {
      framework: "HIPAA",
      controlId: "164.312(e)(1)",
      controlTitle: "Transmission Security",
      requirement: "Implement technical security measures to guard against unauthorized access to ePHI transmitted over electronic networks",
    },
    {
      framework: "PCI-DSS v4.0",
      controlId: "6.2.4",
      controlTitle: "Software Engineering Techniques",
      requirement: "Prevent common software attacks including SSRF vulnerabilities",
    },
    {
      framework: "ISO 27001:2022",
      controlId: "A.8.20",
      controlTitle: "Network Security",
      requirement: "Networks and network devices shall be secured, managed and controlled to protect information in systems and applications",
    },
    {
      framework: "FedRAMP",
      controlId: "SC-7",
      controlTitle: "Boundary Protection",
      requirement: "Monitor and control communications at external boundaries and key internal boundaries",
    },
    {
      framework: "GDPR",
      controlId: "Art. 32",
      controlTitle: "Security of Processing",
      requirement: "Implement appropriate technical measures to ensure a level of security appropriate to the risk",
    },
  ],
  "CWE-22": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.1.2",
      controlTitle: "Transaction & Function Control",
      requirement: "Limit system access to the types of transactions and functions that authorized users are permitted to execute",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.1",
      controlTitle: "Logical and Physical Access Controls",
      requirement: "Implement logical access security to protect against unauthorized access",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V12.3.1",
      controlTitle: "File Execution",
      requirement: "Verify that user-submitted filenames are validated to prevent path traversal",
    },
    {
      framework: "HIPAA",
      controlId: "164.312(a)(1)",
      controlTitle: "Access Control",
      requirement: "Implement technical policies and procedures for systems that maintain ePHI to allow access only to authorized persons",
    },
    {
      framework: "PCI-DSS v4.0",
      controlId: "6.2.4",
      controlTitle: "Software Engineering Techniques",
      requirement: "Prevent common software attacks including path traversal",
    },
    {
      framework: "ISO 27001:2022",
      controlId: "A.8.3",
      controlTitle: "Information Access Restriction",
      requirement: "Access to information and other associated assets shall be restricted in accordance with the established access control policy",
    },
    {
      framework: "FedRAMP",
      controlId: "AC-6",
      controlTitle: "Least Privilege",
      requirement: "Employ the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks",
    },
    {
      framework: "GDPR",
      controlId: "Art. 25",
      controlTitle: "Data Protection by Design",
      requirement: "Implement appropriate technical measures designed to implement data-protection principles effectively",
    },
  ],
  "CWE-79": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.13.1",
      controlTitle: "Boundary Protection",
      requirement: "Monitor, control, and protect communications at system boundaries",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.1",
      controlTitle: "Logical and Physical Access Controls",
      requirement: "Implement logical access security to protect against unauthorized access",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V5.3.3",
      controlTitle: "Output Encoding",
      requirement: "Verify that context-aware output escaping is used to protect against reflected, stored, and DOM XSS",
    },
    {
      framework: "HIPAA",
      controlId: "164.312(c)(1)",
      controlTitle: "Integrity Controls",
      requirement: "Implement policies and procedures to protect ePHI from improper alteration or destruction",
    },
    {
      framework: "PCI-DSS v4.0",
      controlId: "6.2.4",
      controlTitle: "Software Engineering Techniques",
      requirement: "Prevent common software attacks including cross-site scripting",
    },
    {
      framework: "ISO 27001:2022",
      controlId: "A.8.28",
      controlTitle: "Secure Coding",
      requirement: "Secure coding principles shall be applied to software development",
    },
    {
      framework: "FedRAMP",
      controlId: "SI-10",
      controlTitle: "Information Input Validation",
      requirement: "Check the validity of information inputs to the system",
    },
    {
      framework: "GDPR",
      controlId: "Art. 5(1)(f)",
      controlTitle: "Integrity and Confidentiality",
      requirement: "Personal data shall be processed in a manner that ensures appropriate security including protection against unauthorized processing",
    },
  ],
  "CWE-200": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.1.3",
      controlTitle: "CUI Flow Control",
      requirement: "Control the flow of CUI in accordance with approved authorizations",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.5",
      controlTitle: "Disposal of Information",
      requirement: "Restrict unauthorized access to confidential information during disposal",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V7.4.1",
      controlTitle: "Error Handling",
      requirement: "Verify that a generic message is shown when an unexpected or security-sensitive error occurs",
    },
    {
      framework: "HIPAA",
      controlId: "164.312(a)(1)",
      controlTitle: "Access Control",
      requirement: "Implement technical policies and procedures for systems that maintain ePHI to allow access only to authorized persons",
    },
    {
      framework: "PCI-DSS v4.0",
      controlId: "3.4.1",
      controlTitle: "Protect Stored Account Data",
      requirement: "PAN is secured with strong cryptography wherever it is stored",
    },
    {
      framework: "ISO 27001:2022",
      controlId: "A.8.11",
      controlTitle: "Data Masking",
      requirement: "Data masking shall be used in accordance with the organization's access control policy and business requirements",
    },
    {
      framework: "FedRAMP",
      controlId: "SC-28",
      controlTitle: "Protection of Information at Rest",
      requirement: "Protect the confidentiality and integrity of information at rest",
    },
    {
      framework: "GDPR",
      controlId: "Art. 5(1)(f)",
      controlTitle: "Integrity and Confidentiality",
      requirement: "Personal data shall be processed in a manner that ensures appropriate security including protection against unauthorized disclosure",
    },
  ],
  "CWE-201": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.1.3",
      controlTitle: "CUI Flow Control",
      requirement: "Control the flow of CUI in accordance with approved authorizations",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.5",
      controlTitle: "Disposal of Information",
      requirement: "Restrict unauthorized access to confidential information during disposal",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V7.4.1",
      controlTitle: "Error Handling",
      requirement: "Verify that a generic message is shown when an unexpected or security-sensitive error occurs",
    },
    {
      framework: "HIPAA",
      controlId: "164.312(a)(1)",
      controlTitle: "Access Control",
      requirement: "Implement technical policies and procedures for systems that maintain ePHI to allow access only to authorized persons",
    },
    {
      framework: "PCI-DSS v4.0",
      controlId: "3.4.1",
      controlTitle: "Protect Stored Account Data",
      requirement: "PAN is secured with strong cryptography wherever it is stored",
    },
    {
      framework: "ISO 27001:2022",
      controlId: "A.8.11",
      controlTitle: "Data Masking",
      requirement: "Data masking shall be used in accordance with the organization's access control policy and business requirements",
    },
    {
      framework: "FedRAMP",
      controlId: "SC-28",
      controlTitle: "Protection of Information at Rest",
      requirement: "Protect the confidentiality and integrity of information at rest",
    },
    {
      framework: "GDPR",
      controlId: "Art. 5(1)(f)",
      controlTitle: "Integrity and Confidentiality",
      requirement: "Personal data shall be processed in a manner that ensures appropriate security including protection against unauthorized disclosure",
    },
  ],
  "CWE-250": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.1.5",
      controlTitle: "Least Privilege",
      requirement: "Employ the principle of least privilege, including for specific security functions and privileged accounts",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.3",
      controlTitle: "Role-Based Access",
      requirement: "Authorize, modify, or remove access based on roles and responsibilities",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V1.4.3",
      controlTitle: "Access Control Architecture",
      requirement: "Verify that the application uses a single and well-vetted access control mechanism",
    },
    {
      framework: "HIPAA",
      controlId: "164.312(a)(1)",
      controlTitle: "Access Control",
      requirement: "Implement technical policies and procedures for systems that maintain ePHI to allow access only to authorized persons",
    },
    {
      framework: "PCI-DSS v4.0",
      controlId: "7.2.1",
      controlTitle: "Access Control Model",
      requirement: "An access control model is defined and includes granting access based on job classification and function",
    },
    {
      framework: "ISO 27001:2022",
      controlId: "A.8.3",
      controlTitle: "Information Access Restriction",
      requirement: "Access to information and other associated assets shall be restricted in accordance with the established access control policy",
    },
    {
      framework: "FedRAMP",
      controlId: "AC-6",
      controlTitle: "Least Privilege",
      requirement: "Employ the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks",
    },
    {
      framework: "GDPR",
      controlId: "Art. 25",
      controlTitle: "Data Protection by Design",
      requirement: "Implement appropriate technical measures designed to implement data-protection principles effectively",
    },
  ],
  "CWE-269": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.1.5",
      controlTitle: "Least Privilege",
      requirement: "Employ the principle of least privilege, including for specific security functions and privileged accounts",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.3",
      controlTitle: "Role-Based Access",
      requirement: "Authorize, modify, or remove access based on roles and responsibilities",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V1.4.3",
      controlTitle: "Access Control Architecture",
      requirement: "Verify that the application uses a single and well-vetted access control mechanism",
    },
    {
      framework: "HIPAA",
      controlId: "164.312(a)(1)",
      controlTitle: "Access Control",
      requirement: "Implement technical policies and procedures for systems that maintain ePHI to allow access only to authorized persons",
    },
    {
      framework: "PCI-DSS v4.0",
      controlId: "7.2.1",
      controlTitle: "Access Control Model",
      requirement: "An access control model is defined and includes granting access based on job classification and function",
    },
    {
      framework: "ISO 27001:2022",
      controlId: "A.8.3",
      controlTitle: "Information Access Restriction",
      requirement: "Access to information and other associated assets shall be restricted in accordance with the established access control policy",
    },
    {
      framework: "FedRAMP",
      controlId: "AC-6",
      controlTitle: "Least Privilege",
      requirement: "Employ the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks",
    },
    {
      framework: "GDPR",
      controlId: "Art. 25",
      controlTitle: "Data Protection by Design",
      requirement: "Implement appropriate technical measures designed to implement data-protection principles effectively",
    },
  ],
  "CWE-345": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.14.2",
      controlTitle: "Malicious Code Protection",
      requirement: "Provide protection from malicious code at designated locations within organizational systems",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC7.1",
      controlTitle: "Detection and Monitoring",
      requirement: "Detect and monitor for anomalies that indicate risks to the achievement of objectives",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V10.3.2",
      controlTitle: "Deployed Integrity Controls",
      requirement: "Verify that the application employs integrity protections such as code signing or subresource integrity",
    },
    {
      framework: "HIPAA",
      controlId: "164.312(c)(1)",
      controlTitle: "Integrity Controls",
      requirement: "Implement policies and procedures to protect ePHI from improper alteration or destruction",
    },
    {
      framework: "PCI-DSS v4.0",
      controlId: "6.2.4",
      controlTitle: "Software Engineering Techniques",
      requirement: "Prevent common software attacks including tampering with data integrity",
    },
    {
      framework: "ISO 27001:2022",
      controlId: "A.8.24",
      controlTitle: "Use of Cryptography",
      requirement: "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented",
    },
    {
      framework: "FedRAMP",
      controlId: "SI-7",
      controlTitle: "Software, Firmware, and Information Integrity",
      requirement: "Employ integrity verification tools to detect unauthorized changes to software, firmware, and information",
    },
    {
      framework: "GDPR",
      controlId: "Art. 5(1)(f)",
      controlTitle: "Integrity and Confidentiality",
      requirement: "Personal data shall be processed in a manner that ensures appropriate security including protection against unauthorized processing",
    },
  ],
  "CWE-400": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.13.1",
      controlTitle: "Boundary Protection",
      requirement: "Monitor, control, and protect communications at system boundaries",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.6",
      controlTitle: "System Boundary Protections",
      requirement: "Restrict access to system boundaries and implement controls against threats",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V11.1.4",
      controlTitle: "Business Logic Security",
      requirement: "Verify that the application has anti-automation controls to protect against excessive calls",
    },
    {
      framework: "HIPAA",
      controlId: "164.312(a)(1)",
      controlTitle: "Access Control",
      requirement: "Implement technical policies and procedures for systems that maintain ePHI to allow access only to authorized persons",
    },
    {
      framework: "PCI-DSS v4.0",
      controlId: "6.2.4",
      controlTitle: "Software Engineering Techniques",
      requirement: "Prevent common software attacks including resource exhaustion",
    },
    {
      framework: "ISO 27001:2022",
      controlId: "A.8.20",
      controlTitle: "Network Security",
      requirement: "Networks and network devices shall be secured, managed and controlled to protect information in systems and applications",
    },
    {
      framework: "FedRAMP",
      controlId: "SC-5",
      controlTitle: "Denial-of-Service Protection",
      requirement: "Protect against or limit the effects of denial-of-service attacks",
    },
    {
      framework: "GDPR",
      controlId: "Art. 32",
      controlTitle: "Security of Processing",
      requirement: "Implement appropriate technical measures to ensure a level of security appropriate to the risk including the ability to ensure ongoing availability",
    },
  ],
  "CWE-710": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.4.2",
      controlTitle: "Security Configuration Enforcement",
      requirement: "Establish and enforce security configuration settings for IT products",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC8.1",
      controlTitle: "Change Management",
      requirement: "Authorize, design, develop, configure, document, test, and implement changes",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V1.1.7",
      controlTitle: "Secure SDLC",
      requirement: "Verify availability of secure coding checklist, security requirements, or guidelines",
    },
    {
      framework: "HIPAA",
      controlId: "164.312(a)(2)(iv)",
      controlTitle: "Encryption and Decryption",
      requirement: "Implement a mechanism to encrypt and decrypt ePHI when deemed appropriate",
    },
    {
      framework: "PCI-DSS v4.0",
      controlId: "6.2.1",
      controlTitle: "Secure Development",
      requirement: "Bespoke and custom software is developed securely",
    },
    {
      framework: "ISO 27001:2022",
      controlId: "A.8.28",
      controlTitle: "Secure Coding",
      requirement: "Secure coding principles shall be applied to software development",
    },
    {
      framework: "FedRAMP",
      controlId: "SA-11",
      controlTitle: "Developer Testing and Evaluation",
      requirement: "Require the developer to create and implement a security assessment plan",
    },
    {
      framework: "GDPR",
      controlId: "Art. 25",
      controlTitle: "Data Protection by Design",
      requirement: "Implement appropriate technical measures designed to implement data-protection principles effectively",
    },
  ],
  "CWE-732": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.1.2",
      controlTitle: "Transaction & Function Control",
      requirement: "Limit system access to the types of transactions and functions that authorized users are permitted to execute",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.3",
      controlTitle: "Role-Based Access",
      requirement: "Authorize, modify, or remove access based on roles and responsibilities",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V4.1.3",
      controlTitle: "General Access Control",
      requirement: "Verify that the principle of least privilege exists — users should only be able to access functions for which they possess specific authorization",
    },
    {
      framework: "HIPAA",
      controlId: "164.312(a)(1)",
      controlTitle: "Access Control",
      requirement: "Implement technical policies and procedures for systems that maintain ePHI to allow access only to authorized persons",
    },
    {
      framework: "PCI-DSS v4.0",
      controlId: "7.2.1",
      controlTitle: "Access Control Model",
      requirement: "An access control model is defined and includes granting access based on job classification and function",
    },
    {
      framework: "ISO 27001:2022",
      controlId: "A.8.3",
      controlTitle: "Information Access Restriction",
      requirement: "Access to information and other associated assets shall be restricted in accordance with the established access control policy",
    },
    {
      framework: "FedRAMP",
      controlId: "AC-6",
      controlTitle: "Least Privilege",
      requirement: "Employ the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks",
    },
    {
      framework: "GDPR",
      controlId: "Art. 25",
      controlTitle: "Data Protection by Design",
      requirement: "Implement appropriate technical measures designed to implement data-protection principles effectively",
    },
  ],
  "CWE-912": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.14.2",
      controlTitle: "Malicious Code Protection",
      requirement: "Provide protection from malicious code at designated locations within organizational systems",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC7.1",
      controlTitle: "Detection and Monitoring",
      requirement: "Detect and monitor for anomalies that indicate risks to the achievement of objectives",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V10.2.1",
      controlTitle: "Malicious Code Search",
      requirement: "Verify that the application does not contain hidden functionality or backdoors",
    },
    {
      framework: "HIPAA",
      controlId: "164.312(c)(1)",
      controlTitle: "Integrity Controls",
      requirement: "Implement policies and procedures to protect ePHI from improper alteration or destruction",
    },
    {
      framework: "PCI-DSS v4.0",
      controlId: "6.2.4",
      controlTitle: "Software Engineering Techniques",
      requirement: "Prevent common software attacks including hidden backdoor functionality",
    },
    {
      framework: "ISO 27001:2022",
      controlId: "A.8.28",
      controlTitle: "Secure Coding",
      requirement: "Secure coding principles shall be applied to software development",
    },
    {
      framework: "FedRAMP",
      controlId: "SI-7",
      controlTitle: "Software, Firmware, and Information Integrity",
      requirement: "Employ integrity verification tools to detect unauthorized changes to software, firmware, and information",
    },
    {
      framework: "GDPR",
      controlId: "Art. 32",
      controlTitle: "Security of Processing",
      requirement: "Implement appropriate technical measures to ensure a level of security appropriate to the risk",
    },
  ],
  "CWE-20": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.13.1",
      controlTitle: "Boundary Protection",
      requirement: "Monitor, control, and protect communications at system boundaries",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.1",
      controlTitle: "Logical and Physical Access Controls",
      requirement: "Implement logical access security to protect against unauthorized access",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V5.1.3",
      controlTitle: "Input Validation",
      requirement: "Verify that all input is validated, including length, range, format, and business rules",
    },
    {
      framework: "HIPAA",
      controlId: "164.312(a)(1)",
      controlTitle: "Access Control",
      requirement: "Implement technical policies and procedures for systems that maintain ePHI to allow access only to authorized persons",
    },
    {
      framework: "PCI-DSS v4.0",
      controlId: "6.2.4",
      controlTitle: "Software Engineering Techniques",
      requirement: "Prevent common software attacks through proper input validation",
    },
    {
      framework: "ISO 27001:2022",
      controlId: "A.8.28",
      controlTitle: "Secure Coding",
      requirement: "Secure coding principles shall be applied to software development",
    },
    {
      framework: "FedRAMP",
      controlId: "SI-10",
      controlTitle: "Information Input Validation",
      requirement: "Check the validity of information inputs to the system",
    },
    {
      framework: "GDPR",
      controlId: "Art. 32",
      controlTitle: "Security of Processing",
      requirement: "Implement appropriate technical measures to ensure a level of security appropriate to the risk",
    },
  ],
  "CWE-522": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.5.10",
      controlTitle: "Cryptographically-Protected Passwords",
      requirement: "Store and transmit only cryptographically-protected passwords",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.1",
      controlTitle: "Logical and Physical Access Controls",
      requirement: "Implement logical access security to protect against unauthorized access",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V2.4.1",
      controlTitle: "Credential Storage",
      requirement: "Verify that passwords are stored in a form resistant to offline attacks",
    },
    {
      framework: "HIPAA",
      controlId: "164.312(a)(2)(iv)",
      controlTitle: "Encryption and Decryption",
      requirement: "Implement a mechanism to encrypt and decrypt ePHI when deemed appropriate",
    },
    {
      framework: "PCI-DSS v4.0",
      controlId: "8.3.1",
      controlTitle: "Strong Authentication",
      requirement: "All user access to system components is authenticated via strong mechanisms",
    },
    {
      framework: "ISO 27001:2022",
      controlId: "A.8.24",
      controlTitle: "Use of Cryptography",
      requirement: "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented",
    },
    {
      framework: "FedRAMP",
      controlId: "IA-5",
      controlTitle: "Authenticator Management",
      requirement: "Manage information system authenticators by protecting authenticator content from unauthorized disclosure and modification",
    },
    {
      framework: "GDPR",
      controlId: "Art. 32",
      controlTitle: "Security of Processing",
      requirement: "Implement appropriate technical measures including encryption of personal data",
    },
  ],
  "CWE-757": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.13.11",
      controlTitle: "FIPS-Validated Cryptography",
      requirement: "Employ FIPS-validated cryptography when used to protect CUI",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.1",
      controlTitle: "Logical and Physical Access Controls",
      requirement: "Implement logical access security to protect against unauthorized access",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V6.2.1",
      controlTitle: "Algorithms",
      requirement: "Verify that all cryptographic modules fail securely and use industry-proven algorithms",
    },
    {
      framework: "HIPAA",
      controlId: "164.312(a)(2)(iv)",
      controlTitle: "Encryption and Decryption",
      requirement: "Implement a mechanism to encrypt and decrypt ePHI when deemed appropriate",
    },
    {
      framework: "PCI-DSS v4.0",
      controlId: "4.2.1",
      controlTitle: "Strong Cryptography",
      requirement: "Strong cryptography is used to safeguard PAN during transmission over open, public networks",
    },
    {
      framework: "ISO 27001:2022",
      controlId: "A.8.24",
      controlTitle: "Use of Cryptography",
      requirement: "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented",
    },
    {
      framework: "FedRAMP",
      controlId: "SC-13",
      controlTitle: "Cryptographic Protection",
      requirement: "Implement FIPS-validated cryptography in accordance with applicable laws, regulations, and policies",
    },
    {
      framework: "GDPR",
      controlId: "Art. 32",
      controlTitle: "Security of Processing",
      requirement: "Implement appropriate technical measures including encryption of personal data",
    },
  ],
  "CWE-862": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.1.1",
      controlTitle: "Authorized Access Control",
      requirement: "Limit system access to authorized users, processes acting on behalf of authorized users, and devices",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC6.1",
      controlTitle: "Logical and Physical Access Controls",
      requirement: "Implement logical access security to protect against unauthorized access",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V4.1.1",
      controlTitle: "General Access Control",
      requirement: "Verify that the application enforces access control rules on a trusted service layer",
    },
    {
      framework: "HIPAA",
      controlId: "164.312(a)(1)",
      controlTitle: "Access Control",
      requirement: "Implement technical policies and procedures for systems that maintain ePHI to allow access only to authorized persons",
    },
    {
      framework: "PCI-DSS v4.0",
      controlId: "7.2.1",
      controlTitle: "Access Control Model",
      requirement: "An access control model is defined and includes granting access based on job classification and function",
    },
    {
      framework: "ISO 27001:2022",
      controlId: "A.8.3",
      controlTitle: "Information Access Restriction",
      requirement: "Access to information and other associated assets shall be restricted in accordance with the established access control policy",
    },
    {
      framework: "FedRAMP",
      controlId: "AC-3",
      controlTitle: "Access Enforcement",
      requirement: "Enforce approved authorizations for logical access to information and system resources",
    },
    {
      framework: "GDPR",
      controlId: "Art. 25",
      controlTitle: "Data Protection by Design",
      requirement: "Implement appropriate technical measures designed to implement data-protection principles effectively",
    },
  ],
  "CWE-1188": [
    {
      framework: "NIST SP 800-171",
      controlId: "3.4.2",
      controlTitle: "Security Configuration Enforcement",
      requirement: "Establish and enforce security configuration settings for IT products",
    },
    {
      framework: "SOC 2 TSC",
      controlId: "CC8.1",
      controlTitle: "Change Management",
      requirement: "Authorize, design, develop, configure, document, test, and implement changes",
    },
    {
      framework: "OWASP ASVS",
      controlId: "V14.2.1",
      controlTitle: "Dependency",
      requirement: "Verify that all components are up to date with proper security configuration",
    },
    {
      framework: "HIPAA",
      controlId: "164.312(a)(1)",
      controlTitle: "Access Control",
      requirement: "Implement technical policies and procedures for systems that maintain ePHI to allow access only to authorized persons",
    },
    {
      framework: "PCI-DSS v4.0",
      controlId: "2.2.1",
      controlTitle: "System Configuration Standards",
      requirement: "Configuration standards are developed, implemented, and actively managed for all system components",
    },
    {
      framework: "ISO 27001:2022",
      controlId: "A.8.9",
      controlTitle: "Configuration Management",
      requirement: "Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, and reviewed",
    },
    {
      framework: "FedRAMP",
      controlId: "CM-6",
      controlTitle: "Configuration Settings",
      requirement: "Establish and document configuration settings for IT products that reflect the most restrictive mode consistent with operational requirements",
    },
    {
      framework: "GDPR",
      controlId: "Art. 25",
      controlTitle: "Data Protection by Design",
      requirement: "Implement appropriate technical measures designed to implement data-protection principles effectively",
    },
  ],
};

/**
 * Direct finding-to-framework mappings for AI/Agentic security frameworks.
 * These frameworks use category-based mapping (not CWE-based) because many
 * agentic vulnerability classes don't have CWE assignments.
 *
 * Maps finding ID prefixes to framework categories.
 */
export const FINDING_COMPLIANCE_MAP: Record<string, Array<{
  framework: string;
  categoryId: string;
  categoryTitle: string;
  relevance: string;
}>> = {
  // ── OWASP Top 10 for LLM v2.0 (2025) ──────────────────────────────
  // Finding prefixes → LLM categories
  "DI": [
    { framework: "OWASP LLM Top 10 v2.0", categoryId: "LLM01", categoryTitle: "Prompt Injection", relevance: "Direct prompt injection via tool descriptions" },
  ],
  "SM": [
    { framework: "OWASP LLM Top 10 v2.0", categoryId: "LLM01", categoryTitle: "Prompt Injection", relevance: "Schema-embedded prompt injection" },
  ],
  "IPI": [
    { framework: "OWASP LLM Top 10 v2.0", categoryId: "LLM01", categoryTitle: "Prompt Injection", relevance: "Indirect prompt injection vectors" },
  ],
  "SL": [
    { framework: "OWASP LLM Top 10 v2.0", categoryId: "LLM02", categoryTitle: "Sensitive Information Disclosure", relevance: "Hardcoded secrets in tool schemas" },
  ],
  "CE": [
    { framework: "OWASP LLM Top 10 v2.0", categoryId: "LLM02", categoryTitle: "Sensitive Information Disclosure", relevance: "Context extraction and data leakage" },
  ],
  "SC": [
    { framework: "OWASP LLM Top 10 v2.0", categoryId: "LLM03", categoryTitle: "Supply Chain Vulnerabilities", relevance: "Supply chain risk indicators" },
  ],
  "RP": [
    { framework: "OWASP LLM Top 10 v2.0", categoryId: "LLM03", categoryTitle: "Supply Chain Vulnerabilities", relevance: "Rug-pull and schema mutation attacks" },
  ],
  "OI": [
    { framework: "OWASP LLM Top 10 v2.0", categoryId: "LLM05", categoryTitle: "Improper Output Handling", relevance: "Output injection and agent manipulation" },
  ],
  "DC": [
    { framework: "OWASP LLM Top 10 v2.0", categoryId: "LLM06", categoryTitle: "Excessive Agency", relevance: "Dangerous capabilities without constraints" },
  ],
  "TP": [
    { framework: "OWASP LLM Top 10 v2.0", categoryId: "LLM06", categoryTitle: "Excessive Agency", relevance: "Over-permissioned tool configurations" },
  ],
  "TE": [
    { framework: "OWASP LLM Top 10 v2.0", categoryId: "LLM10", categoryTitle: "Unbounded Consumption", relevance: "Token exhaustion risks" },
  ],
  "LT": [
    { framework: "OWASP LLM Top 10 v2.0", categoryId: "LLM10", categoryTitle: "Unbounded Consumption", relevance: "Infinite loop traps" },
  ],

  // ── OWASP Agentic Applications Top 10 (ASI10, 2026) ─────────────────
  "AF": [
    { framework: "OWASP Agentic ASI10", categoryId: "ASI02", categoryTitle: "Tool Misuse & Exploitation", relevance: "Active fuzzer detected exploitable tool" },
  ],
  "AB": [
    { framework: "OWASP Agentic ASI10", categoryId: "ASI05", categoryTitle: "Identity & Access Abuse", relevance: "Authorization boundary violation" },
  ],
  "EC": [
    { framework: "OWASP Agentic ASI10", categoryId: "ASI10", categoryTitle: "Cross-System Propagation", relevance: "Data exfiltration chains across tools" },
  ],
  "NP": [
    { framework: "OWASP Agentic ASI10", categoryId: "ASI07", categoryTitle: "Multi-Agent Trust Erosion", relevance: "Namespace poisoning / tool shadowing" },
  ],
  "TS": [
    { framework: "OWASP Agentic ASI10", categoryId: "ASI07", categoryTitle: "Multi-Agent Trust Erosion", relevance: "Tool shadowing — actual vs declared behavior" },
  ],
  "AV": [
    { framework: "OWASP Agentic ASI10", categoryId: "ASI03", categoryTitle: "Insecure Autonomous Actions", relevance: "Annotation verification failure" },
  ],
  "SI": [
    { framework: "OWASP Agentic ASI10", categoryId: "ASI05", categoryTitle: "Identity & Access Abuse", relevance: "Session isolation failure" },
  ],

  // ── OWASP Agentic Skills Top 10 (AST10) ─────────────────────────────
  // Many prefixes map to both ASI10 and AST10
  "CG": [
    { framework: "OWASP Agentic Skills AST10", categoryId: "AST03", categoryTitle: "Insecure Skill Chaining", relevance: "Capability graph reveals dangerous chains" },
  ],
  "HF": [
    { framework: "OWASP Agentic Skills AST10", categoryId: "AST09", categoryTitle: "Insecure Skill Communication", relevance: "Handshake parameter injection" },
  ],
  "RF": [
    { framework: "OWASP Agentic Skills AST10", categoryId: "AST10", categoryTitle: "Lack of Skill Observability", relevance: "Non-deterministic responses indicating hidden state" },
  ],

  // ── MITRE ATLAS v5.4.0 ──────────────────────────────────────────────
  "SSRF": [
    { framework: "MITRE ATLAS v5.4.0", categoryId: "AML.T0062", categoryTitle: "Exfiltration via AI Agent Tool Invocation", relevance: "SSRF enables data exfiltration through agent tools" },
  ],
  "MA": [
    { framework: "MITRE ATLAS v5.4.0", categoryId: "AML.T0061", categoryTitle: "AI Agent Tools", relevance: "MCP Apps Extension security" },
  ],
  "DS": [
    { framework: "MITRE ATLAS v5.4.0", categoryId: "AML.T0059", categoryTitle: "Publish Poisoned AI Agent Tool", relevance: "Discovery metadata manipulation" },
  ],
};

// Duplicate mappings: some prefixes map to multiple frameworks
// These are merged into the FINDING_COMPLIANCE_MAP entries above where a prefix
// already exists; add additional entries where needed:

// DI also maps to ASI01 and AST01
FINDING_COMPLIANCE_MAP["DI"].push(
  { framework: "OWASP Agentic ASI10", categoryId: "ASI01", categoryTitle: "Agent Goal Hijack", relevance: "Prompt injection hijacks agent goals" },
  { framework: "OWASP Agentic Skills AST10", categoryId: "AST01", categoryTitle: "Malicious Skills", relevance: "Injection-laden tool descriptions" },
  { framework: "MITRE ATLAS v5.4.0", categoryId: "AML.T0051", categoryTitle: "LLM Prompt Injection", relevance: "Direct prompt injection" },
);
FINDING_COMPLIANCE_MAP["IPI"].push(
  { framework: "MITRE ATLAS v5.4.0", categoryId: "AML.T0051.001", categoryTitle: "Indirect Prompt Injection", relevance: "Indirect prompt injection via tool output" },
);
FINDING_COMPLIANCE_MAP["SM"].push(
  { framework: "OWASP Agentic Skills AST10", categoryId: "AST07", categoryTitle: "Insecure Metadata", relevance: "Schema manipulation as metadata attack" },
  { framework: "MITRE ATLAS v5.4.0", categoryId: "AML.T0051", categoryTitle: "LLM Prompt Injection", relevance: "Schema-embedded injection" },
);
FINDING_COMPLIANCE_MAP["SC"].push(
  { framework: "OWASP Agentic Skills AST10", categoryId: "AST08", categoryTitle: "Uncontrolled Skill Installation", relevance: "Supply chain risk in package installation" },
  { framework: "MITRE ATLAS v5.4.0", categoryId: "AML.T0059", categoryTitle: "Publish Poisoned AI Agent Tool", relevance: "Supply chain compromise" },
);
FINDING_COMPLIANCE_MAP["RP"].push(
  { framework: "OWASP Agentic Skills AST10", categoryId: "AST06", categoryTitle: "Insecure Skill Lifecycle", relevance: "Schema mutation / rug-pull detection" },
);
FINDING_COMPLIANCE_MAP["DC"].push(
  { framework: "OWASP Agentic ASI10", categoryId: "ASI02", categoryTitle: "Tool Misuse & Exploitation", relevance: "Dangerous capabilities enable tool misuse" },
  { framework: "OWASP Agentic Skills AST10", categoryId: "AST02", categoryTitle: "Over-Privileged Skills", relevance: "Excessive capabilities" },
  { framework: "MITRE ATLAS v5.4.0", categoryId: "AML.T0061", categoryTitle: "AI Agent Tools", relevance: "Dangerous tool capabilities" },
);
FINDING_COMPLIANCE_MAP["EC"].push(
  { framework: "OWASP Agentic Skills AST10", categoryId: "AST04", categoryTitle: "Skill Data Leakage", relevance: "Exfiltration chain enables data leakage" },
  { framework: "MITRE ATLAS v5.4.0", categoryId: "AML.T0062", categoryTitle: "Exfiltration via AI Agent Tool Invocation", relevance: "Tool-based exfiltration" },
);
FINDING_COMPLIANCE_MAP["NP"].push(
  { framework: "OWASP Agentic Skills AST10", categoryId: "AST05", categoryTitle: "Cross-Skill Confusion", relevance: "Namespace collision enables confusion" },
);
FINDING_COMPLIANCE_MAP["TP"].push(
  { framework: "OWASP Agentic Skills AST10", categoryId: "AST02", categoryTitle: "Over-Privileged Skills", relevance: "Excessive permissions" },
);
FINDING_COMPLIANCE_MAP["TE"].push(
  { framework: "OWASP Agentic ASI10", categoryId: "ASI10", categoryTitle: "Cross-System Propagation", relevance: "Token exhaustion can cascade across systems" },
);
FINDING_COMPLIANCE_MAP["LT"].push(
  { framework: "OWASP Agentic ASI10", categoryId: "ASI10", categoryTitle: "Cross-System Propagation", relevance: "Loop traps propagate through agent chains" },
);

// ── NIST AI RMF (AI 800-1) — Govern / Map / Measure / Manage ─────────────
// Maps finding prefixes to NIST AI Risk Management Framework functions.
// Reference: DeepR_4 — NIST COSAiS / AI 800-1 framework analysis.

// Govern: establish AI risk management policies and accountability
FINDING_COMPLIANCE_MAP["TP"].push(
  { framework: "NIST AI RMF", categoryId: "GOVERN-1.1", categoryTitle: "Legal and regulatory requirements", relevance: "Tool over-permissioning violates least-privilege governance" },
);
FINDING_COMPLIANCE_MAP["AV"].push(
  { framework: "NIST AI RMF", categoryId: "GOVERN-1.5", categoryTitle: "Ongoing monitoring plans", relevance: "Annotation verification failures indicate governance gaps" },
);
FINDING_COMPLIANCE_MAP["DC"].push(
  { framework: "NIST AI RMF", categoryId: "GOVERN-1.2", categoryTitle: "Trustworthy AI characteristics", relevance: "Dangerous capabilities lack governance guardrails" },
);

// Map: categorize and contextualize AI risks
FINDING_COMPLIANCE_MAP["DI"].push(
  { framework: "NIST AI RMF", categoryId: "MAP-1.1", categoryTitle: "Intended purpose and context of use", relevance: "Prompt injection alters intended AI system behavior" },
);
FINDING_COMPLIANCE_MAP["IPI"].push(
  { framework: "NIST AI RMF", categoryId: "MAP-1.6", categoryTitle: "Impacts to individuals, groups, communities", relevance: "Indirect prompt injection can affect unintended targets" },
);
FINDING_COMPLIANCE_MAP["SC"].push(
  { framework: "NIST AI RMF", categoryId: "MAP-3.4", categoryTitle: "Risks of third-party entities", relevance: "Supply chain compromise introduces third-party AI risk" },
);
FINDING_COMPLIANCE_MAP["CG"].push(
  { framework: "NIST AI RMF", categoryId: "MAP-2.3", categoryTitle: "Scientific integrity considerations", relevance: "Capability graph reveals systemic chaining risks" },
);

// Measure: analyze, assess, and track AI risks
FINDING_COMPLIANCE_MAP["AF"].push(
  { framework: "NIST AI RMF", categoryId: "MEASURE-2.6", categoryTitle: "AI system performance assessment", relevance: "Active fuzzer quantifies exploitability risk" },
);
FINDING_COMPLIANCE_MAP["RF"].push(
  { framework: "NIST AI RMF", categoryId: "MEASURE-2.5", categoryTitle: "Prediction and output quality", relevance: "Non-deterministic responses indicate measurement instability" },
);
FINDING_COMPLIANCE_MAP["SSRF"].push(
  { framework: "NIST AI RMF", categoryId: "MEASURE-2.9", categoryTitle: "Security and resilience evaluation", relevance: "SSRF demonstrates network-layer security risk" },
);

// Manage: allocate resources and respond to AI risks
FINDING_COMPLIANCE_MAP["AB"].push(
  { framework: "NIST AI RMF", categoryId: "MANAGE-2.2", categoryTitle: "Mechanisms to supersede, disengage, or deactivate", relevance: "Authorization boundary failures need active management" },
);
FINDING_COMPLIANCE_MAP["EC"].push(
  { framework: "NIST AI RMF", categoryId: "MANAGE-2.4", categoryTitle: "Risk response mechanisms", relevance: "Exfiltration chains require incident response management" },
);
FINDING_COMPLIANCE_MAP["SI"].push(
  { framework: "NIST AI RMF", categoryId: "MANAGE-2.2", categoryTitle: "Mechanisms to supersede, disengage, or deactivate", relevance: "Session isolation failures need deactivation controls" },
);

// ── EU AI Act Article Mapping ─────────────────────────────────────────────
// Maps finding prefixes to specific EU AI Act articles.
// Enforcement date: August 2, 2026.

// EU AI Act findings are generated by the eu-ai-act module with EUAI-* prefix,
// but we also map existing security findings to Articles for cross-framework coverage.
FINDING_COMPLIANCE_MAP["EUAI"] = [
  { framework: "EU AI Act", categoryId: "Art. 9-15", categoryTitle: "High-Risk AI Requirements", relevance: "Direct EU AI Act conformity assessment findings" },
];
FINDING_COMPLIANCE_MAP["DC"].push(
  { framework: "EU AI Act", categoryId: "Art. 9", categoryTitle: "Risk Management System", relevance: "Dangerous capabilities require documented risk management" },
);
FINDING_COMPLIANCE_MAP["TP"].push(
  { framework: "EU AI Act", categoryId: "Art. 14", categoryTitle: "Human Oversight", relevance: "Over-permissioned tools undermine human oversight capability" },
);
FINDING_COMPLIANCE_MAP["SL"].push(
  { framework: "EU AI Act", categoryId: "Art. 15", categoryTitle: "Accuracy, Robustness, Cybersecurity", relevance: "Hardcoded secrets violate cybersecurity requirements" },
);
FINDING_COMPLIANCE_MAP["SM"].push(
  { framework: "EU AI Act", categoryId: "Art. 13", categoryTitle: "Transparency", relevance: "Schema manipulation undermines system transparency" },
);
FINDING_COMPLIANCE_MAP["TE"].push(
  { framework: "EU AI Act", categoryId: "Art. 15", categoryTitle: "Accuracy, Robustness, Cybersecurity", relevance: "Token exhaustion violates robustness requirements" },
);
FINDING_COMPLIANCE_MAP["SC"].push(
  { framework: "EU AI Act", categoryId: "Art. 15", categoryTitle: "Accuracy, Robustness, Cybersecurity", relevance: "Supply chain risks threaten system accuracy and robustness" },
);
