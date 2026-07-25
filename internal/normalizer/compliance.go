package normalizer

import "strings"

// cweToCompliance maps common CWE IDs to compliance framework controls.
// Sources: MITRE CWE → OWASP mapping, PCI-DSS v4.0, SOC 2 TSC, HIPAA Security Rule.
var cweToCompliance = map[string][]ComplianceMapping{
	"CWE-22": {
		{Framework: "OWASP", Control: "A01:2021", Title: "Broken Access Control"},
		{Framework: "PCI-DSS", Control: "6.2.4", Title: "Software engineering to prevent common attacks"},
		{Framework: "SOC 2", Control: "CC6.1", Title: "Logical and Physical Access Controls"},
	},
	"CWE-78": {
		{Framework: "OWASP", Control: "A03:2021", Title: "Injection"},
		{Framework: "PCI-DSS", Control: "6.2.4", Title: "Software engineering to prevent common attacks"},
		{Framework: "SOC 2", Control: "CC6.6", Title: "Security Event Monitoring"},
	},
	"CWE-79": {
		{Framework: "OWASP", Control: "A03:2021", Title: "Injection"},
		{Framework: "PCI-DSS", Control: "6.2.4", Title: "Software engineering to prevent common attacks"},
		{Framework: "SOC 2", Control: "CC6.1", Title: "Logical and Physical Access Controls"},
		{Framework: "HIPAA", Control: "§164.312(e)", Title: "Transmission Security"},
	},
	"CWE-89": {
		{Framework: "OWASP", Control: "A03:2021", Title: "Injection"},
		{Framework: "PCI-DSS", Control: "6.2.4", Title: "Software engineering to prevent common attacks"},
		{Framework: "SOC 2", Control: "CC6.1", Title: "Logical and Physical Access Controls"},
		{Framework: "HIPAA", Control: "§164.312(a)", Title: "Access Control"},
	},
	"CWE-94": {
		{Framework: "OWASP", Control: "A03:2021", Title: "Injection"},
		{Framework: "PCI-DSS", Control: "6.2.4", Title: "Software engineering to prevent common attacks"},
	},
	"CWE-200": {
		{Framework: "OWASP", Control: "A01:2021", Title: "Broken Access Control"},
		{Framework: "SOC 2", Control: "CC6.5", Title: "Restriction of Information Assets"},
		{Framework: "HIPAA", Control: "§164.312(a)", Title: "Access Control"},
	},
	"CWE-256": {
		{Framework: "OWASP", Control: "A07:2021", Title: "Identification and Authentication Failures"},
		{Framework: "PCI-DSS", Control: "8.3.2", Title: "Strong cryptography for credentials"},
		{Framework: "SOC 2", Control: "CC6.1", Title: "Logical and Physical Access Controls"},
		{Framework: "HIPAA", Control: "§164.312(d)", Title: "Person or Entity Authentication"},
	},
	"CWE-287": {
		{Framework: "OWASP", Control: "A07:2021", Title: "Identification and Authentication Failures"},
		{Framework: "PCI-DSS", Control: "8.3", Title: "Authentication management"},
		{Framework: "SOC 2", Control: "CC6.1", Title: "Logical and Physical Access Controls"},
		{Framework: "HIPAA", Control: "§164.312(d)", Title: "Person or Entity Authentication"},
	},
	"CWE-295": {
		{Framework: "OWASP", Control: "A07:2021", Title: "Identification and Authentication Failures"},
		{Framework: "PCI-DSS", Control: "4.2.1", Title: "Strong cryptography for transmission"},
		{Framework: "SOC 2", Control: "CC6.7", Title: "Data Transmission Protection"},
	},
	"CWE-311": {
		{Framework: "OWASP", Control: "A02:2021", Title: "Cryptographic Failures"},
		{Framework: "PCI-DSS", Control: "4.2.1", Title: "Strong cryptography for transmission"},
		{Framework: "SOC 2", Control: "CC6.7", Title: "Data Transmission Protection"},
		{Framework: "HIPAA", Control: "§164.312(e)", Title: "Transmission Security"},
	},
	"CWE-312": {
		{Framework: "OWASP", Control: "A02:2021", Title: "Cryptographic Failures"},
		{Framework: "PCI-DSS", Control: "3.5", Title: "Primary account number protection"},
		{Framework: "SOC 2", Control: "CC6.5", Title: "Restriction of Information Assets"},
		{Framework: "HIPAA", Control: "§164.312(a)", Title: "Access Control"},
	},
	"CWE-326": {
		{Framework: "OWASP", Control: "A02:2021", Title: "Cryptographic Failures"},
		{Framework: "PCI-DSS", Control: "4.2.1", Title: "Strong cryptography for transmission"},
		{Framework: "SOC 2", Control: "CC6.7", Title: "Data Transmission Protection"},
	},
	"CWE-327": {
		{Framework: "OWASP", Control: "A02:2021", Title: "Cryptographic Failures"},
		{Framework: "PCI-DSS", Control: "4.2.1", Title: "Strong cryptography for transmission"},
	},
	"CWE-330": {
		{Framework: "OWASP", Control: "A02:2021", Title: "Cryptographic Failures"},
		{Framework: "PCI-DSS", Control: "6.2.4", Title: "Software engineering to prevent common attacks"},
	},
	"CWE-352": {
		{Framework: "OWASP", Control: "A01:2021", Title: "Broken Access Control"},
		{Framework: "PCI-DSS", Control: "6.2.4", Title: "Software engineering to prevent common attacks"},
		{Framework: "SOC 2", Control: "CC6.1", Title: "Logical and Physical Access Controls"},
	},
	"CWE-502": {
		{Framework: "OWASP", Control: "A08:2021", Title: "Software and Data Integrity Failures"},
		{Framework: "PCI-DSS", Control: "6.2.4", Title: "Software engineering to prevent common attacks"},
	},
	"CWE-522": {
		{Framework: "OWASP", Control: "A07:2021", Title: "Identification and Authentication Failures"},
		{Framework: "PCI-DSS", Control: "8.3.2", Title: "Strong cryptography for credentials"},
		{Framework: "HIPAA", Control: "§164.312(d)", Title: "Person or Entity Authentication"},
	},
	"CWE-601": {
		{Framework: "OWASP", Control: "A01:2021", Title: "Broken Access Control"},
		{Framework: "SOC 2", Control: "CC6.1", Title: "Logical and Physical Access Controls"},
	},
	"CWE-611": {
		{Framework: "OWASP", Control: "A05:2021", Title: "Security Misconfiguration"},
		{Framework: "PCI-DSS", Control: "6.2.4", Title: "Software engineering to prevent common attacks"},
	},
	"CWE-798": {
		{Framework: "OWASP", Control: "A07:2021", Title: "Identification and Authentication Failures"},
		{Framework: "PCI-DSS", Control: "8.6.1", Title: "System/application account credential management"},
		{Framework: "SOC 2", Control: "CC6.1", Title: "Logical and Physical Access Controls"},
		{Framework: "HIPAA", Control: "§164.312(d)", Title: "Person or Entity Authentication"},
	},
	"CWE-918": {
		{Framework: "OWASP", Control: "A10:2021", Title: "Server-Side Request Forgery"},
		{Framework: "PCI-DSS", Control: "6.2.4", Title: "Software engineering to prevent common attacks"},
		{Framework: "SOC 2", Control: "CC6.6", Title: "Security Event Monitoring"},
	},
}

// EnrichCompliance populates Compliance on each Finding based on its CWE IDs.
func EnrichCompliance(findings []Finding) {
	for i := range findings {
		if len(findings[i].CWEIDs) == 0 {
			continue
		}
		seen := map[string]bool{}
		for _, cwe := range findings[i].CWEIDs {
			// Normalize: "CWE-79" → lookup key
			key := strings.TrimSpace(cwe)
			mappings, ok := cweToCompliance[key]
			if !ok {
				continue
			}
			for _, m := range mappings {
				dedup := m.Framework + "|" + m.Control
				if seen[dedup] {
					continue
				}
				seen[dedup] = true
				findings[i].Compliance = append(findings[i].Compliance, m)
			}
		}
	}
}
