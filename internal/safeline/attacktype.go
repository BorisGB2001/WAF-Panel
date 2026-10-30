package safeline

import "strconv"

// AttackTypeName is the English name of an attack type; the panel
// translates it for the reader (see package i18n).
func AttackTypeName(t int) string { return AttackTypeCode(t) }

// attackTypeCodes are stable English names for SIEM correlation rules.
var attackTypeCodes = map[int]string{
	-4: "Large Data", -3: "Deny Rule", -2: "Allow List", -1: "Non Attack",
	0: "SQL Injection", 1: "XSS", 2: "CSRF", 3: "SSRF", 4: "DoS", 5: "Backdoor",
	6: "Deserialization", 7: "Code Execution", 8: "Code Injection", 9: "Command Injection",
	10: "File Upload", 11: "File Inclusion", 12: "Open Redirect", 13: "Improper Permission",
	14: "Information Leak", 15: "Unauthorized Access", 16: "Insecure Config", 17: "XXE",
	18: "XPath Injection", 19: "LDAP Injection", 20: "Path Traversal", 21: "Scanner",
	22: "Horizontal Bypass", 23: "Vertical Bypass", 24: "File Modify", 25: "File Read",
	26: "File Delete", 27: "Logic Error", 28: "CRLF Injection", 29: "SSTI",
	30: "Clickjacking", 31: "Buffer Overflow", 32: "Integer Overflow", 33: "Format String",
	34: "Race Condition", 35: "HTTP Protocol Violation", 36: "HTTP Request Smuggling",
	61: "Timeout", 62: "Unknown", 63: "Threat Intelligence", 64: "Cookie Tampering",
}

func AttackTypeCode(t int) string {
	if n, ok := attackTypeCodes[t]; ok {
		return n
	}
	return "Type " + strconv.Itoa(t)
}
