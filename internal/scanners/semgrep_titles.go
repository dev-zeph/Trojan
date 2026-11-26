package scanners

import "strings"

// friendlySemgrepTitles maps the last segment of common Semgrep registry rule
// IDs to plain-English titles. Without an entry the title is derived from the
// rule ID ("Tainted Sql String"), which means little to a non-specialist.
var friendlySemgrepTitles = map[string]string{
	// PHP
	"tainted-sql-string":           "Database query built from visitor input (SQL injection)",
	"tainted-exec":                 "System command built from visitor input (command injection)",
	"exec-use":                     "Code runs a system command",
	"eval-use":                     "Code runs text as PHP code (eval)",
	"tainted-filename":             "File path built from visitor input",
	"tainted-url-host":             "Server calls an address built from visitor input (SSRF)",
	"tainted-callable":             "Visitor input picks which function runs",
	"tainted-object-instantiation": "Visitor input picks which class is created",
	"md5-loose-equality":           "Password hash compared with == (can be bypassed)",
	"phpinfo-use":                  "phpinfo() page shows server details to anyone",
	"unlink-use":                   "File is deleted using a path that may come from a visitor",
	"unserialize-use":              "Data turned back into PHP objects with unserialize()",
	"php-permissive-cors":          "Any website can read this page's responses (open CORS)",
	"curl-ssl-verifypeer-off":      "HTTPS certificate checks are turned off",
	"openssl-decrypt-validate":     "Decryption result is not checked",
	"echoed-request":               "Visitor input is printed into the page (XSS)",
	"weak-crypto":                  "Weak encryption or hashing is used",
	"mcrypt-use":                   "Outdated mcrypt encryption is used",
	"base-convert-loses-precision": "Random token loses strength through base_convert()",
	"assert-use":                   "assert() can run text as PHP code",
	"backticks-use":                "Code runs a system command with backticks",
	"ftp-use":                      "Unencrypted FTP connection",
	"mb-ereg-replace-eval":         "Regex replace can run text as PHP code",
	"preg-replace-eval":            "Regex replace can run text as PHP code",
	"redirect-to-request-uri":      "Redirect goes to an address from the request (open redirect)",
	"non-literal-header":           "Response header built from a variable",
	"file-inclusion":               "File loaded from a path that may come from a visitor",
	"wp-file-inclusion-audit":      "File loaded from a path that may come from a visitor",
	"laravel-sql-injection":        "Database query built from visitor input (SQL injection)",
	// Common across languages
	"detected-jwt-token":      "Login token (JWT) written in the code",
	"detected-generic-secret": "Secret written in the code",
	"detected-private-key":    "Private key written in the code",
	// Semgrep's secrets rules ("detected-...-value"). Without these the id
	// became "Detected Aws Access Key Id Value" (R3-P3-6).
	"detected-aws-access-key-id-value":      "AWS access key in the code",
	"detected-aws-secret-access-key":        "AWS secret access key in the code",
	"detected-aws-account-id":               "AWS account ID in the code",
	"detected-stripe-api-key":               "Stripe API key in the code",
	"detected-stripe-restricted-api-key":    "Stripe restricted API key in the code",
	"detected-github-token":                 "GitHub token in the code",
	"detected-slack-token":                  "Slack token in the code",
	"detected-slack-webhook":                "Slack webhook address in the code",
	"detected-google-api-key":               "Google API key in the code",
	"detected-google-oauth-access-token":    "Google OAuth token in the code",
	"detected-sendgrid-api-key":             "SendGrid API key in the code",
	"detected-twilio-api-key":               "Twilio API key in the code",
	"detected-mailgun-api-key":              "Mailgun API key in the code",
	"detected-npm-registry-auth-token":      "npm registry token in the code",
	"detected-generic-api-key":              "API key in the code",
	"detected-username-and-password-in-uri": "User name and password in an address in the code",
	"github-actions-mutable-action-tag":     "GitHub workflow uses an action by a tag that can change",
	"run-shell-injection":                   "GitHub workflow runs a command built from untrusted input",
	"detect-non-literal-regexp":             "Regex built from a variable (can freeze the server)",
	"prototype-pollution-loop":              "Object keys from input can change built-in objects (prototype pollution)",
	"eval-detected":                         "Code runs text as JavaScript (eval)",
	"missing-user":                          "Container runs as the root user",
}

// semgrepWordCase gives the house spelling of acronyms and brand names in
// Semgrep rule ids, on top of the gitleaks list. Other words stay lower case.
var semgrepWordCase = map[string]string{
	"sql": "SQL", "nosql": "NoSQL", "xss": "XSS", "csrf": "CSRF", "ssrf": "SSRF", "xxe": "XXE", "rce": "RCE",
	"html": "HTML", "http": "HTTP", "https": "HTTPS", "tls": "TLS", "ssl": "SSL", "cors": "CORS", "csp": "CSP",
	"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256", "rsa": "RSA", "dsa": "DSA", "des": "DES", "aes": "AES",
	"xml": "XML", "json": "JSON", "yaml": "YAML", "dom": "DOM", "uri": "URI", "ip": "IP", "dns": "DNS",
	"iam": "IAM", "s3": "S3", "ec2": "EC2", "k8s": "Kubernetes", "php": "PHP", "js": "JS",
	"javascript": "JavaScript", "typescript": "TypeScript", "nodejs": "Node.js", "jquery": "jQuery",
	"stripe": "Stripe", "slack": "Slack", "google": "Google", "twilio": "Twilio", "mailgun": "Mailgun",
	"docker": "Docker", "django": "Django", "flask": "Flask", "react": "React", "express": "Express",
	"laravel": "Laravel", "wordpress": "WordPress", "wp": "WordPress", "nextjs": "Next.js", "supabase": "Supabase",
}

// semgrepWord spells one word of a rule id: a word that already has capitals
// keeps them, known acronyms and brands get their house spelling, and the rest
// stay lower case.
func semgrepWord(w string) string {
	if strings.ToLower(w) != w {
		return w // original casing, e.g. "useHTTPS" or "AWS"
	}
	if c, ok := semgrepWordCase[w]; ok {
		return c
	}
	if c, ok := gitleaksWordCase[w]; ok && w != "pat" {
		return c
	}
	return w
}

// capitalizeFirst upper-cases the first letter, leaving "npm" and "jQuery"
// style names alone.
func capitalizeFirst(s string) string {
	if s == "" || strings.HasPrefix(s, "npm") || strings.HasPrefix(s, "jQuery") {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ruleIDToTitle derives a sentence-case title from a Semgrep rule id when there
// is no friendly title: "tainted-sql-string" becomes "Tainted SQL string", and
// "detected-x-value" secrets rules become "X in the code".
func ruleIDToTitle(ruleID string) string {
	parts := strings.Split(ruleID, ".")
	last := parts[len(parts)-1]
	words := strings.FieldsFunc(last, func(r rune) bool { return r == '-' || r == '_' || r == ' ' })
	if len(words) == 0 {
		return ruleID
	}
	secret := strings.EqualFold(words[0], "detected") && len(words) > 1
	if secret {
		words = words[1:]
		if n := len(words); n > 1 && strings.EqualFold(words[n-1], "value") {
			words = words[:n-1]
		}
	}
	for i, w := range words {
		words[i] = semgrepWord(w)
	}
	title := capitalizeFirst(strings.Join(words, " "))
	if secret {
		title += " in the code"
	}
	return title
}
