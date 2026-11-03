package scanners

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
	"detected-jwt-token":                "Login token (JWT) written in the code",
	"detected-generic-secret":           "Secret written in the code",
	"detected-private-key":              "Private key written in the code",
	"github-actions-mutable-action-tag": "GitHub workflow uses an action by a tag that can change",
	"run-shell-injection":               "GitHub workflow runs a command built from untrusted input",
	"detect-non-literal-regexp":         "Regex built from a variable (can freeze the server)",
	"prototype-pollution-loop":          "Object keys from input can change built-in objects (prototype pollution)",
	"eval-detected":                     "Code runs text as JavaScript (eval)",
	"missing-user":                      "Container runs as the root user",
}
