package scanners

import (
	"strings"
	"testing"
)

// R3-P3-6: Semgrep titles keep acronyms and brand names, and secrets rules
// read "X in the code" rather than "Detected Aws Access Key Id Value".
func TestSemgrepTitle(t *testing.T) {
	cases := map[string]string{
		"generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value": "AWS access key in the code",
		"generic.secrets.security.detected-stripe-api-key.detected-stripe-api-key":                   "Stripe API key in the code",
		"generic.secrets.security.detected-github-token.detected-github-token":                       "GitHub token in the code",
		"php.lang.security.tainted-sql-string.tainted-sql-string":                                    "Database query built from visitor input (SQL injection)",
	}
	for id, want := range cases {
		if got := semgrepTitle(id); got != want {
			t.Errorf("semgrepTitle(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestRuleIDToTitle(t *testing.T) {
	cases := map[string]string{
		"x.y.detected-openai-api-key-value": "OpenAI API key in the code",
		"x.y.detected-twilio-sid":           "Twilio sid in the code",
		"x.tainted-sql-string":              "Tainted SQL string",
		"x.express-xss-via-html":            "Express XSS via HTML",
		"x.insecure-md5-hash-for-jwt":       "Insecure MD5 hash for JWT",
		"x.use-of-https-without-tls":        "Use of HTTPS without TLS",
		"x.useHTTPS-in-AWS-config":          "UseHTTPS in AWS config",
		"x.npm-install-script":              "npm install script",
		"x.detected":                        "Detected",
		"plain-rule":                        "Plain rule",
		"x.missing_csrf_token":              "Missing CSRF token",
		"x.y.detected-something-value":      "Something in the code",
		"github-actions-cache-poisoning":    "GitHub actions cache poisoning",
	}
	for id, want := range cases {
		got := ruleIDToTitle(id)
		if got != want {
			t.Errorf("ruleIDToTitle(%q) = %q, want %q", id, got, want)
		}
		if strings.ContainsRune(got, '\u2014') {
			t.Errorf("em dash in %q", got)
		}
	}
}

func TestSemgrepWord(t *testing.T) {
	cases := map[string]string{"sql": "SQL", "aws": "AWS", "github": "GitHub", "pat": "pat", "AWS": "AWS", "useHTTPS": "useHTTPS", "string": "string"}
	for in, want := range cases {
		if got := semgrepWord(in); got != want {
			t.Errorf("semgrepWord(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFriendlySemgrepTitlesHaveNoEmDash(t *testing.T) {
	for id, title := range friendlySemgrepTitles {
		if strings.ContainsRune(title, '\u2014') {
			t.Errorf("%s: em dash in %q", id, title)
		}
	}
}
