package scanners

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGitleaksTitle(t *testing.T) {
	cases := []struct{ desc, rule, want string }{
		{"Identified a Stripe Access Token, which may compromise payment processing.", "stripe-access-token", "Leaked Stripe access token"},
		{"Uncovered a JSON Web Token, which may lead to unauthorized access.", "jwt", "Leaked login token (JWT)"},
		{"Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access.", "github-pat", "Leaked GitHub personal access token"},
		{"Identified a pattern that may indicate AWS credentials.", "aws-access-token", "Leaked AWS access token"},
		{"Detected a Generic API Key, potentially exposing access to various services.", "generic-api-key", "Leaked API key"},
		{"Identified a Private Key.", "private-key", "Leaked private key"},
		{"", "slack-webhook-url", "Leaked Slack webhook URL"},
		{"", "openai-api-key", "Leaked OpenAI API key"},
		{"", "shopify-shared-secret", "Leaked Shopify shared secret"},
		{"", "GITLAB-PAT", "Leaked GitLab personal access token"},
		{"Uncovered a", "", "Leaked secret"},
		{"", "", "Leaked secret"},
		{"", "---", "Leaked secret"},
	}
	for _, c := range cases {
		if got := gitleaksTitle(c.desc, c.rule); got != c.want {
			t.Errorf("gitleaksTitle(%q, %q) = %q, want %q", c.desc, c.rule, got, c.want)
		}
	}
}

func TestRelToProject(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ proj, file, want string }{
		{root, filepath.Join(root, "src", "billing.ts"), "src/billing.ts"},
		{root, filepath.Join(root, ".env.example"), ".env.example"},
		{root, "src/billing.ts", "src/billing.ts"}, // history mode: already repo-relative
		{root, "/etc/hosts", "/etc/hosts"},         // outside the project: unchanged
		{root, "", ""},
		{".", "src/billing.ts", "src/billing.ts"},
		{"app", "app/src/billing.ts", "src/billing.ts"}, // relative --source is echoed as a prefix
		{"app", "other/x.ts", "other/x.ts"},
	}
	for _, c := range cases {
		if got := relToProject(c.proj, c.file); got != c.want {
			t.Errorf("relToProject(%q, %q) = %q, want %q", c.proj, c.file, got, c.want)
		}
	}
}
