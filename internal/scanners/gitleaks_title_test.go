package scanners

import "testing"

func TestGitleaksTitle(t *testing.T) {
	cases := []struct{ desc, rule, want string }{
		{"Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure.", "github-pat", "Leaked GitHub Personal Access Token"},
		{"Identified a Stripe Access Token, which may compromise payment processing services and sensitive financial data.", "stripe-access-token", "Leaked Stripe Access Token"},
		{"Detected a Generic API Key, potentially exposing access to various services and sensitive operations.", "generic-api-key", "Leaked Generic API Key"},
		{"Found an AWS Access Key ID; rotate it", "aws-access-token", "Leaked AWS Access Key ID"},
		{"Discovered a potential Slack Webhook, allowing unauthorized posts", "slack-webhook-url", "Leaked Slack Webhook"},
		{"AWS", "aws-access-token", "Leaked AWS"},
		{"Private Key", "private-key", "Leaked Private Key"},
		{"", "aws-access-token", "Leaked aws access token"},
		{"Uncovered a", "", "Leaked secret"},
	}
	for _, c := range cases {
		if got := gitleaksTitle(c.desc, c.rule); got != c.want {
			t.Errorf("gitleaksTitle(%q, %q) = %q, want %q", c.desc, c.rule, got, c.want)
		}
	}
}
