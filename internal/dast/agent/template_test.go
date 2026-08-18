package agent

import (
	"strings"
	"testing"
)

func TestAttackTemplateHintEmpty(t *testing.T) {
	if got := attackTemplateHint(nil); got != "" {
		t.Errorf("nil template should yield no hint, got %q", got)
	}
	if got := attackTemplateHint(&AttackTemplate{Title: "x", Body: "   "}); got != "" {
		t.Errorf("blank body should yield no hint, got %q", got)
	}
}

func TestAttackTemplateHintFraming(t *testing.T) {
	h := attackTemplateHint(&AttackTemplate{
		Title:     "Client-Bundle Secret → Account Takeover",
		Technique: []string{"secrets-exposure", "broken-access-control"},
		Body:      "1. Read the bundle for secrets.\n2. Reuse them once against login.",
	})
	if h == "" {
		t.Fatal("expected a hint")
	}
	// The name, techniques, and body must all be present.
	for _, want := range []string{
		"Client-Bundle Secret → Account Takeover",
		"secrets-exposure, broken-access-control",
		"Read the bundle for secrets",
	} {
		if !strings.Contains(h, want) {
			t.Errorf("hint missing %q:\n%s", want, h)
		}
	}
	// The RoE-subordinate framing is non-negotiable: the template must be stated to
	// grant no permission and to be overridden by the rules of engagement.
	lower := strings.ToLower(h)
	if !strings.Contains(lower, "does not grant") && !strings.Contains(lower, "not grant any permission") {
		t.Errorf("hint must state it grants no permission:\n%s", h)
	}
	if !strings.Contains(lower, "override") {
		t.Errorf("hint must state the rules of engagement override it:\n%s", h)
	}
}
