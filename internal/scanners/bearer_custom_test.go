package scanners

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

const acmeRule = `patterns:
  - |
    alphaPetsLoyaltySecret($<_>)
languages:
  - javascript
metadata:
  description: "Alpha Pets loyalty points secret passed to helper"
  id: alpha_pets_loyalty_secret_leak
severity: high
`

func TestBearerCustomRuleIDs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "bearer.yml"), "scan:\n  external-rule-dir:\n    - ./rules\n")
	writeFile(t, filepath.Join(root, "rules", "acme.yml"), acmeRule)
	writeFile(t, filepath.Join(root, "rules", "nested", "reuse.yaml"), "metadata:\n  id: javascript_lang_hardcoded_secret\n")
	writeFile(t, filepath.Join(root, "rules", "notes.txt"), "metadata:\n  id: not_a_rule\n")
	got := bearerCustomRuleIDs(root)
	for _, id := range []string{"alpha_pets_loyalty_secret_leak", "javascript_lang_hardcoded_secret"} {
		if !got[id] {
			t.Errorf("missing custom rule %q in %v", id, got)
		}
	}
	if got["not_a_rule"] {
		t.Errorf("read a non-yaml file")
	}

	// A single string, not a list.
	root2 := t.TempDir()
	writeFile(t, filepath.Join(root2, "bearer.yml"), "scan:\n  external-rule-dir: rules\n")
	writeFile(t, filepath.Join(root2, "rules", "acme.yml"), acmeRule)
	if !bearerCustomRuleIDs(root2)["alpha_pets_loyalty_secret_leak"] {
		t.Errorf("scalar external-rule-dir not read")
	}

	// No config, broken config: no custom rules, no panic.
	if n := len(bearerCustomRuleIDs(t.TempDir())); n != 0 {
		t.Errorf("no bearer.yml gave %d ids", n)
	}
	root3 := t.TempDir()
	writeFile(t, filepath.Join(root3, "bearer.yml"), "scan: [unclosed\n")
	if n := len(bearerCustomRuleIDs(root3)); n != 0 {
		t.Errorf("broken bearer.yml gave %d ids", n)
	}
}

func TestMarkCustomRule(t *testing.T) {
	custom := map[string]bool{"alpha_pets_loyalty_secret_leak": true, "custom:already": true}
	cases := map[string]string{
		"alpha_pets_loyalty_secret_leak":   "custom:alpha_pets_loyalty_secret_leak",
		"javascript_lang_hardcoded_secret": "javascript_lang_hardcoded_secret",
		"custom:already":                   "custom:already",
		"":                                 "",
	}
	for in, want := range cases {
		if got := markCustomRule(in, custom); got != want {
			t.Errorf("markCustomRule(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsTrojanRuleFile(t *testing.T) {
	cases := map[string]bool{
		"trojan-js-secret-fallback.yaml":   true,
		"._trojan-js-secret-fallback.yaml": false, // macOS AppleDouble
		".hidden.yaml":                     false,
		"README.md":                        false,
	}
	for name, want := range cases {
		if got := isTrojanRuleFile(name); got != want {
			t.Errorf("isTrojanRuleFile(%q) = %v, want %v", name, got, want)
		}
	}
	// Every embedded rule file is one we write.
	entries, err := trojanRulesFS.ReadDir("semgreprules")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !isTrojanRuleFile(e.Name()) {
			t.Errorf("embedded file %q would be skipped", e.Name())
		}
	}
}
