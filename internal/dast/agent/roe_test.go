package agent

import "testing"

func classifier(t *testing.T, tier Tier, env Environment, ack bool, roe RoE) *Envelope {
	t.Helper()
	e, err := NewEnvelope(tier, env, "shop.test", ack)
	if err != nil {
		t.Fatal(err)
	}
	e.SetRoE(roe)
	return e
}

func TestClassifyReadOnlyIsAuto(t *testing.T) {
	e := classifier(t, TierSafeActive, EnvStaging, false, RoE{})
	d := e.Classify("GET", "https://shop.test/api/orders/7", 0)
	if d.Action != ActionAuto {
		t.Fatalf("GET in scope should be auto, got %s (%s)", d.Action, d.Reason)
	}
}

func TestClassifyStateChangingIsApprove(t *testing.T) {
	e := classifier(t, TierSafeActive, EnvStaging, false, RoE{})
	d := e.Classify("POST", "https://shop.test/api/orders/7/comment", 10)
	if d.Action != ActionApprove {
		t.Fatalf("in-scope POST should be gated, got %s (%s)", d.Action, d.Reason)
	}
}

func TestClassifyFloorViolationIsBlock(t *testing.T) {
	// DELETE is destructive → blocked by the hard floor regardless of RoE.
	e := classifier(t, TierAggressive, EnvStaging, true, RoE{AllowDangerous: true})
	if d := e.Classify("DELETE", "https://shop.test/x", 0); d.Action != ActionBlock {
		t.Errorf("destructive verb should block, got %s", d.Action)
	}
	// Off-host → block.
	if d := e.Classify("GET", "https://evil.test/x", 0); d.Action != ActionBlock {
		t.Errorf("off-host should block, got %s", d.Action)
	}
	// POST without the side-effect ack on production → block (floor).
	prod := classifier(t, TierSafeActive, EnvProduction, false, RoE{})
	if d := prod.Classify("POST", "https://shop.test/x", 5); d.Action != ActionBlock {
		t.Errorf("unacked prod POST should block, got %s (%s)", d.Action, d.Reason)
	}
}

func TestClassifyDenylistBlocks(t *testing.T) {
	e := classifier(t, TierSafeActive, EnvStaging, false, RoE{
		EndpointDenylist: []string{"/internal/*"},
	})
	if d := e.Classify("GET", "https://shop.test/internal/metrics", 0); d.Action != ActionBlock {
		t.Fatalf("denylisted path should block even for GET, got %s (%s)", d.Action, d.Reason)
	}
}

func TestClassifyAutoAvoidDangerousPatterns(t *testing.T) {
	e := classifier(t, TierSafeActive, EnvStaging, false, RoE{})
	// A POST to a deletion-shaped path is blocked by auto-avoid, not merely gated.
	if d := e.Classify("POST", "https://shop.test/account/delete", 5); d.Action != ActionBlock {
		t.Fatalf("account deletion should be auto-avoided, got %s (%s)", d.Action, d.Reason)
	}
	// Opting in downgrades it to a normal state-changing approval.
	opted := classifier(t, TierSafeActive, EnvStaging, false, RoE{AllowDangerous: true})
	if d := opted.Classify("POST", "https://shop.test/account/delete", 5); d.Action != ActionApprove {
		t.Fatalf("with AllowDangerous, deletion should be gated not blocked, got %s (%s)", d.Action, d.Reason)
	}
}

func TestClassifyAllowlistScoping(t *testing.T) {
	// Soft allowlist: outside → gated (approve), inside → normal rules.
	soft := classifier(t, TierSafeActive, EnvStaging, false, RoE{
		EndpointAllowlist: []string{"/api/*"},
	})
	if d := soft.Classify("GET", "https://shop.test/marketing/home", 0); d.Action != ActionApprove {
		t.Errorf("outside soft allowlist should gate, got %s", d.Action)
	}
	if d := soft.Classify("GET", "https://shop.test/api/orders/7", 0); d.Action != ActionAuto {
		t.Errorf("inside allowlist GET should be auto, got %s", d.Action)
	}
	// Hard allowlist: outside → block.
	hard := classifier(t, TierSafeActive, EnvStaging, false, RoE{
		EndpointAllowlist: []string{"/api/*"},
		LimitToAllowlist:  true,
	})
	if d := hard.Classify("GET", "https://shop.test/marketing/home", 0); d.Action != ActionBlock {
		t.Errorf("outside hard allowlist should block, got %s (%s)", d.Action, d.Reason)
	}
}

func TestPathGlob(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/api/*", "/api/orders", true},
		{"/api/*", "/api", false}, // "/api/*" requires the trailing slash; use "/api*" or add "/api"
		{"/api*", "/api", true},
		{"/api/orders", "/api/orders", true},
		{"/api/orders", "/api/orders/7", false}, // exact, no wildcard
		{"/admin*", "/administrator", true},
		{"/x", "/y", false},
	}
	for _, c := range cases {
		if got := pathGlob(c.pattern, c.path); got != c.want {
			t.Errorf("pathGlob(%q,%q)=%v want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestProbePath(t *testing.T) {
	cases := map[string]string{
		"https://shop.test/api/orders/7?expand=1": "/api/orders/7",
		"http://shop.test/":                       "/",
		"https://shop.test":                       "/",
		"/api/relative":                           "/api/relative",
	}
	for in, want := range cases {
		if got := probePath(in); got != want {
			t.Errorf("probePath(%q)=%q want %q", in, got, want)
		}
	}
}
