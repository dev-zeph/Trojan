package agent

import "testing"

func TestNewEnvelopeInvariants(t *testing.T) {
	if _, err := NewEnvelope(TierPassive, EnvProduction, "", false); err == nil {
		t.Error("empty host should be rejected")
	}
	if _, err := NewEnvelope(TierAggressive, EnvProduction, "example.com", false); err == nil {
		t.Error("aggressive tier on production should be rejected")
	}
	if _, err := NewEnvelope(TierAggressive, EnvStaging, "example.com", false); err != nil {
		t.Errorf("aggressive tier on staging should be allowed: %v", err)
	}
	e, err := NewEnvelope(TierPassive, EnvProduction, "Example.COM", false)
	if err != nil {
		t.Fatal(err)
	}
	if e.Host != "example.com" {
		t.Errorf("host not normalized: %q", e.Host)
	}
}

func TestValidateProbeMethodTiers(t *testing.T) {
	const host = "app.example.com"
	url := "https://" + host + "/x"

	mustEnv := func(tier Tier, env Environment, ack bool) *Envelope {
		e, err := NewEnvelope(tier, env, host, ack)
		if err != nil {
			t.Fatalf("NewEnvelope: %v", err)
		}
		return e
	}

	cases := []struct {
		name    string
		env     *Envelope
		method  string
		wantErr bool
	}{
		{"GET passive", mustEnv(TierPassive, EnvProduction, false), "GET", false},
		{"HEAD passive", mustEnv(TierPassive, EnvProduction, false), "HEAD", false},
		{"OPTIONS passive", mustEnv(TierPassive, EnvProduction, false), "OPTIONS", false},
		{"lowercase get", mustEnv(TierPassive, EnvProduction, false), "get", false},

		{"DELETE rejected passive", mustEnv(TierPassive, EnvProduction, false), "DELETE", true},
		{"PUT rejected safe-active", mustEnv(TierSafeActive, EnvStaging, false), "PUT", true},
		{"PATCH rejected aggressive", mustEnv(TierAggressive, EnvStaging, false), "PATCH", true},
		{"TRACE rejected", mustEnv(TierSafeActive, EnvStaging, false), "TRACE", true},

		{"POST rejected in passive", mustEnv(TierPassive, EnvStaging, false), "POST", true},
		{"POST ok safe-active staging", mustEnv(TierSafeActive, EnvStaging, false), "POST", false},
		{"POST prod without ack rejected", mustEnv(TierSafeActive, EnvProduction, false), "POST", true},
		{"POST prod with ack ok", mustEnv(TierSafeActive, EnvProduction, true), "POST", false},
		{"POST aggressive staging ok", mustEnv(TierAggressive, EnvStaging, false), "POST", false},
	}
	for _, c := range cases {
		err := c.env.ValidateProbe(c.method, url, 0)
		if c.wantErr && err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
		if !c.wantErr && err != nil {
			t.Errorf("%s: unexpected error: %v", c.name, err)
		}
	}
}

func TestValidateProbeSameHost(t *testing.T) {
	e, _ := NewEnvelope(TierPassive, EnvProduction, "app.example.com", false)
	if err := e.ValidateProbe("GET", "https://app.example.com/path", 0); err != nil {
		t.Errorf("same host should pass: %v", err)
	}
	if err := e.ValidateProbe("GET", "https://evil.example.com/path", 0); err == nil {
		t.Error("off-host probe should be rejected")
	}
	if err := e.ValidateProbe("GET", "https://app.example.com.attacker.net/", 0); err == nil {
		t.Error("look-alike host should be rejected")
	}
	if err := e.ValidateProbe("GET", "ftp://app.example.com/", 0); err == nil {
		t.Error("non-http scheme should be rejected")
	}
}

func TestValidateProbeBodySize(t *testing.T) {
	e, _ := NewEnvelope(TierSafeActive, EnvStaging, "h", false)
	e.MaxRequestBody = 10
	url := "https://h/x"
	if err := e.ValidateProbe("POST", url, 10); err != nil {
		t.Errorf("body at cap should pass: %v", err)
	}
	if err := e.ValidateProbe("POST", url, 11); err == nil {
		t.Error("oversized body should be rejected")
	}
}

func TestParseTierAndEnv(t *testing.T) {
	if tr, _ := ParseTier("safe-active"); tr != TierSafeActive {
		t.Error("parse safe-active")
	}
	if _, err := ParseTier("nonsense"); err == nil {
		t.Error("bad tier should error")
	}
	if env, _ := ParseEnvironment("staging"); env != EnvStaging {
		t.Error("parse staging")
	}
	// Unspecified environment defaults to the stricter production.
	if env, _ := ParseEnvironment(""); env != EnvProduction {
		t.Error("empty environment should default to production")
	}
}
