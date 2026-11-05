package intel

import (
	"encoding/json"
	"testing"
)

func TestSemverCompare(t *testing.T) {
	// Each list is strictly ascending.
	ordered := [][]string{
		// SemVer 2.0 §11 example.
		{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"},
		{"0.0.1", "0.1.0", "0.9.9", "0.10.0", "1.0.0", "1.2.3", "1.10.0", "2.0.0", "10.0.0"},
		{"14.0.0", "14.2.24", "14.2.25", "15.0.0-canary.1", "15.0.0-rc.0", "15.0.0", "15.2.2"},
		{"1.0.0-2", "1.0.0-10", "1.0.0-a"},
		{"1.0.0", "99999999999999999999.0.0"},
	}
	for _, list := range ordered {
		for i := 0; i < len(list)-1; i++ {
			for j := i + 1; j < len(list); j++ {
				a, _ := parseSemver(list[i])
				b, _ := parseSemver(list[j])
				if compareSemver(a, b) != -1 || compareSemver(b, a) != 1 {
					t.Errorf("want %s < %s", list[i], list[j])
				}
			}
		}
	}
	equal := [][2]string{{"v1.2.3", "1.2.3"}, {"1.2.3+build.5", "1.2.3"}, {"1.2", "1.2.0"}, {"=1.0.0", "1.0.0"}, {"01.2.3", "1.2.3"}}
	for _, e := range equal {
		if c, ok := CompareVersions("npm", e[0], e[1]); !ok || c != 0 {
			t.Errorf("want %s == %s (c=%d ok=%v)", e[0], e[1], c, ok)
		}
	}
	for _, bad := range []string{"", "latest", "1.2.3.4", "1.x", "git+https://x", "1.0.0-", "1.0.0-a..b", "^1.0.0"} {
		if _, err := parseSemver(bad); err == nil {
			t.Errorf("parseSemver(%q) should fail", bad)
		}
	}
}

func TestPEP440Compare(t *testing.T) {
	// The ordering example from PEP 440 plus epochs and local labels.
	ordered := []string{
		"1.0.dev456", "1.0a1", "1.0a2.dev456", "1.0a12.dev456", "1.0a12",
		"1.0b1.dev456", "1.0b2", "1.0b2.post345.dev456", "1.0b2.post345",
		"1.0rc1.dev456", "1.0rc1", "1.0", "1.0.post456.dev34", "1.0.post456",
		"1.0.15", "1.1.dev1", "1.1", "1.10", "2!0.1",
	}
	for i := 0; i < len(ordered)-1; i++ {
		for j := i + 1; j < len(ordered); j++ {
			a, err1 := parsePEP440(ordered[i])
			b, err2 := parsePEP440(ordered[j])
			if err1 != nil || err2 != nil {
				t.Fatalf("parse: %v %v", err1, err2)
			}
			if comparePEP440(a, b) != -1 || comparePEP440(b, a) != 1 {
				t.Errorf("want %s < %s", ordered[i], ordered[j])
			}
		}
	}
	equal := [][2]string{
		{"1.0", "1.0.0"}, {"1.0.0.0", "1"}, {"v1.0", "1.0"}, {"1.0-alpha.1", "1.0a1"}, {"1.0c1", "1.0rc1"},
		{"1.0-1", "1.0.post1"}, {"1.0.rev1", "1.0.post1"}, {"1.0-dev", "1.0.dev0"}, {"1.0+ubuntu.1", "1.0"},
		{"0!1.0", "1.0"}, {"1.0PRE1", "1.0rc1"}, {"01.02", "1.2"},
	}
	for _, e := range equal {
		if c, ok := CompareVersions("pypi", e[0], e[1]); !ok || c != 0 {
			t.Errorf("want %s == %s (c=%d ok=%v)", e[0], e[1], c, ok)
		}
	}
	for _, bad := range []string{"", "1.0-", "abc", "1.0.x", "==1.0"} {
		if _, err := parsePEP440(bad); err == nil {
			t.Errorf("parsePEP440(%q) should fail", bad)
		}
	}
}

func ranges(t *testing.T, js string) Ranges {
	t.Helper()
	var r Ranges
	if err := json.Unmarshal([]byte(js), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func strp(s string) *string { return &s }

func TestAdvisoryAffects(t *testing.T) {
	// Next.js-style: four release lines each with their own fix, events in one
	// range and deliberately not in version order.
	nextRanges := `[{"type":"SEMVER","events":[
		{"introduced":"15.0.0"},{"fixed":"15.2.3"},
		{"introduced":"11.1.4"},{"fixed":"12.3.5"},
		{"introduced":"13.0.0"},{"fixed":"13.5.9"},
		{"introduced":"14.0.0"},{"fixed":"14.2.25"}]}]`
	type tc struct {
		version string
		want    bool
		fix     string
	}
	tests := []struct {
		name  string
		adv   Advisory
		cases []tc
	}{
		{"next multi-line", Advisory{Ecosystem: "npm", AffectedRanges: ranges(t, nextRanges), FixedVersion: strp("15.2.3")}, []tc{
			{"11.1.3", false, ""}, {"11.1.4", true, "12.3.5"}, {"12.3.4", true, "12.3.5"}, {"12.3.5", false, ""},
			{"12.9.0", false, ""}, {"13.4.0", true, "13.5.9"}, {"13.5.9", false, ""},
			{"14.1.0", true, "14.2.25"}, {"14.2.25", false, ""}, {"14.3.0-canary.1", false, ""},
			{"15.0.0-rc.1", false, ""}, {"15.0.0", true, "15.2.3"}, {"15.2.2", true, "15.2.3"}, {"15.2.3", false, ""},
			{"15.3.0", false, ""},
		}},
		{"separate ranges", Advisory{Ecosystem: "npm", AffectedRanges: ranges(t, `[
			{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]},
			{"type":"SEMVER","events":[{"introduced":"5.0.0-beta.1"},{"fixed":"5.0.1"}]}]`)}, []tc{
			{"0.0.1", true, "4.17.21"}, {"4.17.20", true, "4.17.21"}, {"4.17.21", false, ""},
			{"5.0.0-alpha", false, ""}, {"5.0.0-beta.1", true, "5.0.1"}, {"5.0.0", true, "5.0.1"}, {"5.0.1", false, ""},
		}},
		{"last_affected", Advisory{Ecosystem: "npm", AffectedRanges: ranges(t,
			`[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"last_affected":"1.4.2"}]}]`)}, []tc{
			{"0.9.0", false, ""}, {"1.0.0", true, ""}, {"1.4.2", true, ""}, {"1.4.3-rc.1", false, ""}, {"1.4.3", false, ""},
		}},
		{"introduced only (unfixed)", Advisory{Ecosystem: "npm", AffectedRanges: ranges(t,
			`{"type":"SEMVER","events":[{"introduced":"2.0.0"}]}`)}, []tc{
			{"1.9.9", false, ""}, {"2.0.0", true, ""}, {"99.0.0", true, ""},
		}},
		{"fixed only treated as from 0", Advisory{Ecosystem: "npm", AffectedRanges: ranges(t,
			`[{"type":"SEMVER","events":[{"fixed":"1.2.0"}]}]`)}, []tc{
			{"0.0.0", true, "1.2.0"}, {"1.1.9", true, "1.2.0"}, {"1.2.0", false, ""},
		}},
		{"git ranges ignored, versions list used", Advisory{Ecosystem: "npm",
			AffectedRanges:   ranges(t, `[{"type":"GIT","repo":"x","events":[{"introduced":"0"},{"fixed":"abc123"}]}]`),
			AffectedVersions: []string{"3.3.6", "v3.3.7"}}, []tc{
			{"3.3.6", true, ""}, {"3.3.7", true, ""}, {"3.3.5", false, ""},
		}},
		{"fixed_version fallback", Advisory{Ecosystem: "npm", FixedVersion: strp("2.0.0")}, []tc{
			{"1.9.0", true, "2.0.0"}, {"2.0.0", false, ""},
		}},
		{"malicious, no range data", Advisory{Ecosystem: "npm", Kind: "malicious"}, []tc{
			{"1.0.0", true, ""}, {"0.0.1-x", true, ""},
		}},
		{"vulnerability, no range data", Advisory{Ecosystem: "npm", Kind: "vulnerability"}, []tc{
			{"1.0.0", false, ""},
		}},
		{"pypi pre/post/dev", Advisory{Ecosystem: "PyPI", AffectedRanges: ranges(t,
			`[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.2.8"},{"introduced":"5.0a1"},{"fixed":"5.0.1"}]}]`)}, []tc{
			{"4.2.7", true, "4.2.8"}, {"4.2.8.dev1", true, "4.2.8"}, {"4.2.8rc1", true, "4.2.8"}, {"4.2.8", false, ""},
			{"4.2.8.post1", false, ""}, {"5.0.dev0", false, ""}, {"5.0a1", true, "5.0.1"}, {"5.0", true, "5.0.1"},
			{"5.0.1+local", false, ""}, {"5.0.1", false, ""},
		}},
		{"pypi affected_versions normalized", Advisory{Ecosystem: "pypi", AffectedVersions: []string{"1.0.0", "2.0rc1"}}, []tc{
			{"1.0", true, ""}, {"2.0.0rc1", true, ""}, {"2.0", false, ""},
		}},
	}
	for _, tt := range tests {
		for _, c := range tt.cases {
			got, fix := tt.adv.AffectsVersion(c.version)
			if got != c.want {
				t.Errorf("%s: %s affected=%v, want %v", tt.name, c.version, got, c.want)
				continue
			}
			wantFix := c.fix
			if c.want && wantFix == "" && tt.adv.FixedVersion != nil {
				wantFix = *tt.adv.FixedVersion
			}
			if got && fix != wantFix {
				t.Errorf("%s: %s fix=%q, want %q", tt.name, c.version, fix, wantFix)
			}
		}
	}
}

func TestRangesUnmarshalLenient(t *testing.T) {
	for _, js := range []string{`null`, `[]`, `{"type":"SEMVER","events":[]}`} {
		var r Ranges
		if err := json.Unmarshal([]byte(js), &r); err != nil {
			t.Errorf("%s: %v", js, err)
		}
	}
	var refs Refs
	if err := json.Unmarshal([]byte(`["https://a", {"type":"WEB","url":"https://b"}]`), &refs); err != nil || len(refs) != 2 || refs[1].URL != "https://b" {
		t.Errorf("refs = %+v %v", refs, err)
	}
}

func TestJSONCToJSONParses(t *testing.T) {
	in := `{"a": "x, }", // c
	"b": [1, 2,], /* d */ "c": {"e": 1,},}`
	var v map[string]any
	if err := json.Unmarshal(jsoncToJSON([]byte(in)), &v); err != nil {
		t.Fatal(err)
	}
	if v["a"] != "x, }" {
		t.Errorf("string mangled: %v", v["a"])
	}
}
