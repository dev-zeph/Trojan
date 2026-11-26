package dast

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Assembled at runtime so no literal key-shaped string sits in the repo.
var (
	urlAPIKey   = "IfuK" + "P6oZZjAvJV3UEdmKtwgFxg9KGWWc"
	urlToken    = "eyJh" + "bGciOiJIUzI1NiJ9." + "eyJzd" + "WIiOiIxIn0." + "dGVzdHNpZ25hdHVyZXRlc3Q"
	urlPassword = "S3cr" + "3tPa55w0rd99"
	urlPathTok  = "aB3d" + "E9fG2hJ4kL6mN8pQ0rS2tU4vW6x"
)

func TestRedactURLKeepsShapeAndMasksSecrets(t *testing.T) {
	in := "https://api.example.com/v1/data?api_key=" + urlAPIKey + "&user=1"
	got := RedactURL(in)
	if strings.Contains(got, urlAPIKey) {
		t.Fatalf("api_key leaked: %s", got)
	}
	if !strings.Contains(got, "https://api.example.com/v1/data?") || !strings.Contains(got, "user=1") || !strings.Contains(got, "api_key=") {
		t.Fatalf("shape lost: %s", got)
	}
	if !strings.Contains(got, "<SECRET removed by Trojan:") || !strings.Contains(got, "type=url_query") {
		t.Fatalf("expected descriptor in query: %s", got)
	}
}

func TestRedactURLUserinfoAndHighEntropyPath(t *testing.T) {
	in := "https://app:" + urlPassword + "@app.example.com/sessions/" + urlToken + "/edit"
	got := RedactURL(in)
	if strings.Contains(got, urlPassword) || strings.Contains(got, urlToken) {
		t.Fatalf("userinfo or path token leaked: %s", got)
	}
	if !strings.Contains(got, "https://app:") || !strings.Contains(got, "@app.example.com/sessions/") || !strings.HasSuffix(got, "/edit") {
		t.Fatalf("path shape lost: %s", got)
	}
	if !strings.Contains(got, "type=url_password") {
		t.Fatalf("password should be labelled: %s", got)
	}
}

func TestRedactURLEmptyUserRedis(t *testing.T) {
	pw := "k6zc" + "bWUsNNA2l7xErhJM"
	in := "redis://:" + pw + "@cache:6379/0"
	got := RedactURL(in)
	if strings.Contains(got, pw) {
		t.Fatalf("redis password leaked: %s", got)
	}
	if !strings.Contains(got, "redis://:") || !strings.Contains(got, "@cache:6379/0") {
		t.Fatalf("redis shape lost: %s", got)
	}
}

func TestRedactURLLeavesOrdinaryIDs(t *testing.T) {
	in := "https://app.example.com/users/42/orders/550e8400-e29b-41d4-a716-446655440000?page=2"
	if got := RedactURL(in); got != in {
		t.Fatalf("ordinary route was rewritten: %s", got)
	}
}

func TestRedactTemplateRequestAndCacheKey(t *testing.T) {
	req := TemplateRequest{
		TargetURL: "https://app.example.com/login?token=" + urlAPIKey,
		Endpoints: []Endpoint{
			{Method: "GET", URL: "https://app.example.com/v1?access_token=" + urlAPIKey, QueryParams: []string{"access_token"}},
			{Method: "POST", URL: "https://app:" + urlPassword + "@app.example.com/admin"},
		},
		TechHints:    []string{"nextjs"},
		MaxTemplates: 10,
	}
	safe := RedactTemplateRequest(req)
	body, err := json.Marshal(safe)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(body)
	for _, secret := range []string{urlAPIKey, urlPassword} {
		if strings.Contains(raw, secret) {
			t.Fatalf("secret %q in marshaled request", secret)
		}
	}
	// Original request is unchanged.
	if req.TargetURL != "https://app.example.com/login?token="+urlAPIKey {
		t.Fatal("input request was modified")
	}

	h1 := crawlHash(safe)
	h2 := crawlHash(RedactTemplateRequest(req))
	if h1 != h2 {
		t.Fatalf("cache key is not deterministic: %s vs %s", h1, h2)
	}
	// The cache key must be the hash of the redacted request, not the raw one.
	if h1 == crawlHash(req) {
		t.Fatal("cache key hashed the unredacted request")
	}
	if strings.Contains(fmt.Sprintf("%x", md5.Sum([]byte(req.TargetURL))), h1) {
		t.Fatal("sanity")
	}
	if !strings.Contains(safe.TargetURL, "<SECRET removed by Trojan:") {
		t.Fatalf("target URL not labelled: %s", safe.TargetURL)
	}
	// Query param names are preserved for template generation.
	if safe.Endpoints[0].QueryParams[0] != "access_token" {
		t.Fatal("query param names should be unchanged")
	}
}
