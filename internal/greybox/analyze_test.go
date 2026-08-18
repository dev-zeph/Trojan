package greybox

import (
	"reflect"
	"testing"
)

func TestAnalyze(t *testing.T) {
	tests := []struct {
		name   string
		code   string
		guards []string
		want   StructuralSummary
	}{
		{
			name: "raw sql concat, no auth -> IDOR/SQLi shape",
			code: `function getUser(req, res) {
				const id = req.params.id;
				return db.query("SELECT * FROM users WHERE id = " + id);
			}`,
			want: StructuralSummary{RawQuery: true, Calls: []string{"query"}},
		},
		{
			name:   "guard from resolver sets has_auth_check",
			code:   `function h(){ return ok() }`,
			guards: []string{"middleware"},
			want:   StructuralSummary{HasAuthCheck: true, Calls: []string{"ok"}},
		},
		{
			name: "sanitized input",
			code: `def create(req):
				clean = sanitize(req.body)
				save(clean)`,
			want: StructuralSummary{SanitizesInput: true, Calls: []string{"sanitize", "save"}},
		},
		{
			name: "reflects input -> XSS shape",
			code: `app.get('/x', (req,res) => { res.send(req.query.q) })`,
			want: StructuralSummary{ReflectsInput: true},
		},
		{
			name: "auth token in body",
			code: `function h(req){ const u = verifyToken(req.headers.authorization); return u }`,
			want: StructuralSummary{HasAuthCheck: true, Calls: []string{"verifyToken"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyze(tt.code, tt.guards)
			// Compare flags.
			if got.HasAuthCheck != tt.want.HasAuthCheck ||
				got.SanitizesInput != tt.want.SanitizesInput ||
				got.RawQuery != tt.want.RawQuery ||
				got.ReflectsInput != tt.want.ReflectsInput {
				t.Errorf("flags:\n got  auth=%v san=%v raw=%v refl=%v\n want auth=%v san=%v raw=%v refl=%v",
					got.HasAuthCheck, got.SanitizesInput, got.RawQuery, got.ReflectsInput,
					tt.want.HasAuthCheck, tt.want.SanitizesInput, tt.want.RawQuery, tt.want.ReflectsInput)
			}
			if tt.want.Calls != nil && !reflect.DeepEqual(got.Calls, tt.want.Calls) {
				t.Errorf("calls = %v, want %v", got.Calls, tt.want.Calls)
			}
		})
	}
}

func TestSymbolDefRegex(t *testing.T) {
	re := symbolDefRegex("getUser")
	matches := []string{
		"func getUser(id string) {",
		"function getUser(req, res) {",
		"  def getUser(self):",
		"const getUser = (req) => {",
		"const getUser = async function() {",
		"export const getUser = () => {",
	}
	for _, m := range matches {
		if !re.MatchString(m) {
			t.Errorf("expected match: %q", m)
		}
	}
	nonMatches := []string{
		"getUserProfile()",     // different symbol
		"return getUser(id)",   // a call, not a def
		"// getUser is great",  // comment mention
	}
	for _, m := range nonMatches {
		if re.MatchString(m) {
			t.Errorf("unexpected match: %q", m)
		}
	}
}
