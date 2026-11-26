package agent

import (
	"strings"
	"testing"

	"github.com/dev-zeph/trojan/internal/graph"
)

// Node files reach the whitebox-agent model project-relative, never with the
// home folder in them.
func TestModelFile(t *testing.T) {
	cases := []struct {
		n    graph.Node
		want string
	}{
		{graph.Node{File: "/Users/alice/shop/src/app.js", Key: "src/app.js#GET /u"}, "src/app.js"},
		{graph.Node{File: "/Users/alice/shop/app.js", Key: "app.js#app"}, "app.js"},
		{graph.Node{File: "/Users/alice/shop/src/app.js", Key: "other.js#x"}, "app.js"},
		{graph.Node{File: "/Users/alice/shop/src/app.js"}, "app.js"},
		{graph.Node{File: "src/app.js", Key: "src/app.js#x"}, "src/app.js"},
		{graph.Node{}, ""},
	}
	for _, c := range cases {
		if got := modelFile(c.n); got != c.want {
			t.Errorf("modelFile(%+v) = %q, want %q", c.n, got, c.want)
		}
	}
	v := viewOf(graph.Node{File: "/Users/alice/shop/src/app.js", Key: "src/app.js#GET /u", Line: 7})
	if v.File != "src/app.js" || v.Location != "src/app.js:7" || strings.Contains(v.File+v.Location, "alice") {
		t.Errorf("viewOf: %+v", v)
	}
}
