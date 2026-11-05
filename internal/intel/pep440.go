package intel

import (
	"fmt"
	"regexp"
	"strings"
)

// pep440Pattern is the VERSION_PATTERN from PyPA's `packaging` library, which
// accepts every spelling PEP 440 says to normalize (1.0-alpha.1, 1.0.post-2,
// 1.0-1, v1.0, ...).
var pep440Pattern = regexp.MustCompile(`^v?` +
	`(?:(?P<epoch>[0-9]+)!)?` +
	`(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?P<pre>[-_.]?(?P<pre_l>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?P<pre_n>[0-9]+)?)?` +
	`(?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]+)?))?` +
	`(?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]+)?)?` +
	`(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`)

var pep440Groups = func() map[string]int {
	m := map[string]int{}
	for i, n := range pep440Pattern.SubexpNames() {
		if n != "" {
			m[n] = i
		}
	}
	return m
}()

// pep440 is a parsed PEP 440 version. Numeric components are decimal strings
// without leading zeros (compared by compareNumStr, so no overflow).
type pep440 struct {
	epoch   string
	release []string // trailing zeros removed: 1.0.0 == 1
	hasPre  bool
	preRank int // 0=a, 1=b, 2=rc
	preN    string
	hasPost bool
	postN   string
	hasDev  bool
	devN    string
	local   string // kept for display; ignored for ordering
}

// parsePEP440 parses a Python package version.
func parsePEP440(s string) (pep440, error) {
	in := strings.ToLower(strings.TrimSpace(s))
	m := pep440Pattern.FindStringSubmatch(in)
	if m == nil {
		return pep440{}, fmt.Errorf("invalid PEP 440 version %q", s)
	}
	g := func(name string) string { return m[pep440Groups[name]] }
	num := func(x string) string {
		if x == "" {
			return "0"
		}
		return trimZeros(x)
	}

	v := pep440{epoch: num(g("epoch")), local: g("local")}
	for _, p := range strings.Split(g("release"), ".") {
		v.release = append(v.release, trimZeros(p))
	}
	for len(v.release) > 1 && v.release[len(v.release)-1] == "0" {
		v.release = v.release[:len(v.release)-1]
	}
	if g("pre") != "" {
		v.hasPre = true
		switch g("pre_l") {
		case "a", "alpha":
			v.preRank = 0
		case "b", "beta":
			v.preRank = 1
		default: // rc, c, pre, preview
			v.preRank = 2
		}
		v.preN = num(g("pre_n"))
	}
	if g("post") != "" {
		v.hasPost = true
		n := g("post_n1")
		if n == "" {
			n = g("post_n2")
		}
		v.postN = num(n)
	}
	if g("dev") != "" {
		v.hasDev = true
		v.devN = num(g("dev_n"))
	}
	return v, nil
}

// comparePEP440 orders two versions per PEP 440 (local labels ignored):
// epoch, release, then pre (a dev-only release sorts before any pre-release of
// it; no pre sorts after all pre-releases), post (none sorts first), dev (none
// sorts last).
func comparePEP440(a, b pep440) int {
	if c := compareNumStr(a.epoch, b.epoch); c != 0 {
		return c
	}
	for i := 0; i < len(a.release) || i < len(b.release); i++ {
		x, y := "0", "0"
		if i < len(a.release) {
			x = a.release[i]
		}
		if i < len(b.release) {
			y = b.release[i]
		}
		if c := compareNumStr(x, y); c != 0 {
			return c
		}
	}
	if c := cmpPre(a, b); c != 0 {
		return c
	}
	// post: absent < present
	switch {
	case a.hasPost && !b.hasPost:
		return 1
	case !a.hasPost && b.hasPost:
		return -1
	case a.hasPost && b.hasPost:
		if c := compareNumStr(a.postN, b.postN); c != 0 {
			return c
		}
	}
	// dev: present < absent
	switch {
	case a.hasDev && !b.hasDev:
		return -1
	case !a.hasDev && b.hasDev:
		return 1
	case a.hasDev && b.hasDev:
		return compareNumStr(a.devN, b.devN)
	}
	return 0
}

// preKey maps the pre-release segment to a sortable class:
// 0 = dev-only release (1.0.dev1: before every 1.0 pre-release),
// 1 = real pre-release, 2 = no pre-release.
func preKey(v pep440) int {
	switch {
	case v.hasPre:
		return 1
	case v.hasDev && !v.hasPost:
		return 0
	}
	return 2
}

func cmpPre(a, b pep440) int {
	ka, kb := preKey(a), preKey(b)
	if ka != kb {
		if ka < kb {
			return -1
		}
		return 1
	}
	if ka != 1 {
		return 0
	}
	if a.preRank != b.preRank {
		if a.preRank < b.preRank {
			return -1
		}
		return 1
	}
	return compareNumStr(a.preN, b.preN)
}
