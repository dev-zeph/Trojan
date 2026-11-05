package intel

import (
	"fmt"
	"strings"
)

// semver is a parsed SemVer 2.0.0 version. Numeric parts are kept as decimal
// strings (no leading zeros) so arbitrarily large components compare
// correctly without overflow.
type semver struct {
	major, minor, patch string
	pre                 []string // dot-separated prerelease identifiers
}

// parseSemver parses an npm-style version. It is lenient in the ways real
// lockfiles and advisories are: a leading "v" or "=" is stripped, missing
// minor/patch default to 0 ("1.2" == "1.2.0"), and build metadata ("+abc") is
// dropped since it never affects precedence.
func parseSemver(s string) (semver, error) {
	orig := s
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "=")
	s = strings.TrimPrefix(strings.TrimPrefix(s, "v"), "V")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var pre string
	if i := strings.IndexByte(s, '-'); i >= 0 {
		s, pre = s[:i], s[i+1:]
		if pre == "" {
			return semver{}, fmt.Errorf("invalid semver %q: empty prerelease", orig)
		}
	}
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return semver{}, fmt.Errorf("invalid semver %q", orig)
	}
	for len(parts) < 3 {
		parts = append(parts, "0")
	}
	for i, p := range parts {
		if !isDigits(p) {
			return semver{}, fmt.Errorf("invalid semver %q", orig)
		}
		parts[i] = trimZeros(p)
	}
	v := semver{major: parts[0], minor: parts[1], patch: parts[2]}
	if pre != "" {
		v.pre = strings.Split(pre, ".")
		for _, id := range v.pre {
			if id == "" {
				return semver{}, fmt.Errorf("invalid semver %q: empty prerelease identifier", orig)
			}
			for _, r := range id {
				if !(r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
					return semver{}, fmt.Errorf("invalid semver %q: bad prerelease identifier", orig)
				}
			}
		}
	}
	return v, nil
}

// compareSemver returns -1, 0 or 1 per SemVer 2.0.0 precedence (§11).
func compareSemver(a, b semver) int {
	if c := compareNumStr(a.major, b.major); c != 0 {
		return c
	}
	if c := compareNumStr(a.minor, b.minor); c != 0 {
		return c
	}
	if c := compareNumStr(a.patch, b.patch); c != 0 {
		return c
	}
	// A version without prerelease has higher precedence.
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		xn, yn := isDigits(x), isDigits(y)
		var c int
		switch {
		case xn && yn:
			c = compareNumStr(trimZeros(x), trimZeros(y))
		case xn: // numeric identifiers have lower precedence than alphanumeric
			c = -1
		case yn:
			c = 1
		default:
			c = strings.Compare(x, y)
		}
		if c != 0 {
			return c
		}
	}
	switch {
	case len(a.pre) < len(b.pre):
		return -1
	case len(a.pre) > len(b.pre):
		return 1
	}
	return 0
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func trimZeros(s string) string {
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}

// compareNumStr compares two non-negative decimal strings without leading zeros.
func compareNumStr(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}
