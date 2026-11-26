package redact

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// decodeShadow returns a copy of s with URL percent-escapes, JSON \uXXXX
// and \xNN / backslash-quote escapes, and a small set of HTML entities unescaped, plus a map from each
// decoded byte offset (and one past the end) to the corresponding original
// byte offset. The original string is not modified; callers use the map to
// place masks back on s.
func decodeShadow(s string) (string, []int) {
	if s == "" {
		return "", []int{0}
	}
	var b strings.Builder
	b.Grow(len(s))
	toOrig := make([]int, 0, len(s)+1)
	i := 0
	for i < len(s) {
		if s[i] == '%' && i+2 < len(s) && isHexByte(s[i+1]) && isHexByte(s[i+2]) {
			v := unhexByte(s[i+1], s[i+2])
			toOrig = append(toOrig, i)
			b.WriteByte(v)
			i += 3
			continue
		}
		if s[i] == '\\' && i+5 < len(s) && (s[i+1] == 'u' || s[i+1] == 'U') && isHex4(s[i+2:i+6]) {
			r, err := strconv.ParseInt(s[i+2:i+6], 16, 32)
			if err == nil {
				start := i
				var buf [utf8.UTFMax]byte
				n := utf8.EncodeRune(buf[:], rune(r))
				for j := 0; j < n; j++ {
					toOrig = append(toOrig, start)
				}
				b.Write(buf[:n])
				i += 6
				continue
			}
		}
		if s[i] == '\\' && i+3 < len(s) && (s[i+1] == 'x' || s[i+1] == 'X') && isHexByte(s[i+2]) && isHexByte(s[i+3]) {
			toOrig = append(toOrig, i)
			b.WriteByte(unhexByte(s[i+2], s[i+3]))
			i += 4
			continue
		}
		if s[i] == '\\' && i+1 < len(s) {
			n := s[i+1]
			if n == '"' || n == '\'' || n == '\\' || n == '/' {
				toOrig = append(toOrig, i)
				b.WriteByte(n)
				i += 2
				continue
			}
		}
		if s[i] == '&' {
			if repl, n := htmlEntityAt(s, i); n > 0 {
				start := i
				for j := 0; j < len(repl); j++ {
					toOrig = append(toOrig, start)
				}
				b.WriteString(repl)
				i += n
				continue
			}
		}
		toOrig = append(toOrig, i)
		b.WriteByte(s[i])
		i++
	}
	toOrig = append(toOrig, len(s))
	return b.String(), toOrig
}

// decodeShadowN applies decodeShadow up to n times so a double-encoded
// value (for example %2522) is still visible to detectors. The offset map
// always points at the original string.
func decodeShadowN(s string, n int) (string, []int) {
	dec, m := decodeShadow(s)
	for pass := 1; pass < n; pass++ {
		next, m2 := decodeShadow(dec)
		if next == dec {
			break
		}
		composed := make([]int, len(m2))
		last := len(m) - 1
		for i, idx := range m2 {
			if idx < 0 {
				idx = 0
			}
			if idx > last {
				idx = last
			}
			composed[i] = m[idx]
		}
		dec, m = next, composed
	}
	return dec, m
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isHex4(s string) bool {
	return len(s) >= 4 && isHexByte(s[0]) && isHexByte(s[1]) && isHexByte(s[2]) && isHexByte(s[3])
}

func unhexByte(a, b byte) byte {
	return unhexNibble(a)<<4 | unhexNibble(b)
}

func unhexNibble(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func htmlEntityAt(s string, i int) (string, int) {
	if i >= len(s) || s[i] != '&' {
		return "", 0
	}
	// Named entities we care about for secret boundaries and URL params.
	named := []struct {
		lit, repl string
	}{
		{"&amp;", "&"},
		{"&lt;", "<"},
		{"&gt;", ">"},
		{"&quot;", "\""},
		{"&apos;", "'"},
	}
	rest := s[i:]
	lower := strings.ToLower(rest)
	for _, e := range named {
		if strings.HasPrefix(lower, e.lit) {
			return e.repl, len(e.lit)
		}
	}
	// Numeric: &#34; or &#x22;
	if len(rest) > 3 && rest[1] == '#' {
		end := strings.IndexByte(rest, ';')
		if end > 2 && end <= 10 {
			body := rest[2:end]
			base := 10
			if body[0] == 'x' || body[0] == 'X' {
				base = 16
				body = body[1:]
			}
			if body != "" {
				if n, err := strconv.ParseInt(body, base, 32); err == nil && n >= 0 && n <= int64(0x10ffff) {
					return string(rune(n)), end + 1
				}
			}
		}
	}
	return "", 0
}

// mapDecodedSpan translates a [start,end) span in decoded into original offsets.
func mapDecodedSpan(toOrig []int, start, end int) (int, int) {
	if len(toOrig) == 0 {
		return start, end
	}
	last := len(toOrig) - 1
	if start < 0 {
		start = 0
	}
	if end < start {
		end = start
	}
	if start > last {
		start = last
	}
	if end > last {
		end = last
	}
	return toOrig[start], toOrig[end]
}

// extendRun grows end through consecutive bytes that are not in stop.
// A cap of 0 or less means "to the next delimiter or the end of the
// string": redaction must be length-independent, and a delimiter set
// already keeps the walk linear.
func extendRun(text string, end int, stop string, cap int) int {
	if stop == "" || end >= len(text) {
		return end
	}
	limit := len(text)
	if cap > 0 && end+cap < limit {
		limit = end + cap
	}
	for end < limit {
		c := text[end]
		if strings.IndexByte(stop, c) >= 0 {
			break
		}
		end++
	}
	return end
}

// includeDanglingQuote reports whether a match at [start,end) is followed by
// a " that is not a wrapping pair, so the quote should be consumed with the
// replacement and not left after the label.
func includeDanglingQuote(text string, start, end int) bool {
	if end >= len(text) || text[end] != '"' {
		return false
	}
	if start > 0 && text[start-1] == '"' {
		return false
	}
	return true
}
