// Package outbound keeps the user's folders out of what Trojan sends to its
// servers (and so to the AI model behind them). Absolute paths name the home
// folder, which is usually the user's name: /Users/alice/clients/acme-shop.
// Requests send paths relative to the project, or just a folder name, and as
// a last step every JSON body has the project folder and the home folder
// removed, so a path that slips through a new field still doesn't leave.
package outbound

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/dev-zeph/trojan/internal/normalizer"
)

// FolderName is the last element of a folder path ("acme-shop"), for requests
// that name the project. "" stays "". Both / and \ count as separators, so a
// Windows path from a saved scan works on any OS.
func FolderName(p string) string {
	p = strings.TrimRight(strings.TrimSpace(p), `/\`)
	if p == "" {
		return ""
	}
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	if p == "" || strings.HasSuffix(p, ":") { // "/" or "C:\"
		return ""
	}
	return p
}

// isURL reports whether p is a web address (website findings keep theirs).
func isURL(p string) bool {
	l := strings.ToLower(p)
	return strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") ||
		strings.HasPrefix(l, "ws://") || strings.HasPrefix(l, "wss://")
}

// isAbs is filepath.IsAbs plus Windows drive and UNC paths on any OS.
func isAbs(p string) bool {
	if filepath.IsAbs(p) || strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\\`) {
		return true
	}
	return len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') &&
		((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z'))
}

// slash turns every separator into "/", Windows ones included, on any OS.
func slash(p string) string { return strings.ReplaceAll(p, `\`, "/") }

// RelPath is p as it may be sent: relative to root ("src/a.ts", or "." for
// root itself), or just the file name when an absolute p is outside root.
// Relative paths and web addresses are returned as they are.
func RelPath(root, p string) string {
	if p == "" || isURL(p) || !isAbs(p) {
		return p
	}
	if root != "" {
		r := strings.TrimRight(slash(root), "/")
		q := slash(p)
		if r != "" && strings.EqualFold(q, r) {
			return "."
		}
		if r != "" && strings.HasPrefix(q, r+"/") {
			return strings.TrimPrefix(q, r+"/")
		}
	}
	return FolderName(p)
}

// Findings returns a copy of fs with FilePath and SourceFile made safe to send
// (RelPath against root). The caller's slice is not changed.
func Findings(root string, fs []normalizer.Finding) []normalizer.Finding {
	out := make([]normalizer.Finding, len(fs))
	for i, f := range fs {
		f.FilePath = RelPath(root, f.FilePath)
		f.SourceFile = RelPath(root, f.SourceFile)
		out[i] = f
	}
	return out
}

// homeDir is a variable so tests can set it.
var homeDir = func() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

// jsonEscaped is s as it appears inside a JSON string.
func jsonEscaped(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}

// isNameByte reports whether c can continue a file or folder name, so
// "/Users/al" is not taken as a prefix of "/Users/alice".
func isNameByte(c byte) bool {
	return c == '.' || c == '-' || c == '_' || c >= 0x80 ||
		(c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// continuesName reports whether rest (the text right after a folder path)
// carries on that folder's name. A full stop counts only when a name follows
// it, so "/Users/alice." at the end of a sentence is still the home folder.
func continuesName(rest string) bool {
	if rest == "" || !isNameByte(rest[0]) {
		return false
	}
	if rest[0] == '.' {
		return len(rest) > 1 && isNameByte(rest[1]) && rest[1] != '.'
	}
	return true
}

// replaceDir replaces dir inside a JSON body: dir followed by a separator
// becomes sub (with no separator when sub is ""), and dir on its own becomes
// bare. Occurrences that are the start of a longer name are left alone.
func replaceDir(body, dir, sub, bare string) string {
	if dir == "" {
		return body
	}
	var b strings.Builder
	for {
		i := strings.Index(body, dir)
		if i < 0 {
			b.WriteString(body)
			return b.String()
		}
		b.WriteString(body[:i])
		rest := body[i+len(dir):]
		switch {
		case strings.HasPrefix(rest, "/"):
			b.WriteString(sub)
			if sub != "" {
				b.WriteString("/")
			}
			body = rest[1:]
		case strings.HasPrefix(rest, `\\`): // an escaped Windows separator
			b.WriteString(sub)
			if sub != "" {
				b.WriteString(`\\`)
			}
			body = rest[2:]
		case continuesName(rest):
			b.WriteString(dir) // part of a longer name
			body = rest
		default:
			b.WriteString(bare)
			body = rest
		}
	}
}

// ScrubJSON removes the project folder (root, when known) and the home folder
// from a JSON request body: "<root>/src/a.ts" becomes "src/a.ts", "<root>"
// becomes ".", "<home>/x" becomes "~/x" and "<home>" becomes "~". Apply it to
// the JSON before any base64 wrapping. Folders shorter than 4 characters ("/",
// "C:\") are ignored, so nothing else is rewritten.
func ScrubJSON(body []byte, root string) []byte {
	s := string(body)
	clean := func(d string) string {
		d = strings.TrimRight(d, `/\`)
		if len(d) < 4 {
			return ""
		}
		return d
	}
	if r := clean(root); r != "" {
		s = replaceDir(s, jsonEscaped(r), "", ".")
	}
	if h := clean(homeDir()); h != "" {
		s = replaceDir(s, jsonEscaped(h), "~", "~")
	}
	return []byte(s)
}
