package redact

import (
	"encoding/base64"
	"regexp"
	"unicode/utf8"
)

// reB64Blob matches a standalone base64 or base64url run long enough to
// hide a vendor key. One wrapping level only; see the package limits comment.
var reB64Blob = regexp.MustCompile(`[A-Za-z0-9+/_\-]{20,}={0,2}`)

// findBase64Wrapped looks for base64 (or base64url) blobs in text whose
// decoded payload itself contains a detected secret, and returns a secret
// covering the original blob. already-taken spans are skipped. The inner
// search does not unwrap further wrappers.
func findBase64Wrapped(text string, taken func(s, e int) bool) []Secret {
	if text == "" {
		return nil
	}
	var out []Secret
	for _, m := range reB64Blob.FindAllStringIndex(text, -1) {
		s, e := m[0], m[1]
		if taken != nil && taken(s, e) {
			continue
		}
		blob := text[s:e]
		decoded := tryBase64Decode(blob)
		if decoded == "" || decoded == blob {
			continue
		}
		inner := findSecrets(decoded, false)
		if len(inner) == 0 {
			continue
		}
		if taken != nil && taken(s, e) {
			continue
		}
		out = append(out, Secret{Start: s, End: e, Value: blob, Type: inner[0].Type})
	}
	return out
}

// tryBase64Decode decodes s as standard or URL-safe base64, with or without
// padding. The result is returned only when it looks like text (so a random
// binary blob is not searched for secrets).
func tryBase64Decode(s string) string {
	if s == "" {
		return ""
	}
	// Raw encodings accept input with or without padding once "=" is trimmed.
	trimmed := trimBase64Pad(s)
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding} {
		b, err := enc.DecodeString(trimmed)
		if err != nil || len(b) == 0 {
			continue
		}
		if looksDecodedText(b) {
			return string(b)
		}
	}
	return ""
}

func trimBase64Pad(s string) string {
	for len(s) > 0 && s[len(s)-1] == '=' {
		s = s[:len(s)-1]
	}
	return s
}

func looksDecodedText(b []byte) bool {
	if len(b) == 0 || !utf8.Valid(b) {
		return false
	}
	ctrl := 0
	for _, c := range b {
		if c < 0x09 || (c > 0x0d && c < 0x20) {
			ctrl++
		}
	}
	return ctrl*4 < len(b)
}
