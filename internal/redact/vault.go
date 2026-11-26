package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Vault redacts with stable references (ref=S1, S2, …) and can map a
// descriptor the model hands back in a tool input to the raw value, locally.
// It lives only in memory for one agent run; it is never serialized.
type Vault struct {
	mu      sync.Mutex
	finder  Finder
	byValue map[string]string // raw value -> ref
	byRef   map[string]string // ref -> raw value
	seq     int

	// Agent histories are re-sent every turn, so redacted blocks are cached by
	// their raw bytes. knownGen invalidates the cache when a new known value
	// is registered (a block redacted earlier may contain it).
	knownGen  int
	knownSeen map[string]bool
	cache     map[string]json.RawMessage
	cacheGen  int
}

// NewVault returns an empty vault.
func NewVault() *Vault {
	return &Vault{byValue: map[string]string{}, byRef: map[string]string{}}
}

// Known registers exact values (e.g. captured session cookies) so they are
// redacted even when no pattern recognises them.
func (v *Vault) Known(typ string, values ...string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.knownSeen == nil {
		v.knownSeen = map[string]bool{}
	}
	for _, val := range values {
		if !v.knownSeen[val] {
			v.knownSeen[val] = true
			v.knownGen++
		}
	}
	v.finder.Known(typ, values...)
}

func (v *Vault) refFor(val string) string {
	if r, ok := v.byValue[val]; ok {
		return r
	}
	v.seq++
	r := fmt.Sprintf("S%d", v.seq)
	v.byValue[val] = r
	v.byRef[r] = val
	return r
}

// Redact replaces every secret in text with a descriptor carrying a ref.
func (v *Vault) Redact(text string) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.finder.replace(text, func(s Secret) string {
		return Descriptor(s, "", v.refFor(s.Value))
	})
}

var reDescriptorRef = regexp.MustCompile(`<SECRET:[^>]*?\bref=(S\d+)\b[^>]*>`)

// Restore maps descriptors (anything of the form <SECRET: … ref=Sn …>) back
// to their raw values. Unknown refs are left as they are.
func (v *Vault) Restore(text string) string {
	if !strings.Contains(text, "<SECRET:") {
		return text
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return reDescriptorRef.ReplaceAllStringFunc(text, func(m string) string {
		sub := reDescriptorRef.FindStringSubmatch(m)
		if raw, ok := v.byRef[sub[1]]; ok {
			return raw
		}
		return m
	})
}

// RestoreJSON restores descriptors inside every string of a JSON document
// (a tool_use input). Invalid JSON is returned unchanged.
func (v *Vault) RestoreJSON(raw json.RawMessage) json.RawMessage {
	if !bytes.Contains(raw, []byte("SECRET:")) {
		return raw
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return raw
	}
	doc = walkStrings(doc, v.Restore)
	out, err := marshalNoEscape(doc)
	if err != nil {
		return raw
	}
	return out
}

// RedactBlocks returns a redacted copy of user-turn content blocks: the text
// of "text" blocks and the content of "tool_result" blocks (string or nested
// text blocks). Other blocks (images, tool_use, thinking) pass through
// byte-for-byte.
func (v *Vault) RedactBlocks(blocks []json.RawMessage) []json.RawMessage {
	v.mu.Lock()
	if v.cache == nil || v.cacheGen != v.knownGen {
		v.cache, v.cacheGen = map[string]json.RawMessage{}, v.knownGen
	}
	v.mu.Unlock()
	out := make([]json.RawMessage, len(blocks))
	for i, raw := range blocks {
		key := string(raw)
		v.mu.Lock()
		hit, ok := v.cache[key]
		v.mu.Unlock()
		if ok {
			out[i] = hit
			continue
		}
		out[i] = v.redactBlock(raw)
		v.mu.Lock()
		v.cache[key] = out[i]
		v.mu.Unlock()
	}
	return out
}

func (v *Vault) redactBlock(raw json.RawMessage) json.RawMessage {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	changed := false
	switch m["type"] {
	case "text":
		if s, ok := m["text"].(string); ok {
			if r := v.Redact(s); r != s {
				m["text"], changed = r, true
			}
		}
	case "tool_result":
		switch c := m["content"].(type) {
		case string:
			if r := v.Redact(c); r != c {
				m["content"], changed = r, true
			}
		case []any:
			for j, item := range c {
				if blk, ok := item.(map[string]any); ok && blk["type"] == "text" {
					if s, ok := blk["text"].(string); ok {
						if r := v.Redact(s); r != s {
							blk["text"], changed = r, true
							c[j] = blk
						}
					}
				}
			}
		}
	}
	if !changed {
		return raw
	}
	b, err := marshalNoEscape(m)
	if err != nil {
		return raw
	}
	return b
}

// walkStrings applies fn to every string value (not keys) in a decoded JSON doc.
func walkStrings(doc any, fn func(string) string) any {
	switch t := doc.(type) {
	case string:
		return fn(t)
	case []any:
		for i := range t {
			t[i] = walkStrings(t[i], fn)
		}
		return t
	case map[string]any:
		for k := range t {
			t[k] = walkStrings(t[k], fn)
		}
		return t
	}
	return doc
}

func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
