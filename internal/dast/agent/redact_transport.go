package agent

import (
	"context"

	"github.com/dev-zeph/trojan/internal/redact"
)

// Vault returns the run's secret vault (created on first use).
func (t *Toolbox) Vault() *redact.Vault {
	t.vaultOnce.Do(func() { t.vault = redact.NewVault() })
	return t.vault
}

// secretRedactingTransport redacts every user turn (task text, tool results,
// approval outcomes) before it reaches the inner transport. Assistant turns
// are passed through byte-for-byte (Claude requires thinking blocks echoed
// verbatim); they only ever contain descriptors, since the model never saw a
// raw value. The local message history, and so the 0600 checkpoint, keeps the
// raw content, so a resumed run re-derives the same refs in the same order.
type secretRedactingTransport struct {
	inner Transport
	tb    *Toolbox
}

func redactingTransport(inner Transport, tb *Toolbox) Transport {
	if _, already := inner.(*secretRedactingTransport); already || inner == nil {
		return inner
	}
	return &secretRedactingTransport{inner: inner, tb: tb}
}

func (s *secretRedactingTransport) Turn(ctx context.Context, messages []Message) (*TurnResult, error) {
	v := s.tb.Vault()
	// Identity header values (user-supplied logins and captured sessions) are
	// secret even when no pattern recognises them.
	v.Known("session_credential", s.tb.secretValues()...)
	out := make([]Message, len(messages))
	for i, m := range messages {
		if m.Role == "user" {
			m.Content = v.RedactBlocks(m.Content)
		}
		out[i] = m
	}
	return s.inner.Turn(ctx, out)
}
