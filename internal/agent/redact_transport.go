package agent

import (
	"context"

	"github.com/dev-zeph/trojan/internal/redact"
)

// secretRedactingTransport redacts secrets from every user turn (the seed
// and the tool results carrying source chunks) before the white-box agent's
// model sees them. Assistant turns pass through byte-for-byte.
type secretRedactingTransport struct {
	inner Transport
	vault *redact.Vault
}

func redactingTransport(inner Transport) Transport {
	if _, already := inner.(*secretRedactingTransport); already || inner == nil {
		return inner
	}
	return &secretRedactingTransport{inner: inner, vault: redact.NewVault()}
}

func (s *secretRedactingTransport) Turn(ctx context.Context, messages []Message) (*TurnResult, error) {
	out := make([]Message, len(messages))
	for i, m := range messages {
		if m.Role == "user" {
			m.Content = s.vault.RedactBlocks(m.Content)
		}
		out[i] = m
	}
	return s.inner.Turn(ctx, out)
}
