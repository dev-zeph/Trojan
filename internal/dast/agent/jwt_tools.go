package agent

import (
	"encoding/json"
	"fmt"

	"github.com/dev-zeph/trojan/internal/redact"
)

// jwtMutateInput is the jwt_mutate tool's input. ref names a token the model
// has only seen as a label (<SECRET: ref=S1, type=jwt …>); the mutation is
// applied on the user's machine.
type jwtMutateInput struct {
	Ref string `json:"ref"`
	redact.JWTMutation
}

// JWTMutate runs jwt_mutate: look up the ref in the run's vault, forge the
// token locally, store the forged token under a NEW ref and return only its
// label, header/claim names, allow-listed safe values and what was applied.
// The returned string is the tool_result content; it never contains a token.
// A later http_probe that uses the new label gets the forged token locally.
func (t *Toolbox) JWTMutate(input json.RawMessage) (string, bool) {
	var in jwtMutateInput
	if err := json.Unmarshal(input, &in); err != nil {
		return fmt.Sprintf("invalid jwt_mutate input: %v", err), true
	}
	v := t.Vault()
	// The wire transport restores a descriptor passed as "ref" to its raw value
	// before the tool runs, so "ref" may be a bare ref ("S1") or already the raw
	// token. Resolve both; never accept anything else.
	var raw, ref string
	if r := redact.ParseRef(in.Ref); r != "" {
		val, ok := v.Lookup(r)
		if !ok {
			return fmt.Sprintf("unknown ref %q: use the ref from a <SECRET: ref=…, type=jwt> label seen in this run", r), true
		}
		raw, ref = val, r
	} else if _, _, _, err := redact.SplitJWT(in.Ref); err == nil {
		raw = in.Ref
		if r, ok := v.RefOf(raw); ok {
			ref = r
		} else {
			ref = "(unrefed)"
		}
	} else {
		return `invalid jwt_mutate input: "ref" must be a token label's ref (e.g. "S1") from a <SECRET: …, type=jwt> label seen in this run`, true
	}
	res, err := redact.MutateJWT(raw, in.JWTMutation)
	if err != nil {
		return "jwt_mutate failed: " + err.Error(), true
	}
	newRef, label := v.Remember("jwt_forged", res.Token)
	out := map[string]any{
		"ok":           true,
		"from_ref":     ref,
		"ref":          newRef,
		"label":        label,
		"header_names": res.HeaderNames,
		"claim_names":  res.ClaimNames,
		"applied":      res.Applied,
		"usage":        fmt.Sprintf("Put %q (or \"Bearer \" + it) in an http_probe header; Trojan substitutes the forged token locally. The token itself is never shown to you.", label),
	}
	if len(res.SafeValues) > 0 {
		out["safe_values"] = res.SafeValues
	}
	if res.WeakKeyFound {
		out["weak_key_found"] = true
		out["note"] = "The original token's HMAC signature verified with a key from Trojan's local weak-key list: the signing secret is guessable. Record this as a finding. The key itself stays on the user's machine."
	}
	return marshalResult(out), false
}
