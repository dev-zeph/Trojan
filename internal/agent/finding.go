package agent

// Finding is the structured output of one pass of the hypothesis loop: a single
// attack hypothesis the model formed by querying the graph, ranked and
// justified. It is deliberately small and grounded, so downstream steps (the
// same adversarial-verification idea the DAST agent uses) can try to prove or
// disprove it rather than trusting the model's prose.
type Finding struct {
	// Hypothesis is the attack in one or two sentences: what an attacker feeds
	// in, where it lands, and what that achieves.
	Hypothesis string `json:"hypothesis"`
	// Severity is a coarse rank: "high" | "medium" | "low". The model is asked
	// to justify it against the sink severity and whether the path touches PII.
	Severity string `json:"severity"`
	// Path is the human-readable node chain from entrypoint to sink, e.g.
	// ["api.loginHandler", "api.lookupUser", "db.Query"]. It anchors the
	// hypothesis to concrete graph nodes.
	Path []string `json:"path"`
	// Rationale explains why the hypothesis holds, citing the file:line anchors
	// the tools returned.
	Rationale string `json:"rationale"`

	// SourceID and SinkID are the graph node ids the hypothesis is anchored on,
	// when the model supplied them. Optional, so a hypothesis is still valid
	// without them, but they let a verifier re-query the exact route.
	SourceID int `json:"source_id,omitempty"`
	SinkID   int `json:"sink_id,omitempty"`
}
