// Package agent implements the safety spine of Trojan's agentic DAST (Phase 3):
// the bounded toolset the AI agent is allowed to act through, plus the safe-mode
// enforcement and hard caps that make an autonomous loop safe to point at a live
// app. Everything here is deterministic and unit-testable WITHOUT a model wired
// in — the Claude loop and the agentic-dast edge function land in Phase 4.
//
// The agent's only ways to act (§3.3 of docs/agentic-dast.md):
//
//   - get_crawl_map  — read-only view of discovered endpoints/params/tech
//   - http_probe     — a single constrained HTTP request (safe-mode enforced)
//   - note_finding   — record a candidate vuln with evidence (no network)
//   - finish         — end the run
//
// Deliberately NOT an agent tool: run_nuclei_template. Across both Phase-0
// spikes the model never once authored Nuclei YAML mid-loop — it always reached
// for http_probe + reasoning. Per the locked Phase-0 decision, Nuclei runs as a
// deterministic PRE-PASS up front (breadth, zero tokens) via internal/scanners,
// and the agent gets only http_probe for the adaptive layer. See §3.3 and the
// Phase-0 "decisive learnings" in the design doc.
//
// Safe-mode (§6): probes are report-only by construction. Destructive verbs
// (PUT/PATCH/DELETE/TRACE/CONNECT) are never permitted; POST is gated by the
// scan-intensity tier and environment (§6.2); every probe is same-host scoped;
// response reads are size-capped. Step / request / wall-clock caps bound cost
// and time (§8), and tripping any cap surfaces a visible "stopped: <reason>" —
// never a silent truncation (§11 / §12).
package agent
