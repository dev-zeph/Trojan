package mcpserver

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dev-zeph/trojan/internal/gitignore"
	"github.com/dev-zeph/trojan/internal/intel"
)

// Intel match lifecycle, persisted at <project>/.trojan/intel/matches.json.
//
// A match PROPOSES a risk; nothing here asserts one. matched_unproven is the
// starting point and only prove_intel_match moves a match anywhere else.
const (
	intelMatched     = "matched_unproven"
	intelProving     = "proving"
	intelConfirmed   = "confirmed"
	intelFixed       = "fixed"
	intelNotAffected = "not_affected"
	intelResolved    = "resolved" // vanished from the lockfiles between check_intel runs
)

const intelMatchesRel = ".trojan/intel/matches.json"

// proofEvent is one entry in a match's proof history.
type proofEvent struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"`   // version | hosted_test
	Result string    `json:"result"` // confirmed | fixed | not_affected | started | inconclusive
	Detail string    `json:"detail,omitempty"`
}

// intelRecord is one match's saved state.
type intelRecord struct {
	MatchID      string       `json:"match_id"`
	Status       string       `json:"status"`
	FirstSeen    time.Time    `json:"first_seen"`
	LastSeen     time.Time    `json:"last_seen"`
	ResolvedAt   *time.Time   `json:"resolved_at,omitempty"`
	Match        intel.Match  `json:"match"` // snapshot incl. the advisory text
	ProofKind    string       `json:"proof_kind,omitempty"`
	ProofHistory []proofEvent `json:"proof_history,omitempty"`
	TestID       string       `json:"test_id,omitempty"`
	TestURL      string       `json:"test_url,omitempty"`
	TestStarted  *time.Time   `json:"test_started_at,omitempty"`
	FindingID    string       `json:"finding_id,omitempty"`
	DraftPath    string       `json:"playbook_draft,omitempty"`
}

type intelStore struct {
	UpdatedAt time.Time     `json:"updated_at"`
	Records   []intelRecord `json:"records"`
}

func loadIntelStore(project string) *intelStore {
	s := &intelStore{}
	data, err := os.ReadFile(filepath.Join(project, filepath.FromSlash(intelMatchesRel)))
	if err == nil {
		json.Unmarshal(data, s) //nolint:errcheck // a corrupt file starts fresh
	}
	return s
}

func (s *intelStore) save(project string) error {
	path := filepath.Join(project, filepath.FromSlash(intelMatchesRel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	gitignore.EnsureTrojanIgnored(project)
	s.UpdatedAt = time.Now().UTC()
	sort.Slice(s.Records, func(i, j int) bool { return s.Records[i].MatchID < s.Records[j].MatchID })
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *intelStore) find(id string) *intelRecord {
	for i := range s.Records {
		if s.Records[i].MatchID == id {
			return &s.Records[i]
		}
	}
	return nil
}

func (s *intelStore) findByFindingID(id string) *intelRecord {
	for i := range s.Records {
		if s.Records[i].FindingID == id {
			return &s.Records[i]
		}
	}
	return nil
}

// merge folds a fresh check into the store. Promoted statuses (confirmed,
// not_affected, proving) survive a rerun; a fixed or resolved match that
// shows up again (a downgrade) starts over as matched_unproven; matches that
// vanished become resolved with a timestamp.
func (s *intelStore) merge(matches []intel.Match, now time.Time) {
	seen := map[string]bool{}
	for _, m := range matches {
		seen[m.ID] = true
		r := s.find(m.ID)
		if r == nil {
			s.Records = append(s.Records, intelRecord{MatchID: m.ID, Status: intelMatched, FirstSeen: now, LastSeen: now, Match: m})
			continue
		}
		r.LastSeen, r.Match = now, m
		if r.Status == intelFixed || r.Status == intelResolved {
			r.Status, r.ResolvedAt, r.ProofKind = intelMatched, nil, ""
		}
	}
	for i := range s.Records {
		r := &s.Records[i]
		if seen[r.MatchID] || r.Status == intelResolved || r.Status == intelFixed {
			continue
		}
		t := now
		r.Status, r.ResolvedAt = intelResolved, &t
	}
}

func intelFindingID(matchID string) string {
	h := sha1.Sum([]byte(matchID))
	return "intel-" + hex.EncodeToString(h[:])[:12]
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func safeName(s string) string {
	s = strings.Trim(unsafeName.ReplaceAllString(s, "_"), "._")
	if s == "" {
		return "advisory"
	}
	return s
}
