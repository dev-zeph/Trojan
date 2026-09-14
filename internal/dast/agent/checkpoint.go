package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dev-zeph/trojan/internal/dast"
)

// CheckpointVersion is bumped whenever the on-disk shape changes incompatibly.
// A checkpoint written by a different version is refused rather than
// half-restored, because a partially-rehydrated agent would silently re-probe
// endpoints or lose facts it had already established.
const CheckpointVersion = 1

// ErrCheckpointVersion is returned when a checkpoint predates the running build.
var ErrCheckpointVersion = errors.New("checkpoint was written by an incompatible version")

// Checkpoint is the resumable state of one agentic run, written after every
// turn. Its purpose is twofold: a run that exhausts the user's Trojan Token
// balance can be continued after a top-up instead of being lost, and a run
// killed by a crash or a closed laptop can be picked up rather than restarted.
//
// WHERE IT LIVES. ~/.trojan/runs/<run-id>.json, 0600, in a 0700 directory --
// deliberately NOT the project's .trojan/ directory. Checkpoints contain
// Identity auth headers and captured response bodies from the target
// application, and project-local .trojan files have a demonstrated habit of
// being committed to git (this repository has .trojan/scans/*.json checked in).
// Keeping them under $HOME removes that failure mode entirely.
//
// WHAT IS DELIBERATELY ABSENT. Config.AccessToken is never written: it is a
// credential with its own lifecycle, and it is re-supplied on resume from
// ~/.trojan/config.json. SourceReader, Approvals and OnEvent are live objects
// rebuilt by the caller.
type Checkpoint struct {
	Version   int       `json:"version"`
	RunID     string    `json:"run_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// ── Run shape: enough to rebuild the Envelope, Budget and Toolbox ──
	TargetURL         string           `json:"target_url"`
	Task              string           `json:"task"`
	Crawl             dast.CrawlResult `json:"crawl"`
	Tier              Tier             `json:"tier"`
	Env               Environment      `json:"env"`
	AcceptSideEffects bool             `json:"accept_side_effects"`
	Limits            Limits           `json:"limits"`
	MaxRunTokens      int              `json:"max_run_tokens"`
	RoE               RoE              `json:"roe"`
	Identities        []Identity       `json:"identities,omitempty"`

	// ── Live state ──
	// Messages is the whole conversation, raw. Claude requires assistant turns
	// (including thinking blocks) replayed byte-for-byte, which is why content
	// is carried as json.RawMessage all the way through rather than re-encoded.
	Messages   []Message   `json:"messages"`
	Usage      Usage       `json:"usage"`
	Findings   []Candidate `json:"findings"`
	Facts      []Fact      `json:"facts"`
	GraphNodes []GraphNode `json:"graph_nodes"`
	GraphEdges []GraphEdge `json:"graph_edges"`

	Steps    int           `json:"steps"`
	Requests int           `json:"requests"`
	Elapsed  time.Duration `json:"elapsed"`

	// StopReason records why the run halted, so the UI can distinguish "ran out
	// of tokens, resumable on top-up" from "hit the step cap, finished".
	StopReason StopReason `json:"stop_reason,omitempty"`
	// Resumable is false once the agent called finish() -- a completed run has
	// nothing to continue.
	Resumable bool `json:"resumable"`
}

// runsDir is ~/.trojan/runs, created 0700 on first use.
func runsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locating home directory: %w", err)
	}
	dir := filepath.Join(home, ".trojan", "runs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating %s: %w", dir, err)
	}
	return dir, nil
}

// safeRunID rejects anything that could escape runsDir. Run ids are
// server-minted UUIDs, but this is the boundary where a hostile id would become
// an arbitrary file write, so it is checked rather than assumed.
func safeRunID(runID string) error {
	if runID == "" {
		return errors.New("run id is empty")
	}
	if strings.ContainsAny(runID, `/\:`) || strings.Contains(runID, "..") {
		return fmt.Errorf("invalid run id %q", runID)
	}
	return nil
}

func checkpointPath(runID string) (string, error) {
	if err := safeRunID(runID); err != nil {
		return "", err
	}
	dir, err := runsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, runID+".json"), nil
}

// SaveCheckpoint writes the checkpoint atomically: a temp file in the same
// directory, then a rename. A crash mid-write therefore leaves the previous
// good checkpoint intact rather than a truncated file that would fail to parse
// on the very resume it exists to enable.
func SaveCheckpoint(cp *Checkpoint) error {
	if cp == nil {
		return errors.New("nil checkpoint")
	}
	path, err := checkpointPath(cp.RunID)
	if err != nil {
		return err
	}

	cp.Version = CheckpointVersion
	now := time.Now().UTC()
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = now
	}
	cp.UpdatedAt = now

	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding checkpoint: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".ckpt-*")
	if err != nil {
		return fmt.Errorf("creating temp checkpoint: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("securing temp checkpoint: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing checkpoint: %w", err)
	}
	// Flush to disk before the rename: without this, a power loss can leave the
	// renamed file present but empty on some filesystems.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("syncing checkpoint: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing checkpoint: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("committing checkpoint: %w", err)
	}
	return nil
}

// LoadCheckpoint reads a checkpoint by run id.
func LoadCheckpoint(runID string) (*Checkpoint, error) {
	path, err := checkpointPath(runID)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cp Checkpoint
	if err := json.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("decoding checkpoint %s: %w", runID, err)
	}
	if cp.Version != CheckpointVersion {
		return nil, fmt.Errorf("%w: file is v%d, build expects v%d",
			ErrCheckpointVersion, cp.Version, CheckpointVersion)
	}
	return &cp, nil
}

// DeleteCheckpoint removes a run's checkpoint. Called once a run finishes, so
// completed runs don't accumulate on disk with their captured response bodies.
func DeleteCheckpoint(runID string) error {
	path, err := checkpointPath(runID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// CheckpointSummary is the listing shape — enough for a "resume a run" picker
// without loading every full conversation into memory.
type CheckpointSummary struct {
	RunID      string     `json:"run_id"`
	TargetURL  string     `json:"target_url"`
	UpdatedAt  time.Time  `json:"updated_at"`
	Steps      int        `json:"steps"`
	Findings   int        `json:"findings"`
	StopReason StopReason `json:"stop_reason,omitempty"`
	Resumable  bool       `json:"resumable"`
}

// ListCheckpoints returns resumable runs, newest first. Unreadable or
// version-mismatched files are skipped rather than failing the whole listing:
// one bad file must not hide every other resumable run.
func ListCheckpoints() ([]CheckpointSummary, error) {
	dir, err := runsDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	out := make([]CheckpointSummary, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		runID := strings.TrimSuffix(e.Name(), ".json")
		cp, err := LoadCheckpoint(runID)
		if err != nil {
			continue
		}
		out = append(out, CheckpointSummary{
			RunID:      cp.RunID,
			TargetURL:  cp.TargetURL,
			UpdatedAt:  cp.UpdatedAt,
			Steps:      cp.Steps,
			Findings:   len(cp.Findings),
			StopReason: cp.StopReason,
			Resumable:  cp.Resumable,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out, nil
}
