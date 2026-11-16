package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dev-zeph/trojan/internal/gitignore"
)

// CacheRelPath is where the last intel response is kept, relative to the
// project root (.trojan is gitignored by internal/gitignore).
const CacheRelPath = ".trojan/intel/advisories.json"

// Cache is the on-disk copy of the last successful intel fetch.
type Cache struct {
	FetchedAt   time.Time  `json:"fetched_at"`
	GeneratedAt string     `json:"generated_at"`
	Advisories  []Advisory `json:"advisories"`
	// Packages are the "ecosystem|name@version" keys that were queried, so an
	// offline re-run can tell which installed packages the cache doesn't cover.
	Packages []string `json:"packages"`
}

func cacheKey(p Package) string { return p.Ecosystem + "|" + p.Name + "@" + p.Version }

// LoadCache reads <project>/.trojan/intel/advisories.json.
func LoadCache(projectPath string) (*Cache, error) {
	data, err := os.ReadFile(filepath.Join(projectPath, filepath.FromSlash(CacheRelPath)))
	if err != nil {
		return nil, err
	}
	var c Cache
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("corrupt intel cache: %w", err)
	}
	return &c, nil
}

// SaveCache writes the cache and makes sure .trojan is gitignored.
func SaveCache(projectPath string, c *Cache) error {
	path := filepath.Join(projectPath, filepath.FromSlash(CacheRelPath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	gitignore.EnsureTrojanIgnored(projectPath)
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Options tunes Check.
type Options struct {
	// Client defaults to NewClient().
	Client *Client
	// Offline skips the network and uses only the cache.
	Offline bool
	// NoCache neither reads nor writes the on-disk cache.
	NoCache bool
}

// Result is the outcome of Check.
type Result struct {
	Matches         []Match  `json:"matches"`
	PackagesScanned int      `json:"packages_scanned"`
	Lockfiles       []string `json:"lockfiles"`
	// IntelGeneratedAt is the server's generated_at for the intel used.
	IntelGeneratedAt string `json:"intel_generated_at"`
	// FromCache is true when the advisories came from the on-disk cache
	// (offline, or the server was unreachable); FetchedAt says how old.
	FromCache bool      `json:"from_cache"`
	FetchedAt time.Time `json:"fetched_at"`
	// UncoveredPackages counts installed packages the cached intel was never
	// queried for (only non-zero when FromCache).
	UncoveredPackages int `json:"uncovered_packages,omitempty"`
	// Warnings: lockfiles that failed to parse, a fetch error that forced the
	// cache fallback, and similar non-fatal problems.
	Warnings []string `json:"warnings,omitempty"`
}

// Check parses the project's lockfiles, fetches intel for the inventory and
// matches it locally. On a network or server (5xx) failure it falls back to
// the cached intel when there is one; ErrNotSignedIn and
// ErrSubscriptionRequired are always returned as errors (no fallback), so
// callers can tell the user exactly what to do.
func Check(ctx context.Context, projectPath string, opts Options) (*Result, error) {
	root, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, err
	}
	pkgs, files, warnings, err := ParseProjectWithWarnings(root)
	if err != nil {
		return nil, err
	}
	res := &Result{PackagesScanned: len(pkgs), Lockfiles: files, Warnings: warnings, Matches: []Match{}}
	if files == nil {
		res.Lockfiles = []string{}
	}
	if len(pkgs) == 0 {
		return res, nil
	}

	useCache := func(reason error) (*Result, error) {
		c, cerr := LoadCache(root)
		if cerr != nil {
			if reason != nil {
				return nil, reason
			}
			return nil, fmt.Errorf("no cached intel for this project yet: %w", cerr)
		}
		if reason != nil {
			res.Warnings = append(res.Warnings, "intel fetch failed, using cached intel: "+reason.Error())
		}
		queried := make(map[string]bool, len(c.Packages))
		for _, k := range c.Packages {
			queried[k] = true
		}
		for _, p := range pkgs {
			if !queried[cacheKey(p)] {
				res.UncoveredPackages++
			}
		}
		res.FromCache = true
		res.FetchedAt = c.FetchedAt
		res.IntelGeneratedAt = c.GeneratedAt
		res.Matches = nonNil(MatchAdvisories(pkgs, c.Advisories))
		return res, nil
	}

	if opts.Offline {
		if opts.NoCache {
			return nil, errors.New("offline with no cache: nothing to check against")
		}
		return useCache(nil)
	}

	client := opts.Client
	if client == nil {
		client = NewClient()
	}
	resp, err := client.Fetch(ctx, pkgs)
	if err != nil {
		var se *StatusError
		retryable := !errors.Is(err, ErrNotSignedIn) && !errors.Is(err, ErrSubscriptionRequired) &&
			(!errors.As(err, &se) || se.Code >= 500)
		if retryable && !opts.NoCache && ctx.Err() == nil {
			return useCache(err)
		}
		return nil, err
	}

	res.FetchedAt = time.Now().UTC()
	res.IntelGeneratedAt = resp.GeneratedAt
	res.Matches = nonNil(MatchAdvisories(pkgs, resp.Advisories))
	if !opts.NoCache {
		keys := make([]string, len(pkgs))
		for i, p := range pkgs {
			keys[i] = cacheKey(p)
		}
		if err := SaveCache(root, &Cache{FetchedAt: res.FetchedAt, GeneratedAt: resp.GeneratedAt,
			Advisories: resp.Advisories, Packages: keys}); err != nil {
			res.Warnings = append(res.Warnings, "could not write intel cache: "+err.Error())
		}
	}
	return res, nil
}

func nonNil(m []Match) []Match {
	if m == nil {
		return []Match{}
	}
	return m
}
