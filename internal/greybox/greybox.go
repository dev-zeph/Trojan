// Package greybox is Trojan's unfair advantage (docs §6.2, §6.6): it hands the
// running DAST agent read access to the target's OWN source. A black-box agent
// fuzzes; a grey-box agent reads the handler and forms specific, grounded
// hypotheses a black-box tool cannot — because it can see the *missing* check
// (no ownership guard → IDOR; raw SQL sink → injection; auth on GET but not POST
// → authz bypass).
//
// It composes the pieces already built: the route resolver (URL→handler, §7),
// the local code index (semantic search, §9.1.2/§4), and enclosing-block
// extraction. Everything runs locally in Go; only retrieved chunks transit to
// the edge for embedding (same opt-in boundary as triage). No target traffic —
// read_source costs the token budget, never the request budget.
package greybox

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/dev-zeph/trojan/internal/ai"
	"github.com/dev-zeph/trojan/internal/rag"
	"github.com/dev-zeph/trojan/internal/routes"
)

// ReadSourceRequest is a read_source tool call: exactly one mode should be set.
type ReadSourceRequest struct {
	Endpoint *EndpointRef `json:"endpoint,omitempty"` // resolve a live URL to its handler
	Symbol   string       `json:"symbol,omitempty"`   // look up a named function/symbol
	Query    string       `json:"query,omitempty"`    // semantic search the code index
}

// EndpointRef is a live method+path to resolve to source.
type EndpointRef struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// SourceChunk is one returned region of source, anchored to file:line.
type SourceChunk struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Symbol string `json:"symbol,omitempty"`
	Code   string `json:"code"`
}

// StructuralSummary is the cheap, heuristic security read of a handler that
// primes the agent's hypotheses (§6.6). It is APPROXIMATE by design — a starting
// point the agent must runtime-verify, never trusted as ground truth.
type StructuralSummary struct {
	HasAuthCheck   bool     `json:"has_auth_check"`
	SanitizesInput bool     `json:"sanitizes_input"`
	RawQuery       bool     `json:"raw_query"`
	ReflectsInput  bool     `json:"reflects_input"`
	Calls          []string `json:"calls,omitempty"`
}

// ReadSourceResult is what the tool returns to the agent.
type ReadSourceResult struct {
	Chunks  []SourceChunk      `json:"chunks"`
	Summary *StructuralSummary `json:"summary,omitempty"`
	Guards  []string           `json:"guards,omitempty"`
	Note    string             `json:"note,omitempty"`
}

// Source is the grey-box reader. Fields are optional: a nil resolver disables
// endpoint mode, a nil retriever disables query mode — each degrades to a note
// rather than an error, so a partially-available project still helps.
type Source struct {
	projectPath string
	resolver    *routes.Resolver
	retriever   ai.ContextRetriever
}

// New builds a grey-box reader over a project. resolver and retriever may be nil.
func New(projectPath string, resolver *routes.Resolver, retriever ai.ContextRetriever) *Source {
	return &Source{projectPath: projectPath, resolver: resolver, retriever: retriever}
}

const defaultQueryK = 4

// ReadSource dispatches to the requested mode.
func (s *Source) ReadSource(req ReadSourceRequest) (ReadSourceResult, error) {
	switch {
	case req.Endpoint != nil:
		return s.byEndpoint(req.Endpoint.Method, req.Endpoint.Path), nil
	case req.Symbol != "":
		return s.bySymbol(req.Symbol), nil
	case req.Query != "":
		return s.byQuery(req.Query), nil
	default:
		return ReadSourceResult{Note: "specify one of: endpoint, symbol, query"}, nil
	}
}

// byEndpoint resolves a live URL to its handler, reads the handler body, and
// summarizes it — the workhorse of source-informed hypothesis forming.
func (s *Source) byEndpoint(method, path string) ReadSourceResult {
	if s.resolver == nil {
		return ReadSourceResult{Note: "no route resolver: source not indexed for this project"}
	}
	route, ok := s.resolver.Resolve(method, path)
	if !ok {
		// Fall back to semantic search on the endpoint description.
		if s.retriever != nil {
			r := s.byQuery(method + " " + path)
			r.Note = "endpoint not resolved to a handler; showing semantically-related code"
			return r
		}
		return ReadSourceResult{Note: "no handler found for " + method + " " + path}
	}
	code := s.readEnclosing(route.HandlerFile, route.HandlerLine)
	summary := analyze(code, route.Guards)
	return ReadSourceResult{
		Chunks: []SourceChunk{{
			File:   route.HandlerFile,
			Line:   route.HandlerLine,
			Symbol: route.HandlerSymbol,
			Code:   code,
		}},
		Summary: &summary,
		Guards:  route.Guards,
	}
}

// bySymbol greps the source tree for a definition of name and returns its
// enclosing block. Falls back to semantic search when no definition is found.
func (s *Source) bySymbol(name string) ReadSourceResult {
	defRe := symbolDefRegex(name)
	files, _ := rag.WalkSource(s.projectPath)
	for _, abs := range files {
		data, err := os.ReadFile(abs)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(data), "\n") {
			if defRe.MatchString(line) {
				rel := relOrBase(s.projectPath, abs)
				code := s.readEnclosing(rel, i+1)
				summary := analyze(code, nil)
				return ReadSourceResult{
					Chunks:  []SourceChunk{{File: rel, Line: i + 1, Symbol: name, Code: code}},
					Summary: &summary,
				}
			}
		}
	}
	if s.retriever != nil {
		r := s.byQuery(name)
		r.Note = "no definition found by name; showing semantically-related code"
		return r
	}
	return ReadSourceResult{Note: "symbol " + name + " not found"}
}

// byQuery semantically searches the code index.
func (s *Source) byQuery(query string) ReadSourceResult {
	if s.retriever == nil {
		return ReadSourceResult{Note: "no code index: run `trojan index` to enable semantic source search"}
	}
	chunks, err := s.retriever.Retrieve(query, defaultQueryK)
	if err != nil {
		return ReadSourceResult{Note: "search failed: " + err.Error()}
	}
	if len(chunks) == 0 {
		return ReadSourceResult{Note: "no related code found"}
	}
	out := ReadSourceResult{}
	for _, c := range chunks {
		out.Chunks = append(out.Chunks, SourceChunk{File: c.FilePath, Line: c.StartLine, Code: c.Text})
	}
	// Summarize the top hit so the agent gets an immediate structural read.
	top := analyze(chunks[0].Text, nil)
	out.Summary = &top
	return out
}

// EndpointTable resolves every crawled endpoint to its handler + guards, for the
// push context handed to the agent at run start (§6.6). Empty when there's no
// resolver. Each row is one line: "METHOD /path -> file:line [guards] flags".
func (s *Source) EndpointTable() []string {
	if s.resolver == nil {
		return nil
	}
	var rows []string
	for _, r := range s.resolver.Routes() {
		m := r.Method
		if m == "" {
			m = "ANY"
		}
		flags := ""
		if len(r.Guards) == 0 {
			flags = " [no-guard]" // the interesting ones: unguarded endpoints
		}
		rows = append(rows, m+" "+r.PathPattern+" -> "+r.HandlerFile+":"+itoa(r.HandlerLine)+flags)
	}
	sort.Strings(rows)
	return rows
}

// readEnclosing reads the enclosing function/block at a project-relative
// file:line using the CGO-free extractor.
func (s *Source) readEnclosing(relFile string, line int) string {
	if relFile == "" || line <= 0 {
		return ""
	}
	return ai.ExtractEnclosingContext(filepath.Join(s.projectPath, relFile), line)
}

func relOrBase(root, file string) string {
	if rel, err := filepath.Rel(root, file); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.Base(file)
}

func itoa(n int) string {
	if n == 0 {
		return "?"
	}
	return strconv.Itoa(n)
}
