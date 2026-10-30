package agent

import (
	"fmt"
	"strings"
	"time"

	"github.com/dev-zeph/trojan/internal/graph"
	"github.com/dev-zeph/trojan/internal/greybox"
)

// The white-box summary tools: one-call overviews of the riskiest structure in
// the graph (unguarded routes, client exposures), plus grey-box source reads
// and the project's security history. All results are compact and capped.

// RouteExposure groups what one unguarded entrypoint reaches.
type RouteExposure struct {
	Entrypoint string   `json:"entrypoint"` // node key
	Location   string   `json:"location"`
	Reaches    []string `json:"reaches"` // e.g. "writes datastore:orders", "calls pool.query"
	TouchesPII bool     `json:"touches_pii,omitempty"`
}

// UnguardedPaths summarises every entrypoint with no auth check on the way to
// a datastore or dangerous call, one row per entrypoint.
func (t *Toolbox) UnguardedPaths() []RouteExposure {
	var order []string
	rows := map[string]*RouteExposure{}
	for _, p := range t.g.UnguardedPaths() {
		k := nodeKey(p.Source)
		r, ok := rows[k]
		if !ok {
			r = &RouteExposure{Entrypoint: k, Location: fmt.Sprintf("%s:%d", p.Source.File, p.Source.Line)}
			rows[k] = r
			order = append(order, k)
		}
		r.Reaches = appendOnce(r.Reaches, accessOf(p)+" "+nodeKey(p.Sink))
		r.TouchesPII = r.TouchesPII || p.TouchPII
	}
	out := make([]RouteExposure, 0, len(order))
	for i, k := range order {
		if i >= maxListItems {
			break
		}
		out = append(out, *rows[k])
	}
	return out
}

// ClientExposureView is one privileged thing reachable from browser code.
type ClientExposureView struct {
	Client   string   `json:"client"` // node key of the ClientSide function
	Location string   `json:"location"`
	Reaches  string   `json:"reaches"`
	Via      []string `json:"via,omitempty"`
}

// ClientExposures summarises privileged clients, server-only imports and
// high-severity sinks reachable from code that runs in the browser.
func (t *Toolbox) ClientExposures() []ClientExposureView {
	out := []ClientExposureView{}
	for _, e := range t.g.ClientExposures() {
		if len(out) >= maxListItems {
			break
		}
		via := make([]string, 0, len(e.Via))
		for _, n := range e.Via {
			via = append(via, nodeKey(n))
		}
		out = append(out, ClientExposureView{
			Client:   nodeKey(e.Client),
			Location: fmt.Sprintf("%s:%d", e.Client.File, e.Client.Line),
			Reaches:  e.Reached.Name,
			Via:      via,
		})
	}
	return out
}

// ReadSource reads a handler or symbol through the grey-box reader, capping
// the code it returns. Without a reader it answers with a note, not an error,
// so the model just reasons from the graph.
func (t *Toolbox) ReadSource(req greybox.ReadSourceRequest) (string, error) {
	if t.source == nil {
		return toJSON(greybox.ReadSourceResult{Note: "source reading is not available for this project; reason from the graph tools"})
	}
	res, err := t.source.ReadSource(req)
	if err != nil {
		return "", err
	}
	if len(res.Chunks) > maxSourceChunks {
		res.Chunks = res.Chunks[:maxSourceChunks]
	}
	for i := range res.Chunks {
		if c := res.Chunks[i].Code; len(c) > maxChunkCode {
			res.Chunks[i].Code = strings.ToValidUTF8(c[:maxChunkCode], "") + "\n..."
		}
	}
	return toJSON(res)
}

// HistoryItem is one past result about the project, compact for the model.
type HistoryItem struct {
	Kind     string `json:"kind"`
	NodeKey  string `json:"node_key,omitempty"`
	File     string `json:"file,omitempty"`
	Title    string `json:"title"`
	Evidence string `json:"evidence,omitempty"`
	Date     string `json:"date"`
}

// SecurityHistory returns what past runs learned (confirmed issues, false
// positives, facts, accepted risks), newest first, optionally filtered to one
// node key or file.
func (t *Toolbox) SecurityHistory(nodeKey, file string) (string, error) {
	out := []HistoryItem{}
	if t.history == nil {
		return toJSON(out)
	}
	events, err := t.history.All()
	if err != nil {
		return "", err
	}
	for i := len(events) - 1; i >= 0 && len(out) < maxHistory; i-- {
		e := events[i]
		if nodeKey != "" && e.NodeKey != nodeKey {
			continue
		}
		if file != "" && e.File != file {
			continue
		}
		ev := e.Evidence
		if len(ev) > 200 {
			ev = strings.ToValidUTF8(ev[:200], "") + "..."
		}
		out = append(out, HistoryItem{
			Kind: string(e.Kind), NodeKey: e.NodeKey, File: e.File,
			Title: e.Title, Evidence: ev, Date: e.At.Format(time.DateOnly),
		})
	}
	return toJSON(out)
}

func nodeKey(n graph.Node) string {
	if n.Key != "" {
		return n.Key
	}
	if n.File != "" {
		return n.File + "#" + n.Name
	}
	return n.Name
}

func accessOf(p graph.AttackPath) string {
	switch p.Access {
	case graph.EdgeWrites:
		return "writes"
	case graph.EdgeReads:
		return "reads"
	}
	return "calls"
}

func appendOnce(ss []string, s string) []string {
	for _, x := range ss {
		if x == s {
			return ss
		}
	}
	return append(ss, s)
}
