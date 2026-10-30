package agent

import (
	"encoding/json"
	"strconv"
	"strings"
)

// UnmarshalJSON decodes a note_finding input tolerantly. The source location is
// optional and model-written, so it accepts "line" as a number or a numeric
// string, and a "file" written as "path:42" (or "path#L42") when no separate
// line is given. A malformed location is dropped rather than failing the
// whole finding.
func (c *Candidate) UnmarshalJSON(data []byte) error {
	var raw struct {
		Title     string          `json:"title"`
		Severity  string          `json:"severity"`
		URL       string          `json:"url"`
		Evidence  string          `json:"evidence"`
		Rationale string          `json:"rationale"`
		File      string          `json:"file"`
		Line      json.RawMessage `json:"line"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*c = Candidate{
		Title:     raw.Title,
		Severity:  raw.Severity,
		URL:       raw.URL,
		Evidence:  raw.Evidence,
		Rationale: raw.Rationale,
	}
	file := strings.TrimSpace(raw.File)
	line := parseLine(raw.Line)
	if line == 0 {
		file, line = splitFileLine(file)
	}
	c.File, c.Line = file, line
	return nil
}

// parseLine reads a positive line number from a JSON number or string.
func parseLine(m json.RawMessage) int {
	s := strings.Trim(strings.TrimSpace(string(m)), `"`)
	if s == "" || s == "null" {
		return 0
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && f >= 1 {
		return int(f)
	}
	return 0
}

// splitFileLine splits "path:42" or "path#L42" into its parts. Anything else is
// returned unchanged with line 0.
func splitFileLine(file string) (string, int) {
	if i := strings.LastIndex(file, "#L"); i > 0 {
		if n, err := strconv.Atoi(file[i+2:]); err == nil && n > 0 {
			return file[:i], n
		}
	}
	if i := strings.LastIndex(file, ":"); i > 0 {
		if n, err := strconv.Atoi(file[i+1:]); err == nil && n > 0 {
			return file[:i], n
		}
	}
	return file, 0
}

// withHandler fills a candidate's source location from the read_source handler
// of its endpoint when the agent didn't name one itself.
func (c Candidate) withHandler(h *HandlerRef) Candidate {
	if c.File == "" && h != nil && h.File != "" {
		c.File, c.Line = h.File, h.Line
	}
	return c
}
