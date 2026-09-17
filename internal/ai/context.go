package ai

import (
	"bufio"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"github.com/dev-zeph/trojan/internal/scanners"
)

// DetectLanguage returns the programming language for a file based on its extension.
func DetectLanguage(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".ts", ".tsx":
		return "typescript"
	case ".js", ".jsx", ".mjs", ".cjs":
		return "javascript"
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".rb":
		return "ruby"
	case ".java":
		return "java"
	case ".tf", ".tfvars":
		return "hcl"
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	case ".rs":
		return "rust"
	case ".php":
		return "php"
	case ".cs":
		return "csharp"
	case ".cpp", ".cc", ".cxx":
		return "cpp"
	case ".c":
		return "c"
	case ".sh", ".bash":
		return "bash"
	default:
		return ""
	}
}

// ExtractSurroundingCode reads a file and returns up to radius lines before
// and after the given line number. Returns "" if line == 0 (DAST/SCA findings
// have no meaningful line number) or if the file cannot be read.
func ExtractSurroundingCode(filePath string, line, radius int) string {
	if line <= 0 || filePath == "" {
		return ""
	}

	f, err := os.Open(filePath)
	if err != nil {
		return ""
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if scanner.Err() != nil || len(lines) == 0 {
		return ""
	}

	// line is 1-indexed
	start := line - 1 - radius
	if start < 0 {
		start = 0
	}
	end := line - 1 + radius
	if end >= len(lines) {
		end = len(lines) - 1
	}

	return strings.Join(lines[start:end+1], "\n")
}

// enclosingFallbackRadius is the line window used when the enclosing block can't
// be resolved (parse error, unsupported language, block too large).
const enclosingFallbackRadius = 15

// maxEnclosingLines caps how much enclosing context is returned so a large
// function doesn't blow the triage token budget; beyond it we fall back to a
// tight radius window centered on the finding.
const maxEnclosingLines = 120

// ExtractEnclosingContext returns the source of the function/block enclosing the
// given line — richer than a fixed radius, so triage sees the guard clauses and
// sanitizers a taint finding depends on (A4 / dictionary §3.2 Layer 1). It is
// CGO-free: Go uses go/parser; C-family languages use brace matching; Python and
// Ruby use indentation. Any failure (parse error, unsupported language, oversized
// block) degrades gracefully to a radius window, so the result is never worse
// than ExtractSurroundingCode.
func ExtractEnclosingContext(filePath string, line int) string {
	if line <= 0 || filePath == "" {
		return ""
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return ""
	}

	fallback := func() string {
		return ExtractSurroundingCode(filePath, line, enclosingFallbackRadius)
	}

	var start, end int // 1-indexed, inclusive
	var ok bool
	switch DetectLanguage(filePath) {
	case "go":
		start, end, ok = goEnclosingFunc(data, line)
	case "python", "ruby":
		start, end, ok = indentEnclosingBlock(lines, line)
	case "javascript", "typescript", "java", "c", "cpp", "csharp", "php", "rust":
		start, end, ok = braceEnclosingBlock(lines, line)
	}
	if !ok || start < 1 || end > len(lines) || end < start {
		return fallback()
	}
	if end-start+1 > maxEnclosingLines {
		return fallback()
	}
	return strings.Join(lines[start-1:end], "\n")
}

// goEnclosingFunc parses Go source and returns the 1-indexed line span of the
// function declaration containing line. ok is false on a parse error (common for
// partial/broken files) so the caller can fall back.
func goEnclosingFunc(src []byte, line int) (start, end int, ok bool) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "", src, parser.SkipObjectResolution)
	if err != nil || file == nil {
		return 0, 0, false
	}
	for _, d := range file.Decls {
		fn, isFn := d.(interface{ Pos() token.Pos })
		if !isFn {
			continue
		}
		s := fset.Position(fn.Pos()).Line
		e := fset.Position(d.End()).Line
		if line >= s && line <= e {
			return s, e, true // top-level decls don't nest
		}
	}
	return 0, 0, false
}

// braceEnclosingBlock finds the {...} block enclosing line (1-indexed) by walking
// outward and matching brace depth. Returns the span from the line bearing the
// opening brace (usually the signature) through its matching close.
func braceEnclosingBlock(lines []string, line int) (start, end int, ok bool) {
	idx := line - 1 // 0-indexed target
	if idx < 0 || idx >= len(lines) {
		return 0, 0, false
	}

	// Walk up until brace depth goes negative — that line holds the opening
	// brace of the enclosing block.
	depth := 0
	openLine := -1
	for i := idx; i >= 0; i-- {
		for _, r := range lines[i] {
			switch r {
			case '}':
				depth++
			case '{':
				depth--
			}
		}
		if depth < 0 {
			openLine = i
			break
		}
	}
	if openLine < 0 {
		return 0, 0, false
	}

	// Walk down from the opening brace to its matching close.
	depth = 0
	closeLine := -1
	for i := openLine; i < len(lines); i++ {
		for _, r := range lines[i] {
			switch r {
			case '{':
				depth++
			case '}':
				depth--
			}
		}
		if depth <= 0 && i >= idx {
			closeLine = i
			break
		}
	}
	if closeLine < 0 {
		return 0, 0, false
	}
	return openLine + 1, closeLine + 1, true
}

// indentEnclosingBlock finds the enclosing block for indentation-scoped languages
// (Python, Ruby): the nearest less-indented header line above the target, down to
// where indentation returns to that header's level.
func indentEnclosingBlock(lines []string, line int) (start, end int, ok bool) {
	idx := line - 1
	if idx < 0 || idx >= len(lines) {
		return 0, 0, false
	}
	targetIndent := indentWidth(lines[idx])

	// Find the header: nearest non-blank line above with smaller indentation.
	header := -1
	for i := idx - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		if indentWidth(lines[i]) < targetIndent {
			header = i
			break
		}
	}
	if header < 0 {
		return 0, 0, false
	}
	headerIndent := indentWidth(lines[header])

	// Block ends at the next non-blank line indented at or below the header.
	last := len(lines) - 1
	for i := idx + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}
		if indentWidth(lines[i]) <= headerIndent {
			last = i - 1
			break
		}
	}
	return header + 1, last + 1, true
}

// indentWidth counts leading whitespace, treating a tab as one column (sufficient
// for relative-indent comparisons within a single file).
func indentWidth(s string) int {
	n := 0
	for _, r := range s {
		if r == ' ' || r == '\t' {
			n++
		} else {
			break
		}
	}
	return n
}

// DetectFramework inspects the project's dependency files and returns the
// primary web framework in use. Returns "" if none is detected.
func DetectFramework(projectPath string) string {
	// Check Node.js (package.json)
	if fw := detectNodeFramework(projectPath); fw != "" {
		return fw
	}
	// Check Go (go.mod)
	if fw := detectGoFramework(projectPath); fw != "" {
		return fw
	}
	// Check Python (requirements.txt / pyproject.toml)
	if fw := detectPythonFramework(projectPath); fw != "" {
		return fw
	}
	return ""
}

func detectNodeFramework(projectPath string) string {
	data, err := os.ReadFile(filepath.Join(projectPath, "package.json"))
	if err != nil {
		return ""
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return ""
	}
	all := make(map[string]string)
	for k, v := range pkg.Dependencies {
		all[k] = v
	}
	for k, v := range pkg.DevDependencies {
		all[k] = v
	}
	for _, fw := range []string{"next", "express", "fastify", "koa", "hapi", "nestjs", "remix", "nuxt", "sveltekit"} {
		if _, ok := all[fw]; ok {
			return fw
		}
	}
	// NestJS uses @nestjs/core
	if _, ok := all["@nestjs/core"]; ok {
		return "nestjs"
	}
	return ""
}

func detectGoFramework(projectPath string) string {
	data, err := os.ReadFile(filepath.Join(projectPath, "go.mod"))
	if err != nil {
		return ""
	}
	content := string(data)
	frameworks := map[string]string{
		"gin-gonic/gin":   "gin",
		"labstack/echo":   "echo",
		"gofiber/fiber":   "fiber",
		"go-chi/chi":      "chi",
		"gorilla/mux":     "gorilla-mux",
		"beego/beego":     "beego",
	}
	for module, name := range frameworks {
		if strings.Contains(content, module) {
			return name
		}
	}
	return ""
}

func detectPythonFramework(projectPath string) string {
	candidates := []string{"requirements.txt", "pyproject.toml", "setup.py"}
	frameworks := map[string]string{
		"fastapi":  "fastapi",
		"django":   "django",
		"flask":    "flask",
		"starlette": "starlette",
		"tornado":  "tornado",
		"aiohttp":  "aiohttp",
	}
	for _, candidate := range candidates {
		data, err := os.ReadFile(filepath.Join(projectPath, candidate))
		if err != nil {
			continue
		}
		content := strings.ToLower(string(data))
		for pkg, name := range frameworks {
			if strings.Contains(content, pkg) {
				return name
			}
		}
	}
	return ""
}

// DetectProjectTypeName returns a human-readable project type string
// (e.g. "nextjs", "go-api", "python-api") by combining the existing
// DetectProject result with framework detection.
func DetectProjectTypeName(projectPath string) string {
	p := scanners.DetectProject(projectPath)
	fw := DetectFramework(projectPath)

	switch {
	case p.HasNode && fw == "next":
		return "nextjs"
	case p.HasNode && fw == "remix":
		return "remix"
	case p.HasNode && fw == "nuxt":
		return "nuxt"
	case p.HasNode && (fw == "express" || fw == "fastify" || fw == "koa" || fw == "hapi"):
		return "node-api"
	case p.HasNode && fw == "nestjs":
		return "nestjs"
	case p.HasNode:
		return "node"
	case p.HasGo:
		return "go-api"
	case p.HasPython && fw == "django":
		return "django"
	case p.HasPython && fw == "fastapi":
		return "fastapi"
	case p.HasPython && fw == "flask":
		return "flask"
	case p.HasPython:
		return "python"
	case p.HasRuby:
		return "ruby"
	case p.HasJava:
		return "java"
	case p.HasIaC:
		return "infrastructure"
	default:
		return "unknown"
	}
}
