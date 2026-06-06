package ai

import (
	"bufio"
	"encoding/json"
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
