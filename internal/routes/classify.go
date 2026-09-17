package routes

import (
	"os"
	"path/filepath"
	"strings"
)

// Framework identifies a web framework whose routing Trojan can extract. Empty
// means unknown/unsupported — the resolver then falls back (semantic/none)
// rather than guessing.
type Framework string

const (
	FrameworkNextjs  Framework = "nextjs"
	FrameworkExpress Framework = "express"
	FrameworkNestjs  Framework = "nestjs"
	FrameworkFastAPI Framework = "fastapi"
	FrameworkFlask   Framework = "flask"
	FrameworkDjango  Framework = "django"
	FrameworkGin     Framework = "gin"
	FrameworkEcho    Framework = "echo"
	FrameworkChi     Framework = "chi"
	FrameworkFiber   Framework = "fiber"
	FrameworkUnknown Framework = ""
)

// Classify reads a project's dependency manifests to determine its web
// framework. It reads, never parses/executes — just substring checks over the
// manifest text, so it's fast and CGO-free (§7). The order matters: more
// specific frameworks (Next.js, NestJS) are checked before the libraries they
// build on (React, Express).
func Classify(projectPath string) Framework {
	if fw := classifyNode(projectPath); fw != FrameworkUnknown {
		return fw
	}
	if fw := classifyGo(projectPath); fw != FrameworkUnknown {
		return fw
	}
	if fw := classifyPython(projectPath); fw != FrameworkUnknown {
		return fw
	}
	return FrameworkUnknown
}

func classifyNode(projectPath string) Framework {
	data, err := os.ReadFile(filepath.Join(projectPath, "package.json"))
	if err != nil {
		return FrameworkUnknown
	}
	txt := string(data)
	// Order: Next.js and NestJS before Express (Next projects also list React;
	// Nest projects list Express under the hood).
	switch {
	case depPresent(txt, "next"):
		return FrameworkNextjs
	case depPresent(txt, "@nestjs/core"):
		return FrameworkNestjs
	case depPresent(txt, "express"):
		return FrameworkExpress
	}
	return FrameworkUnknown
}

func classifyGo(projectPath string) Framework {
	data, err := os.ReadFile(filepath.Join(projectPath, "go.mod"))
	if err != nil {
		return FrameworkUnknown
	}
	txt := string(data)
	for module, fw := range map[string]Framework{
		"gin-gonic/gin": FrameworkGin,
		"labstack/echo": FrameworkEcho,
		"go-chi/chi":    FrameworkChi,
		"gofiber/fiber": FrameworkFiber,
	} {
		if strings.Contains(txt, module) {
			return fw
		}
	}
	return FrameworkUnknown
}

func classifyPython(projectPath string) Framework {
	for _, name := range []string{"requirements.txt", "pyproject.toml", "setup.py", "Pipfile"} {
		data, err := os.ReadFile(filepath.Join(projectPath, name))
		if err != nil {
			continue
		}
		txt := strings.ToLower(string(data))
		switch {
		case strings.Contains(txt, "fastapi"):
			return FrameworkFastAPI
		case strings.Contains(txt, "django"):
			return FrameworkDjango
		case strings.Contains(txt, "flask"):
			return FrameworkFlask
		}
	}
	return FrameworkUnknown
}

// depPresent reports whether name appears as a JSON dependency key ("name":) in
// a package.json body — avoids matching it as a substring of another package.
func depPresent(packageJSON, name string) bool {
	return strings.Contains(packageJSON, `"`+name+`"`)
}
