package routes

import (
	"os"
	"path/filepath"
	"strings"
)

var phpExts = map[string]bool{".php": true}

// classifyPHP recognizes a plain, file-routed PHP app: .php files in the
// project root and no framework router in composer.json. Laravel/Symfony-style
// apps route through a front controller, so mapping files to URLs would be
// wrong there; they stay unknown until they get a real extractor.
func classifyPHP(projectPath string) Framework {
	if data, err := os.ReadFile(filepath.Join(projectPath, "composer.json")); err == nil {
		txt := strings.ToLower(string(data))
		for _, fw := range []string{"laravel/framework", "symfony/framework-bundle", "slim/slim", "cakephp/cakephp", "codeigniter4/framework", "yiisoft/yii2"} {
			if strings.Contains(txt, fw) {
				return FrameworkUnknown
			}
		}
	}
	matches, _ := filepath.Glob(filepath.Join(projectPath, "*.php"))
	if len(matches) == 0 {
		return FrameworkUnknown
	}
	return FrameworkPHP
}

// extractPHP maps every shipping .php file to the URL the web server serves it
// at (/admin.php, /api/user.php). index.php also answers its directory (/ or
// /api). Every method is accepted: plain PHP branches on $_SERVER inside the
// file. Line is 0 (the whole file is the handler). Filesystem-derived, so
// confidence is 1.0 for the path itself.
func extractPHP(projectPath string) []Route {
	var routes []Route
	for _, file := range walkFiles(projectPath, phpExts) {
		rel := relOrBase(projectPath, file)
		mk := func(pattern string) Route {
			return Route{
				PathPattern: pattern,
				HandlerFile: rel,
				Framework:   string(FrameworkPHP),
				Confidence:  1.0,
				Source:      "filesystem",
			}
		}
		routes = append(routes, mk("/"+rel))
		if filepath.Base(rel) == "index.php" {
			dir := strings.TrimSuffix(strings.TrimSuffix(rel, "index.php"), "/")
			routes = append(routes, mk(joinPath("/", dir)))
		}
	}
	return routes
}
