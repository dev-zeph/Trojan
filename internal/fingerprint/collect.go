package fingerprint

import (
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/dev-zeph/trojan/internal/normalizer"
	"github.com/dev-zeph/trojan/internal/routes"
)

// MaxPayloadBytes is the soft cap for a serialized Fingerprint. Collect trims
// the longest lists until the JSON fits.
const MaxPayloadBytes = 20 * 1024

const (
	maxWalkFiles     = 30000
	maxWalkDepth     = 4
	maxDependencies  = 80
	maxRoutes        = 80
	maxDataStores    = 60
	maxEnvVars       = 60
	maxOutline       = 40
	maxManifestBytes = 1 << 20
	maxSQLBytes      = 2 << 20
)

// Collect builds the fingerprint for the project at root. It reads manifests,
// migrations and env files, but only ever keeps names: env var VALUES and file
// contents are never stored in the result.
func Collect(root string) (Fingerprint, error) {
	info, err := os.Stat(root)
	if err != nil {
		return Fingerprint{}, err
	}
	if !info.IsDir() {
		return Fingerprint{}, &fs.PathError{Op: "fingerprint", Path: root, Err: fs.ErrInvalid}
	}

	w := walk(root)

	var fp Fingerprint
	fp.Framework = string(routes.Classify(root))

	// Dependencies from every manifest found.
	depSet := map[string]bool{}
	for _, m := range w.manifests {
		for _, d := range readManifest(root, m) {
			depSet[d] = true
		}
	}
	allDeps := sortedKeys(depSet)
	fp.ThirdParty = thirdParties(allDeps)
	fp.AuthLibraries = authLibraries(allDeps)
	fp.Dependencies = capList(allDeps, maxDependencies)

	// The routes classifier only reads root manifests; fall back to every
	// manifest we found (monorepos).
	if fp.Framework == "" {
		fp.Framework = frameworkFromDeps(depSet)
	}

	fp.Languages = languages(w.extCount)

	// Routes.
	for _, r := range routes.NewResolver(root).Routes() {
		fp.Routes = append(fp.Routes, RouteSummary{Method: r.Method, Path: r.PathPattern, File: filepath.ToSlash(r.HandlerFile)})
	}
	sort.SliceStable(fp.Routes, func(i, j int) bool {
		if fp.Routes[i].Path != fp.Routes[j].Path {
			return fp.Routes[i].Path < fp.Routes[j].Path
		}
		return fp.Routes[i].Method < fp.Routes[j].Method
	})
	if len(fp.Routes) > maxRoutes {
		fp.Routes = fp.Routes[:maxRoutes]
	}

	// Data stores.
	storeSet := map[string]bool{}
	for _, f := range w.sqlFiles {
		for _, t := range tablesFromSQL(readCapped(filepath.Join(root, f), maxSQLBytes)) {
			storeSet[t] = true
		}
	}
	for _, f := range w.prismaFiles {
		for _, t := range modelsFromPrisma(readCapped(filepath.Join(root, f), maxManifestBytes)) {
			storeSet[t] = true
		}
	}
	for _, f := range w.pyModelFiles {
		for _, t := range tablesFromPython(readCapped(filepath.Join(root, f), maxManifestBytes)) {
			storeSet[t] = true
		}
	}
	fp.DataStores = capList(sortedKeys(storeSet), maxDataStores)

	// Env var names only.
	envSet := map[string]bool{}
	for _, f := range w.envFiles {
		for _, n := range envNames(readCapped(filepath.Join(root, f), maxManifestBytes)) {
			envSet[n] = true
		}
	}
	fp.EnvVarNames = capList(sortedKeys(envSet), maxEnvVars)

	fp.Outline = capList(outline(w.outlineCandidates), maxOutline)

	return fit(fp), nil
}

// fit trims lists, biggest first, until the serialized payload fits the cap.
func fit(fp Fingerprint) Fingerprint {
	size := func() int { b, _ := json.Marshal(fp); return len(b) }
	for size() > MaxPayloadBytes {
		switch {
		case len(fp.Routes) > 10 && len(fp.Routes) >= len(fp.Dependencies):
			fp.Routes = fp.Routes[:len(fp.Routes)*3/4]
		case len(fp.Dependencies) > 10:
			fp.Dependencies = fp.Dependencies[:len(fp.Dependencies)*3/4]
		case len(fp.Outline) > 0:
			fp.Outline = fp.Outline[:len(fp.Outline)/2]
		case len(fp.Routes) > 0:
			fp.Routes = fp.Routes[:len(fp.Routes)/2]
		case len(fp.EnvVarNames) > 0:
			fp.EnvVarNames = fp.EnvVarNames[:len(fp.EnvVarNames)/2]
		case len(fp.DataStores) > 0:
			fp.DataStores = fp.DataStores[:len(fp.DataStores)/2]
		default:
			return fp
		}
	}
	return fp
}

// ---- walk ----

type walkResult struct {
	manifests         []string
	sqlFiles          []string
	prismaFiles       []string
	pyModelFiles      []string
	envFiles          []string
	outlineCandidates []string
	extCount          map[string]int
}

var manifestNames = map[string]bool{
	"package.json": true, "requirements.txt": true, "pyproject.toml": true, "go.mod": true, "Pipfile": true,
}

var outlineRe = regexp.MustCompile(`(?i)(admin|auth|login|signup|middleware|payment|billing|checkout|webhook|stripe|schema\.|migration|upload|account|session|permission|role)`)

func walk(root string) walkResult {
	w := walkResult{extCount: map[string]int{}}
	n := 0
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			if strings.HasPrefix(d.Name(), ".") || normalizer.IsNonShipping(rel) || strings.Count(rel, "/")+1 > maxWalkDepth {
				return fs.SkipDir
			}
			return nil
		}
		n++
		if n > maxWalkFiles {
			return fs.SkipAll
		}
		name := d.Name()
		ext := strings.ToLower(filepath.Ext(name))

		// Env files are the one dotfile family we read (names only).
		if name == ".env" || strings.HasPrefix(name, ".env.") {
			w.envFiles = append(w.envFiles, rel)
			return nil
		}
		if strings.HasPrefix(name, ".") || normalizer.IsNonShipping(rel) {
			return nil
		}
		if manifestNames[name] {
			w.manifests = append(w.manifests, rel)
		}
		w.extCount[ext]++
		switch {
		case ext == ".sql":
			if strings.Contains(rel, "migrations/") || strings.Contains(rel, "schema") || strings.Contains(rel, "supabase/") {
				w.sqlFiles = append(w.sqlFiles, rel)
			}
		case name == "schema.prisma":
			w.prismaFiles = append(w.prismaFiles, rel)
		case ext == ".py" && (strings.HasPrefix(name, "models") || strings.Contains(rel, "/models/")):
			w.pyModelFiles = append(w.pyModelFiles, rel)
		}
		if outlineRe.MatchString(rel) && isSourceExt(ext) {
			w.outlineCandidates = append(w.outlineCandidates, rel)
		}
		return nil
	})
	return w
}

func isSourceExt(ext string) bool {
	switch ext {
	case ".ts", ".tsx", ".js", ".jsx", ".mjs", ".py", ".go", ".sql", ".prisma", ".rb", ".php", ".java":
		return true
	}
	return false
}

func outline(cands []string) []string {
	sort.Slice(cands, func(i, j int) bool {
		// shallower paths first: more likely to be entry points.
		di, dj := strings.Count(cands[i], "/"), strings.Count(cands[j], "/")
		if di != dj {
			return di < dj
		}
		return cands[i] < cands[j]
	})
	return cands
}

var langByExt = map[string]string{
	".ts": "typescript", ".tsx": "typescript", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
	".py": "python", ".go": "go", ".rb": "ruby", ".java": "java", ".rs": "rust", ".php": "php", ".cs": "csharp",
	".kt": "kotlin", ".swift": "swift",
}

func languages(ext map[string]int) []string {
	byLang := map[string]int{}
	for e, c := range ext {
		if l, ok := langByExt[e]; ok {
			byLang[l] += c
		}
	}
	langs := make([]string, 0, len(byLang))
	for l := range byLang {
		langs = append(langs, l)
	}
	sort.Slice(langs, func(i, j int) bool {
		if byLang[langs[i]] != byLang[langs[j]] {
			return byLang[langs[i]] > byLang[langs[j]]
		}
		return langs[i] < langs[j]
	})
	return langs
}

// ---- manifests ----

var (
	reqNameRe = regexp.MustCompile(`^[A-Za-z0-9_.\-]+`)
	goReqRe   = regexp.MustCompile(`^\s*(?:require\s+)?([A-Za-z0-9_.\-]+\.[A-Za-z0-9_.\-]+/[^\s]+)\s+v`)
	pyDepRe   = regexp.MustCompile(`"([A-Za-z0-9_.\-]+)\s*(?:[=<>!~\[;].*)?"`)
)

func readManifest(root, rel string) []string {
	data := readCapped(filepath.Join(root, rel), maxManifestBytes)
	if data == "" {
		return nil
	}
	switch filepath.Base(rel) {
	case "package.json":
		var pkg struct {
			Dependencies    map[string]json.RawMessage `json:"dependencies"`
			DevDependencies map[string]json.RawMessage `json:"devDependencies"`
		}
		if json.Unmarshal([]byte(data), &pkg) != nil {
			return nil
		}
		var out []string
		for k := range pkg.Dependencies {
			out = append(out, strings.ToLower(k))
		}
		for k := range pkg.DevDependencies {
			out = append(out, strings.ToLower(k))
		}
		return out
	case "requirements.txt":
		var out []string
		for _, line := range strings.Split(data, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
				continue
			}
			if m := reqNameRe.FindString(line); m != "" {
				out = append(out, strings.ToLower(m))
			}
		}
		return out
	case "pyproject.toml":
		var out []string
		inDeps := false
		for _, line := range strings.Split(data, "\n") {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "[") {
				inDeps = strings.Contains(t, "dependencies")
				continue
			}
			if strings.HasPrefix(t, "dependencies") {
				inDeps = true
			}
			if !inDeps {
				continue
			}
			for _, m := range pyDepRe.FindAllStringSubmatch(t, -1) {
				out = append(out, strings.ToLower(m[1]))
			}
			// poetry style: name = "^1.0"
			if i := strings.Index(t, " = "); i > 0 {
				key := t[:i]
				if key != "dependencies" && key != "python" && !strings.ContainsAny(key, "\" ") {
					out = append(out, strings.ToLower(key))
				}
			}
		}
		return out
	case "Pipfile":
		var out []string
		in := false
		for _, line := range strings.Split(data, "\n") {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "[") {
				in = t == "[packages]" || t == "[dev-packages]"
				continue
			}
			if in {
				if i := strings.Index(t, "="); i > 0 {
					out = append(out, strings.ToLower(strings.TrimSpace(t[:i])))
				}
			}
		}
		return out
	case "go.mod":
		var out []string
		for _, line := range strings.Split(data, "\n") {
			if m := goReqRe.FindStringSubmatch(line); m != nil {
				out = append(out, strings.ToLower(m[1]))
			}
		}
		return out
	}
	return nil
}

// ---- service / auth maps ----

// A dep matches a service when it equals a needle or starts with it.
var serviceNeedles = []struct {
	service string
	needles []string
}{
	{"supabase", []string{"@supabase/", "supabase"}},
	{"stripe", []string{"stripe", "@stripe/"}},
	{"firebase", []string{"firebase", "@firebase/", "firebase-admin"}},
	{"openai", []string{"openai"}},
	{"anthropic", []string{"@anthropic-ai/", "anthropic"}},
	{"resend", []string{"resend"}},
	{"twilio", []string{"twilio"}},
	{"sendgrid", []string{"@sendgrid/", "sendgrid"}},
	{"mailgun", []string{"mailgun"}},
	{"postmark", []string{"postmark"}},
	{"clerk", []string{"@clerk/"}},
	{"auth0", []string{"@auth0/", "auth0"}},
	{"sentry", []string{"@sentry/", "sentry-sdk"}},
	{"aws", []string{"@aws-sdk/", "aws-sdk", "boto3"}},
	{"google-cloud", []string{"@google-cloud/", "google-cloud"}},
	{"vercel", []string{"@vercel/"}},
	{"upstash", []string{"@upstash/"}},
	{"mongodb", []string{"mongodb", "mongoose", "pymongo"}},
	{"postgres", []string{"pg", "postgres", "psycopg2", "psycopg", "asyncpg", "github.com/lib/pq", "github.com/jackc/pgx"}},
	{"redis", []string{"redis", "ioredis"}},
	{"prisma", []string{"@prisma/", "prisma"}},
	{"paypal", []string{"@paypal/", "paypal"}},
	{"plaid", []string{"plaid"}},
	{"slack", []string{"@slack/", "slack-sdk"}},
	{"github", []string{"@octokit/", "octokit", "pygithub"}},
	{"algolia", []string{"algoliasearch"}},
	{"cloudinary", []string{"cloudinary"}},
	{"uploadthing", []string{"uploadthing"}},
	{"mailchimp", []string{"@mailchimp/", "mailchimp"}},
	{"posthog", []string{"posthog"}},
	{"segment", []string{"@segment/", "analytics-node"}},
}

var authNeedles = []string{
	"next-auth", "@auth/", "@clerk/", "@auth0/", "auth0", "passport", "jsonwebtoken", "jose", "@supabase/ssr",
	"@supabase/auth-helpers", "@supabase/auth", "firebase-admin", "lucia", "better-auth", "iron-session", "bcrypt",
	"bcryptjs", "argon2", "express-session", "flask-login", "flask-jwt-extended", "fastapi-users", "python-jose",
	"pyjwt", "authlib", "django-allauth", "passlib", "github.com/golang-jwt/", "github.com/coreos/go-oidc",
}

func matchNeedle(dep, needle string) bool {
	if strings.HasSuffix(needle, "/") || strings.HasPrefix(needle, "github.com/") {
		return strings.HasPrefix(dep, needle)
	}
	return dep == needle || strings.HasPrefix(dep, needle+"-") || strings.HasPrefix(dep, needle+"/") || strings.HasPrefix(dep, needle+"_")
}

func thirdParties(deps []string) []string {
	set := map[string]bool{}
	for _, d := range deps {
		for _, s := range serviceNeedles {
			for _, n := range s.needles {
				if matchNeedle(d, n) {
					set[s.service] = true
				}
			}
		}
	}
	return sortedKeys(set)
}

func authLibraries(deps []string) []string {
	set := map[string]bool{}
	for _, d := range deps {
		for _, n := range authNeedles {
			if matchNeedle(d, n) {
				set[d] = true
			}
		}
	}
	return capList(sortedKeys(set), 15)
}

func frameworkFromDeps(deps map[string]bool) string {
	for _, c := range []struct{ dep, fw string }{
		{"next", "nextjs"}, {"@nestjs/core", "nestjs"}, {"express", "express"}, {"fastapi", "fastapi"},
		{"django", "django"}, {"flask", "flask"},
	} {
		if deps[c.dep] {
			return c.fw
		}
	}
	return ""
}

// ---- data stores ----

var (
	createTableRe = regexp.MustCompile("(?i)create\\s+table\\s+(?:if\\s+not\\s+exists\\s+)?((?:[\"`\\w]+\\.)?[\"`\\w]+)")
	prismaModelRe = regexp.MustCompile(`(?m)^\s*model\s+(\w+)\s*\{`)
	djangoModelRe = regexp.MustCompile(`(?m)^class\s+(\w+)\s*\([^)]*(?:models\.Model|db\.Model|SQLModel)[^)]*\)`)
	tableNameRe   = regexp.MustCompile(`__tablename__\s*=\s*["'](\w+)["']`)
)

func tablesFromSQL(sql string) []string {
	var out []string
	for _, m := range createTableRe.FindAllStringSubmatch(sql, -1) {
		name := strings.Trim(m[1], "\"`")
		if i := strings.LastIndex(name, "."); i >= 0 {
			name = strings.Trim(name[i+1:], "\"`")
		}
		if name != "" {
			out = append(out, strings.ToLower(name))
		}
	}
	return out
}

func modelsFromPrisma(s string) []string {
	var out []string
	for _, m := range prismaModelRe.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

func tablesFromPython(s string) []string {
	var out []string
	for _, m := range tableNameRe.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	for _, m := range djangoModelRe.FindAllStringSubmatch(s, -1) {
		out = append(out, m[1])
	}
	return out
}

// ---- env ----

var envNameRe = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=`)

// envNames returns only the variable NAMES. The value half of each line is
// never captured.
func envNames(content string) []string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		if m := envNameRe.FindStringSubmatch(line); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

// ---- helpers ----

func readCapped(path string, max int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf, _ := io.ReadAll(io.LimitReader(f, max))
	return string(buf)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func capList(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
