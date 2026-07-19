package dast

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"
)

const (
	maxURLs   = 200
	userAgent = "Trojan-DAST/1.0 (security scanner — authorized use only)"
)

// Endpoint represents a discovered HTTP endpoint.
type Endpoint struct {
	URL         string   `json:"url"`
	Method      string   `json:"method"`      // "GET" or "POST"
	FormFields  []string `json:"formFields"`  // <input name="..."> values
	QueryParams []string `json:"queryParams"` // distinct query param keys
}

// CrawlResult holds everything the crawler discovered.
type CrawlResult struct {
	Endpoints []Endpoint `json:"endpoints"`
	TechHints []string   `json:"techHints"` // e.g. "nextjs", "fastapi", "react"
}

// Crawl performs a BFS HTTP crawl starting from baseURL up to the given depth.
// It stays on the same host, follows up to maxURLs pages, and respects timeoutSec.
func Crawl(baseURL string, depth, timeoutSec int) CrawlResult {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	base, err := url.Parse(baseURL)
	if err != nil {
		return CrawlResult{}
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// follow redirects but stay on same host
			if req.URL.Host != base.Host {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	type queueItem struct {
		rawURL string
		depth  int
	}

	visited := map[string]bool{}
	queue := []queueItem{{rawURL: baseURL, depth: 0}}
	techHints := map[string]bool{}
	var endpoints []Endpoint

	for len(queue) > 0 && len(visited) < maxURLs {
		select {
		case <-ctx.Done():
			goto done
		default:
		}

		item := queue[0]
		queue = queue[1:]

		normalized := normalizeURL(item.rawURL)
		if normalized == "" || visited[normalized] {
			continue
		}
		visited[normalized] = true

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, item.rawURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", userAgent)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		// Collect tech hints from response headers.
		detectFromHeaders(resp.Header, techHints)

		// Parse HTML for links, forms, and inline hints.
		links, forms, pageHints := parseHTML(resp.Body, base, item.rawURL)
		resp.Body.Close()

		for h := range pageHints {
			techHints[h] = true
		}

		// Add this page as a GET endpoint.
		endpoints = append(endpoints, Endpoint{
			URL:         item.rawURL,
			Method:      "GET",
			QueryParams: queryKeys(item.rawURL),
		})

		// Add forms as POST endpoints.
		for _, f := range forms {
			endpoints = append(endpoints, f)
		}

		// Enqueue discovered links if we haven't hit the depth limit.
		if item.depth < depth {
			for _, link := range links {
				n := normalizeURL(link)
				if n != "" && !visited[n] && sameHost(link, base) {
					queue = append(queue, queueItem{rawURL: link, depth: item.depth + 1})
				}
			}
		}
	}

done:
	hints := make([]string, 0, len(techHints))
	for h := range techHints {
		hints = append(hints, h)
	}

	return CrawlResult{
		Endpoints: deduplicateEndpoints(endpoints),
		TechHints: hints,
	}
}

// parseHTML extracts links, forms, and tech hints from an HTML response body.
func parseHTML(body interface{ Read([]byte) (int, error) }, base *url.URL, pageURL string) (links []string, forms []Endpoint, hints map[string]bool) {
	hints = map[string]bool{}

	doc, err := html.Parse(body.(interface {
		Read([]byte) (int, error)
		Close() error
	}))
	if err != nil {
		return
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a":
				href := attr(n, "href")
				if href != "" {
					if abs := resolveURL(href, base, pageURL); abs != "" {
						links = append(links, abs)
					}
				}

			case "form":
				action := attr(n, "action")
				method := strings.ToUpper(attr(n, "method"))
				if method == "" {
					method = "GET"
				}
				formURL := resolveURL(action, base, pageURL)
				if formURL == "" {
					formURL = pageURL
				}

				var fields []string
				collectInputs(n, &fields)

				forms = append(forms, Endpoint{
					URL:        formURL,
					Method:     method,
					FormFields: fields,
				})

			case "script":
				src := attr(n, "src")
				if strings.Contains(src, "_next/") {
					hints["nextjs"] = true
				}
				if strings.Contains(src, "react") || strings.Contains(src, "React") {
					hints["react"] = true
				}

			case "meta":
				name := strings.ToLower(attr(n, "name"))
				content := attr(n, "content")
				if name == "generator" {
					if strings.Contains(strings.ToLower(content), "next") {
						hints["nextjs"] = true
					}
					if strings.Contains(strings.ToLower(content), "nuxt") {
						hints["nuxt"] = true
					}
					if strings.Contains(strings.ToLower(content), "remix") {
						hints["remix"] = true
					}
				}
			}
		}

		if n.Type == html.TextNode {
			// __NEXT_DATA__ in page source = Next.js
			if strings.Contains(n.Data, "__NEXT_DATA__") {
				hints["nextjs"] = true
			}
			if strings.Contains(n.Data, "window.__nuxt__") {
				hints["nuxt"] = true
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return
}

// collectInputs recursively finds <input name="..."> inside a form node.
func collectInputs(n *html.Node, fields *[]string) {
	if n.Type == html.ElementNode && (n.Data == "input" || n.Data == "select" || n.Data == "textarea") {
		if name := attr(n, "name"); name != "" {
			*fields = append(*fields, name)
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		collectInputs(c, fields)
	}
}

// detectFromHeaders inspects HTTP response headers for tech hints.
func detectFromHeaders(headers http.Header, hints map[string]bool) {
	server := strings.ToLower(headers.Get("Server"))
	powered := strings.ToLower(headers.Get("X-Powered-By"))

	if strings.Contains(server, "fastapi") || strings.Contains(powered, "fastapi") {
		hints["fastapi"] = true
	}
	if strings.Contains(server, "django") || strings.Contains(powered, "django") {
		hints["django"] = true
	}
	if strings.Contains(powered, "express") {
		hints["express"] = true
	}
	if strings.Contains(powered, "next.js") {
		hints["nextjs"] = true
	}
	if headers.Get("x-nextjs-cache") != "" || headers.Get("x-nextjs-matched-path") != "" {
		hints["nextjs"] = true
	}
	if strings.Contains(powered, "php") {
		hints["php"] = true
	}
	if strings.Contains(powered, "rails") {
		hints["rails"] = true
	}
	if strings.Contains(powered, "asp.net") {
		hints["aspnet"] = true
	}
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func resolveURL(href string, base *url.URL, pageURL string) string {
	if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "mailto:") {
		return ""
	}
	page, err := url.Parse(pageURL)
	if err != nil {
		page = base
	}
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	resolved := page.ResolveReference(ref)
	resolved.Fragment = ""
	return resolved.String()
}

func sameHost(rawURL string, base *url.URL) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return u.Host == base.Host
}

func normalizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	u.Fragment = ""
	return u.String()
}

func queryKeys(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	var keys []string
	for k := range u.Query() {
		keys = append(keys, k)
	}
	return keys
}

func deduplicateEndpoints(endpoints []Endpoint) []Endpoint {
	seen := map[string]bool{}
	out := []Endpoint{}
	for _, e := range endpoints {
		key := e.Method + ":" + e.URL
		if !seen[key] {
			seen[key] = true
			out = append(out, e)
		}
	}
	return out
}
