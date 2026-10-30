package graph

import (
	"strings"
	"unicode"
)

// Auth guard heuristics shared by the JS/TS and Python builders. Without
// type information "is this an auth check?" is answered by name: the
// middleware, decorator, dependency or call a real app uses to gate a route
// is almost always called something like requireAuth, login_required or
// get_current_user. The word lists below are deliberately narrow, because a
// false guard hides a real finding while a missed guard only adds noise.

// nameWords splits an identifier into lowercase words on non-alphanumerics
// and camelCase boundaries: "requireAuth" -> [require auth],
// "get_current_user" -> [get current user], "passport.authenticate" ->
// [passport authenticate].
func nameWords(name string) []string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(name)
	for i, r := range rs {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush()
			continue
		}
		if unicode.IsUpper(r) && len(cur) > 0 {
			prevLower := unicode.IsLower(rs[i-1]) || unicode.IsDigit(rs[i-1])
			nextLower := i+1 < len(rs) && unicode.IsLower(rs[i+1])
			if prevLower || (unicode.IsUpper(rs[i-1]) && nextLower) {
				flush()
			}
		}
		cur = append(cur, r)
	}
	flush()
	return words
}

// authWords alone mark a name as an auth guard.
var authWords = map[string]bool{
	"auth": true, "authenticate": true, "authenticated": true, "authentication": true,
	"authed": true, "login": true, "loggedin": true, "signedin": true, "jwt": true,
	"protect": true, "protected": true, "guard": true, "oauth2": true,
}

// authVerbs + authObjects together mark a guard: requireUser, ensure_admin,
// verify_api_key, is_logged ... ("user" alone is not a guard).
var (
	authVerbs   = map[string]bool{"require": true, "requires": true, "ensure": true, "verify": true, "check": true, "assert": true, "must": true, "is": true, "validate": true, "current": true, "required": true}
	authObjects = map[string]bool{"user": true, "admin": true, "logged": true, "signed": true, "session": true, "token": true, "key": true, "apikey": true, "role": true, "roles": true, "permission": true, "permissions": true, "staff": true, "superuser": true}
	// notGuardWords veto a match: rate limiters, validators, routers and
	// loggers often carry "login"/"auth" in their name without gating
	// anything (loginLimiter, authRouter, validateLoginBody).
	notGuardWords = map[string]bool{"limiter": true, "limit": true, "ratelimit": true, "router": true, "routes": true, "route": true, "logger": true, "log": true, "cors": true, "parser": true, "schema": true, "body": true, "callback": true, "page": true, "form": true, "handler": true, "controller": true}
)

// isAuthLikeName reports whether a middleware, decorator or dependency name
// looks like an auth gate (requireAuth, login_required, get_current_user,
// passport.authenticate, oauth2_scheme).
func isAuthLikeName(name string) bool {
	words := nameWords(name)
	if len(words) == 0 {
		return false
	}
	verb, object, auth := false, false, false
	for _, w := range words {
		if notGuardWords[w] {
			return false
		}
		if authWords[w] {
			auth = true
		}
		if authVerbs[w] {
			verb = true
		}
		if authObjects[w] {
			object = true
		}
	}
	return auth || (verb && object)
}

// guardCallNames are bare (or trailing) callee names that check the signed-in
// user in Next.js / Node apps: NextAuth getServerSession and v5 auth(), Clerk
// auth()/currentUser()/getAuth(), next-auth/jwt getToken.
var guardCallNames = map[string]bool{
	"getServerSession": true, "auth": true, "currentUser": true, "getAuth": true,
	"getToken": true, "getCurrentUser": true, "requireAuth": true, "requireUser": true,
	"get_current_user": true, "verifyIdToken": true, "verify_id_token": true,
	"jwtVerify": true, "login_required": true, "getKindeServerSession": true,
}

// guardMethods are methods that check a session when called on an auth
// object: supabase.auth.getUser(), auth.protect(), auth.api.getSession()
// (better-auth), supabase.auth.get_user() in Python.
var guardMethods = map[string]bool{
	"getUser": true, "getSession": true, "getClaims": true, "protect": true,
	"get_user": true, "get_session": true, "verifyIdToken": true, "verify_id_token": true,
}

// isGuardCall reports whether a callee expression (source text, e.g.
// "supabase.auth.getUser", "auth", "jwt.verify") checks authentication.
func isGuardCall(callee string) bool {
	callee = strings.TrimSpace(callee)
	callee = strings.TrimSuffix(callee, "!")
	last := callee
	recv := ""
	if i := strings.LastIndex(callee, "."); i >= 0 {
		last, recv = callee[i+1:], strings.ToLower(callee[:i])
	}
	if recv == "" && guardCallNames[last] {
		return true
	}
	if recv != "" && guardMethods[last] && strings.Contains(recv, "auth") {
		return true
	}
	if (recv == "jwt" || strings.HasSuffix(recv, ".jwt")) && (last == "verify" || last == "decode") {
		return true
	}
	// requireSession(), ensureAdmin(), with_auth(), withAuth(handler), ...
	words := nameWords(last)
	if len(words) >= 2 {
		switch words[0] {
		case "require", "requires", "ensure", "assert", "verify", "check", "with", "must":
			return isAuthLikeName(last)
		}
	}
	return false
}

// isSelfBlockingGuard reports whether a guard call stops the request by
// itself when there is no user (requireAuth(), auth.protect(), withAuth(fn),
// login_required), as opposed to merely reading the session
// (supabase.auth.getUser(), getServerSession(), auth()), which only gates
// when the function then refuses: see blocksRequest.
func isSelfBlockingGuard(callee string) bool {
	last := callee
	if i := strings.LastIndex(callee, "."); i >= 0 {
		last = callee[i+1:]
	}
	if last == "protect" || last == "verify" || last == "decode" || last == "jwtVerify" {
		return true
	}
	words := nameWords(last)
	if len(words) == 0 {
		return false
	}
	switch words[0] {
	case "require", "requires", "ensure", "assert", "with", "must", "login":
		return true
	}
	return false
}

// blocksRequest reports whether a function's source refuses the request
// somewhere: a 401/403, a redirect, a throw/raise, abort(). A session read
// plus one of these is the "check the user, bail out if missing" shape; a
// session read alone (Supabase's best-effort session refresh in
// middleware) guards nothing.
func blocksRequest(body string) bool {
	for _, m := range []string{"401", "403", "redirect", "Redirect", "throw ", "raise ", "abort(", "Unauthorized", "unauthorized", "Forbidden", "forbidden", "notFound(", "HTTPException"} {
		if strings.Contains(body, m) {
			return true
		}
	}
	return false
}

// propagateGuards finishes Node.Guarded for one builder's graph slice.
// direct holds functions that check auth in their own body; routeGuarded
// holds sources gated by route-level means (middleware in the handler list,
// a decorator, a FastAPI dependency, Next.js middleware coverage).
//
//  1. A function is guarded if it checks auth itself, or calls (up to two
//     levels deep) a function that does: route -> requireUser() -> getUser().
//  2. Route-gated sources are guarded.
//  3. A non-source function every one of whose reaching sources is guarded
//     is itself guarded ("every route reaching it sits behind auth").
func propagateGuards(g *Graph, direct, routeGuarded map[int]bool) {
	callers := make(map[int][]int)
	calls := make(map[int][]int)
	for _, e := range g.Edges {
		if e.Kind == EdgeCalls {
			callers[e.Dst] = append(callers[e.Dst], e.Src)
			calls[e.Src] = append(calls[e.Src], e.Dst)
		}
	}
	for id := range direct {
		g.Nodes[id].Guarded = true
		frontier := []int{id}
		for depth := 0; depth < 2; depth++ {
			var next []int
			for _, n := range frontier {
				for _, c := range callers[n] {
					if !g.Nodes[c].Guarded {
						g.Nodes[c].Guarded = true
						next = append(next, c)
					}
				}
			}
			frontier = next
		}
	}
	for id, ok := range routeGuarded {
		if ok {
			g.Nodes[id].Guarded = true
		}
	}

	// 3: reachability from guarded vs unguarded sources, never walking
	// through a guarded node from an unguarded source.
	open := make(map[int]bool)
	gated := make(map[int]bool)
	for _, n := range g.Nodes {
		if n.Kind != KindFunc || !n.Source {
			continue
		}
		mark := open
		if n.Guarded {
			mark = gated
		}
		seen := map[int]bool{n.ID: true}
		queue := []int{n.ID}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, nx := range calls[cur] {
				if seen[nx] {
					continue
				}
				seen[nx] = true
				mark[nx] = true
				if !g.Nodes[nx].Guarded {
					queue = append(queue, nx)
				}
			}
		}
	}
	for id := range gated {
		if !open[id] && !g.Nodes[id].Source {
			g.Nodes[id].Guarded = true
		}
	}
}
