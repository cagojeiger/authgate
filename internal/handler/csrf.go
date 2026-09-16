package handler

import (
	"crypto/subtle"
	"net/http"
)

// CSRF cookie base names. The cookies are HttpOnly and travel only between an
// authgate page and authgate's own POST endpoint, so no relying party reads
// them.
const (
	logoutCSRFCookie = "end_session_csrf"
	deviceCSRFCookie = "device_csrf"
)

// csrfCookieName returns the name the CSRF cookie is set and read under.
//
// Outside dev it carries the __Host- prefix (RFC 6265bis §4.1.3.2), which the
// browser only honors for a Secure, host-only cookie with Path=/. That is what
// keeps a sibling subdomain — any other *.project-jelly.io app — from writing
// a cookie authgate would read back: without the prefix, a cookie set with
// Domain=project-jelly.io shadows ours and plain double-submit compares the
// attacker's token against itself (OWASP CSRF Prevention Cheat Sheet, "Naive
// Double-Submit"). SameSite is no defense here: it is scoped to the
// registrable domain, so a sibling subdomain counts as same-site.
//
// devMode drops the prefix because the prefix requires Secure: Chrome and
// Safari ignore a __Host- cookie over plain http on localhost entirely, which
// would make every local approval fail its CSRF check. There is no fallback to
// the unprefixed name in production — accepting both would hand the attacker
// back the cookie they can write.
func csrfCookieName(base string, devMode bool) string {
	if devMode {
		return base
	}
	return "__Host-" + base
}

// setCSRFCookie issues a CSRF cookie. Path is / because __Host- requires it;
// a narrower path was never a defense, since cookies are not origin- or
// path-isolated against a writer on a sibling subdomain.
func setCSRFCookie(w http.ResponseWriter, base, token string, devMode bool) {
	//nolint:gosec // Secure=false is allowed only in explicit DEV_MODE for localhost development.
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName(base, devMode),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   !devMode,
	})
}

// clearCSRFCookie expires a CSRF cookie. Every attribute but the value and
// MaxAge must match setCSRFCookie or the browser keeps the old cookie.
func clearCSRFCookie(w http.ResponseWriter, base string, devMode bool) {
	//nolint:gosec // Secure=false is allowed only in explicit DEV_MODE for localhost development.
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName(base, devMode),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   !devMode,
	})
}

// validCSRFToken reports whether the submitted form token matches the cookie.
// The comparison is constant time, and an empty form token never passes.
func validCSRFToken(r *http.Request, base, formToken string, devMode bool) bool {
	cookieToken := ""
	if c, err := r.Cookie(csrfCookieName(base, devMode)); err == nil {
		cookieToken = c.Value
	}
	return formToken != "" && subtle.ConstantTimeCompare([]byte(formToken), []byte(cookieToken)) == 1
}

// sameOriginPost reports whether a state-changing POST came from authgate's
// own pages, using the signals the browser itself supplies and the form cannot
// forge.
//
// Sec-Fetch-Site is the precise one: a form on a sibling subdomain sends
// "same-site", not "same-origin", so it is refused even though its cookies are
// same-site. Origin is the fallback for browsers without Fetch Metadata; it is
// compared against the Host the request was routed to, which an attacker
// cannot change without losing the route to authgate.
//
// When the browser sends neither header the request is left to the CSRF token
// check. Every browser that can be driven into a cross-site POST sends at
// least Origin, so the gap is non-browser callers, which are not the threat
// this guards.
func sameOriginPost(r *http.Request, devMode bool) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin"
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	scheme := "https"
	if devMode {
		scheme = "http"
	}
	return origin == scheme+"://"+r.Host
}
